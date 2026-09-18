-- =============================================================================
-- 0003_functions.sql — transactional core of the approval loop
--
-- Every state change that must be atomic lives here as one security-definer
-- function. Edge Functions only validate input, verify HMAC, call these, and
-- perform outbound I/O (callbacks, FCM).
--
-- Callable by:
--   * service_role  — record_*, create_agent, get_agent_inbound_context,
--                     prune_fcm_tokens (Edge Functions only)
--   * authenticated — register_fcm_token, unregister_fcm_token (app, via RPC)
-- =============================================================================

create extension if not exists supabase_vault with schema vault;

-- Per-action callback override. n8n's "Wait → On webhook call" node and similar
-- tools issue a unique resume URL per execution, so an inbound action may name
-- its own callback; otherwise the agent's callback_url is used. Only
-- actions-inbound writes this column, and it validates the URL first.
alter table public.action add column callback_url text;

-- -----------------------------------------------------------------------------
-- Device tokens (app → RPC)
-- -----------------------------------------------------------------------------

create function public.register_fcm_token(p_token text)
returns void
language plpgsql
security definer
set search_path = public
as $$
declare
  v_max_tokens constant int := 10;
begin
  if auth.uid() is null then
    raise exception 'unauthorized' using errcode = '28000';
  end if;
  if p_token is null or length(p_token) = 0 or length(p_token) > 4096 then
    raise exception 'invalid_token' using errcode = '22023';
  end if;

  update public.app_user u
     set fcm_tokens = (
           select coalesce(array_agg(t order by ord), '{}')
             from (
               select t, ord
                 from unnest(array_append(array_remove(u.fcm_tokens, p_token), p_token))
                      with ordinality as x(t, ord)
                order by ord desc
                limit v_max_tokens
             ) newest
         )
   where u.id = auth.uid();
end;
$$;

create function public.unregister_fcm_token(p_token text)
returns void
language plpgsql
security definer
set search_path = public
as $$
begin
  if auth.uid() is null then
    raise exception 'unauthorized' using errcode = '28000';
  end if;
  update public.app_user
     set fcm_tokens = array_remove(fcm_tokens, p_token)
   where id = auth.uid();
end;
$$;

-- Removes tokens FCM reported as invalid, wherever they are registered.
create function public.prune_fcm_tokens(p_tokens text[])
returns void
language sql
security definer
set search_path = public
as $$
  update public.app_user
     set fcm_tokens = array(select t from unnest(fcm_tokens) t where t <> all (p_tokens))
   where fcm_tokens && p_tokens;
$$;

-- -----------------------------------------------------------------------------
-- Agents
-- -----------------------------------------------------------------------------

-- Creates an agent and stores its inbound secret in Vault in one transaction,
-- so no orphan secret or secret-less agent can exist (TR-8).
create function public.create_agent(
  p_user_id      uuid,
  p_name         text,
  p_platform     text,
  p_callback_url text,
  p_secret       text
)
returns public.agent
language plpgsql
security definer
set search_path = public
as $$
declare
  v_workspace_id uuid;
  v_agent_id     uuid := gen_random_uuid();
  v_secret_id    uuid;
  v_agent        public.agent;
begin
  select workspace_id into v_workspace_id
    from public.app_user
   where id = p_user_id;
  if v_workspace_id is null then
    raise exception 'workspace_not_found' using errcode = 'P0002';
  end if;
  if p_secret is null or length(p_secret) < 32 then
    raise exception 'invalid_secret' using errcode = '22023';
  end if;

  v_secret_id := vault.create_secret(
    p_secret,
    'agent_inbound_' || v_agent_id::text,
    'Cockpit agent inbound HMAC secret'
  );

  insert into public.agent
    (id, workspace_id, name, platform, callback_url, inbound_secret_id, secret_hint)
  values
    (v_agent_id, v_workspace_id, p_name, p_platform, p_callback_url, v_secret_id, right(p_secret, 4))
  returning * into v_agent;

  return v_agent;
end;
$$;

-- Everything actions-inbound needs to authenticate a request, in one call.
-- Returns no row for an unknown agent.
create function public.get_agent_inbound_context(p_agent_id uuid)
returns table (workspace_id uuid, status text, callback_url text, secret text)
language sql
stable
security definer
set search_path = public
as $$
  select a.workspace_id, a.status, a.callback_url, s.decrypted_secret
    from public.agent a
    left join vault.decrypted_secrets s on s.id = a.inbound_secret_id
   where a.id = p_agent_id;
$$;

-- -----------------------------------------------------------------------------
-- Inbound actions (TR-2)
-- -----------------------------------------------------------------------------

-- Inserts an action idempotently on (agent_id, external_id). Only a genuinely
-- new action gets an audit row and returns device tokens, so a retried inbound
-- request never produces a duplicate push.
create function public.record_action_inbound(
  p_agent_id        uuid,
  p_external_id     text,
  p_type            text,
  p_title           text,
  p_summary         text,
  p_payload         jsonb,
  p_editable_fields text[],
  p_callback_url    text,
  p_expires_at      timestamptz
)
returns table (action_id uuid, is_new boolean, fcm_tokens text[])
language plpgsql
security definer
set search_path = public
as $$
#variable_conflict use_column
declare
  v_workspace_id uuid;
  v_status       text;
  v_action_id    uuid;
  v_tokens       text[];
begin
  select a.workspace_id, a.status
    into v_workspace_id, v_status
    from public.agent a
   where a.id = p_agent_id
     for share;

  if v_workspace_id is null then
    raise exception 'agent_not_found' using errcode = 'P0002';
  end if;
  if v_status <> 'active' then
    raise exception 'agent_disabled' using errcode = 'P0001';
  end if;

  insert into public.action
    (workspace_id, agent_id, external_id, type, title, summary, payload,
     editable_fields, callback_url, expires_at)
  values
    (v_workspace_id, p_agent_id, p_external_id, p_type, p_title, p_summary,
     coalesce(p_payload, '{}'::jsonb), coalesce(p_editable_fields, '{}'),
     p_callback_url, p_expires_at)
  on conflict (agent_id, external_id) do nothing
  returning id into v_action_id;

  if v_action_id is null then
    select id into v_action_id
      from public.action
     where agent_id = p_agent_id and external_id = p_external_id;
    return query select v_action_id, false, '{}'::text[];
    return;
  end if;

  insert into public.audit_entry (workspace_id, action_id, event, original_payload, metadata)
  values (v_workspace_id, v_action_id, 'action_received', p_payload,
          jsonb_build_object('type', p_type));

  update public.agent set last_action_at = now() where id = p_agent_id;

  select coalesce(array_agg(distinct t), '{}')
    into v_tokens
    from public.app_user u
    cross join lateral unnest(u.fcm_tokens) t
   where u.workspace_id = v_workspace_id;

  return query select v_action_id, true, v_tokens;
end;
$$;

-- -----------------------------------------------------------------------------
-- Decisions (TR-3, TR-6)
-- -----------------------------------------------------------------------------

-- Records a decision and its audit row atomically. Outcomes:
--   recorded         decision committed; caller should deliver the callback
--   duplicate        this Idempotency-Key was already used for this workspace;
--                    returns the stored callback payload, never re-decides
--   already_decided  the action is no longer pending (decided elsewhere)
--   expired          the action passed expires_at (marked expired)
--   invalid_edit     edited_payload touches fields not in editable_fields
--   not_found        no such action in the caller's workspace
create function public.record_decision(
  p_action_id       uuid,
  p_actor_user_id   uuid,
  p_decision        text,
  p_edited_payload  jsonb,
  p_reason          text,
  p_idempotency_key text
)
returns table (
  outcome          text,
  callback_url     text,
  callback_payload jsonb,
  agent_id         uuid,
  callback_status  text
)
language plpgsql
security definer
set search_path = public
as $$
#variable_conflict use_column
declare
  v_workspace_id uuid;
  v_action       public.action;
  v_existing     public.audit_entry;
  v_agent_url    text;
  v_edits        jsonb;
  v_payload      jsonb;
  v_now          timestamptz := now();
begin
  if p_decision not in ('approved', 'approved_with_edits', 'rejected') then
    raise exception 'invalid_decision' using errcode = '22023';
  end if;
  if p_idempotency_key is null or length(p_idempotency_key) not between 8 and 200 then
    raise exception 'invalid_idempotency_key' using errcode = '22023';
  end if;

  select workspace_id into v_workspace_id
    from public.app_user
   where id = p_actor_user_id;
  if v_workspace_id is null then
    return query select 'not_found', null::text, null::jsonb, null::uuid, null::text;
    return;
  end if;

  -- Lock the action first so concurrent requests serialize, then check the
  -- key: a racing duplicate sees the committed audit row and replays it.
  select * into v_action
    from public.action
   where id = p_action_id
     for update;

  select * into v_existing
    from public.audit_entry
   where idempotency_key = p_idempotency_key;

  if found then
    if v_existing.workspace_id <> v_workspace_id then
      return query select 'not_found', null::text, null::jsonb, null::uuid, null::text;
      return;
    end if;
    select * into v_action from public.action where id = v_existing.action_id;
    select a.callback_url into v_agent_url from public.agent a where a.id = v_action.agent_id;
    return query select 'duplicate',
                        coalesce(v_action.callback_url, v_agent_url),
                        v_existing.metadata -> 'callback_payload',
                        v_action.agent_id,
                        v_action.callback_status;
    return;
  end if;

  if v_action.id is null or v_action.workspace_id <> v_workspace_id then
    return query select 'not_found', null::text, null::jsonb, null::uuid, null::text;
    return;
  end if;

  if v_action.status <> 'pending' then
    return query select 'already_decided', null::text, null::jsonb, null::uuid, v_action.callback_status;
    return;
  end if;

  if v_action.expires_at is not null and v_action.expires_at <= v_now then
    update public.action set status = 'expired' where id = v_action.id;
    return query select 'expired', null::text, null::jsonb, null::uuid, null::text;
    return;
  end if;

  if p_decision = 'approved_with_edits' then
    v_edits := coalesce(p_edited_payload, '{}'::jsonb);
    if v_edits = '{}'::jsonb
       or exists (
         select 1 from jsonb_object_keys(v_edits) k
          where k <> all (v_action.editable_fields)
       ) then
      return query select 'invalid_edit', null::text, null::jsonb, null::uuid, null::text;
      return;
    end if;
  end if;

  v_payload := jsonb_build_object(
    'action_id',      v_action.id,
    'external_id',    v_action.external_id,
    'decision',       p_decision,
    'payload',        v_action.payload || coalesce(v_edits, '{}'::jsonb),
    'edited_payload', v_edits,
    'reason',         p_reason,
    'decided_at',     v_now
  );

  update public.action
     set status          = 'decided',
         decision        = p_decision,
         decided_by      = p_actor_user_id,
         decided_at      = v_now,
         callback_status = 'pending'
   where id = v_action.id;

  -- Audit is written inside the decision transaction, before any callback
  -- can be attempted (TR-6).
  insert into public.audit_entry
    (workspace_id, action_id, actor_user_id, event, decision,
     original_payload, edited_payload, reason, idempotency_key, metadata)
  values
    (v_workspace_id, v_action.id, p_actor_user_id, 'decision_made', p_decision,
     v_action.payload, v_edits, p_reason, p_idempotency_key,
     jsonb_build_object('callback_payload', v_payload));

  select a.callback_url into v_agent_url from public.agent a where a.id = v_action.agent_id;

  return query select 'recorded',
                      coalesce(v_action.callback_url, v_agent_url),
                      v_payload,
                      v_action.agent_id,
                      'pending'::text;
end;
$$;

-- -----------------------------------------------------------------------------
-- Callback results (TR-7 — retry itself is Phase 2)
-- -----------------------------------------------------------------------------

create function public.record_callback_result(
  p_action_id uuid,
  p_delivered boolean,
  p_detail    text
)
returns void
language plpgsql
security definer
set search_path = public
as $$
declare
  v_workspace_id uuid;
begin
  update public.action
     set callback_status   = case when p_delivered then 'delivered' else 'failed' end,
         callback_attempts = callback_attempts + 1
   where id = p_action_id
  returning workspace_id into v_workspace_id;

  if v_workspace_id is null then
    raise exception 'action_not_found' using errcode = 'P0002';
  end if;

  insert into public.audit_entry (workspace_id, action_id, event, metadata)
  values (
    v_workspace_id,
    p_action_id,
    case when p_delivered then 'callback_delivered' else 'callback_failed' end,
    jsonb_build_object('detail', left(p_detail, 500))
  );
end;
$$;

-- -----------------------------------------------------------------------------
-- Privileges. Supabase grants EXECUTE on new public functions to anon and
-- authenticated by default, so revoke explicitly.
-- -----------------------------------------------------------------------------

revoke all on function public.register_fcm_token(text)   from public, anon;
revoke all on function public.unregister_fcm_token(text) from public, anon;
grant execute on function public.register_fcm_token(text)   to authenticated, service_role;
grant execute on function public.unregister_fcm_token(text) to authenticated, service_role;

revoke all on function public.prune_fcm_tokens(text[]) from public, anon, authenticated;
revoke all on function public.create_agent(uuid, text, text, text, text) from public, anon, authenticated;
revoke all on function public.get_agent_inbound_context(uuid) from public, anon, authenticated;
revoke all on function public.record_action_inbound(uuid, text, text, text, text, jsonb, text[], text, timestamptz) from public, anon, authenticated;
revoke all on function public.record_decision(uuid, uuid, text, jsonb, text, text) from public, anon, authenticated;
revoke all on function public.record_callback_result(uuid, boolean, text) from public, anon, authenticated;

grant execute on function public.prune_fcm_tokens(text[]) to service_role;
grant execute on function public.create_agent(uuid, text, text, text, text) to service_role;
grant execute on function public.get_agent_inbound_context(uuid) to service_role;
grant execute on function public.record_action_inbound(uuid, text, text, text, text, jsonb, text[], text, timestamptz) to service_role;
grant execute on function public.record_decision(uuid, uuid, text, jsonb, text, text) to service_role;
grant execute on function public.record_callback_result(uuid, boolean, text) to service_role;
