-- =============================================================================
-- 0014_service_decisions.sql — decisions on service cards through the gateway,
-- reject delivery + retry, and the account-deletion fan-out to services.
--
-- Additive; ordinary agents, their decisions, callbacks and retries behave
-- exactly as before.
--
--   resolve_action_service     the service behind an action in the actor's
--                              workspace (no row for ordinary agents)
--   resolve_agent_service      the service behind a service agent (retries)
--   get_service_endpoint       registry fields a call needs (no secrets)
--   record_decision            same signature and behaviour; for a SERVICE
--       agent the audit keeps {hook} (not the payload) and the stored
--       delivery payload is the slim decision.apply input
--   delete_account_data        same signature and behaviour, plus: before an
--       owner's workspace is deleted, one service_deletion_job per service the
--       workspace consented to or used (service_slug + subject; no PII, no
--       workspace FK, so the job outlives the workspace), counted in
--       account_deletion_log.service_jobs
--   claim_due_deletion_jobs / record_deletion_job_result
--   invoke_service_deletions_retry + pg_cron cockpit-service-deletions-retry
--
-- Privileges: EXECUTE for service_role only, one by one; the invoker runs as
-- its owner from pg_cron and is granted to nobody (as in 0004).
-- =============================================================================

alter table public.account_deletion_log
  add column service_jobs integer not null default 0 check (service_jobs >= 0);

-- -----------------------------------------------------------------------------
-- Resolution
-- -----------------------------------------------------------------------------

-- The service behind [p_action_id] when the action is in [p_user_id]'s
-- workspace and its agent is a service agent; no row otherwise.
create function public.resolve_action_service(p_action_id uuid, p_user_id uuid)
returns table (
  action_status text,
  expires_at    timestamptz,
  idea_id       text,
  agent_id      uuid,
  workspace_id  uuid,
  service_slug  text,
  subject       text,
  access_state  text
)
language sql
stable
security definer
set search_path = public
as $$
  select a.status, a.expires_at, a.payload->>'idea_id', a.agent_id, a.workspace_id,
         s.service_slug, s.subject, s.state
    from public.action a
    join public.app_user u on u.id = p_user_id and u.workspace_id = a.workspace_id
    join public.agent g on g.id = a.agent_id and g.platform = 'service'
    join public.service_access s on s.agent_id = g.id
   where a.id = p_action_id
$$;

-- The service behind a service agent (for retries); no row otherwise.
create function public.resolve_agent_service(p_agent_id uuid)
returns table (workspace_id uuid, service_slug text, subject text, access_state text)
language sql
stable
security definer
set search_path = public
as $$
  select s.workspace_id, s.service_slug, s.subject, s.state
    from public.service_access s
    join public.agent g on g.id = s.agent_id and g.platform = 'service'
   where s.agent_id = p_agent_id
$$;

-- Registry fields a gateway call needs. No key ids, no secrets.
create function public.get_service_endpoint(p_slug text)
returns table (
  slug             text,
  status           text,
  base_url         text,
  contract_version text,
  manifest         jsonb,
  open_until       timestamptz
)
language sql
stable
security definer
set search_path = public
as $$
  select s.slug, s.status, s.base_url, s.contract_version, s.manifest, s.open_until
    from public.agent_service s
   where s.slug = p_slug
$$;

-- -----------------------------------------------------------------------------
-- record_decision: hook-only audit + slim delivery payload for service agents
-- -----------------------------------------------------------------------------

-- Same signature, behaviour and grants as 0003. Only the two payloads differ
-- for a SERVICE agent: the audit's original_payload is {hook}, and the stored
-- callback_payload is the decision.apply input
--   { action_id, external_id, idea_id, decision, reason, decided_by, decided_at }
-- so no card text (topic) enters the audit. Every other agent is unchanged.
create or replace function public.record_decision(
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
  v_platform     text;
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

  select a.platform into v_platform from public.agent a where a.id = v_action.agent_id;

  if v_platform = 'service' then
    v_payload := jsonb_build_object(
      'action_id',   v_action.id,
      'external_id', v_action.external_id,
      'idea_id',     v_action.payload->>'idea_id',
      'decision',    p_decision,
      'reason',      p_reason,
      'decided_by',  p_actor_user_id,
      'decided_at',  v_now
    );
  else
    v_payload := jsonb_build_object(
      'action_id',      v_action.id,
      'external_id',    v_action.external_id,
      'decision',       p_decision,
      'payload',        v_action.payload || coalesce(v_edits, '{}'::jsonb),
      'edited_payload', v_edits,
      'reason',         p_reason,
      'decided_at',     v_now
    );
  end if;

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
     case when v_platform = 'service'
          then jsonb_build_object('hook', v_action.payload->'hook')
          else v_action.payload end,
     v_edits, p_reason, p_idempotency_key,
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
-- delete_account_data: + service deletion jobs
-- -----------------------------------------------------------------------------

-- Same signature, behaviour and grants as 0007. Added: an owner's deletion
-- first queues one service_deletion_job per service the workspace consented
-- to or used; the count is logged as service_jobs. Approvers queue nothing.
create or replace function public.delete_account_data(p_user_id uuid)
returns table (
  outcome           text,
  role              text,
  workspace_deleted boolean,
  members_moved     integer
)
language plpgsql
security definer
set search_path = public
as $$
declare
  v_user         public.app_user;
  v_workspace_id uuid;
  v_member       record;
  v_new_ws       uuid;
  v_moved        integer := 0;
  v_actions      integer := 0;
  v_audit        integer := 0;
  v_jobs         integer := 0;
begin
  if p_user_id is null then
    raise exception 'invalid_user' using errcode = '22023';
  end if;

  -- Two deletions of the same user never interleave.
  perform pg_advisory_xact_lock(hashtextextended('account_delete:' || p_user_id::text, 0));

  select * into v_user from public.app_user u where u.id = p_user_id for update;
  if not found then
    return query select 'already_deleted'::text, null::text, false, 0;
    return;
  end if;

  perform set_config('cockpit.erasure', 'on', true);

  if v_user.role = 'owner' then
    v_workspace_id := v_user.workspace_id;
    perform 1 from public.workspace w where w.id = v_workspace_id for update;

    -- Every other member keeps their account in a new personal workspace.
    for v_member in
      select m.id, m.email
        from public.app_user m
       where m.workspace_id = v_workspace_id
         and m.id <> p_user_id
       order by m.created_at, m.id
    loop
      insert into public.workspace (name)
      values (left(coalesce(nullif(split_part(v_member.email, '@', 1), ''), 'My workspace'), 120))
      returning id into v_new_ws;

      update public.app_user
         set workspace_id = v_new_ws,
             role = 'owner'
       where id = v_member.id;

      update public.workspace
         set owner_user_id = v_member.id
       where id = v_new_ws;

      v_moved := v_moved + 1;
    end loop;

    -- 0014: ask every service the workspace used to forget it. Queued before
    -- the cascade removes service_access; the job keeps only slug + subject.
    insert into public.service_deletion_job (service_slug, subject)
    select s.service_slug, s.subject
      from public.service_access s
     where s.workspace_id = v_workspace_id
       and (s.consented_at is not null or s.first_used_at is not null);
    get diagnostics v_jobs = row_count;

    -- Vault secrets are not reachable by FK cascade.
    delete from vault.secrets s
     where s.id in (
       select a.inbound_secret_id from public.agent a
        where a.workspace_id = v_workspace_id and a.inbound_secret_id is not null
       union
       select t.trigger_secret_id from public.agent_trigger t
        where t.workspace_id = v_workspace_id
     );

    -- audit_entry has no cascade (append-only); remove it explicitly first.
    delete from public.audit_entry e where e.workspace_id = v_workspace_id;
    get diagnostics v_audit = row_count;

    select count(*)::int into v_actions from public.action a where a.workspace_id = v_workspace_id;

    delete from public.app_user u where u.id = p_user_id;
    -- Cascades: agent, action, agent_trigger, trigger_run, agent_rate,
    -- service_access, gateway_call (0011).
    delete from public.workspace w where w.id = v_workspace_id;
  else
    update public.audit_entry e
       set actor_user_id = null
     where e.actor_user_id = p_user_id;
    get diagnostics v_audit = row_count;

    -- action.decided_by / trigger_run.triggered_by are ON DELETE SET NULL.
    delete from public.app_user u where u.id = p_user_id;
  end if;

  perform set_config('cockpit.erasure', 'off', true);

  insert into public.account_deletion_log
    (subject_hash, role, workspace_deleted, members_moved, actions_deleted, audit_entries, service_jobs)
  values (
    encode(sha256(convert_to(p_user_id::text, 'UTF8')), 'hex'),
    v_user.role,
    v_user.role = 'owner',
    v_moved,
    v_actions,
    v_audit,
    v_jobs
  );

  return query select 'deleted'::text, v_user.role, v_user.role = 'owner', v_moved;
end;
$$;

-- -----------------------------------------------------------------------------
-- Deletion jobs: claim (lease) + result (backoff)
-- -----------------------------------------------------------------------------

-- Due jobs (pending, next_attempt_at reached), row-locked and leased so
-- overlapping runs never send the same job twice.
create function public.claim_due_deletion_jobs(p_limit integer, p_lease_seconds integer default 120)
returns table (id uuid, service_slug text, subject text, attempts integer)
language plpgsql
security definer
set search_path = public
as $$
#variable_conflict use_column
begin
  if p_limit is null or p_limit not between 1 and 100 then
    raise exception 'invalid_limit' using errcode = '22023';
  end if;
  if p_lease_seconds is null or p_lease_seconds not between 10 and 3600 then
    raise exception 'invalid_lease' using errcode = '22023';
  end if;
  return query
  with due as (
    select j.id
      from public.service_deletion_job j
     where j.status = 'pending' and j.next_attempt_at <= now()
     order by j.next_attempt_at
     limit p_limit
       for update skip locked
  )
  update public.service_deletion_job j
     set next_attempt_at = now() + make_interval(secs => p_lease_seconds),
         updated_at = now()
    from due
   where j.id = due.id
  returning j.id, j.service_slug, j.subject, j.attempts;
end;
$$;

-- Records one attempt: done; pending again after [p_retry_in_seconds]; or
-- terminal failed when no retry is given. [p_detail] is a short code.
create function public.record_deletion_job_result(
  p_job_id           uuid,
  p_done             boolean,
  p_detail           text,
  p_retry_in_seconds integer
)
returns text
language plpgsql
security definer
set search_path = public
as $$
declare
  v_status text;
begin
  if p_retry_in_seconds is not null and p_retry_in_seconds < 0 then
    raise exception 'invalid_retry_delay' using errcode = '22023';
  end if;
  v_status := case when p_done then 'done' when p_retry_in_seconds is not null then 'pending' else 'failed' end;
  update public.service_deletion_job j
     set status = v_status,
         attempts = j.attempts + 1,
         last_error = case when p_done then null else left(p_detail, 100) end,
         next_attempt_at = case when v_status = 'pending'
                                then now() + make_interval(secs => p_retry_in_seconds)
                                else j.next_attempt_at end,
         updated_at = now()
   where j.id = p_job_id and j.status = 'pending';
  if not found then
    if exists (select 1 from public.service_deletion_job where id = p_job_id) then
      return (select status from public.service_deletion_job where id = p_job_id);
    end if;
    raise exception 'job_not_found' using errcode = 'P0002';
  end if;
  return v_status;
end;
$$;

-- pg_cron → service-deletions-retry (0004 pattern): skips the HTTP call when
-- nothing is due or the endpoint / cron secret are not configured in Vault.
--   select vault.create_secret('<functions base>/service-deletions-retry', 'cockpit_service_deletions_retry_url');
create function public.invoke_service_deletions_retry()
returns bigint
language plpgsql
security definer
set search_path = public
as $$
declare
  v_url    text;
  v_secret text;
begin
  if not exists (
    select 1 from public.service_deletion_job
     where status = 'pending' and next_attempt_at <= now()
  ) then
    return null;
  end if;
  select decrypted_secret into v_url
    from vault.decrypted_secrets where name = 'cockpit_service_deletions_retry_url';
  select decrypted_secret into v_secret
    from vault.decrypted_secrets where name = 'cockpit_cron_secret';
  if v_url is null or v_secret is null then
    return null;
  end if;
  return net.http_post(
    url                  := v_url,
    body                 := '{}'::jsonb,
    headers              := jsonb_build_object('Content-Type', 'application/json', 'X-Cron-Secret', v_secret),
    timeout_milliseconds := 55000
  );
end;
$$;

select cron.schedule('cockpit-service-deletions-retry', '*/5 * * * *', 'select public.invoke_service_deletions_retry()');

-- -----------------------------------------------------------------------------
-- Privileges (explicit, one by one). record_decision / delete_account_data
-- keep their grants (CREATE OR REPLACE preserves them).
-- -----------------------------------------------------------------------------

revoke all on function public.invoke_service_deletions_retry() from public, anon, authenticated, service_role;

grant execute on function public.resolve_action_service(uuid, uuid)  to service_role;
grant execute on function public.resolve_agent_service(uuid)          to service_role;
grant execute on function public.get_service_endpoint(text)           to service_role;
grant execute on function public.claim_due_deletion_jobs(integer, integer) to service_role;
grant execute on function public.record_deletion_job_result(uuid, boolean, text, integer) to service_role;
