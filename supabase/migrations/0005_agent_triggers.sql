-- =============================================================================
-- 0005_agent_triggers.sql — Agent Triggers (app → agent), feature-flagged
--
-- The reverse direction of the core loop: a signed-in user starts an agent.
-- Cockpit POSTs a signed payload (X-Cockpit-Trigger-Signature, HMAC with a
-- per-agent trigger secret) to the agent's trigger_url.
--
-- Everything here is additive and feature-isolated: two new tables (droppable
-- with the feature), four new RPCs, and three new audit events. No existing
-- function, RPC or policy changes. The Edge Functions gate on
-- FEATURE_AGENT_TRIGGERS; with it off these objects are simply unused.
--
-- Secrets: the trigger secret lives in Vault (agent_trigger.trigger_secret_id),
-- written inside configure_agent_trigger (same transaction, no orphans) and
-- returned only to the service role by begin_trigger_run. Clients can read
-- secret_hint, never the secret or its Vault id.
-- =============================================================================

-- -----------------------------------------------------------------------------
-- Audit: three new events. Trigger events belong to an agent, not an action,
-- so action_id may be null for them — and only for them.
-- -----------------------------------------------------------------------------
alter table public.audit_entry drop constraint audit_entry_event_check;
alter table public.audit_entry add constraint audit_entry_event_check check (event in (
  'action_received', 'decision_made', 'callback_attempted',
  'callback_delivered', 'callback_failed',
  'trigger_configured', 'trigger_fired', 'trigger_failed'));

alter table public.audit_entry alter column action_id drop not null;
alter table public.audit_entry add constraint audit_entry_action_required check (
  action_id is not null
  or event in ('trigger_configured', 'trigger_fired', 'trigger_failed'));

-- -----------------------------------------------------------------------------
-- Tables
-- -----------------------------------------------------------------------------

-- One trigger per agent.
create table public.agent_trigger (
  agent_id          uuid        primary key references public.agent (id) on delete cascade,
  workspace_id      uuid        not null references public.workspace (id) on delete cascade,
  trigger_url       text        not null check (trigger_url ~ '^https?://'),
  trigger_secret_id uuid        not null,              -- vault.secrets.id
  secret_hint       text        not null,
  enabled           boolean     not null default true,
  min_interval_secs integer     not null default 30 check (min_interval_secs between 1 and 86400),
  created_at        timestamptz not null default now(),
  updated_at        timestamptz not null default now()
);

create index agent_trigger_workspace_idx on public.agent_trigger (workspace_id);

-- One row per attempt to start an agent.
create table public.trigger_run (
  id           uuid        primary key default gen_random_uuid(),
  agent_id     uuid        not null references public.agent (id) on delete cascade,
  workspace_id uuid        not null references public.workspace (id) on delete cascade,
  triggered_by uuid        references public.app_user (id) on delete set null,
  status       text        not null default 'pending' check (status in ('pending', 'sent', 'failed')),
  detail       text        check (char_length(detail) <= 500),
  created_at   timestamptz not null default now()
);

-- Rate-limit lookup (latest run per agent) and history.
create index trigger_run_agent_created_idx on public.trigger_run (agent_id, created_at desc);
create index trigger_run_workspace_created_idx on public.trigger_run (workspace_id, created_at desc);

-- -----------------------------------------------------------------------------
-- RLS: owners' workspace may read; nobody writes from the client.
-- -----------------------------------------------------------------------------
alter table public.agent_trigger enable row level security;
alter table public.trigger_run   enable row level security;

create policy agent_trigger_select_own_workspace on public.agent_trigger
  for select to authenticated using (workspace_id = public.current_workspace_id());

create policy trigger_run_select_own_workspace on public.trigger_run
  for select to authenticated using (workspace_id = public.current_workspace_id());

revoke all on public.agent_trigger from anon, authenticated;
revoke all on public.trigger_run   from anon, authenticated;

-- Column-level read: never the Vault secret id.
grant select (agent_id, workspace_id, trigger_url, secret_hint, enabled,
              min_interval_secs, created_at, updated_at)
  on public.agent_trigger to authenticated;
grant select on public.trigger_run to authenticated;

-- -----------------------------------------------------------------------------
-- RPCs
-- -----------------------------------------------------------------------------

-- Creates or reconfigures the trigger of an agent the actor owns. The secret is
-- written to Vault in the same transaction (created on first configure,
-- replaced in place on reconfigure, so the old one stops working). URL policy
-- (https / SSRF) is enforced by the Edge Function; this only checks the scheme.
create function public.configure_agent_trigger(
  p_actor_user_id uuid,
  p_agent_id      uuid,
  p_trigger_url   text,
  p_secret        text,
  p_min_interval  integer default 30
)
returns table (
  agent_id          uuid,
  trigger_url       text,
  secret_hint       text,
  enabled           boolean,
  min_interval_secs integer,
  updated_at        timestamptz
)
language plpgsql
security definer
set search_path = public
as $$
#variable_conflict use_column
declare
  v_agent    public.agent;
  v_existing public.agent_trigger;
  v_secret_id uuid;
  v_hint     text;
begin
  if p_trigger_url is null or p_trigger_url !~ '^https?://' or length(p_trigger_url) > 2048 then
    raise exception 'invalid_trigger_url' using errcode = '22023';
  end if;
  if p_min_interval is null or p_min_interval not between 1 and 86400 then
    raise exception 'invalid_min_interval' using errcode = '22023';
  end if;
  if p_secret is null or length(p_secret) < 32 then
    raise exception 'invalid_secret' using errcode = '22023';
  end if;

  select a.* into v_agent
    from public.agent a
    join public.app_user u on u.workspace_id = a.workspace_id
   where a.id = p_agent_id and u.id = p_actor_user_id and u.role = 'owner';
  if v_agent.id is null then
    raise exception 'agent_not_found' using errcode = 'P0002';
  end if;

  v_hint := right(p_secret, 4);

  select t.* into v_existing
    from public.agent_trigger t
   where t.agent_id = p_agent_id
     for update;

  if v_existing.agent_id is null then
    v_secret_id := vault.create_secret(
      p_secret, 'agent_trigger_' || p_agent_id::text, 'Cockpit agent trigger HMAC secret');
    insert into public.agent_trigger
      (agent_id, workspace_id, trigger_url, trigger_secret_id, secret_hint, min_interval_secs)
    values
      (p_agent_id, v_agent.workspace_id, p_trigger_url, v_secret_id, v_hint, p_min_interval);
  else
    perform vault.update_secret(v_existing.trigger_secret_id, p_secret);
    update public.agent_trigger t
       set trigger_url = p_trigger_url,
           secret_hint = v_hint,
           min_interval_secs = p_min_interval,
           updated_at = now()
     where t.agent_id = p_agent_id;
  end if;

  insert into public.audit_entry (workspace_id, action_id, actor_user_id, event, metadata)
  values (v_agent.workspace_id, null, p_actor_user_id, 'trigger_configured',
          jsonb_build_object('agent_id', p_agent_id, 'min_interval_secs', p_min_interval,
                             'rotated', v_existing.agent_id is not null));

  return query
    select t.agent_id, t.trigger_url, t.secret_hint, t.enabled, t.min_interval_secs, t.updated_at
      from public.agent_trigger t
     where t.agent_id = p_agent_id;
end;
$$;

-- Enables / disables the trigger of an agent the actor owns.
create function public.set_agent_trigger_enabled(
  p_actor_user_id uuid,
  p_agent_id      uuid,
  p_enabled       boolean
)
returns table (
  agent_id          uuid,
  trigger_url       text,
  secret_hint       text,
  enabled           boolean,
  min_interval_secs integer,
  updated_at        timestamptz
)
language plpgsql
security definer
set search_path = public
as $$
#variable_conflict use_column
declare
  v_workspace_id uuid;
begin
  if p_enabled is null then
    raise exception 'invalid_enabled' using errcode = '22023';
  end if;

  update public.agent_trigger t
     set enabled = p_enabled, updated_at = now()
    from public.app_user u
   where t.agent_id = p_agent_id
     and u.id = p_actor_user_id
     and u.role = 'owner'
     and u.workspace_id = t.workspace_id
  returning t.workspace_id into v_workspace_id;

  if v_workspace_id is null then
    -- Unknown agent, not the owner, or no trigger configured: all look alike.
    raise exception 'trigger_not_found' using errcode = 'P0002';
  end if;

  insert into public.audit_entry (workspace_id, action_id, actor_user_id, event, metadata)
  values (v_workspace_id, null, p_actor_user_id, 'trigger_configured',
          jsonb_build_object('agent_id', p_agent_id, 'enabled', p_enabled));

  return query
    select t.agent_id, t.trigger_url, t.secret_hint, t.enabled, t.min_interval_secs, t.updated_at
      from public.agent_trigger t
     where t.agent_id = p_agent_id;
end;
$$;

-- Starts a trigger run for an agent in the actor's workspace. Outcomes:
--   ok              run recorded ('pending') + audit 'trigger_fired'; url and
--                   secret returned for delivery (service role only)
--   not_found       no such agent in the actor's workspace
--   not_configured  the agent has no trigger
--   disabled        trigger (or agent) is disabled
--   rate_limited    a run started less than min_interval_secs ago
-- The trigger row is locked so concurrent calls serialize on the interval
-- check: at most one 'ok' per interval.
create function public.begin_trigger_run(p_agent_id uuid, p_actor_user_id uuid)
returns table (
  outcome        text,
  trigger_run_id uuid,
  trigger_url    text,
  trigger_secret text,
  retry_after_seconds integer
)
language plpgsql
security definer
set search_path = public
as $$
#variable_conflict use_column
declare
  v_workspace_id uuid;
  v_agent_status text;
  v_trigger      public.agent_trigger;
  v_last         timestamptz;
  v_run_id       uuid;
  v_secret       text;
begin
  select a.workspace_id, a.status into v_workspace_id, v_agent_status
    from public.agent a
    join public.app_user u on u.workspace_id = a.workspace_id
   where a.id = p_agent_id and u.id = p_actor_user_id;
  if v_workspace_id is null then
    return query select 'not_found', null::uuid, null::text, null::text, null::integer;
    return;
  end if;

  select t.* into v_trigger
    from public.agent_trigger t
   where t.agent_id = p_agent_id
     for update;
  if v_trigger.agent_id is null then
    return query select 'not_configured', null::uuid, null::text, null::text, null::integer;
    return;
  end if;
  if not v_trigger.enabled or v_agent_status <> 'active' then
    return query select 'disabled', null::uuid, null::text, null::text, null::integer;
    return;
  end if;

  select max(r.created_at) into v_last
    from public.trigger_run r
   where r.agent_id = p_agent_id;
  if v_last is not null
     and v_last > clock_timestamp() - make_interval(secs => v_trigger.min_interval_secs) then
    return query select 'rate_limited', null::uuid, null::text, null::text,
      greatest(1, ceil(extract(epoch from
        (v_last + make_interval(secs => v_trigger.min_interval_secs) - clock_timestamp()))))::integer;
    return;
  end if;

  insert into public.trigger_run (agent_id, workspace_id, triggered_by, status, created_at)
  values (p_agent_id, v_workspace_id, p_actor_user_id, 'pending', clock_timestamp())
  returning id into v_run_id;

  insert into public.audit_entry (workspace_id, action_id, actor_user_id, event, metadata)
  values (v_workspace_id, null, p_actor_user_id, 'trigger_fired',
          jsonb_build_object('agent_id', p_agent_id, 'trigger_run_id', v_run_id));

  select s.decrypted_secret into v_secret
    from vault.decrypted_secrets s
   where s.id = v_trigger.trigger_secret_id;

  return query select 'ok', v_run_id, v_trigger.trigger_url, v_secret, null::integer;
end;
$$;

-- Records the delivery result of a run. 'failed' is audited as
-- 'trigger_failed'. A run that was already recorded is left as is.
create function public.record_trigger_result(
  p_trigger_run_id uuid,
  p_delivered      boolean,
  p_detail         text
)
returns text
language plpgsql
security definer
set search_path = public
as $$
declare
  v_run public.trigger_run;
begin
  update public.trigger_run r
     set status = case when p_delivered then 'sent' else 'failed' end,
         detail = left(p_detail, 500)
   where r.id = p_trigger_run_id and r.status = 'pending'
  returning r.* into v_run;

  if v_run.id is null then
    select r.* into v_run from public.trigger_run r where r.id = p_trigger_run_id;
    if v_run.id is null then
      raise exception 'trigger_run_not_found' using errcode = 'P0002';
    end if;
    return v_run.status;
  end if;

  if not p_delivered then
    insert into public.audit_entry (workspace_id, action_id, actor_user_id, event, metadata)
    values (v_run.workspace_id, null, v_run.triggered_by, 'trigger_failed',
            jsonb_build_object('agent_id', v_run.agent_id, 'trigger_run_id', v_run.id,
                               'detail', left(p_detail, 500)));
  end if;

  return v_run.status;
end;
$$;

-- -----------------------------------------------------------------------------
-- Privileges: service role only.
-- -----------------------------------------------------------------------------
revoke all on function public.configure_agent_trigger(uuid, uuid, text, text, integer) from public, anon, authenticated;
revoke all on function public.set_agent_trigger_enabled(uuid, uuid, boolean) from public, anon, authenticated;
revoke all on function public.begin_trigger_run(uuid, uuid) from public, anon, authenticated;
revoke all on function public.record_trigger_result(uuid, boolean, text) from public, anon, authenticated;

grant execute on function public.configure_agent_trigger(uuid, uuid, text, text, integer) to service_role;
grant execute on function public.set_agent_trigger_enabled(uuid, uuid, boolean) to service_role;
grant execute on function public.begin_trigger_run(uuid, uuid) to service_role;
grant execute on function public.record_trigger_result(uuid, boolean, text) to service_role;
