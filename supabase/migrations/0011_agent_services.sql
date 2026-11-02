-- =============================================================================
-- 0011_agent_services.sql — agent services gateway: data layer + RPCs
--
-- Cockpit-hosted "agent services" (e.g. a content creator) that a workspace
-- switches on from the app. The future agent-proxy Edge Function will call
-- them on the user's behalf; this migration only adds the state it needs.
-- Everything is additive: existing rows, rules, RPCs and policies keep their
-- behaviour (feature flag `agent_services`, 0010, stays off).
--
--   agent_service         registry (one row per service; admin-managed via
--                         register_agent_service / scripts/register-service.ts)
--   service_access        a workspace's consent + state for one service
--   gateway_rate          fixed-window limits per user + service + op class
--   gateway_nonce         replay guard for signed service responses
--   gateway_call          per-call metrics, ids only (no payloads)
--   service_deletion_job  outbox for "delete this subject's data" requests to
--                         services; no FK to workspace and no PII, so it
--                         outlives the workspace it was queued for
--
-- agent: platform gains 'service'. A service agent (one per workspace and
-- service, created by enable_service) has no callback_url / inbound secret —
-- allowed ONLY for platform = 'service'; every other row keeps both required.
-- action: `revision` (edits by the service bump it later). audit_entry: four
-- new events; the two service events carry no action.
--
-- Manifest (agent_service.manifest, validated in depth by
-- functions/_shared/service_manifest.ts; the database checks its shape):
--   { "ui": "native" | "sdui", "ui_schema_version": 1,
--     "ops": { "<op>": { "class": "read" | "write" | "destructive",
--                        "roles": ["owner", "approver"],
--                        "timeout_ms": 1..30000,
--                        "max_request_bytes": n, "max_response_bytes": n } },
--     "card_types": [..], "data_categories": [..], "deletion_op": "<op>" }
--
-- Privileges follow the 0009 matrix (privileges_test.sql and
-- scripts/deploy-check.ts are updated in the same change):
--   authenticated  SELECT of a safe column list of agent_service (never
--                  base_url, signing key ids or the manifest), only for
--                  active / paused services; SELECT of its own workspace's
--                  service_access rows (safe columns; not subject /
--                  consented_by). No writes, no RPCs.
--   service_role   DML on every new table, EXECUTE on the new RPCs.
--   anon           nothing.
-- =============================================================================

-- -----------------------------------------------------------------------------
-- Existing tables (additive)
-- -----------------------------------------------------------------------------

alter table public.agent drop constraint agent_platform_check;
alter table public.agent add constraint agent_platform_check
  check (platform in ('n8n', 'make', 'zapier', 'custom', 'service'));

alter table public.agent alter column callback_url drop not null;
alter table public.agent alter column inbound_secret_id drop not null;
alter table public.agent add constraint agent_endpoint_required check (
  platform = 'service' or (callback_url is not null and inbound_secret_id is not null));

alter table public.action add column revision integer not null default 1
  check (revision >= 1);

alter table public.audit_entry drop constraint audit_entry_event_check;
alter table public.audit_entry add constraint audit_entry_event_check check (event in (
  'action_received', 'decision_made', 'callback_attempted',
  'callback_delivered', 'callback_failed',
  'trigger_configured', 'trigger_fired', 'trigger_failed',
  'action_updated', 'action_withdrawn', 'service_enabled', 'service_disabled'));

alter table public.audit_entry drop constraint audit_entry_action_required;
alter table public.audit_entry add constraint audit_entry_action_required check (
  action_id is not null
  or event in ('trigger_configured', 'trigger_fired', 'trigger_failed',
               'service_enabled', 'service_disabled'));

-- -----------------------------------------------------------------------------
-- Registry
-- -----------------------------------------------------------------------------

create table public.agent_service (
  slug                   text        primary key check (slug ~ '^[a-z][a-z0-9-]{1,39}$'),
  display_name           text        not null check (char_length(display_name) between 1 and 60),
  description            text        not null default '' check (char_length(description) <= 500),
  icon                   text        check (char_length(icon) <= 200),
  -- https in the cloud; the proxy applies the callback URL policy (http only
  -- with the local-development switch).
  base_url               text        not null check (base_url ~ '^https?://[^\s]+$'),
  status                 text        not null default 'draft'
                           check (status in ('draft', 'active', 'paused', 'retired')),
  contract_version       text        not null default '1.0'
                           check (contract_version ~ '^[0-9]+\.[0-9]+$'),
  min_app_version        text        check (min_app_version ~ '^[0-9]+\.[0-9]+\.[0-9]+$'),
  -- coalesce: a missing key yields NULL, which a CHECK would let through.
  manifest               jsonb       not null check (coalesce(
                           jsonb_typeof(manifest) = 'object'
                           and manifest->>'ui' in ('native', 'sdui')
                           and jsonb_typeof(manifest->'ui_schema_version') = 'number'
                           and jsonb_typeof(manifest->'ops') = 'object', false)),
  ui                     text        generated always as (manifest->>'ui') stored,
  ui_schema_version      integer     generated always as ((manifest->>'ui_schema_version')::integer) stored,
  signing_key_current_id uuid,       -- vault.secrets.id
  signing_key_next_id    uuid,       -- vault.secrets.id (rotation)
  consecutive_failures   integer     not null default 0 check (consecutive_failures >= 0),
  open_until             timestamptz,  -- circuit breaker
  created_at             timestamptz not null default now(),
  updated_at             timestamptz not null default now()
);

create table public.service_access (
  id              uuid        primary key default gen_random_uuid(),
  workspace_id    uuid        not null references public.workspace (id) on delete cascade,
  service_slug    text        not null references public.agent_service (slug),
  agent_id        uuid        references public.agent (id) on delete set null,
  state           text        not null default 'active'
                    check (state in ('active', 'disabled', 'blocked')),
  -- The id sent to the service for this workspace (raw workspace id for now).
  subject         text        not null check (char_length(subject) between 1 and 128),
  consent_version text        check (char_length(consent_version) between 1 and 32),
  consented_at    timestamptz,
  consented_by    uuid        references public.app_user (id) on delete set null,
  first_used_at   timestamptz,
  created_at      timestamptz not null default now(),
  updated_at      timestamptz not null default now(),
  constraint service_access_workspace_service_uniq unique (workspace_id, service_slug)
);

create index service_access_service_idx on public.service_access (service_slug);

create table public.gateway_rate (
  user_id      uuid        not null references public.app_user (id) on delete cascade,
  service_slug text        not null,
  op_class     text        not null check (op_class in ('read', 'write', 'destructive')),
  window_start timestamptz not null,
  count        integer     not null default 0 check (count >= 0),
  primary key (user_id, service_slug, op_class, window_start)
);

create table public.gateway_nonce (
  key_id  uuid        not null,
  nonce   text        not null check (char_length(nonce) between 16 and 128),
  seen_at timestamptz not null default now(),
  primary key (key_id, nonce)
);

create index gateway_nonce_seen_idx on public.gateway_nonce (seen_at);

create table public.gateway_call (
  id           uuid        primary key default gen_random_uuid(),
  workspace_id uuid        not null references public.workspace (id) on delete cascade,
  service_slug text        not null,
  op           text        not null check (op ~ '^[a-z][a-z0-9_.-]{0,63}$'),
  status       integer     not null check (status between 100 and 599),
  latency_ms   integer     not null check (latency_ms >= 0),
  created_at   timestamptz not null default now()
);

create index gateway_call_service_created_idx on public.gateway_call (service_slug, created_at desc);

create table public.service_deletion_job (
  id              uuid        primary key default gen_random_uuid(),
  service_slug    text        not null references public.agent_service (slug),
  subject         text        not null check (char_length(subject) between 1 and 128),
  status          text        not null default 'pending'
                    check (status in ('pending', 'sent', 'failed', 'done')),
  attempts        integer     not null default 0 check (attempts >= 0),
  next_attempt_at timestamptz not null default now(),
  last_error      text        check (char_length(last_error) <= 100),  -- a code, never a body
  created_at      timestamptz not null default now(),
  updated_at      timestamptz not null default now()
);

create index service_deletion_job_due_idx on public.service_deletion_job (next_attempt_at)
  where status in ('pending', 'failed');

-- -----------------------------------------------------------------------------
-- RLS (SELECT-only policies; writes only through the service role)
-- -----------------------------------------------------------------------------

alter table public.agent_service        enable row level security;
alter table public.service_access       enable row level security;
alter table public.gateway_rate         enable row level security;
alter table public.gateway_nonce        enable row level security;
alter table public.gateway_call         enable row level security;
alter table public.service_deletion_job enable row level security;

-- Drafts and retired services stay invisible to the app.
create policy agent_service_read_listed on public.agent_service
  for select to authenticated using (status in ('active', 'paused'));

create policy service_access_select_own_workspace on public.service_access
  for select to authenticated using (workspace_id = public.current_workspace_id());

-- -----------------------------------------------------------------------------
-- RPCs (service role)
-- -----------------------------------------------------------------------------

-- Everything the proxy needs to authorize a call, in one read. Creates
-- nothing. No signing key ids or secrets. access_state / subject / agent_id
-- are null when the workspace never enabled the service.
create function public.resolve_service_access(p_user_id uuid, p_slug text)
returns table (
  workspace_id         uuid,
  role                 text,
  slug                 text,
  display_name         text,
  status               text,
  base_url             text,
  contract_version     text,
  min_app_version      text,
  manifest             jsonb,
  ui                   text,
  ui_schema_version    integer,
  consecutive_failures integer,
  open_until           timestamptz,
  access_state         text,
  subject              text,
  agent_id             uuid,
  consent_version      text
)
language plpgsql
stable
security definer
set search_path = public
as $$
#variable_conflict use_column
declare
  v_user public.app_user;
begin
  select * into v_user from public.app_user u where u.id = p_user_id;
  if v_user.id is null then
    raise exception 'workspace_not_found' using errcode = 'P0002';
  end if;
  if not exists (select 1 from public.agent_service s where s.slug = p_slug) then
    raise exception 'service_not_found' using errcode = 'P0002';
  end if;

  return query
    select v_user.workspace_id, v_user.role,
           s.slug, s.display_name, s.status, s.base_url, s.contract_version,
           s.min_app_version, s.manifest, s.ui, s.ui_schema_version,
           s.consecutive_failures, s.open_until,
           a.state, a.subject, a.agent_id, a.consent_version
      from public.agent_service s
      left join public.service_access a
        on a.service_slug = s.slug and a.workspace_id = v_user.workspace_id
     where s.slug = p_slug;
end;
$$;

-- Turns a service on for the actor's workspace. Owner only, idempotent:
--   * first time: creates service_access (subject = workspace id) and the
--     workspace's service agent row (platform 'service', lazily: only when
--     the access row has none), records consent, audits 'service_enabled'.
--   * re-enable after disable_service: same row and agent, re-activated.
--   * already active with the same consent version: no change, no audit.
--   * already active, new consent version: consent updated, audited.
-- Refusals: not the owner → forbidden; unknown / draft / retired service →
-- service_not_found; paused → service_paused; blocked access → service_blocked.
create function public.enable_service(p_user_id uuid, p_slug text, p_consent_version text)
returns table (
  service_slug    text,
  state           text,
  consent_version text,
  consented_at    timestamptz,
  agent_id        uuid,
  changed         boolean
)
language plpgsql
security definer
set search_path = public
as $$
#variable_conflict use_column
declare
  v_user     public.app_user;
  v_service  public.agent_service;
  v_access   public.service_access;
  v_agent_id uuid;
  v_changed  boolean := true;
begin
  if p_consent_version is null or char_length(p_consent_version) not between 1 and 32 then
    raise exception 'invalid_consent_version' using errcode = '22023';
  end if;

  select * into v_user from public.app_user u where u.id = p_user_id;
  if v_user.id is null then
    raise exception 'workspace_not_found' using errcode = 'P0002';
  end if;
  if v_user.role <> 'owner' then
    raise exception 'forbidden' using errcode = '42501';
  end if;

  select * into v_service from public.agent_service s where s.slug = p_slug;
  if v_service.slug is null or v_service.status in ('draft', 'retired') then
    raise exception 'service_not_found' using errcode = 'P0002';
  end if;
  if v_service.status = 'paused' then
    raise exception 'service_paused' using errcode = 'P0001';
  end if;

  -- Serialize concurrent enables of the same service in the same workspace.
  perform pg_advisory_xact_lock(
    hashtextextended('service_access:' || v_user.workspace_id::text || ':' || p_slug, 0));

  select * into v_access
    from public.service_access a
   where a.workspace_id = v_user.workspace_id and a.service_slug = p_slug
     for update;

  if v_access.state = 'blocked' then
    raise exception 'service_blocked' using errcode = '42501';
  end if;

  if v_access.id is not null
     and v_access.state = 'active'
     and v_access.consent_version = p_consent_version then
    v_changed := false;
  else
    v_agent_id := v_access.agent_id;
    if v_agent_id is null then
      insert into public.agent (workspace_id, name, platform, status)
      values (v_user.workspace_id, left(v_service.display_name, 60), 'service', 'active')
      returning id into v_agent_id;
    else
      update public.agent g set status = 'active' where g.id = v_agent_id;
    end if;

    if v_access.id is null then
      insert into public.service_access
        (workspace_id, service_slug, agent_id, state, subject,
         consent_version, consented_at, consented_by)
      values
        (v_user.workspace_id, p_slug, v_agent_id, 'active', v_user.workspace_id::text,
         p_consent_version, now(), p_user_id);
    else
      update public.service_access a
         set state = 'active',
             agent_id = v_agent_id,
             consent_version = p_consent_version,
             consented_at = now(),
             consented_by = p_user_id,
             updated_at = now()
       where a.id = v_access.id;
    end if;

    insert into public.audit_entry (workspace_id, action_id, actor_user_id, event, metadata)
    values (v_user.workspace_id, null, p_user_id, 'service_enabled',
            jsonb_build_object('service_slug', p_slug,
                               'consent_version', p_consent_version,
                               'agent_id', v_agent_id,
                               'previous_state', v_access.state));
  end if;

  return query
    select a.service_slug, a.state, a.consent_version, a.consented_at, a.agent_id, v_changed
      from public.service_access a
     where a.workspace_id = v_user.workspace_id and a.service_slug = p_slug;
end;
$$;

-- Turns a service off for the actor's workspace. Owner only, idempotent:
-- active → disabled (service agent disabled too, audited 'service_disabled');
-- never enabled / already disabled / blocked → no change, no audit (a
-- blocked row stays blocked). Returns no row when it was never enabled.
create function public.disable_service(p_user_id uuid, p_slug text)
returns table (
  service_slug    text,
  state           text,
  consent_version text,
  consented_at    timestamptz,
  agent_id        uuid,
  changed         boolean
)
language plpgsql
security definer
set search_path = public
as $$
#variable_conflict use_column
declare
  v_user   public.app_user;
  v_access public.service_access;
begin
  select * into v_user from public.app_user u where u.id = p_user_id;
  if v_user.id is null then
    raise exception 'workspace_not_found' using errcode = 'P0002';
  end if;
  if v_user.role <> 'owner' then
    raise exception 'forbidden' using errcode = '42501';
  end if;
  if not exists (select 1 from public.agent_service s where s.slug = p_slug) then
    raise exception 'service_not_found' using errcode = 'P0002';
  end if;

  perform pg_advisory_xact_lock(
    hashtextextended('service_access:' || v_user.workspace_id::text || ':' || p_slug, 0));

  select * into v_access
    from public.service_access a
   where a.workspace_id = v_user.workspace_id and a.service_slug = p_slug
     for update;

  if v_access.state = 'active' then
    update public.service_access a
       set state = 'disabled', updated_at = now()
     where a.id = v_access.id;
    if v_access.agent_id is not null then
      update public.agent g set status = 'disabled' where g.id = v_access.agent_id;
    end if;
    insert into public.audit_entry (workspace_id, action_id, actor_user_id, event, metadata)
    values (v_user.workspace_id, null, p_user_id, 'service_disabled',
            jsonb_build_object('service_slug', p_slug, 'agent_id', v_access.agent_id));
  end if;

  return query
    select a.service_slug, a.state, a.consent_version, a.consented_at, a.agent_id,
           v_access.state = 'active'
      from public.service_access a
     where a.workspace_id = v_user.workspace_id and a.service_slug = p_slug;
end;
$$;

-- Counts one call for (user, service, op class) in the current fixed window
-- and reports whether it exceeds [p_max]. Mirrors hit_rate_limit (0004):
-- single upsert, earlier windows for the same key dropped.
create function public.hit_gateway_rate(
  p_user_id uuid,
  p_slug    text,
  p_class   text,
  p_max     integer,
  p_window  interval
)
returns table (limited boolean, hits integer, retry_after_seconds integer)
language plpgsql
security definer
set search_path = public
as $$
declare
  v_seconds double precision := extract(epoch from p_window);
  v_start   timestamptz;
  v_hits    integer;
begin
  if p_max is null or p_max < 1 or v_seconds is null or v_seconds < 1 then
    raise exception 'invalid_rate_limit' using errcode = '22023';
  end if;
  if p_class is null or p_class not in ('read', 'write', 'destructive') then
    raise exception 'invalid_op_class' using errcode = '22023';
  end if;

  v_start := to_timestamp(floor(extract(epoch from now()) / v_seconds) * v_seconds);

  insert into public.gateway_rate as r (user_id, service_slug, op_class, window_start, count)
  values (p_user_id, p_slug, p_class, v_start, 1)
  on conflict (user_id, service_slug, op_class, window_start) do update set count = r.count + 1
  returning r.count into v_hits;

  delete from public.gateway_rate
   where user_id = p_user_id and service_slug = p_slug and op_class = p_class
     and window_start < v_start;

  return query select
    v_hits > p_max,
    v_hits,
    greatest(1, ceil(extract(epoch from (v_start + p_window - now()))))::integer;
end;
$$;

-- Records one proxied call (ids and numbers only). A 2xx also stamps the
-- workspace's first use of the service.
create function public.record_gateway_call(
  p_workspace_id uuid,
  p_slug         text,
  p_op           text,
  p_status       integer,
  p_latency_ms   integer
)
returns void
language plpgsql
security definer
set search_path = public
as $$
begin
  if p_op is null or p_op !~ '^[a-z][a-z0-9_.-]{0,63}$' then
    raise exception 'invalid_op' using errcode = '22023';
  end if;
  if p_status is null or p_status not between 100 and 599
     or p_latency_ms is null or p_latency_ms < 0 then
    raise exception 'invalid_gateway_call' using errcode = '22023';
  end if;

  insert into public.gateway_call (workspace_id, service_slug, op, status, latency_ms)
  values (p_workspace_id, p_slug, p_op, p_status, p_latency_ms);

  if p_status between 200 and 299 then
    update public.service_access a
       set first_used_at = now(), updated_at = now()
     where a.workspace_id = p_workspace_id and a.service_slug = p_slug
       and a.first_used_at is null;
  end if;
end;
$$;

-- Admin: inserts or updates a registry row (scripts/register-service.ts).
-- A new row starts as 'draft' unless [p_status] says otherwise; an update
-- keeps the status when [p_status] is null. Signing secrets go to Vault in
-- the same transaction: given on insert (required) or to rotate both keys.
-- Returns whether the row was created and whether keys were (re)written;
-- never a secret or a Vault id.
create function public.register_agent_service(
  p_slug             text,
  p_display_name     text,
  p_description      text,
  p_icon             text,
  p_base_url         text,
  p_contract_version text,
  p_min_app_version  text,
  p_manifest         jsonb,
  p_status           text,
  p_signing_current  text,
  p_signing_next     text
)
returns table (slug text, status text, created boolean, keys_written boolean)
language plpgsql
security definer
set search_path = public
as $$
#variable_conflict use_column
declare
  v_existing public.agent_service;
  v_current  uuid;
  v_next     uuid;
  v_keys     boolean := p_signing_current is not null or p_signing_next is not null;
begin
  if v_keys and (p_signing_current is null or p_signing_next is null
                 or length(p_signing_current) < 32 or length(p_signing_next) < 32
                 or p_signing_current = p_signing_next) then
    raise exception 'invalid_secret' using errcode = '22023';
  end if;

  select * into v_existing from public.agent_service s where s.slug = p_slug for update;

  if v_existing.slug is null then
    if not v_keys then
      raise exception 'invalid_secret' using errcode = '22023';
    end if;
    v_current := vault.create_secret(p_signing_current, 'agent_service_' || p_slug || '_k1',
                                     'Cockpit agent service signing key');
    v_next := vault.create_secret(p_signing_next, 'agent_service_' || p_slug || '_k2',
                                  'Cockpit agent service signing key (next)');
    insert into public.agent_service
      (slug, display_name, description, icon, base_url, status, contract_version,
       min_app_version, manifest, signing_key_current_id, signing_key_next_id)
    values
      (p_slug, p_display_name, coalesce(p_description, ''), p_icon, p_base_url,
       coalesce(p_status, 'draft'), coalesce(p_contract_version, '1.0'),
       p_min_app_version, p_manifest, v_current, v_next);
  else
    if v_keys then
      perform vault.update_secret(v_existing.signing_key_current_id, p_signing_current);
      perform vault.update_secret(v_existing.signing_key_next_id, p_signing_next);
    end if;
    update public.agent_service s
       set display_name = p_display_name,
           description = coalesce(p_description, ''),
           icon = p_icon,
           base_url = p_base_url,
           status = coalesce(p_status, s.status),
           contract_version = coalesce(p_contract_version, s.contract_version),
           min_app_version = p_min_app_version,
           manifest = p_manifest,
           updated_at = now()
     where s.slug = p_slug;
  end if;

  return query
    select s.slug, s.status, v_existing.slug is null, v_keys
      from public.agent_service s
     where s.slug = p_slug;
end;
$$;

-- -----------------------------------------------------------------------------
-- Privileges (explicit, one by one)
-- -----------------------------------------------------------------------------

grant select (slug, display_name, description, icon, status, contract_version,
              min_app_version, ui, ui_schema_version)
  on public.agent_service to authenticated;
grant select (workspace_id, service_slug, agent_id, state, consent_version,
              consented_at, first_used_at, created_at, updated_at)
  on public.service_access to authenticated;

grant select, insert, update, delete on public.agent_service        to service_role;
grant select, insert, update, delete on public.service_access       to service_role;
grant select, insert, update, delete on public.gateway_rate         to service_role;
grant select, insert, update, delete on public.gateway_nonce        to service_role;
grant select, insert, update, delete on public.gateway_call         to service_role;
grant select, insert, update, delete on public.service_deletion_job to service_role;

grant execute on function public.resolve_service_access(uuid, text)                     to service_role;
grant execute on function public.enable_service(uuid, text, text)                       to service_role;
grant execute on function public.disable_service(uuid, text)                            to service_role;
grant execute on function public.hit_gateway_rate(uuid, text, text, integer, interval)  to service_role;
grant execute on function public.record_gateway_call(uuid, text, text, integer, integer) to service_role;
grant execute on function public.register_agent_service(text, text, text, text, text, text, text, jsonb, text, text, text)
  to service_role;
