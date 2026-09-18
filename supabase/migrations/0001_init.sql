-- =============================================================================
-- 0001_init.sql — Cockpit core schema
--
-- Source of truth: technical/04-technical-blueprint.md §4 (data model) and §8
-- (security). Five tables: workspace, app_user, agent, action, audit_entry.
--
-- Access model (RLS):
--   * The app (role `authenticated`) may only SELECT rows of its own workspace.
--   * All writes to agent / action / audit_entry go through Edge Functions using
--     the service role, which bypasses RLS. No INSERT/UPDATE/DELETE policies are
--     defined for `authenticated`, so those operations are denied by default.
--   * audit_entry is append-only: grants revoked + trigger blocks UPDATE/DELETE.
--
-- Status: scaffold — not yet applied to any Supabase project.
-- =============================================================================

-- gen_random_uuid() is built into Postgres 13+ (Supabase ships 15+).

-- -----------------------------------------------------------------------------
-- workspace — tenant boundary for every RLS policy
-- -----------------------------------------------------------------------------
create table public.workspace (
  id            uuid primary key default gen_random_uuid(),
  name          text not null check (char_length(name) between 1 and 120),
  plan          text not null default 'solo'
                  check (plan in ('solo', 'pro', 'consultant')),
  owner_user_id uuid,                     -- FK added below (circular with app_user)
  created_at    timestamptz not null default now()
);

-- -----------------------------------------------------------------------------
-- app_user — one row per auth user; one workspace per user in v1
-- -----------------------------------------------------------------------------
create table public.app_user (
  id           uuid primary key references auth.users (id) on delete cascade,
  workspace_id uuid not null references public.workspace (id) on delete cascade,
  email        text not null,
  role         text not null default 'owner' check (role in ('owner', 'approver')),
  fcm_tokens   text[] not null default '{}',   -- maintained by rpc register_fcm_token (TODO)
  locale       text not null default 'en',
  created_at   timestamptz not null default now()
);

alter table public.workspace
  add constraint workspace_owner_user_fk
  foreign key (owner_user_id) references public.app_user (id)
  on delete set null deferrable initially deferred;

-- -----------------------------------------------------------------------------
-- agent — external automation authenticated by an HMAC inbound secret
--
-- NOTE: the blueprint lists `inbound_secret_hash`, but verifying an HMAC needs
-- the raw secret, which a hash cannot provide. The secret is therefore stored
-- encrypted in Supabase Vault and referenced here by id. Only `secret_hint`
-- (last 4 chars) is readable by the app. Plaintext is returned once by
-- agents-create / agents-rotate-secret (TR-8).
-- -----------------------------------------------------------------------------
create table public.agent (
  id                uuid primary key default gen_random_uuid(),
  workspace_id      uuid not null references public.workspace (id) on delete cascade,
  name              text not null check (char_length(name) between 1 and 60),
  callback_url      text not null check (callback_url like 'https://%'),
  platform          text not null default 'custom'
                      check (platform in ('n8n', 'make', 'zapier', 'custom')),
  inbound_secret_id uuid not null,        -- vault.secrets.id
  secret_hint       text,
  status            text not null default 'active' check (status in ('active', 'disabled')),
  last_action_at    timestamptz,
  created_at        timestamptz not null default now()
);

create index agent_workspace_idx on public.agent (workspace_id);

-- -----------------------------------------------------------------------------
-- action — a proposed agent action awaiting / holding a decision
-- -----------------------------------------------------------------------------
create table public.action (
  id                uuid primary key default gen_random_uuid(),
  workspace_id      uuid not null references public.workspace (id) on delete cascade,
  agent_id          uuid not null references public.agent (id) on delete cascade,
  external_id       text not null,        -- agent's own id; idempotent inbound
  type              text not null,        -- email | diff | table | any (TR-5)
  title             text not null,
  summary           text,
  payload           jsonb not null default '{}'::jsonb,
  editable_fields   text[] not null default '{}',
  status            text not null default 'pending'
                      check (status in ('pending', 'decided', 'expired')),
  decision          text check (decision in ('approved', 'approved_with_edits', 'rejected')),
  decided_by        uuid references public.app_user (id) on delete set null,
  decided_at        timestamptz,
  callback_status   text not null default 'pending'
                      check (callback_status in ('pending', 'delivered', 'retrying', 'failed')),
  callback_attempts integer not null default 0 check (callback_attempts >= 0),
  expires_at        timestamptz,
  created_at        timestamptz not null default now(),

  constraint action_agent_external_uniq unique (agent_id, external_id),
  constraint action_decision_consistent check ((status = 'decided') = (decision is not null))
);

-- Pending feed (TR-4 poll) and realtime filter.
create index action_pending_idx on public.action (workspace_id, created_at desc)
  where status = 'pending';
-- Retry scheduler (TR-7).
create index action_callback_retry_idx on public.action (callback_status)
  where callback_status = 'retrying';

-- -----------------------------------------------------------------------------
-- audit_entry — append-only audit trail (TR-6)
--
-- FKs use the default ON DELETE NO ACTION on purpose: cascades would be
-- DELETE/UPDATE operations that the append-only trigger rejects. Deleting a
-- workspace/user with audit history therefore needs an explicit, audited admin
-- procedure (DPDP / GDPR erasure) — TODO.
-- -----------------------------------------------------------------------------
create table public.audit_entry (
  id               bigint generated always as identity primary key,
  workspace_id     uuid not null references public.workspace (id),
  action_id        uuid not null references public.action (id),
  actor_user_id    uuid references public.app_user (id),   -- null for system events
  event            text not null check (event in (
                     'action_received', 'decision_made', 'callback_attempted',
                     'callback_delivered', 'callback_failed')),
  decision         text check (decision in ('approved', 'approved_with_edits', 'rejected')),
  original_payload jsonb,
  edited_payload   jsonb,
  reason           text check (char_length(reason) <= 500),
  idempotency_key  text unique,           -- TR-3; null for non-decision events
  metadata         jsonb not null default '{}'::jsonb,
  created_at       timestamptz not null default now()
);

create index audit_entry_workspace_created_idx
  on public.audit_entry (workspace_id, created_at desc);
create index audit_entry_action_idx on public.audit_entry (action_id);

create function public.audit_entry_forbid_mutation()
returns trigger
language plpgsql
as $$
begin
  raise exception 'audit_entry is append-only: % is not allowed', tg_op;
end;
$$;

create trigger audit_entry_append_only
  before update or delete on public.audit_entry
  for each row execute function public.audit_entry_forbid_mutation();

-- =============================================================================
-- Row-Level Security
-- =============================================================================

-- Workspace of the calling user. SECURITY DEFINER so policies on app_user do
-- not recurse into themselves.
create function public.current_workspace_id()
returns uuid
language sql
stable
security definer
set search_path = public
as $$
  select workspace_id from public.app_user where id = auth.uid()
$$;

alter table public.workspace   enable row level security;
alter table public.app_user    enable row level security;
alter table public.agent       enable row level security;
alter table public.action      enable row level security;
alter table public.audit_entry enable row level security;

create policy workspace_select_own on public.workspace
  for select to authenticated using (id = public.current_workspace_id());

create policy app_user_select_own_workspace on public.app_user
  for select to authenticated using (workspace_id = public.current_workspace_id());

create policy agent_select_own_workspace on public.agent
  for select to authenticated using (workspace_id = public.current_workspace_id());

create policy action_select_own_workspace on public.action
  for select to authenticated using (workspace_id = public.current_workspace_id());

create policy audit_entry_select_own_workspace on public.audit_entry
  for select to authenticated using (workspace_id = public.current_workspace_id());

-- Defence in depth for the append-only log.
revoke update, delete, truncate on public.audit_entry from anon, authenticated;

-- Realtime feed for the app (TR-4); RLS still applies to realtime.
alter publication supabase_realtime add table public.action;

-- TODO(next migrations):
--   * rpc register_fcm_token / unregister_fcm_token (security definer).
--   * rpc decide_action: conditional UPDATE + audit INSERT in one transaction.
--   * workspace + app_user bootstrap on first sign-in (auth.users trigger).
--   * pg_cron schedule for callbacks-retry; payload retention purge per plan.
