-- 0010 — feature flags in the database (no app re-release to switch a feature)
--
-- One row per feature. The row is the source of truth for both sides:
--   * Edge Functions read it through _shared/flags.ts (service role, cached
--     ≤ 30 s per isolate). A missing row falls back to the old env variable
--     (FEATURE_<KEY>); a failed read fails closed (feature off).
--   * The app reads key / enabled / min_app_version after sign-in and hides
--     the feature's UI while it is off (fail closed when nothing is cached).
--
-- Writes only with the service role (scripts/set-feature.ts); no client role
-- can write and anon can read nothing. Seeds reproduce today's behaviour:
-- agent_triggers was off unless FEATURE_AGENT_TRIGGERS=true, so its row is
-- off; agent_services is new and off.
--
-- Grants follow the 0009 matrix (keep privileges_test.sql and
-- scripts/deploy-check.ts in sync).

create table public.feature_setting (
  key             text primary key check (key ~ '^[a-z][a-z0-9_]{0,62}$'),
  enabled         boolean not null default false,
  -- Lowest app version (semver x.y.z) that may show the feature; null = any.
  min_app_version text check (min_app_version ~ '^[0-9]+\.[0-9]+\.[0-9]+$'),
  note            text,
  updated_at      timestamptz not null default now()
);

comment on table public.feature_setting is
  'Feature flags (source of truth for Edge Functions and the app). Service-role writes only.';

insert into public.feature_setting (key, enabled, note) values
  ('agent_triggers', false, 'Agent Triggers: the app starts an agent (0005).'),
  ('agent_services', false, 'Agent services gateway (agent-proxy).');

alter table public.feature_setting enable row level security;

-- Flags are global (not per workspace): every signed-in user reads every row.
create policy feature_setting_read on public.feature_setting
  for select to authenticated using (true);

-- Column reads only: note / updated_at are operator data.
grant select (key, enabled, min_app_version) on public.feature_setting to authenticated;
grant select, insert, update, delete on public.feature_setting to service_role;
