-- pgTAP: 0010 — feature_setting. Seeds reproduce today's behaviour (both
-- off), anon reads nothing, authenticated reads key / enabled /
-- min_app_version only and can write nothing, service_role writes.
-- Runs in one transaction and is rolled back.
begin;
create extension if not exists pgtap with schema extensions;

select plan(17);

-- Seeds -----------------------------------------------------------------------
select results_eq(
  $$select key, enabled, min_app_version from public.feature_setting order by key$$,
  $$values ('agent_services'::text, false, null::text), ('agent_triggers', false, null)$$,
  'seeded rows: agent_services and agent_triggers, both off, no min version');

select col_is_pk('public', 'feature_setting', 'key', 'key is the primary key');
select col_not_null('public', 'feature_setting', 'enabled', 'enabled is not null');
select col_default_is('public', 'feature_setting', 'enabled', 'false', 'enabled defaults to false');

select throws_ok($$insert into public.feature_setting (key) values ('Bad-Key')$$,
  '23514', null, 'key must be lower snake case');
select throws_ok($$insert into public.feature_setting (key, min_app_version) values ('x', '1.2')$$,
  '23514', null, 'min_app_version must be x.y.z');

select ok((select relrowsecurity from pg_class where oid = 'public.feature_setting'::regclass),
  'RLS is enabled');
select is(
  (select string_agg(cmd || ':' || array_to_string(roles, ','), ';')
     from pg_policies where schemaname = 'public' and tablename = 'feature_setting'),
  'SELECT:authenticated',
  'the only policy is SELECT for authenticated (no write policy)');

-- A signed-in user (any user; flags are global). ------------------------------
insert into auth.users (instance_id, id, aud, role, email)
values ('00000000-0000-0000-0000-000000000000', 'f1f1f1f1-f1f1-4f1f-8f1f-f1f1f1f1f1f1',
        'authenticated', 'authenticated', 'flags@test.dev');

-- anon --------------------------------------------------------------------------
set local role anon;
select throws_ok($$select key from public.feature_setting$$, '42501', null,
  'anon cannot read feature_setting');
reset role;

-- authenticated -------------------------------------------------------------------
set local role authenticated;
select set_config('request.jwt.claims',
  '{"sub":"f1f1f1f1-f1f1-4f1f-8f1f-f1f1f1f1f1f1","role":"authenticated"}', true);

select results_eq(
  $$select key, enabled, min_app_version from public.feature_setting order by key$$,
  $$values ('agent_services'::text, false, null::text), ('agent_triggers', false, null)$$,
  'authenticated reads key, enabled and min_app_version of every flag');
select throws_ok($$select note from public.feature_setting$$, '42501', null,
  'authenticated cannot read note');
select throws_ok($$select updated_at from public.feature_setting$$, '42501', null,
  'authenticated cannot read updated_at');
select throws_ok($$update public.feature_setting set enabled = true where key = 'agent_triggers'$$,
  '42501', null, 'authenticated cannot update a flag');
select throws_ok($$insert into public.feature_setting (key, enabled) values ('sneaky', true)$$,
  '42501', null, 'authenticated cannot insert a flag');
select throws_ok($$delete from public.feature_setting$$,
  '42501', null, 'authenticated cannot delete flags');
reset role;

-- service_role --------------------------------------------------------------------
set local role service_role;
update public.feature_setting set enabled = true, updated_at = now() where key = 'agent_triggers';
select is((select enabled from public.feature_setting where key = 'agent_triggers'), true,
  'service_role can switch a flag on');
reset role;

-- Nothing else changed: the flag table is independent of workspace data.
select is((select count(*)::int from public.feature_setting), 2, 'no extra rows');

select * from finish();
rollback;
