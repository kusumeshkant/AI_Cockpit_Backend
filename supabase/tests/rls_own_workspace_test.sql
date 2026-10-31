-- pgTAP: a signed-in user reads their own profile and workspace — with the
-- exact columns the app selects — and never another workspace's rows (RLS
-- under the 0009 column grants). Runs in one transaction and is rolled back.
begin;
create extension if not exists pgtap with schema extensions;

select plan(12);

-- ---------------------------------------------------------------------------
-- Fixtures: Ada and Bo, each with their own workspace (handle_new_user).
-- ---------------------------------------------------------------------------
insert into auth.users (instance_id, id, aud, role, email)
values
  ('00000000-0000-0000-0000-000000000000', '77777777-7777-4777-8777-777777777771',
   'authenticated', 'authenticated', 'ada@test.dev'),
  ('00000000-0000-0000-0000-000000000000', '77777777-7777-4777-8777-777777777772',
   'authenticated', 'authenticated', 'bo@test.dev');

select set_config('t.ada', '77777777-7777-4777-8777-777777777771', true);
select set_config('t.bo',  '77777777-7777-4777-8777-777777777772', true);
select set_config('t.ada_ws',
  (select workspace_id::text from public.app_user where id = current_setting('t.ada')::uuid), true);
select set_config('t.bo_ws',
  (select workspace_id::text from public.app_user where id = current_setting('t.bo')::uuid), true);

select isnt(current_setting('t.ada_ws'), current_setting('t.bo_ws'),
  'fixtures: Ada and Bo are in different workspaces');

-- ---------------------------------------------------------------------------
-- As Ada (authenticated, as PostgREST runs a request with her JWT).
-- ---------------------------------------------------------------------------
set local role authenticated;
select set_config('request.jwt.claims',
  json_build_object('sub', current_setting('t.ada'), 'role', 'authenticated')::text, true);

-- The app's profile read (auth_remote_ds): app_user + embedded workspace plan.
select results_eq(
  $$select u.id::text, u.email, u.workspace_id::text, w.plan
      from public.app_user u left join public.workspace w on w.id = u.workspace_id
     where u.id = current_setting('t.ada')::uuid$$,
  $$values (current_setting('t.ada'), 'ada@test.dev', current_setting('t.ada_ws'), 'solo')$$,
  'Ada reads her own profile and her workspace plan');

select results_eq(
  $$select role from public.app_user where id = current_setting('t.ada')::uuid$$,
  $$values ('owner')$$,
  'Ada reads her role (workspace_role_ds)');

select is_empty(
  $$select id from public.app_user where id = current_setting('t.bo')::uuid$$,
  'Ada cannot read Bo''s profile');

select is_empty(
  $$select id from public.workspace where id = current_setting('t.bo_ws')::uuid$$,
  'Ada cannot read Bo''s workspace');

select results_eq(
  $$select count(id)::int from public.app_user$$, $$values (1)$$,
  'Ada sees exactly one app_user row (her own)');

select results_eq(
  $$select count(id)::int from public.workspace$$, $$values (1)$$,
  'Ada sees exactly one workspace (her own)');

select throws_ok(
  $$select fcm_tokens from public.app_user where id = current_setting('t.ada')::uuid$$,
  '42501', null, 'not even her own push tokens are readable through the API');

select throws_ok(
  $$update public.app_user set email = 'x@test.dev' where id = current_setting('t.ada')::uuid$$,
  '42501', null, 'Ada cannot write her profile directly');

select throws_ok(
  $$insert into public.workspace (name) values ('Sneaky')$$,
  '42501', null, 'Ada cannot create a workspace directly');

-- ---------------------------------------------------------------------------
-- As Bo: the mirror image.
-- ---------------------------------------------------------------------------
select set_config('request.jwt.claims',
  json_build_object('sub', current_setting('t.bo'), 'role', 'authenticated')::text, true);

select results_eq(
  $$select u.id::text, w.id::text from public.app_user u
      join public.workspace w on w.id = u.workspace_id$$,
  $$values (current_setting('t.bo'), current_setting('t.bo_ws'))$$,
  'Bo reads only his own profile and workspace');

-- No JWT (anon): nothing at all.
reset role;
set local role anon;
select throws_ok($$select id from public.workspace$$, '42501', null,
  'anon cannot read workspace');

select * from finish();
rollback;
