-- pgTAP: 0006 — a device token belongs to one user (F05) and agent creation
-- is owner-only (F08). Runs in one transaction and is rolled back.
begin;
create extension if not exists pgtap with schema extensions;

select plan(14);

-- ---------------------------------------------------------------------------
-- Fixtures: owner Uma + approver Vic (same workspace), outsider Walt.
-- ---------------------------------------------------------------------------
insert into auth.users (instance_id, id, aud, role, email)
values
  ('00000000-0000-0000-0000-000000000000', '99999999-9999-4999-8999-999999999991',
   'authenticated', 'authenticated', 'uma@test.dev'),
  ('00000000-0000-0000-0000-000000000000', '99999999-9999-4999-8999-999999999992',
   'authenticated', 'authenticated', 'vic@test.dev'),
  ('00000000-0000-0000-0000-000000000000', '99999999-9999-4999-8999-999999999993',
   'authenticated', 'authenticated', 'walt@test.dev');

select set_config('t.uma',  '99999999-9999-4999-8999-999999999991', true);
select set_config('t.vic',  '99999999-9999-4999-8999-999999999992', true);
select set_config('t.walt', '99999999-9999-4999-8999-999999999993', true);

update public.app_user
   set workspace_id = (select workspace_id from public.app_user where id = current_setting('t.uma')::uuid),
       role = 'approver'
 where id = current_setting('t.vic')::uuid;

-- ---------------------------------------------------------------------------
-- F08: create_agent is owner-only
-- ---------------------------------------------------------------------------
select lives_ok(
  $$select set_config('t.agent', (public.create_agent(
      current_setting('t.uma')::uuid, 'Owner agent', 'n8n', 'https://agent.example/cb',
      'whsec_uma_inbound_secret_0123456789abcdef')).id::text, true)$$,
  'an owner can create an agent');

select throws_ok(
  $$select public.create_agent(
      current_setting('t.vic')::uuid, 'Approver agent', 'n8n', 'https://agent.example/cb',
      'whsec_vic_inbound_secret_0123456789abcdef')$$,
  '42501', 'forbidden', 'an approver cannot create an agent (forbidden)');

select is(
  (select count(*)::int from public.agent
    where workspace_id = (select workspace_id from public.app_user where id = current_setting('t.uma')::uuid)),
  1, 'the rejected call created no agent');

select is(
  (select count(*)::int from vault.secrets where description = 'Cockpit agent inbound HMAC secret'
     and name like 'agent_inbound_%'
     and name not in (select 'agent_inbound_' || id::text from public.agent)),
  0, 'the rejected call left no orphaned Vault secret');

select lives_ok(
  $$select public.create_agent(
      current_setting('t.walt')::uuid, 'Walt agent', 'make', 'https://walt.example/cb',
      'whsec_walt_inbound_secret_0123456789abcde')$$,
  'an owner of another workspace is unaffected');

-- Approvers keep deciding actions.
select set_config('t.action', (select action_id::text from public.record_action_inbound(
  current_setting('t.agent')::uuid, 'ext-roles-1', 'email', 'Decide me', null,
  '{"subject":"Hi"}'::jsonb, array['subject'], null, null)), true);

select is(
  (select outcome from public.record_decision(
     current_setting('t.action')::uuid, current_setting('t.vic')::uuid,
     'approved', null, null, 'roles-key-0001')),
  'recorded', 'an approver can still decide an action');

-- ---------------------------------------------------------------------------
-- F05: one device token = one user
-- ---------------------------------------------------------------------------
set local role authenticated;
select set_config('request.jwt.claims',
  json_build_object('sub', current_setting('t.uma'), 'role', 'authenticated')::text, true);
select lives_ok(
  $$select public.register_fcm_token('shared-device-token'); select public.register_fcm_token('uma-tablet-token')$$,
  'Uma registers her phone and her tablet');

select set_config('request.jwt.claims',
  json_build_object('sub', current_setting('t.walt'), 'role', 'authenticated')::text, true);
select lives_ok(
  $$select public.register_fcm_token('shared-device-token')$$,
  'Walt signs in on the same phone and registers its token');
reset role;

select is(
  (select fcm_tokens from public.app_user where id = current_setting('t.uma')::uuid),
  array['uma-tablet-token'], 'the phone token moved off Uma''s row; her tablet token stays');

select is(
  (select fcm_tokens from public.app_user where id = current_setting('t.walt')::uuid),
  array['shared-device-token'], 'the phone token now belongs to Walt only');

select is(
  (select count(*)::int from public.app_user where 'shared-device-token' = any (fcm_tokens)),
  1, 'exactly one user holds the token');

select ok(
  not exists (
    select 1
      from public.record_action_inbound(
        current_setting('t.agent')::uuid, 'ext-roles-2', 'email', 'After handover', null,
        '{"subject":"Hi"}'::jsonb, array['subject'], null, null) r
     where 'shared-device-token'::text = any (r.fcm_tokens)),
  'a new action in Uma''s workspace is no longer pushed to the handed-over phone');

-- Re-registering on the same account keeps a single copy (unchanged behaviour).
set local role authenticated;
select set_config('request.jwt.claims',
  json_build_object('sub', current_setting('t.walt'), 'role', 'authenticated')::text, true);
select lives_ok(
  $$select public.register_fcm_token('shared-device-token')$$,
  'registering the same token again is fine');
reset role;

select is(
  (select fcm_tokens from public.app_user where id = current_setting('t.walt')::uuid),
  array['shared-device-token'], 'the token is stored once');

select * from finish();
rollback;
