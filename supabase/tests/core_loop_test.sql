-- pgTAP: RLS, privileges and the transactional core (run: supabase test db).
-- Everything runs in one transaction and is rolled back.
begin;
create extension if not exists pgtap with schema extensions;

select plan(30);

-- ---------------------------------------------------------------------------
-- Fixtures (as postgres). Ids are carried in transaction-local settings so
-- they stay readable after switching to the `authenticated` role.
-- ---------------------------------------------------------------------------
insert into auth.users (instance_id, id, aud, role, email)
values
  ('00000000-0000-0000-0000-000000000000', '11111111-1111-4111-8111-111111111111',
   'authenticated', 'authenticated', 'alice@test.dev'),
  ('00000000-0000-0000-0000-000000000000', '22222222-2222-4222-8222-222222222222',
   'authenticated', 'authenticated', 'bob@test.dev');

select set_config('t.user_a', '11111111-1111-4111-8111-111111111111', true);
select set_config('t.user_b', '22222222-2222-4222-8222-222222222222', true);

select set_config('t.agent_a', (public.create_agent(
  current_setting('t.user_a')::uuid, 'Agent A', 'n8n', 'https://a.example/cb',
  'whsec_alice_secret_0123456789abcdefghij')).id::text, true);
select set_config('t.agent_b', (public.create_agent(
  current_setting('t.user_b')::uuid, 'Agent B', 'make', 'https://b.example/cb',
  'whsec_bob_secret_0123456789abcdefghijkl')).id::text, true);

-- ---------------------------------------------------------------------------
-- Auth bootstrap (0002)
-- ---------------------------------------------------------------------------
select is(
  (select count(*)::int from public.app_user
    where id in (current_setting('t.user_a')::uuid, current_setting('t.user_b')::uuid)),
  2, 'sign-up provisions an app_user per auth user');

select is(
  (select w.owner_user_id from public.workspace w
     join public.app_user u on u.workspace_id = w.id
    where u.id = current_setting('t.user_a')::uuid),
  current_setting('t.user_a')::uuid, 'new user owns their workspace');

select is(
  (select role from public.app_user where id = current_setting('t.user_a')::uuid),
  'owner', 'first user of a workspace is owner');

-- ---------------------------------------------------------------------------
-- Agents + Vault
-- ---------------------------------------------------------------------------
select is(
  (select secret from public.get_agent_inbound_context(current_setting('t.agent_a')::uuid)),
  'whsec_alice_secret_0123456789abcdefghij', 'agent secret round-trips through Vault');

select is(
  (select secret_hint from public.agent where id = current_setting('t.agent_a')::uuid),
  'ghij', 'only the last 4 characters are stored on the agent row');

-- ---------------------------------------------------------------------------
-- Inbound idempotency (TR-2)
-- ---------------------------------------------------------------------------
select set_config('t.action_a', (
  select action_id::text from public.record_action_inbound(
    current_setting('t.agent_a')::uuid, 'ext-1', 'email', 'Reply to Priya', 'Refund',
    '{"to":"p@example.com","subject":"Hi","body":"Hello"}', array['subject','body'], null, null)),
  true);

select is(
  (select is_new from public.record_action_inbound(
    current_setting('t.agent_a')::uuid, 'ext-1', 'email', 'Reply to Priya', 'Refund',
    '{"to":"p@example.com","subject":"Hi","body":"Hello"}', array['subject','body'], null, null)),
  false, 'repeated inbound (same external_id) is reported as duplicate');

select is(
  (select count(*)::int from public.action
    where agent_id = current_setting('t.agent_a')::uuid and external_id = 'ext-1'),
  1, 'duplicate inbound does not create a second action');

select is(
  (select count(*)::int from public.audit_entry
    where action_id = current_setting('t.action_a')::uuid and event = 'action_received'),
  1, 'duplicate inbound does not add a second audit row');

select set_config('t.action_b', (
  select action_id::text from public.record_action_inbound(
    current_setting('t.agent_b')::uuid, 'ext-1', 'table', 'Post invoice', null,
    '{"amount":100}', '{}', null, null)),
  true);

-- ---------------------------------------------------------------------------
-- Decisions (TR-3, TR-6)
-- ---------------------------------------------------------------------------
select is(
  (select outcome from public.record_decision(
    current_setting('t.action_a')::uuid, current_setting('t.user_b')::uuid,
    'approved', null, null, 'key-cross-workspace')),
  'not_found', 'a user cannot decide another workspace''s action');

select is(
  (select outcome from public.record_decision(
    current_setting('t.action_a')::uuid, current_setting('t.user_a')::uuid,
    'approved_with_edits', '{"to":"evil@example.com"}', null, 'key-bad-edit')),
  'invalid_edit', 'edits to non-editable fields are refused');

select is(
  (select outcome from public.record_decision(
    current_setting('t.action_a')::uuid, current_setting('t.user_a')::uuid,
    'approved_with_edits', '{"subject":"Re: Hi"}', null, 'key-decision-1')),
  'recorded', 'first decision is recorded');

select is(
  (select outcome from public.record_decision(
    current_setting('t.action_a')::uuid, current_setting('t.user_a')::uuid,
    'approved_with_edits', '{"subject":"Re: Hi"}', null, 'key-decision-1')),
  'duplicate', 'same Idempotency-Key replays instead of re-deciding');

select is(
  (select callback_payload -> 'payload' ->> 'subject' from public.record_decision(
    current_setting('t.action_a')::uuid, current_setting('t.user_a')::uuid,
    'approved_with_edits', '{"subject":"Re: Hi"}', null, 'key-decision-1')),
  'Re: Hi', 'duplicate returns the stored callback payload with merged edits');

select is(
  (select count(*)::int from public.audit_entry
    where action_id = current_setting('t.action_a')::uuid and event = 'decision_made'),
  1, 'exactly one decision audit row despite retries');

select is(
  (select outcome from public.record_decision(
    current_setting('t.action_a')::uuid, current_setting('t.user_a')::uuid,
    'rejected', null, 'changed my mind', 'key-decision-2')),
  'already_decided', 'a different key on a decided action conflicts');

select is(
  (select status || '/' || decision from public.action where id = current_setting('t.action_a')::uuid),
  'decided/approved_with_edits', 'action row reflects the decision');

select lives_ok(
  format($$select public.record_callback_result(%L, true, 'http_200')$$, current_setting('t.action_a')),
  'callback result can be recorded');

select is(
  (select callback_status || '/' || callback_attempts from public.action
    where id = current_setting('t.action_a')::uuid),
  'delivered/1', 'callback result updates status and attempts');

-- ---------------------------------------------------------------------------
-- Append-only audit (as postgres — even the owner cannot rewrite history)
-- ---------------------------------------------------------------------------
select throws_ok(
  $$update public.audit_entry set reason = 'rewritten'$$, 'P0001', null,
  'audit_entry rows cannot be updated');

select throws_ok(
  $$delete from public.audit_entry$$, 'P0001', null,
  'audit_entry rows cannot be deleted');

-- ---------------------------------------------------------------------------
-- As an authenticated client (user A)
-- ---------------------------------------------------------------------------
set local role authenticated;
select set_config('request.jwt.claims',
  json_build_object('sub', current_setting('t.user_a'), 'role', 'authenticated')::text, true);

select is(
  (select count(*)::int from public.action),
  1, 'RLS: user sees only their workspace''s actions');

select is(
  (select count(*)::int from public.agent where id = current_setting('t.agent_b')::uuid),
  0, 'RLS: user cannot see another workspace''s agent');

select throws_ok(
  format($$insert into public.action (workspace_id, agent_id, external_id, type, title)
           select workspace_id, id, 'client-insert', 'email', 'x' from public.agent where id = %L$$,
         current_setting('t.agent_a')),
  '42501', null, 'RLS: clients cannot insert actions');

select lives_ok(
  $$update public.action set title = 'hacked'$$,
  'RLS: client update runs but matches no rows');

select throws_ok(
  format($$insert into public.audit_entry (workspace_id, action_id, event)
           select workspace_id, id, 'decision_made' from public.action where id = %L$$,
         current_setting('t.action_a')),
  '42501', null, 'clients cannot write audit entries');

select throws_ok(
  format($$select * from public.record_decision(%L, %L, 'approved', null, null, 'key-from-client')$$,
         current_setting('t.action_a'), current_setting('t.user_a')),
  '42501', null, 'clients cannot call record_decision directly');

select throws_ok(
  format($$select * from public.get_agent_inbound_context(%L)$$, current_setting('t.agent_a')),
  '42501', null, 'clients cannot read agent secrets');

select lives_ok(
  $$select public.register_fcm_token('device-token-1'); select public.register_fcm_token('device-token-1')$$,
  'clients can register a device token (repeatably)');

reset role;

select is(
  (select title from public.action where id = current_setting('t.action_a')::uuid),
  'Reply to Priya', 'client update did not change any row');

select is(
  (select fcm_tokens from public.app_user where id = current_setting('t.user_a')::uuid),
  array['device-token-1'], 'registering the same token twice stores it once');

select * from finish();
rollback;
