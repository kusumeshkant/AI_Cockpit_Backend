-- pgTAP: Phase 2 — callback retry claims, secret rotation, rate limit,
-- ownership and privileges (run: supabase test db). Rolled back at the end.
--
-- now() is fixed for the whole transaction, so "make it due" is done by
-- moving next_attempt_at into the past explicitly.
begin;
create extension if not exists pgtap with schema extensions;

select plan(37);

-- ---------------------------------------------------------------------------
-- Fixtures: owner Carol, approver Dan (same workspace), outsider Erin.
-- ---------------------------------------------------------------------------
insert into auth.users (instance_id, id, aud, role, email)
values
  ('00000000-0000-0000-0000-000000000000', '33333333-3333-4333-8333-333333333333',
   'authenticated', 'authenticated', 'carol@test.dev'),
  ('00000000-0000-0000-0000-000000000000', '44444444-4444-4444-8444-444444444444',
   'authenticated', 'authenticated', 'dan@test.dev'),
  ('00000000-0000-0000-0000-000000000000', '55555555-5555-4555-8555-555555555555',
   'authenticated', 'authenticated', 'erin@test.dev');

select set_config('t.carol', '33333333-3333-4333-8333-333333333333', true);
select set_config('t.dan',   '44444444-4444-4444-8444-444444444444', true);
select set_config('t.erin',  '55555555-5555-4555-8555-555555555555', true);

-- Dan joins Carol's workspace as an approver.
update public.app_user
   set workspace_id = (select workspace_id from public.app_user where id = current_setting('t.carol')::uuid),
       role = 'approver'
 where id = current_setting('t.dan')::uuid;

select set_config('t.agent', (public.create_agent(
  current_setting('t.carol')::uuid, 'Retry agent', 'n8n', 'https://agent.example/cb',
  'whsec_carol_original_secret_0123456789ab')).id::text, true);

-- A decided action whose first callback failed and is scheduled for retry.
select set_config('t.action', (select action_id::text from public.record_action_inbound(
  current_setting('t.agent')::uuid, 'ext-retry-1', 'email', 'Retry me', null,
  '{"subject":"Hi"}'::jsonb, array['subject'], null, null)), true);
select * from public.record_decision(
  current_setting('t.action')::uuid, current_setting('t.carol')::uuid,
  'approved', null, null, 'retry-key-0001');

-- ---------------------------------------------------------------------------
-- record_callback_result v2 (TR-7)
-- ---------------------------------------------------------------------------
select is(
  public.record_callback_result(current_setting('t.action')::uuid, false, 'network_error', 30),
  'retrying', 'a failed attempt with a delay becomes retrying');

select is(
  (select next_attempt_at from public.action where id = current_setting('t.action')::uuid),
  now() + interval '30 seconds', 'next_attempt_at = now() + delay');

select is(
  (select callback_attempts from public.action where id = current_setting('t.action')::uuid),
  1, 'the attempt is counted');

select is(
  (select metadata ->> 'attempt' from public.audit_entry
    where action_id = current_setting('t.action')::uuid and event = 'callback_attempted'),
  '1', 'intermediate failure is audited as callback_attempted with the attempt number');

select throws_ok(
  format($$select public.record_callback_result(%L, false, 'x', -1)$$, current_setting('t.action')),
  '22023', 'invalid_retry_delay', 'a negative delay is rejected');

-- ---------------------------------------------------------------------------
-- claim_due_callbacks: only due rows, leased so a second run can't re-claim
-- ---------------------------------------------------------------------------
select is(
  (select count(*)::int from public.claim_due_callbacks(10)),
  0, 'nothing is claimed before next_attempt_at');

update public.action set next_attempt_at = now() - interval '1 second'
 where id = current_setting('t.action')::uuid;

create temp table claimed on commit drop as
  select * from public.claim_due_callbacks(10);

select is((select count(*)::int from claimed), 1, 'a due retry is claimed');

select is(
  (select callback_url from claimed), 'https://agent.example/cb',
  'claim falls back to the agent callback_url');

select is(
  (select idempotency_key from claimed), 'retry-key-0001',
  'claim returns the decision''s Idempotency-Key');

select is(
  (select callback_payload ->> 'external_id' from claimed), 'ext-retry-1',
  'claim returns the stored callback payload');

select is((select attempts from claimed), 1, 'claim reports the attempts made so far');

select is(
  (select next_attempt_at from public.action where id = current_setting('t.action')::uuid),
  now() + interval '120 seconds', 'the claimed row is leased for p_lease_seconds');

select is(
  (select count(*)::int from public.claim_due_callbacks(10)),
  0, 'a leased row is not claimed again (no double send)');

select throws_ok(
  $$select * from public.claim_due_callbacks(0)$$,
  '22023', 'invalid_limit', 'claim rejects a limit outside 1..100');

-- ---------------------------------------------------------------------------
-- Terminal failure, and a late result can't undo a delivery
-- ---------------------------------------------------------------------------
select is(
  public.record_callback_result(current_setting('t.action')::uuid, false, 'http_500', null),
  'failed', 'no delay → terminal failed');

select is(
  (select count(*)::int from public.audit_entry
    where action_id = current_setting('t.action')::uuid and event = 'callback_failed'),
  1, 'terminal failure is audited as callback_failed');

select ok(
  (select next_attempt_at is null from public.action where id = current_setting('t.action')::uuid),
  'a failed callback has no next attempt');

update public.action set next_attempt_at = now() - interval '1 second'
 where id = current_setting('t.action')::uuid;
select is(
  (select count(*)::int from public.claim_due_callbacks(10)),
  0, 'failed callbacks are never claimed');

select is(
  public.record_callback_result(current_setting('t.action')::uuid, true, 'http_200', null),
  'delivered', 'a later success is recorded');

select is(
  public.record_callback_result(current_setting('t.action')::uuid, false, 'timeout', 60),
  'delivered', 'a result after delivery is ignored');

select is(
  (select callback_status from public.action where id = current_setting('t.action')::uuid),
  'delivered', 'the action stays delivered');

-- ---------------------------------------------------------------------------
-- Ownership + rotation (TR-8)
-- ---------------------------------------------------------------------------
select is(
  (select count(*)::int from public.get_owned_agent(current_setting('t.carol')::uuid, current_setting('t.agent')::uuid)),
  1, 'the owner owns the agent');

select is(
  (select count(*)::int from public.get_owned_agent(current_setting('t.dan')::uuid, current_setting('t.agent')::uuid)),
  0, 'an approver in the same workspace does not manage agents');

select is(
  (select count(*)::int from public.get_owned_agent(current_setting('t.erin')::uuid, current_setting('t.agent')::uuid)),
  0, 'another workspace does not own the agent');

select set_config('t.secret_id',
  (select inbound_secret_id::text from public.agent where id = current_setting('t.agent')::uuid), true);

select is(
  (public.rotate_agent_secret(current_setting('t.carol')::uuid, current_setting('t.agent')::uuid,
     'whsec_carol_rotated_secret_abcdefghij9876')).secret_hint,
  '9876', 'rotation updates the hint');

select is(
  (select secret from public.get_agent_inbound_context(current_setting('t.agent')::uuid)),
  'whsec_carol_rotated_secret_abcdefghij9876', 'the new secret is what inbound verifies against');

select isnt(
  (select secret from public.get_agent_inbound_context(current_setting('t.agent')::uuid)),
  'whsec_carol_original_secret_0123456789ab', 'the old secret no longer verifies');

select is(
  (select inbound_secret_id::text from public.agent where id = current_setting('t.agent')::uuid),
  current_setting('t.secret_id'), 'the Vault secret is replaced in place (one secret per agent)');

select throws_ok(
  format($$select public.rotate_agent_secret(%L, %L, 'whsec_erin_takeover_secret_0123456789ab')$$,
         current_setting('t.erin'), current_setting('t.agent')),
  'P0002', 'agent_not_found', 'another workspace cannot rotate the secret');

-- ---------------------------------------------------------------------------
-- hit_rate_limit (fixed window)
-- ---------------------------------------------------------------------------
select is(
  (select array_agg(limited order by n) from (
     select n, (public.hit_rate_limit(current_setting('t.agent')::uuid, 2, interval '60 seconds')).limited
       from generate_series(1, 3) n) hits),
  array[false, false, true], 'the (max + 1)-th hit in a window is limited');

select ok(
  (select retry_after_seconds between 1 and 60
     from public.hit_rate_limit(current_setting('t.agent')::uuid, 2, interval '60 seconds')),
  'retry_after_seconds points at the end of the window');

-- A stale window from the past doesn't count and is cleaned up.
insert into public.agent_rate (agent_id, window_start, count)
values (current_setting('t.agent')::uuid, now() - interval '10 minutes', 999);
delete from public.agent_rate
 where agent_id = current_setting('t.agent')::uuid and window_start > now() - interval '5 minutes';

select is(
  (select hits from public.hit_rate_limit(current_setting('t.agent')::uuid, 2, interval '60 seconds')),
  1, 'a new window starts counting from 1');

select is(
  (select count(*)::int from public.agent_rate where agent_id = current_setting('t.agent')::uuid),
  1, 'earlier windows are deleted');

-- ---------------------------------------------------------------------------
-- Privileges: none of this is callable by the app
-- ---------------------------------------------------------------------------
set local role authenticated;
select set_config('request.jwt.claims', json_build_object('sub', current_setting('t.carol'))::text, true);

select throws_ok(
  $$select * from public.claim_due_callbacks(10)$$,
  '42501', null, 'clients cannot claim callbacks');

select throws_ok(
  format($$select public.rotate_agent_secret(%L, %L, 'whsec_client_rotation_attempt_0123456789')$$,
         current_setting('t.carol'), current_setting('t.agent')),
  '42501', null, 'clients cannot rotate secrets directly');

select throws_ok(
  format($$select * from public.hit_rate_limit(%L, 1000, interval '60 seconds')$$, current_setting('t.agent')),
  '42501', null, 'clients cannot touch the rate limiter');

select throws_ok(
  $$select * from public.agent_rate$$,
  '42501', null, 'clients cannot read rate counters');

reset role;

select * from finish();
rollback;
