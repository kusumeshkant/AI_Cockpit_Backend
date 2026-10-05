-- pgTAP: Agent Triggers (0005) — RPC outcomes, audit rows, rate-limit
-- boundary, RLS, and that the existing tables / policies are unchanged.
-- Runs in one transaction and is rolled back.
begin;
create extension if not exists pgtap with schema extensions;

select plan(47);

-- ---------------------------------------------------------------------------
-- Fixtures: owner Olive + approver Pete (same workspace), outsider Quinn.
-- ---------------------------------------------------------------------------
insert into auth.users (instance_id, id, aud, role, email)
values
  ('00000000-0000-0000-0000-000000000000', '66666666-6666-4666-8666-666666666666',
   'authenticated', 'authenticated', 'olive@test.dev'),
  ('00000000-0000-0000-0000-000000000000', '77777777-7777-4777-8777-777777777777',
   'authenticated', 'authenticated', 'pete@test.dev'),
  ('00000000-0000-0000-0000-000000000000', '88888888-8888-4888-8888-888888888888',
   'authenticated', 'authenticated', 'quinn@test.dev');

select set_config('t.olive', '66666666-6666-4666-8666-666666666666', true);
select set_config('t.pete',  '77777777-7777-4777-8777-777777777777', true);
select set_config('t.quinn', '88888888-8888-4888-8888-888888888888', true);

update public.app_user
   set workspace_id = (select workspace_id from public.app_user where id = current_setting('t.olive')::uuid),
       role = 'approver'
 where id = current_setting('t.pete')::uuid;

select set_config('t.agent', (public.create_agent(
  current_setting('t.olive')::uuid, 'Trigger agent', 'n8n', 'https://agent.example/cb',
  'whsec_olive_inbound_secret_0123456789abc')).id::text, true);
select set_config('t.agent2', (public.create_agent(
  current_setting('t.olive')::uuid, 'No trigger', 'custom', 'https://agent.example/cb2',
  'whsec_olive_inbound_secret_2_0123456789')).id::text, true);

-- ---------------------------------------------------------------------------
-- Existing schema untouched
-- ---------------------------------------------------------------------------
select is(
  (select count(*)::int from pg_class
    where relnamespace = 'public'::regnamespace
      and relname in ('workspace', 'app_user', 'agent', 'action', 'audit_entry')
      and relrowsecurity),
  5, 'the five core tables still have RLS enabled');

select is(
  (select count(*)::int from pg_policies
    where schemaname = 'public'
      and tablename in ('workspace', 'app_user', 'agent', 'action', 'audit_entry')),
  5, 'the five core tables keep exactly their five select policies');

select throws_ok(
  format($$insert into public.audit_entry (workspace_id, action_id, event)
           select workspace_id, null, 'decision_made' from public.agent where id = %L$$,
         current_setting('t.agent')),
  '23514', null, 'non-trigger audit events still require an action');

-- ---------------------------------------------------------------------------
-- configure_agent_trigger
-- ---------------------------------------------------------------------------
select is(
  (select secret_hint from public.configure_agent_trigger(
     current_setting('t.olive')::uuid, current_setting('t.agent')::uuid,
     'https://agent.example/trigger', 'whtrig_first_secret_0123456789abcdefghWXYZ', 30)),
  'WXYZ', 'owner configures a trigger; only the hint comes back');

select is(
  (select s.decrypted_secret from public.agent_trigger t
     join vault.decrypted_secrets s on s.id = t.trigger_secret_id
    where t.agent_id = current_setting('t.agent')::uuid),
  'whtrig_first_secret_0123456789abcdefghWXYZ', 'the trigger secret is stored in Vault');

select set_config('t.secret_id',
  (select trigger_secret_id::text from public.agent_trigger
    where agent_id = current_setting('t.agent')::uuid), true);

select ok(
  (select enabled and min_interval_secs = 30 from public.agent_trigger
    where agent_id = current_setting('t.agent')::uuid),
  'a new trigger is enabled with the given interval');

select is(
  (select count(*)::int from public.audit_entry
    where event = 'trigger_configured' and action_id is null
      and actor_user_id = current_setting('t.olive')::uuid
      and metadata ->> 'agent_id' = current_setting('t.agent')),
  1, 'configuring is audited as trigger_configured (no action)');

select throws_ok(
  format($$select * from public.configure_agent_trigger(%L, %L, 'https://x.example/t',
           'whtrig_pete_secret_0123456789abcdefghijk', 30)$$,
         current_setting('t.pete'), current_setting('t.agent')),
  'P0002', 'agent_not_found', 'an approver cannot configure triggers');

select throws_ok(
  format($$select * from public.configure_agent_trigger(%L, %L, 'https://x.example/t',
           'whtrig_quinn_secret_0123456789abcdefghij', 30)$$,
         current_setting('t.quinn'), current_setting('t.agent')),
  'P0002', 'agent_not_found', 'another workspace cannot configure the trigger');

select throws_ok(
  format($$select * from public.configure_agent_trigger(%L, %L, 'ftp://x.example/t',
           'whtrig_bad_url_secret_0123456789abcdefg', 30)$$,
         current_setting('t.olive'), current_setting('t.agent')),
  '22023', 'invalid_trigger_url', 'non-http(s) trigger URLs are rejected');

select throws_ok(
  format($$select * from public.configure_agent_trigger(%L, %L, 'https://x.example/t',
           'whtrig_interval_secret_0123456789abcdef', 0)$$,
         current_setting('t.olive'), current_setting('t.agent')),
  '22023', 'invalid_min_interval', 'min_interval_secs must be at least 1');

select throws_ok(
  format($$select * from public.configure_agent_trigger(%L, %L, 'https://x.example/t', 'short', 30)$$,
         current_setting('t.olive'), current_setting('t.agent')),
  '22023', 'invalid_secret', 'short secrets are rejected');

-- Reconfigure rotates the secret in place.
select is(
  (select secret_hint from public.configure_agent_trigger(
     current_setting('t.olive')::uuid, current_setting('t.agent')::uuid,
     'https://agent.example/trigger2', 'whtrig_rotated_secret_0123456789abcdefgROTA', 30)),
  'ROTA', 'reconfiguring returns the new hint');

select is(
  (select trigger_secret_id::text from public.agent_trigger where agent_id = current_setting('t.agent')::uuid),
  current_setting('t.secret_id'), 'the Vault secret is replaced in place');

select is(
  (select decrypted_secret from vault.decrypted_secrets where id = current_setting('t.secret_id')::uuid),
  'whtrig_rotated_secret_0123456789abcdefgROTA', 'the old trigger secret is gone');

select is(
  (select trigger_url from public.agent_trigger where agent_id = current_setting('t.agent')::uuid),
  'https://agent.example/trigger2', 'reconfiguring updates the URL');

-- ---------------------------------------------------------------------------
-- begin_trigger_run
-- ---------------------------------------------------------------------------
select is(
  (select outcome from public.begin_trigger_run(current_setting('t.agent')::uuid, current_setting('t.quinn')::uuid)),
  'not_found', 'another workspace cannot fire the trigger');

select is(
  (select outcome from public.begin_trigger_run(current_setting('t.agent2')::uuid, current_setting('t.olive')::uuid)),
  'not_configured', 'an agent without a trigger is not_configured');

create temp table first_run on commit drop as
  select * from public.begin_trigger_run(current_setting('t.agent')::uuid, current_setting('t.pete')::uuid);

select is((select outcome from first_run), 'ok', 'a workspace member (approver) can fire the trigger');
select is((select trigger_url from first_run), 'https://agent.example/trigger2', 'ok returns the trigger URL');
select is((select trigger_secret from first_run), 'whtrig_rotated_secret_0123456789abcdefgROTA',
  'ok returns the current secret (service role only)');

select is(
  (select status from public.trigger_run where id = (select trigger_run_id from first_run)),
  'pending', 'the run is recorded as pending before anything is sent');

select is(
  (select count(*)::int from public.audit_entry
    where event = 'trigger_fired' and action_id is null
      and actor_user_id = current_setting('t.pete')::uuid
      and metadata ->> 'trigger_run_id' = (select trigger_run_id::text from first_run)),
  1, 'firing is audited as trigger_fired');

select is(
  (select outcome from public.begin_trigger_run(current_setting('t.agent')::uuid, current_setting('t.olive')::uuid)),
  'rate_limited', 'a second run inside min_interval_secs is rate_limited');

select ok(
  (select retry_after_seconds between 1 and 30
     from public.begin_trigger_run(current_setting('t.agent')::uuid, current_setting('t.olive')::uuid)),
  'rate_limited carries retry_after_seconds');

select is(
  (select count(*)::int from public.trigger_run where agent_id = current_setting('t.agent')::uuid),
  1, 'rate-limited attempts record nothing');

-- Boundary: 29s ago is still limited, 31s ago is allowed (interval 30s).
update public.trigger_run set created_at = clock_timestamp() - interval '29 seconds'
 where agent_id = current_setting('t.agent')::uuid;
select is(
  (select outcome from public.begin_trigger_run(current_setting('t.agent')::uuid, current_setting('t.olive')::uuid)),
  'rate_limited', 'one second inside the interval is still limited');

update public.trigger_run set created_at = clock_timestamp() - interval '31 seconds'
 where agent_id = current_setting('t.agent')::uuid;
select is(
  (select outcome from public.begin_trigger_run(current_setting('t.agent')::uuid, current_setting('t.olive')::uuid)),
  'ok', 'one second past the interval is allowed');

-- ---------------------------------------------------------------------------
-- set_agent_trigger_enabled
-- ---------------------------------------------------------------------------
select is(
  (select enabled from public.set_agent_trigger_enabled(
     current_setting('t.olive')::uuid, current_setting('t.agent')::uuid, false)),
  false, 'the owner can disable the trigger');

update public.trigger_run set created_at = clock_timestamp() - interval '1 hour'
 where agent_id = current_setting('t.agent')::uuid;
select is(
  (select outcome from public.begin_trigger_run(current_setting('t.agent')::uuid, current_setting('t.olive')::uuid)),
  'disabled', 'a disabled trigger does not fire');

select throws_ok(
  format($$select * from public.set_agent_trigger_enabled(%L, %L, true)$$,
         current_setting('t.pete'), current_setting('t.agent')),
  'P0002', 'trigger_not_found', 'an approver cannot enable / disable triggers');

select throws_ok(
  format($$select * from public.set_agent_trigger_enabled(%L, %L, true)$$,
         current_setting('t.olive'), current_setting('t.agent2')),
  'P0002', 'trigger_not_found', 'enabling a missing trigger is trigger_not_found');

select is(
  (select enabled from public.set_agent_trigger_enabled(
     current_setting('t.olive')::uuid, current_setting('t.agent')::uuid, true)),
  true, 'the owner can re-enable the trigger');

-- ---------------------------------------------------------------------------
-- record_trigger_result
-- ---------------------------------------------------------------------------
select is(
  public.record_trigger_result((select trigger_run_id from first_run), true, 'http_200'),
  'sent', 'a delivered run becomes sent');

select is(
  (select count(*)::int from public.audit_entry
    where event = 'trigger_failed' and metadata ->> 'trigger_run_id' = (select trigger_run_id::text from first_run)),
  0, 'a sent run is not audited as failed');

select is(
  public.record_trigger_result((select trigger_run_id from first_run), false, 'late'),
  'sent', 'a result for an already-recorded run is ignored');

select set_config('t.run2', (select r.id::text from public.trigger_run r
   where r.agent_id = current_setting('t.agent')::uuid and r.status = 'pending' limit 1), true);

select is(
  public.record_trigger_result(current_setting('t.run2')::uuid, false, 'network_error'),
  'failed', 'an undelivered run becomes failed');

select is(
  (select count(*)::int from public.audit_entry
    where event = 'trigger_failed' and action_id is null
      and metadata ->> 'trigger_run_id' = current_setting('t.run2')),
  1, 'a failed run is audited as trigger_failed');

select throws_ok(
  $$select public.record_trigger_result(gen_random_uuid(), true, 'x')$$,
  'P0002', 'trigger_run_not_found', 'unknown runs are trigger_run_not_found');

-- ---------------------------------------------------------------------------
-- RLS / privileges from the app's side
-- ---------------------------------------------------------------------------
set local role authenticated;
select set_config('request.jwt.claims', json_build_object('sub', current_setting('t.olive'))::text, true);

select is(
  (select count(*)::int from public.agent_trigger),
  1, 'the owner sees their workspace''s trigger');

select is(
  (select secret_hint from public.agent_trigger),
  'ROTA', 'clients can read the secret hint');

select throws_ok(
  $$select trigger_secret_id from public.agent_trigger$$,
  '42501', null, 'clients cannot read the Vault secret id');

select ok(
  (select count(*) from public.trigger_run) >= 2,
  'the owner sees their workspace''s trigger runs');

select throws_ok(
  format($$insert into public.trigger_run (agent_id, workspace_id, status)
           values (%L, (select workspace_id from public.agent_trigger limit 1), 'sent')$$,
         current_setting('t.agent')),
  '42501', null, 'clients cannot write trigger runs');

select throws_ok(
  $$update public.agent_trigger set enabled = false$$,
  '42501', null, 'clients cannot change triggers');

select throws_ok(
  format($$select * from public.begin_trigger_run(%L, %L)$$,
         current_setting('t.agent'), current_setting('t.olive')),
  '42501', null, 'clients cannot call begin_trigger_run directly');

select set_config('request.jwt.claims', json_build_object('sub', current_setting('t.quinn'))::text, true);

select is(
  (select count(*)::int from public.agent_trigger) + (select count(*)::int from public.trigger_run),
  0, 'another workspace sees no triggers or runs');

reset role;

select * from finish();
rollback;
