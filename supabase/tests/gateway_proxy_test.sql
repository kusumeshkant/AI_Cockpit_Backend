-- pgTAP: 0012 — signing key read + swap, call outcome (ids only, attempts,
-- first use, circuit breaker), pruning + its cron job, privileges.
-- Runs in one transaction and is rolled back.
begin;
create extension if not exists pgtap with schema extensions;

select plan(30);

-- ---------------------------------------------------------------------------
-- Fixtures: owner Olga with the stub service enabled.
-- ---------------------------------------------------------------------------
insert into auth.users (instance_id, id, aud, role, email)
values ('00000000-0000-0000-0000-000000000000', 'f6f6f6f6-f6f6-4f6f-8f6f-f6f6f6f6f6f6',
        'authenticated', 'authenticated', 'olga.gw@test.dev');
select set_config('t.olga', 'f6f6f6f6-f6f6-4f6f-8f6f-f6f6f6f6f6f6', true);
select set_config('t.ws', (select workspace_id::text from public.app_user
                            where id = current_setting('t.olga')::uuid), true);

select lives_ok($$select * from public.register_agent_service(
  'gw-stub', 'Stub', '', null, 'https://stub.example', '1.0', null,
  '{"ui": "native", "ui_schema_version": 1, "ops": {"ideas.list": {"class": "read", "roles": ["owner"]}},
    "data_categories": ["content"], "deletion_op": "ideas.list"}'::jsonb,
  'active', 'svcsig_gw_current_0123456789abcdefghijklmnop', 'svcsig_gw_next_0123456789abcdefghijklmnopqrs')$$,
  'fixture: registered service');
select lives_ok($$select * from public.enable_service(current_setting('t.olga')::uuid, 'gw-stub', 'v1')$$,
  'fixture: enabled');
select set_config('t.k1', (select signing_key_current_id::text from public.agent_service where slug = 'gw-stub'), true);
select set_config('t.k2', (select signing_key_next_id::text from public.agent_service where slug = 'gw-stub'), true);

-- ---------------------------------------------------------------------------
-- Signing keys
-- ---------------------------------------------------------------------------
select results_eq(
  $$select key_id::text, secret from public.get_service_signing_key('gw-stub')$$,
  $$values (current_setting('t.k1'), 'svcsig_gw_current_0123456789abcdefghijklmnop'::text)$$,
  'the current key id and secret come from Vault');
select is_empty($$select * from public.get_service_signing_key('nope')$$, 'unknown service → no key');

select results_eq(
  $$select current_key_id::text, next_key_id::text from public.swap_service_signing_keys('gw-stub')$$,
  $$values (current_setting('t.k2'), current_setting('t.k1'))$$, 'swap: next becomes current');
select is((select secret from public.get_service_signing_key('gw-stub')),
  'svcsig_gw_next_0123456789abcdefghijklmnopqrs', 'after the swap the proxy signs with the former next key');
select results_eq(
  $$select current_key_id::text, next_key_id::text from public.swap_service_signing_keys('gw-stub')$$,
  $$values (current_setting('t.k1'), current_setting('t.k2'))$$, 'swapping back restores the pair');
select throws_ok($$select * from public.swap_service_signing_keys('nope')$$, 'P0002', 'service_not_found',
  'swap: unknown service');
select unalike(pg_get_function_result('public.swap_service_signing_keys(text)'::regprocedure), '%secret%',
  'swap never returns a secret');

-- ---------------------------------------------------------------------------
-- record_gateway_outcome
-- ---------------------------------------------------------------------------
select results_eq(
  $$select consecutive_failures, open_until from public.record_gateway_outcome(
      current_setting('t.ws')::uuid, 'gw-stub', 'service.enable', 200, 12, 0, null, false)$$,
  $$values (0, null::timestamptz)$$, 'a built-in op is recorded without touching the breaker');
select is((select first_used_at from public.service_access where service_slug = 'gw-stub'), null,
  'built-in ops do not count as first use');
select results_eq(
  $$select status, latency_ms, attempts from public.gateway_call
     where service_slug = 'gw-stub' and op = 'service.enable'$$,
  $$values (200, 12, 0)$$, 'attempts is stored (0 = not forwarded)');

select lives_ok($$select * from public.record_gateway_outcome(
  current_setting('t.ws')::uuid, 'gw-stub', 'ideas.list', 200, 80, 1, true, true)$$, 'a forwarded success');
select isnt((select first_used_at from public.service_access where service_slug = 'gw-stub'), null,
  'a forwarded success stamps first use');

-- Four failures keep it closed; the fifth opens it for ~30 s.
select lives_ok($$select public.record_gateway_outcome(current_setting('t.ws')::uuid, 'gw-stub',
  'ideas.list', 503, 5, 2, false, true) from generate_series(1, 4)$$, 'four agent failures');
select results_eq(
  $$select consecutive_failures, open_until from public.agent_service where slug = 'gw-stub'$$,
  $$values (4, null::timestamptz)$$, 'still closed after four');
select results_eq(
  $$select consecutive_failures, open_until between now() + interval '29 seconds' and now() + interval '31 seconds'
      from public.record_gateway_outcome(current_setting('t.ws')::uuid, 'gw-stub', 'ideas.list', 504, 5, 2, false, true)$$,
  $$values (5, true)$$, 'the fifth consecutive failure opens the breaker for 30 s');
select is((select first_used_at is not null from public.service_access where service_slug = 'gw-stub'), true,
  'failures never clear first use');
select results_eq(
  $$select consecutive_failures, open_until from public.record_gateway_outcome(
      current_setting('t.ws')::uuid, 'gw-stub', 'ideas.list', 422, 9, 1, true, true)$$,
  $$values (0, null::timestamptz)$$, 'a sane answer (even a 4xx envelope) closes and resets it');
select throws_ok($$select * from public.record_gateway_outcome(current_setting('t.ws')::uuid, 'gw-stub',
  'Bad Op', 200, 1, 1, true, true)$$, '22023', 'invalid_op', 'op names are validated');
select throws_ok($$select * from public.record_gateway_outcome(current_setting('t.ws')::uuid, 'gw-stub',
  'ideas.list', 200, 1, 4, true, true)$$, '22023', 'invalid_gateway_call', 'attempts is at most 3');

-- ---------------------------------------------------------------------------
-- Pruning
-- ---------------------------------------------------------------------------
insert into public.gateway_nonce (key_id, nonce, seen_at) values
  (current_setting('t.k1')::uuid, 'old-nonce-0123456789', now() - interval '25 hours'),
  (current_setting('t.k1')::uuid, 'new-nonce-0123456789', now() - interval '1 hour');
insert into public.gateway_call (workspace_id, service_slug, op, status, latency_ms, created_at) values
  (current_setting('t.ws')::uuid, 'gw-stub', 'ideas.list', 200, 1, now() - interval '31 days');
insert into public.gateway_rate (user_id, service_slug, op_class, window_start, count) values
  (current_setting('t.olga')::uuid, 'gw-stub', 'read', now() - interval '2 days', 3),
  (current_setting('t.olga')::uuid, 'gw-stub', 'read', date_trunc('minute', now()), 1);
select set_config('t.calls_before', (select count(*)::text from public.gateway_call), true);

select results_eq($$select nonces, calls, rate_windows from public.prune_gateway()$$,
  $$values (1, 1, 1)$$, 'prune removes exactly the expired rows');
select is((select count(*)::int from public.gateway_nonce), 1, 'the recent nonce stays');
select is((select count(*)::int from public.gateway_call), current_setting('t.calls_before')::int - 1,
  'recent calls stay');
select is((select count(*)::int from public.gateway_rate), 1, 'the current rate window stays');
select results_eq(
  $$select schedule, command, active from cron.job where jobname = 'cockpit-gateway-prune'$$,
  $$values ('17 * * * *'::text, 'select public.prune_gateway()'::text, true)$$,
  'pruning runs hourly from pg_cron');

-- ---------------------------------------------------------------------------
-- Privileges
-- ---------------------------------------------------------------------------
select is(
  (select count(*)::int from unnest(array['anon', 'authenticated']) r,
          unnest(array['public.get_service_signing_key(text)', 'public.swap_service_signing_keys(text)',
                       'public.record_gateway_outcome(uuid, text, text, integer, integer, integer, boolean, boolean)',
                       'public.prune_gateway()']) f
    where has_function_privilege(r, f, 'EXECUTE')),
  0, 'no client role can call the 0012 functions');
select ok(not has_function_privilege('service_role', 'public.prune_gateway()', 'EXECUTE'),
  'prune_gateway is cron-only');
select ok(has_function_privilege('service_role', 'public.get_service_signing_key(text)', 'EXECUTE'),
  'service_role reads the signing key');

set local role authenticated;
select throws_ok($$select * from public.get_service_signing_key('gw-stub')$$, '42501', null,
  'the app cannot read a signing key');
reset role;

select * from finish();
rollback;
