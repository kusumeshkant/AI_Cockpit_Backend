-- pgTAP: 0013 — inbound key pair (register / read / swap), nonce claims,
-- resolution by subject, record_action_inbound (hook-only audit for service
-- agents, unchanged for others), record_action_update / _withdraw.
-- Runs in one transaction and is rolled back.
begin;
create extension if not exists pgtap with schema extensions;

select plan(36);

insert into auth.users (instance_id, id, aud, role, email)
values ('00000000-0000-0000-0000-000000000000', 'a7a7a7a7-a7a7-4a7a-8a7a-a7a7a7a7a7a7',
        'authenticated', 'authenticated', 'cara.cards@test.dev');
select set_config('t.cara', 'a7a7a7a7-a7a7-4a7a-8a7a-a7a7a7a7a7a7', true);
select set_config('t.ws', (select workspace_id::text from public.app_user where id = current_setting('t.cara')::uuid), true);

create temp table m (manifest jsonb);
insert into m values ('{"ui": "native", "ui_schema_version": 1,
  "ops": {"subject.delete": {"class": "destructive", "roles": ["owner"], "max_request_bytes": 64, "max_response_bytes": 64}},
  "card_types": ["social_post_draft"], "data_categories": ["content"], "deletion_op": "subject.delete"}'::jsonb);

-- ---------------------------------------------------------------------------
-- Registry: four keys
-- ---------------------------------------------------------------------------
select throws_ok(
  $$select * from public.register_agent_service('cards-svc', 'Cards', '', null, 'https://cards.example', '1.0', null,
      (select manifest from m), 'active', 'svcsig_out_current_0123456789abcdefghijklmn',
      'svcsig_out_next_0123456789abcdefghijklmnopq', null, null)$$,
  '22023', 'invalid_secret', 'a new service needs the inbound pair too');
select throws_ok(
  $$select * from public.register_agent_service('cards-svc', 'Cards', '', null, 'https://cards.example', '1.0', null,
      (select manifest from m), 'active', 'svcsig_out_current_0123456789abcdefghijklmn',
      'svcsig_out_next_0123456789abcdefghijklmnopq', 'svcsig_out_current_0123456789abcdefghijklmn',
      'svcsig_in_next_0123456789abcdefghijklmnopqrs')$$,
  '22023', 'invalid_secret', 'an inbound secret may not reuse an outbound one');
select results_eq(
  $$select slug, status, created, keys_written, inbound_keys_written
      from public.register_agent_service('cards-svc', 'Cards', '', null, 'https://cards.example', '1.0', null,
        (select manifest from m), 'active', 'svcsig_out_current_0123456789abcdefghijklmn',
        'svcsig_out_next_0123456789abcdefghijklmnopq', 'svcsig_in_current_0123456789abcdefghijklmno',
        'svcsig_in_next_0123456789abcdefghijklmnopqrs')$$,
  $$values ('cards-svc'::text, 'active'::text, true, true, true)$$, 'a new service gets four keys');
select ok((select inbound_key_current_id is not null and inbound_key_next_id is not null
             and inbound_key_current_id not in (signing_key_current_id, signing_key_next_id)
            from public.agent_service where slug = 'cards-svc'),
  'the inbound pair is separate from the outbound pair');
select set_config('t.in1', (select inbound_key_current_id::text from public.agent_service where slug = 'cards-svc'), true);
select set_config('t.in2', (select inbound_key_next_id::text from public.agent_service where slug = 'cards-svc'), true);
select results_eq(
  $$select key_id::text, secret, slot from public.get_service_inbound_keys('cards-svc')$$,
  $$values (current_setting('t.in1'), 'svcsig_in_current_0123456789abcdefghijklmno'::text, 'current'::text),
           (current_setting('t.in2'), 'svcsig_in_next_0123456789abcdefghijklmnopqrs'::text, 'next'::text)$$,
  'both inbound keys come from Vault, current first');
select is_empty($$select * from public.get_service_inbound_keys('nope')$$, 'unknown service → no keys');
select results_eq(
  $$select current_key_id::text, next_key_id::text from public.swap_service_inbound_keys('cards-svc')$$,
  $$values (current_setting('t.in2'), current_setting('t.in1'))$$, 'inbound swap: next becomes current');
select results_eq(
  $$select current_key_id::text from public.swap_service_inbound_keys('cards-svc')$$,
  $$values (current_setting('t.in1'))$$, 'swapping back restores it');
select results_eq(
  $$select inbound_keys_written, keys_written from public.register_agent_service('cards-svc', 'Cards', 'x', null,
      'https://cards.example', '1.0', null, (select manifest from m), null, null, null, null, null)$$,
  $$values (false, false)$$, 'an update without keys keeps all four');
select is((select inbound_key_current_id::text from public.agent_service where slug = 'cards-svc'),
  current_setting('t.in1'), 'inbound key ids unchanged by an update');

-- The 0011 overload still works (no inbound keys; they come with --rotate-keys).
select lives_ok($$select * from public.register_agent_service('legacy-svc', 'Legacy', '', null, 'https://l.example',
  '1.0', null, (select manifest from m), null, 'svcsig_legacy_current_0123456789abcdefgh',
  'svcsig_legacy_next_0123456789abcdefghijklm')$$, 'the 11-arg register still works');
select is((select inbound_key_current_id from public.agent_service where slug = 'legacy-svc'), null,
  'a legacy registration has no inbound keys');
select results_eq(
  $$select inbound_keys_written from public.register_agent_service('legacy-svc', 'Legacy', '', null, 'https://l.example',
      '1.0', null, (select manifest from m), null, 'svcsig_legacy2_current_0123456789abcdefg',
      'svcsig_legacy2_next_0123456789abcdefghijkl', 'svcsig_legacy2_in_current_0123456789abcd',
      'svcsig_legacy2_in_next_0123456789abcdefghi')$$,
  $$values (true)$$, 'rotating keys gives an existing service its inbound pair');
select isnt((select inbound_key_next_id from public.agent_service where slug = 'legacy-svc'), null,
  'legacy service now has inbound keys');

-- ---------------------------------------------------------------------------
-- Nonces and resolution
-- ---------------------------------------------------------------------------
select ok(public.claim_gateway_nonce(current_setting('t.in1')::uuid, 'nonce-cards-0123456789'), 'a fresh nonce is accepted');
select ok(not public.claim_gateway_nonce(current_setting('t.in1')::uuid, 'nonce-cards-0123456789'), 'a replay is refused');
select ok(not public.claim_gateway_nonce(current_setting('t.in1')::uuid, 'short'), 'a too-short nonce is refused');

select lives_ok($$select * from public.enable_service(current_setting('t.cara')::uuid, 'cards-svc', 'v1')$$, 'fixture: enabled');
select set_config('t.svc_agent', (select agent_id::text from public.service_access where service_slug = 'cards-svc'), true);
select results_eq(
  $$select workspace_id, service_status, card_types, access_state, agent_id::text
      from public.resolve_service_inbound('cards-svc', current_setting('t.ws'))$$,
  $$values (current_setting('t.ws')::uuid, 'active'::text, '["social_post_draft"]'::jsonb, 'active'::text,
            current_setting('t.svc_agent'))$$,
  'resolve by (slug, subject)');
select is_empty($$select * from public.resolve_service_inbound('cards-svc', gen_random_uuid()::text)$$,
  'an unknown subject resolves to nothing');

-- ---------------------------------------------------------------------------
-- Cards
-- ---------------------------------------------------------------------------
create temp table card (payload jsonb);
insert into card values ('{"schema": 1, "service": "cards-svc", "idea_id": "i-1", "format": "reel",
  "topic": "TOPICMARK gardening", "hook": "HOOKMARK start small", "findings": {"blocking": 0, "to_fix": 1, "warnings": 2},
  "revision": 1}'::jsonb);

select results_eq(
  $$select is_new from public.record_action_inbound(current_setting('t.svc_agent')::uuid, 'idea_i-1', 'social_post_draft',
      'Post idea: TOPICMARK gardening', 'HOOKMARK start small', (select payload from card), '{}', null, now() + interval '7 days')$$,
  $$values (true)$$, 'a service card is created through record_action_inbound');
select set_config('t.card', (select id::text from public.action where external_id = 'idea_i-1'), true);
select is((select original_payload from public.audit_entry where action_id = current_setting('t.card')::uuid
            and event = 'action_received'),
  '{"hook": "HOOKMARK start small"}'::jsonb, 'the audit keeps the hook only (service agent)');
select results_eq(
  $$select is_new from public.record_action_inbound(current_setting('t.svc_agent')::uuid, 'idea_i-1', 'social_post_draft',
      'x', 'y', (select payload from card), '{}', null, null)$$,
  $$values (false)$$, 'a duplicate create is a no-op');

-- Ordinary agents keep the full payload in the audit (unchanged).
select set_config('t.plain', (public.create_agent(current_setting('t.cara')::uuid, 'Plain', 'n8n',
  'https://plain.example/cb', 'whsec_cards_plain_0123456789abcdefghijk')).id::text, true);
select lives_ok($$select * from public.record_action_inbound(current_setting('t.plain')::uuid, 'e-1', 'email', 'Hi',
  null, '{"body": "full text"}'::jsonb, '{}', null, null)$$, 'an ordinary action');
select is((select e.original_payload from public.audit_entry e join public.action a on a.id = e.action_id
            where a.external_id = 'e-1'), '{"body": "full text"}'::jsonb, 'ordinary agents: audit unchanged');

select results_eq(
  $$select outcome from public.record_action_update(current_setting('t.svc_agent')::uuid, 'idea_i-1', 2,
      'Post idea: TOPICMARK v2', 'HOOKMARK v2', jsonb_set((select payload from card), '{revision}', '2'), null)$$,
  $$values ('updated'::text)$$, 'a higher revision applies');
select results_eq(
  $$select revision, title from public.action where id = current_setting('t.card')::uuid$$,
  $$values (2, 'Post idea: TOPICMARK v2'::text)$$, 'revision and text replaced');
select is((select metadata from public.audit_entry where action_id = current_setting('t.card')::uuid and event = 'action_updated'),
  '{"revision": 2}'::jsonb, 'action_updated audits the revision only');
select results_eq(
  $$select outcome from public.record_action_update(current_setting('t.svc_agent')::uuid, 'idea_i-1', 2, 'a', 'b', null, null)
    union all
    select outcome from public.record_action_update(current_setting('t.svc_agent')::uuid, 'idea_i-1', 1, 'a', 'b', null, null)$$,
  $$values ('stale'::text), ('stale'::text)$$, 'equal or lower revisions are stale');
select throws_ok($$select * from public.record_action_update(current_setting('t.svc_agent')::uuid, 'nope', 3, 'a', 'b', null, null)$$,
  'P0002', 'action_not_found', 'update of an unknown card');

select results_eq(
  $$select outcome, status from public.record_action_withdraw(current_setting('t.svc_agent')::uuid, 'idea_i-1', 'regenerated')$$,
  $$values ('withdrawn'::text, 'expired'::text)$$, 'withdraw expires a pending card');
select is((select metadata from public.audit_entry where action_id = current_setting('t.card')::uuid and event = 'action_withdrawn'),
  '{"reason_code": "regenerated"}'::jsonb, 'action_withdrawn audits the reason code only');
select results_eq(
  $$select outcome, status from public.record_action_withdraw(current_setting('t.svc_agent')::uuid, 'idea_i-1', 'regenerated')
    union all
    select outcome, status from public.record_action_update(current_setting('t.svc_agent')::uuid, 'idea_i-1', 9, 'a', 'b', null, null)$$,
  $$values ('noop'::text, 'expired'::text), ('noop'::text, 'expired'::text)$$,
  'withdraw is idempotent; a non-pending card is never updated');
select throws_ok($$select * from public.record_action_withdraw(current_setting('t.svc_agent')::uuid, 'idea_i-1', 'Bad Code')$$,
  '22023', 'invalid_reason_code', 'reason codes are validated');

select is((select count(*)::int from public.audit_entry e
            where e.workspace_id = current_setting('t.ws')::uuid and e::text like '%TOPICMARK%'),
  0, 'no audit row contains card text other than the hook');

set local role authenticated;
select throws_ok($$select * from public.record_action_update(current_setting('t.svc_agent')::uuid, 'idea_i-1', 9, 'a', 'b', null, null)$$,
  '42501', null, 'the app cannot call card RPCs');
reset role;

select * from finish();
rollback;
