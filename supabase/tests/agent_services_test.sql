-- pgTAP: 0011 — agent services gateway base. Registry + Vault keys, the
-- 'service' agent platform constraint (existing agents untouched), owner-only
-- idempotent enable / disable with consent + audit + lazy agent row, access
-- resolution, gateway rate windows, call records, RLS / grants, and what
-- delete_account_data does with the new tables today.
-- Runs in one transaction and is rolled back.
begin;
create extension if not exists pgtap with schema extensions;

select plan(83);

-- ---------------------------------------------------------------------------
-- Fixtures: owner Olive + approver Pete (same workspace), owner Quinn (other).
-- ---------------------------------------------------------------------------
insert into auth.users (instance_id, id, aud, role, email)
values
  ('00000000-0000-0000-0000-000000000000', 'a1a1a1a1-a1a1-4a1a-8a1a-a1a1a1a1a1a1',
   'authenticated', 'authenticated', 'olive.svc@test.dev'),
  ('00000000-0000-0000-0000-000000000000', 'b2b2b2b2-b2b2-4b2b-8b2b-b2b2b2b2b2b2',
   'authenticated', 'authenticated', 'pete.svc@test.dev'),
  ('00000000-0000-0000-0000-000000000000', 'c3c3c3c3-c3c3-4c3c-8c3c-c3c3c3c3c3c3',
   'authenticated', 'authenticated', 'quinn.svc@test.dev');

select set_config('t.olive', 'a1a1a1a1-a1a1-4a1a-8a1a-a1a1a1a1a1a1', true);
select set_config('t.pete',  'b2b2b2b2-b2b2-4b2b-8b2b-b2b2b2b2b2b2', true);
select set_config('t.quinn', 'c3c3c3c3-c3c3-4c3c-8c3c-c3c3c3c3c3c3', true);

update public.app_user
   set workspace_id = (select workspace_id from public.app_user where id = current_setting('t.olive')::uuid),
       role = 'approver'
 where id = current_setting('t.pete')::uuid;

select set_config('t.ws', (select workspace_id::text from public.app_user
                            where id = current_setting('t.olive')::uuid), true);
select set_config('t.ws_q', (select workspace_id::text from public.app_user
                              where id = current_setting('t.quinn')::uuid), true);

-- An ordinary agent, created the existing way.
select set_config('t.plain', (public.create_agent(
  current_setting('t.olive')::uuid, 'Plain agent', 'n8n', 'https://agent.example/cb',
  'whsec_olive_inbound_secret_0123456789abc')).id::text, true);

create temp table m (manifest jsonb);
insert into m values ('{
  "ui": "native", "ui_schema_version": 1,
  "ops": {"draft.create": {"class": "write", "roles": ["owner", "approver"], "timeout_ms": 10000,
                           "max_request_bytes": 16384, "max_response_bytes": 262144}},
  "card_types": ["social_post_draft"], "data_categories": ["content"], "deletion_op": "subject.delete"
}'::jsonb);
grant select on m to authenticated, anon;

-- ---------------------------------------------------------------------------
-- Existing tables: additive changes only
-- ---------------------------------------------------------------------------
select is(
  (select row(platform, callback_url, inbound_secret_id is not null, status)::text
     from public.agent where id = current_setting('t.plain')::uuid),
  row('n8n'::text, 'https://agent.example/cb'::text, true, 'active'::text)::text,
  'an ordinary agent is created exactly as before');
select throws_ok(
  $$insert into public.agent (workspace_id, name, platform, inbound_secret_id)
    values (current_setting('t.ws')::uuid, 'No callback', 'custom', gen_random_uuid())$$,
  '23514', null, 'a non-service agent still needs a callback_url');
select throws_ok(
  $$insert into public.agent (workspace_id, name, platform, callback_url)
    values (current_setting('t.ws')::uuid, 'No secret', 'n8n', 'https://x.example/cb')$$,
  '23514', null, 'a non-service agent still needs an inbound secret');
select throws_ok(
  $$insert into public.agent (workspace_id, name, platform, callback_url, inbound_secret_id)
    values (current_setting('t.ws')::uuid, 'Bad', 'other', 'https://x.example/cb', gen_random_uuid())$$,
  '23514', null, 'unknown platforms are still rejected');
select throws_ok(
  $$update public.agent set callback_url = null where id = current_setting('t.plain')::uuid$$,
  '23514', null, 'an existing agent cannot lose its callback_url');
select col_default_is('public', 'action', 'revision', '1', 'action.revision defaults to 1');
select col_not_null('public', 'action', 'revision', 'action.revision is not null');
select throws_ok(
  $$insert into public.audit_entry (workspace_id, action_id, event)
    values (current_setting('t.ws')::uuid, null, 'action_updated')$$,
  '23514', null, 'action_updated still needs an action');
select lives_ok(
  $$insert into public.audit_entry (workspace_id, action_id, event)
    values (current_setting('t.ws')::uuid, null, 'service_disabled')$$,
  'service events may have no action');

-- ---------------------------------------------------------------------------
-- Registry (register_agent_service)
-- ---------------------------------------------------------------------------
select throws_ok(
  $$select * from public.register_agent_service('content-creator', 'Content creator', 'Drafts posts',
      'sparkles', 'https://svc.example', '1.0', null, (select manifest from m), null, null, null)$$,
  '22023', 'invalid_secret', 'a new service needs both signing secrets');
select throws_ok(
  $$select * from public.register_agent_service('content-creator', 'Content creator', 'Drafts posts',
      'sparkles', 'https://svc.example', '1.0', null, (select manifest from m), null,
      'svcsig_same_secret_0123456789abcdefghij', 'svcsig_same_secret_0123456789abcdefghij')$$,
  '22023', 'invalid_secret', 'the two signing secrets must differ');
select results_eq(
  $$select slug, status, created, keys_written from public.register_agent_service(
      'content-creator', 'Content creator', 'Drafts posts', 'sparkles', 'https://svc.example',
      '1.0', null, (select manifest from m), null,
      'svcsig_current_0123456789abcdefghijklmn', 'svcsig_next_0123456789abcdefghijklmnopq')$$,
  $$values ('content-creator'::text, 'draft'::text, true, true)$$,
  'a new service is created as draft with keys');
select is(
  (select count(*)::int from vault.decrypted_secrets v join public.agent_service s
      on v.id in (s.signing_key_current_id, s.signing_key_next_id)
    where s.slug = 'content-creator'
      and v.decrypted_secret in ('svcsig_current_0123456789abcdefghijklmn',
                                 'svcsig_next_0123456789abcdefghijklmnopq')),
  2, 'both signing secrets are in Vault under the stored ids');
select results_eq(
  $$select ui, ui_schema_version from public.agent_service where slug = 'content-creator'$$,
  $$values ('native'::text, 1)$$, 'ui / ui_schema_version come from the manifest');
select set_config('t.k1', (select signing_key_current_id::text from public.agent_service
                            where slug = 'content-creator'), true);
select results_eq(
  $$select slug, status, created, keys_written from public.register_agent_service(
      'content-creator', 'Content creator', 'Drafts social posts', 'sparkles',
      'https://svc.example', '1.0', null, (select manifest from m), null, null, null)$$,
  $$values ('content-creator'::text, 'draft'::text, false, false)$$,
  'an update without keys keeps status and keys');
select is((select signing_key_current_id::text from public.agent_service where slug = 'content-creator'),
  current_setting('t.k1'), 'key ids unchanged by an update');
select throws_ok(
  $$insert into public.agent_service (slug, display_name, base_url, manifest)
    values ('bad-ui', 'Bad', 'https://x.example', '{"ui": "web", "ui_schema_version": 1, "ops": {}}')$$,
  '23514', null, 'manifest ui must be native or sdui');
select throws_ok(
  $$insert into public.agent_service (slug, display_name, base_url, manifest)
    values ('no-ops', 'Bad', 'https://x.example', '{"ui": "sdui", "ui_schema_version": 1}')$$,
  '23514', null, 'manifest needs ops');
select throws_ok(
  $$insert into public.agent_service (slug, display_name, base_url, manifest)
    values ('no-ui', 'Bad', 'https://x.example', '{"ui_schema_version": 1, "ops": {}}')$$,
  '23514', null, 'manifest needs ui');
select throws_ok(
  $$insert into public.agent_service (slug, display_name, base_url, manifest)
    values ('Bad_Slug', 'Bad', 'https://x.example', (select manifest from m))$$,
  '23514', null, 'slug is lower kebab case');

-- ---------------------------------------------------------------------------
-- enable_service / disable_service
-- ---------------------------------------------------------------------------
select throws_ok(
  $$select * from public.enable_service(current_setting('t.olive')::uuid, 'content-creator', 'v1')$$,
  'P0002', 'service_not_found', 'a draft service cannot be enabled');

select lives_ok(
  $$select * from public.register_agent_service('content-creator', 'Content creator',
      'Drafts social posts', 'sparkles', 'https://svc.example', '1.0', null,
      (select manifest from m), 'active', null, null)$$,
  'admin activates the service');

select throws_ok(
  $$select * from public.enable_service(current_setting('t.pete')::uuid, 'content-creator', 'v1')$$,
  '42501', 'forbidden', 'an approver cannot enable a service');
select throws_ok(
  $$select * from public.enable_service(current_setting('t.olive')::uuid, 'content-creator', '')$$,
  '22023', 'invalid_consent_version', 'a consent version is required');
select throws_ok(
  $$select * from public.enable_service(current_setting('t.olive')::uuid, 'nope', 'v1')$$,
  'P0002', 'service_not_found', 'unknown service');
select throws_ok(
  $$select * from public.enable_service(gen_random_uuid(), 'content-creator', 'v1')$$,
  'P0002', 'workspace_not_found', 'unknown user');

select set_config('t.agent_count', (select count(*)::text from public.agent), true);

select results_eq(
  $$select state, consent_version, changed
      from public.enable_service(current_setting('t.olive')::uuid, 'content-creator', 'v1')$$,
  $$values ('active'::text, 'v1'::text, true)$$, 'the owner enables the service');
select set_config('t.svc_agent', (select agent_id::text from public.service_access
   where workspace_id = current_setting('t.ws')::uuid and service_slug = 'content-creator'), true);

select results_eq(
  $$select subject, consented_by, consented_at is not null, first_used_at is null
      from public.service_access
     where workspace_id = current_setting('t.ws')::uuid and service_slug = 'content-creator'$$,
  $$values (current_setting('t.ws'), current_setting('t.olive')::uuid, true, true)$$,
  'consent record: subject = workspace id, who and when, not used yet');
select results_eq(
  $$select workspace_id, platform, callback_url, inbound_secret_id, status, name
      from public.agent where id = current_setting('t.svc_agent')::uuid$$,
  $$values (current_setting('t.ws')::uuid, 'service'::text, null::text, null::uuid,
            'active'::text, 'Content creator'::text)$$,
  'a service agent row (no callback, no secret) is created for the workspace');
select is((select count(*)::int from public.agent), current_setting('t.agent_count')::int + 1,
  'exactly one agent row was added');
select results_eq(
  $$select actor_user_id, action_id, metadata->>'service_slug', metadata->>'consent_version'
      from public.audit_entry
     where workspace_id = current_setting('t.ws')::uuid and event = 'service_enabled'$$,
  $$values (current_setting('t.olive')::uuid, null::uuid, 'content-creator'::text, 'v1'::text)$$,
  'enable is audited (no action)');

select results_eq(
  $$select changed, agent_id::text
      from public.enable_service(current_setting('t.olive')::uuid, 'content-creator', 'v1')$$,
  $$values (false, current_setting('t.svc_agent'))$$, 'enabling again is a no-op');
select is((select count(*)::int from public.audit_entry
            where workspace_id = current_setting('t.ws')::uuid and event = 'service_enabled'),
  1, 'the no-op is not audited');
select is((select count(*)::int from public.agent), current_setting('t.agent_count')::int + 1,
  'no second agent row');

select results_eq(
  $$select changed, consent_version, agent_id::text
      from public.enable_service(current_setting('t.olive')::uuid, 'content-creator', 'v2')$$,
  $$values (true, 'v2'::text, current_setting('t.svc_agent'))$$,
  'a new consent version is recorded on the same row and agent');
select is((select count(*)::int from public.audit_entry
            where workspace_id = current_setting('t.ws')::uuid and event = 'service_enabled'),
  2, 're-consent is audited');

select throws_ok(
  $$select * from public.disable_service(current_setting('t.pete')::uuid, 'content-creator')$$,
  '42501', 'forbidden', 'an approver cannot disable a service');
select results_eq(
  $$select state, changed from public.disable_service(current_setting('t.olive')::uuid, 'content-creator')$$,
  $$values ('disabled'::text, true)$$, 'the owner disables the service');
select is((select status from public.agent where id = current_setting('t.svc_agent')::uuid),
  'disabled', 'the service agent is disabled with it');
select is((select count(*)::int from public.audit_entry
            where workspace_id = current_setting('t.ws')::uuid and event = 'service_disabled'
              and metadata ? 'service_slug'),
  1, 'disable is audited');
select results_eq(
  $$select state, changed from public.disable_service(current_setting('t.olive')::uuid, 'content-creator')$$,
  $$values ('disabled'::text, false)$$, 'disabling again is a no-op');
select is((select count(*)::int from public.audit_entry
            where workspace_id = current_setting('t.ws')::uuid and event = 'service_disabled'
              and metadata ? 'service_slug'),
  1, 'the no-op is not audited');

select results_eq(
  $$select state, changed, agent_id::text
      from public.enable_service(current_setting('t.olive')::uuid, 'content-creator', 'v2')$$,
  $$values ('active'::text, true, current_setting('t.svc_agent'))$$,
  're-enabling reuses the access row and agent');
select is((select status from public.agent where id = current_setting('t.svc_agent')::uuid),
  'active', 'the service agent is active again');

select is_empty(
  $$select * from public.disable_service(current_setting('t.quinn')::uuid, 'content-creator')$$,
  'disabling a never-enabled service returns nothing');

-- Blocked access (set by an operator) is never lifted by the owner.
update public.service_access set state = 'blocked'
 where workspace_id = current_setting('t.ws')::uuid and service_slug = 'content-creator';
select throws_ok(
  $$select * from public.enable_service(current_setting('t.olive')::uuid, 'content-creator', 'v3')$$,
  '42501', 'service_blocked', 'a blocked service cannot be re-enabled');
select results_eq(
  $$select state, changed from public.disable_service(current_setting('t.olive')::uuid, 'content-creator')$$,
  $$values ('blocked'::text, false)$$, 'disable leaves a blocked row blocked');
update public.service_access set state = 'active'
 where workspace_id = current_setting('t.ws')::uuid and service_slug = 'content-creator';

update public.agent_service set status = 'paused' where slug = 'content-creator';
select throws_ok(
  $$select * from public.enable_service(current_setting('t.quinn')::uuid, 'content-creator', 'v1')$$,
  'P0001', 'service_paused', 'a paused service cannot be newly enabled');
update public.agent_service set status = 'active' where slug = 'content-creator';

-- ---------------------------------------------------------------------------
-- resolve_service_access
-- ---------------------------------------------------------------------------
select results_eq(
  $$select workspace_id, role, slug, status, base_url, access_state, subject, agent_id::text, ui
      from public.resolve_service_access(current_setting('t.pete')::uuid, 'content-creator')$$,
  $$values (current_setting('t.ws')::uuid, 'approver'::text, 'content-creator'::text,
            'active'::text, 'https://svc.example'::text, 'active'::text, current_setting('t.ws'),
            current_setting('t.svc_agent'), 'native'::text)$$,
  'resolve: workspace, role, registry row and access for a member');
select results_eq(
  $$select access_state, subject from public.resolve_service_access(current_setting('t.quinn')::uuid, 'content-creator')$$,
  $$values (null::text, null::text)$$, 'resolve: never enabled → no access');
select throws_ok(
  $$select * from public.resolve_service_access(current_setting('t.olive')::uuid, 'nope')$$,
  'P0002', 'service_not_found', 'resolve: unknown service');
select unalike(
  pg_get_function_result('public.resolve_service_access(uuid, text)'::regprocedure),
  '%signing%', 'resolve never returns signing key ids');
select is((select count(*)::int from public.service_access), 1, 'resolve creates nothing');

-- ---------------------------------------------------------------------------
-- hit_gateway_rate / record_gateway_call / gateway_nonce
-- ---------------------------------------------------------------------------
select results_eq(
  $$select limited, hits from public.hit_gateway_rate(current_setting('t.olive')::uuid,
      'content-creator', 'write', 2, interval '1 minute')$$,
  $$values (false, 1)$$, 'rate: first call passes');
select lives_ok(
  $$select * from public.hit_gateway_rate(current_setting('t.olive')::uuid, 'content-creator',
      'write', 2, interval '1 minute')$$, 'rate: second call');
select results_eq(
  $$select limited, hits, retry_after_seconds between 1 and 60
      from public.hit_gateway_rate(current_setting('t.olive')::uuid, 'content-creator', 'write', 2,
                                   interval '1 minute')$$,
  $$values (true, 3, true)$$, 'rate: third call over the limit, with retry-after');
select results_eq(
  $$select limited, hits from public.hit_gateway_rate(current_setting('t.olive')::uuid,
      'content-creator', 'read', 2, interval '1 minute')$$,
  $$values (false, 1)$$, 'rate: op classes are counted separately');
select throws_ok(
  $$select * from public.hit_gateway_rate(current_setting('t.olive')::uuid, 'content-creator',
      'admin', 2, interval '1 minute')$$,
  '22023', 'invalid_op_class', 'rate: unknown op class');

select lives_ok(
  $$select public.record_gateway_call(current_setting('t.ws')::uuid, 'content-creator',
      'draft.create', 200, 180)$$, 'a call is recorded');
select results_eq(
  $$select service_slug, op, status, latency_ms from public.gateway_call
     where workspace_id = current_setting('t.ws')::uuid$$,
  $$values ('content-creator'::text, 'draft.create'::text, 200, 180)$$,
  'gateway_call holds ids and numbers only');
select isnt((select first_used_at from public.service_access
              where workspace_id = current_setting('t.ws')::uuid), null,
  'a 2xx call stamps first_used_at');
select throws_ok(
  $$select public.record_gateway_call(current_setting('t.ws')::uuid, 'content-creator', 'Bad Op', 200, 1)$$,
  '22023', 'invalid_op', 'op names are validated');

insert into public.gateway_nonce (key_id, nonce) values (current_setting('t.k1')::uuid, 'nonce-0123456789abcdef');
select throws_ok(
  $$insert into public.gateway_nonce (key_id, nonce) values (current_setting('t.k1')::uuid, 'nonce-0123456789abcdef')$$,
  '23505', null, 'a nonce is accepted once per key');

-- ---------------------------------------------------------------------------
-- Client roles
-- ---------------------------------------------------------------------------
insert into public.agent_service (slug, display_name, base_url, manifest)
values ('hidden-draft', 'Hidden', 'https://hidden.example', (select manifest from m));

-- Agent RLS (0011): service agents are hidden from clients, ordinary agents
-- are not; an action of a service agent stays visible with a null agent embed.
select set_config('t.svc_action',   'd4d4d4d4-d4d4-4d4d-8d4d-d4d4d4d4d4d4', true);
select set_config('t.plain_action', 'e5e5e5e5-e5e5-4e5e-8e5e-e5e5e5e5e5e5', true);
insert into public.action (id, workspace_id, agent_id, external_id, type, title)
values
  (current_setting('t.svc_action')::uuid, current_setting('t.ws')::uuid,
   current_setting('t.svc_agent')::uuid, 'svc-1', 'social_post_draft', 'Service draft'),
  (current_setting('t.plain_action')::uuid, current_setting('t.ws')::uuid,
   current_setting('t.plain')::uuid, 'plain-1', 'email', 'Plain draft');

set local role service_role;
select is((select count(*)::int from public.agent where id = current_setting('t.svc_agent')::uuid),
  1, 'service_role sees the service agent');
reset role;

set local role authenticated;
select set_config('request.jwt.claims',
  json_build_object('sub', current_setting('t.pete'), 'role', 'authenticated')::text, true);
select results_eq(
  $$select id::text, name, platform from public.agent order by created_at$$,
  $$values (current_setting('t.plain'), 'Plain agent'::text, 'n8n'::text)$$,
  'an approver sees the ordinary agents as before, not the service agent');
reset role;

set local role authenticated;
select set_config('request.jwt.claims',
  json_build_object('sub', current_setting('t.olive'), 'role', 'authenticated')::text, true);
select results_eq(
  $$select id::text, name, platform from public.agent order by created_at$$,
  $$values (current_setting('t.plain'), 'Plain agent'::text, 'n8n'::text)$$,
  'the owner sees the ordinary agents as before');
select is_empty(
  $$select id from public.agent where platform = 'service' or id = current_setting('t.svc_agent')::uuid$$,
  'the service agent row is invisible to the app');
-- PostgREST's embed action → agent:agent_id(name, platform) is a left join
-- under the agent policy.
select results_eq(
  $$select a.id::text, g.name, g.platform
      from public.action a left join public.agent g on g.id = a.agent_id
     where a.id in (current_setting('t.svc_action')::uuid, current_setting('t.plain_action')::uuid)
     order by a.title$$,
  $$values (current_setting('t.plain_action'), 'Plain agent'::text, 'n8n'::text),
           (current_setting('t.svc_action'), null::text, null::text)$$,
  'the action stays visible; its service agent embed is null, an ordinary one is not');

select results_eq(
  $$select slug, display_name, status, ui, ui_schema_version from public.agent_service order by slug$$,
  $$values ('content-creator'::text, 'Content creator'::text, 'active'::text, 'native'::text, 1)$$,
  'members see listed services only (no drafts), safe columns');
select throws_ok($$select base_url from public.agent_service$$, '42501', null,
  'base_url is not readable');
select throws_ok($$select manifest from public.agent_service$$, '42501', null,
  'the manifest is not readable');
select throws_ok($$select signing_key_current_id from public.agent_service$$, '42501', null,
  'signing key ids are not readable');
select results_eq(
  $$select service_slug, state from public.service_access$$,
  $$values ('content-creator'::text, 'active'::text)$$, 'the owner reads their workspace access');
select throws_ok($$select subject from public.service_access$$, '42501', null,
  'subject is not readable');
select throws_ok(
  $$update public.service_access set state = 'active'$$, '42501', null, 'no client writes to access');
select throws_ok(
  $$select * from public.enable_service(current_setting('t.olive')::uuid, 'content-creator', 'v9')$$,
  '42501', null, 'enable_service is not callable by the app');
select throws_ok($$select count(*) from public.gateway_call$$, '42501', null,
  'gateway tables are service-role only');

select set_config('request.jwt.claims',
  json_build_object('sub', current_setting('t.quinn'), 'role', 'authenticated')::text, true);
select is_empty($$select service_slug from public.service_access$$,
  'another workspace sees none of it');
reset role;

set local role anon;
select throws_ok($$select slug from public.agent_service$$, '42501', null, 'anon reads no services');
select throws_ok($$select id from public.agent$$, '42501', null, 'anon reads no agents');
reset role;

-- ---------------------------------------------------------------------------
-- delete_account_data (unchanged in 0011): what it does with the new tables.
-- ---------------------------------------------------------------------------
select results_eq(
  $$select outcome, workspace_deleted from public.delete_account_data(current_setting('t.olive')::uuid)$$,
  $$values ('deleted'::text, true)$$, 'deleting the owner still works with services enabled');
select is(
  (select count(*)::int from public.service_access where workspace_id = current_setting('t.ws')::uuid)
  + (select count(*)::int from public.gateway_call where workspace_id = current_setting('t.ws')::uuid)
  + (select count(*)::int from public.gateway_rate where user_id = current_setting('t.olive')::uuid),
  0, 'access, calls and rate rows cascade with the workspace / user');
-- Follow-up (not in this migration): no deletion job is queued for the
-- services the workspace used, so their copy of the subject's data stays.
select is((select count(*)::int from public.service_deletion_job), 0,
  'KNOWN GAP: delete_account_data queues no service_deletion_job yet');

select * from finish();
rollback;
