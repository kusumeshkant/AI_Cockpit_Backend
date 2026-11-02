-- pgTAP: 0014 — service decisions (record_decision branch, resolution),
-- deletion fan-out (delete_account_data jobs, claim + result), cron, grants.
-- Runs in one transaction and is rolled back.
begin;
create extension if not exists pgtap with schema extensions;

select plan(35);

-- Owner Dora + approver Abe (same workspace), outsider Otto, approver-only Vic.
insert into auth.users (instance_id, id, aud, role, email)
values
  ('00000000-0000-0000-0000-000000000000', 'd1d1d1d1-d1d1-4d1d-8d1d-d1d1d1d1d1d1', 'authenticated', 'authenticated', 'dora.dec@test.dev'),
  ('00000000-0000-0000-0000-000000000000', 'd2d2d2d2-d2d2-4d2d-8d2d-d2d2d2d2d2d2', 'authenticated', 'authenticated', 'abe.dec@test.dev'),
  ('00000000-0000-0000-0000-000000000000', 'd3d3d3d3-d3d3-4d3d-8d3d-d3d3d3d3d3d3', 'authenticated', 'authenticated', 'otto.dec@test.dev');
select set_config('t.dora', 'd1d1d1d1-d1d1-4d1d-8d1d-d1d1d1d1d1d1', true);
select set_config('t.abe',  'd2d2d2d2-d2d2-4d2d-8d2d-d2d2d2d2d2d2', true);
select set_config('t.otto', 'd3d3d3d3-d3d3-4d3d-8d3d-d3d3d3d3d3d3', true);
select set_config('t.ws', (select workspace_id::text from public.app_user where id = current_setting('t.dora')::uuid), true);
update public.app_user set workspace_id = current_setting('t.ws')::uuid, role = 'approver'
 where id = current_setting('t.abe')::uuid;

create temp table m (manifest jsonb);
insert into m values ('{"ui": "native", "ui_schema_version": 1,
  "ops": {"decision.apply": {"class": "write", "roles": ["owner", "approver"], "max_request_bytes": 2048, "max_response_bytes": 2048},
          "subject.delete": {"class": "destructive", "roles": ["owner"], "max_request_bytes": 64, "max_response_bytes": 64}},
  "card_types": ["social_post_draft"], "data_categories": ["content"], "deletion_op": "subject.delete"}'::jsonb);

select lives_ok($$select * from public.register_agent_service('dec-svc', 'Dec', '', null, 'https://dec.example', '1.0', null,
  (select manifest from m), 'active', 'svcsig_dec_out_current_0123456789abcdefghi', 'svcsig_dec_out_next_0123456789abcdefghijkl',
  'svcsig_dec_in_current_0123456789abcdefghijk', 'svcsig_dec_in_next_0123456789abcdefghijklmn')$$, 'fixture: service');
select lives_ok($$select * from public.register_agent_service('unused-svc', 'Unused', '', null, 'https://u.example', '1.0', null,
  (select manifest from m), 'active', 'svcsig_unused_out_current_0123456789abcde', 'svcsig_unused_out_next_0123456789abcdefgh',
  'svcsig_unused_in_current_0123456789abcdefg', 'svcsig_unused_in_next_0123456789abcdefghij')$$, 'fixture: second service');
select lives_ok($$select * from public.enable_service(current_setting('t.dora')::uuid, 'dec-svc', 'v1')$$, 'fixture: enabled');
select set_config('t.svc_agent', (select agent_id::text from public.service_access where service_slug = 'dec-svc'), true);

-- Two cards and one ordinary action.
select set_config('t.c1', (select action_id::text from public.record_action_inbound(current_setting('t.svc_agent')::uuid,
  'idea_1', 'social_post_draft', 'Post idea: TOPICMARK', 'HOOKMARK', '{"schema": 1, "service": "dec-svc", "idea_id": "i-1",
  "format": "reel", "topic": "TOPICMARK", "hook": "HOOKMARK", "findings": {"blocking": 0, "to_fix": 0, "warnings": 0},
  "revision": 1}'::jsonb, '{}', null, null)), true);
select set_config('t.c2', (select action_id::text from public.record_action_inbound(current_setting('t.svc_agent')::uuid,
  'idea_2', 'social_post_draft', 'Post idea: TOPICMARK 2', 'HOOKMARK 2', '{"schema": 1, "service": "dec-svc", "idea_id": "i-2",
  "format": "photo", "topic": "TOPICMARK 2", "hook": "HOOKMARK 2", "findings": {"blocking": 0, "to_fix": 0, "warnings": 0},
  "revision": 1}'::jsonb, '{}', null, null)), true);
select set_config('t.plain', (public.create_agent(current_setting('t.dora')::uuid, 'Plain', 'n8n', 'https://p.example/cb',
  'whsec_dec_plain_0123456789abcdefghijklmn')).id::text, true);
select set_config('t.pa', (select action_id::text from public.record_action_inbound(current_setting('t.plain')::uuid,
  'e-1', 'email', 'Hi', null, '{"body": "full"}'::jsonb, '{}', null, null)), true);

-- ---------------------------------------------------------------------------
-- Resolution
-- ---------------------------------------------------------------------------
select results_eq(
  $$select action_status, idea_id, agent_id::text, service_slug, subject, access_state
      from public.resolve_action_service(current_setting('t.c1')::uuid, current_setting('t.abe')::uuid)$$,
  $$values ('pending'::text, 'i-1'::text, current_setting('t.svc_agent'), 'dec-svc'::text, current_setting('t.ws'), 'active'::text)$$,
  'a member (approver) resolves the service behind a card');
select is_empty($$select * from public.resolve_action_service(current_setting('t.c1')::uuid, current_setting('t.otto')::uuid)$$,
  'a non-member resolves nothing');
select is_empty($$select * from public.resolve_action_service(current_setting('t.pa')::uuid, current_setting('t.dora')::uuid)$$,
  'an ordinary agent''s action resolves nothing (old path)');
select results_eq(
  $$select service_slug, subject from public.resolve_agent_service(current_setting('t.svc_agent')::uuid)$$,
  $$values ('dec-svc'::text, current_setting('t.ws'))$$, 'resolve a service agent for retries');
select is_empty($$select * from public.resolve_agent_service(current_setting('t.plain')::uuid)$$, 'not for ordinary agents');
select unalike(pg_get_function_result('public.get_service_endpoint(text)'::regprocedure), '%key%',
  'get_service_endpoint returns no key ids');

-- ---------------------------------------------------------------------------
-- record_decision
-- ---------------------------------------------------------------------------
select results_eq(
  $$select outcome, callback_url, agent_id::text from public.record_decision(current_setting('t.c1')::uuid,
      current_setting('t.abe')::uuid, 'rejected', null, 'not on brand', 'key-dec-0001')$$,
  $$values ('recorded'::text, null::text, current_setting('t.svc_agent'))$$, 'a service card reject records (no callback URL)');
select is(
  (select (select array_agg(k order by k) from jsonb_object_keys(metadata->'callback_payload') k) from public.audit_entry
    where action_id = current_setting('t.c1')::uuid and event = 'decision_made'),
  array['action_id', 'decided_at', 'decided_by', 'decision', 'external_id', 'idea_id', 'reason'],
  'the stored delivery payload is the slim decision.apply input');
select is((select metadata->'callback_payload'->>'idea_id' from public.audit_entry
            where action_id = current_setting('t.c1')::uuid and event = 'decision_made'), 'i-1', 'idea id from the card');
select is((select original_payload from public.audit_entry where action_id = current_setting('t.c1')::uuid and event = 'decision_made'),
  '{"hook": "HOOKMARK"}'::jsonb, 'the decision audit keeps the hook only');
select is((select count(*)::int from public.audit_entry e
            where e.workspace_id = current_setting('t.ws')::uuid and e::text like '%TOPICMARK%'),
  0, 'no audit row contains the topic');
select results_eq(
  $$select outcome from public.record_decision(current_setting('t.c1')::uuid, current_setting('t.abe')::uuid,
      'rejected', null, 'not on brand', 'key-dec-0001')$$,
  $$values ('duplicate'::text)$$, 'replay with the same key → duplicate');
select results_eq(
  $$select outcome from public.record_decision(current_setting('t.c2')::uuid, current_setting('t.otto')::uuid,
      'approved', null, null, 'key-dec-0002')$$,
  $$values ('not_found'::text)$$, 'a non-member cannot decide');

select lives_ok($$select * from public.record_decision(current_setting('t.pa')::uuid, current_setting('t.dora')::uuid,
  'approved', null, null, 'key-dec-plain')$$, 'an ordinary decision');
select results_eq(
  $$select metadata->'callback_payload'->'payload', original_payload from public.audit_entry
     where action_id = current_setting('t.pa')::uuid and event = 'decision_made'$$,
  $$values ('{"body": "full"}'::jsonb, '{"body": "full"}'::jsonb)$$, 'ordinary agents: payloads unchanged');

-- ---------------------------------------------------------------------------
-- delete_account_data fan-out
-- ---------------------------------------------------------------------------
-- unused-svc: enabled then the consent cleared → neither consented nor used.
select lives_ok($$select * from public.enable_service(current_setting('t.dora')::uuid, 'unused-svc', 'v1')$$, 'fixture: second access');
update public.service_access set consented_at = null where service_slug = 'unused-svc';

select results_eq($$select outcome from public.delete_account_data(current_setting('t.abe')::uuid)$$,
  $$values ('deleted'::text)$$, 'deleting an approver works');
select is((select count(*)::int from public.service_deletion_job), 0, 'an approver deletion queues nothing');
select is((select service_jobs from public.account_deletion_log where role = 'approver'), 0, 'logged: 0 jobs');

select results_eq($$select outcome, workspace_deleted from public.delete_account_data(current_setting('t.dora')::uuid)$$,
  $$values ('deleted'::text, true)$$, 'deleting the owner works');
select results_eq($$select service_slug, subject, status, attempts from public.service_deletion_job$$,
  $$values ('dec-svc'::text, current_setting('t.ws'), 'pending'::text, 0)$$,
  'one job per consented / used service (slug + subject only)');
select is((select count(*)::int from public.workspace where id = current_setting('t.ws')::uuid), 0,
  'the job survives the workspace delete');
select is((select service_jobs from public.account_deletion_log where role = 'owner'), 1, 'logged: 1 job');
select is(
  (select array_agg(column_name::text order by ordinal_position) from information_schema.columns
    where table_schema = 'public' and table_name = 'service_deletion_job'),
  array['id', 'service_slug', 'subject', 'status', 'attempts', 'next_attempt_at', 'last_error', 'created_at', 'updated_at'],
  'the job has no PII column');

-- ---------------------------------------------------------------------------
-- Claim + result
-- ---------------------------------------------------------------------------
select set_config('t.job', (select id::text from public.service_deletion_job), true);
select results_eq($$select id::text, attempts from public.claim_due_deletion_jobs(10, 60)$$,
  $$values (current_setting('t.job'), 0)$$, 'a due job is claimed');
select is_empty($$select * from public.claim_due_deletion_jobs(10, 60)$$, 'a leased job is not claimed twice');
select is(public.record_deletion_job_result(current_setting('t.job')::uuid, false, 'network', 30), 'pending',
  'a failed attempt reschedules');
select is((select status || ':' || attempts || ':' || last_error from public.service_deletion_job), 'pending:1:network',
  'attempt counted, code kept');
select is(public.record_deletion_job_result(current_setting('t.job')::uuid, true, 'agent_deleted', null), 'done',
  'success marks it done');
select is((select status || ':' || attempts || ':' || coalesce(last_error, '-') from public.service_deletion_job), 'done:2:-',
  'done, error cleared');

-- ---------------------------------------------------------------------------
-- Cron and privileges
-- ---------------------------------------------------------------------------
select results_eq(
  $$select schedule, command, active from cron.job where jobname = 'cockpit-service-deletions-retry'$$,
  $$values ('*/5 * * * *'::text, 'select public.invoke_service_deletions_retry()'::text, true)$$, 'the fan-out runs from pg_cron');
select is(
  (select count(*)::int from unnest(array['anon', 'authenticated']) r,
          unnest(array['public.resolve_action_service(uuid, uuid)', 'public.resolve_agent_service(uuid)',
                       'public.get_service_endpoint(text)', 'public.claim_due_deletion_jobs(integer, integer)',
                       'public.record_deletion_job_result(uuid, boolean, text, integer)',
                       'public.invoke_service_deletions_retry()']) f
    where has_function_privilege(r, f, 'EXECUTE'))
  + (case when has_function_privilege('service_role', 'public.invoke_service_deletions_retry()', 'EXECUTE') then 1 else 0 end),
  0, 'no client role can call the 0014 functions; the invoker is cron-only');

select * from finish();
rollback;
