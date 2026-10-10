-- pgTAP: 0007 — account deletion (F02). Runs in one transaction and is rolled back.
begin;
create extension if not exists pgtap with schema extensions;

select plan(30);

-- ---------------------------------------------------------------------------
-- Fixtures: owner Olga with approvers Adam (deleted first) and Mia (moved when
-- Olga goes); Pete owns an unrelated workspace.
-- ---------------------------------------------------------------------------
insert into auth.users (instance_id, id, aud, role, email)
values
  ('00000000-0000-0000-0000-000000000000', '77777777-7777-4777-8777-777777777771',
   'authenticated', 'authenticated', 'olga@test.dev'),
  ('00000000-0000-0000-0000-000000000000', '77777777-7777-4777-8777-777777777772',
   'authenticated', 'authenticated', 'adam@test.dev'),
  ('00000000-0000-0000-0000-000000000000', '77777777-7777-4777-8777-777777777773',
   'authenticated', 'authenticated', 'mia@test.dev'),
  ('00000000-0000-0000-0000-000000000000', '77777777-7777-4777-8777-777777777774',
   'authenticated', 'authenticated', 'pete@test.dev');

select set_config('t.olga', '77777777-7777-4777-8777-777777777771', true);
select set_config('t.adam', '77777777-7777-4777-8777-777777777772', true);
select set_config('t.mia',  '77777777-7777-4777-8777-777777777773', true);
select set_config('t.pete', '77777777-7777-4777-8777-777777777774', true);
select set_config('t.ws', (select workspace_id::text from public.app_user
                            where id = current_setting('t.olga')::uuid), true);

update public.app_user
   set workspace_id = current_setting('t.ws')::uuid, role = 'approver'
 where id in (current_setting('t.adam')::uuid, current_setting('t.mia')::uuid);

-- Olga's agent (Vault inbound secret) with a trigger (Vault trigger secret).
select set_config('t.agent', (public.create_agent(
    current_setting('t.olga')::uuid, 'Olga agent', 'n8n', 'https://agent.example/cb',
    'whsec_olga_inbound_secret_0123456789abcdef')).id::text, true);
select set_config('t.inbound_secret', (select inbound_secret_id::text from public.agent
                                        where id = current_setting('t.agent')::uuid), true);
select * from public.configure_agent_trigger(
  current_setting('t.olga')::uuid, current_setting('t.agent')::uuid,
  'https://agent.example/trigger', 'whsec_olga_trigger_secret_0123456789abcdef', 30);
select set_config('t.trigger_secret', (select trigger_secret_id::text from public.agent_trigger
                                        where agent_id = current_setting('t.agent')::uuid), true);

-- Two actions: Adam decides one, Mia the other (audit entries with actors).
select set_config('t.a1', (select action_id::text from public.record_action_inbound(
  current_setting('t.agent')::uuid, 'del-1', 'email', 'Adam decides', null,
  '{"subject":"Hi"}'::jsonb, array['subject'], null, null)), true);
select set_config('t.a2', (select action_id::text from public.record_action_inbound(
  current_setting('t.agent')::uuid, 'del-2', 'email', 'Mia decides', null,
  '{"subject":"Hi"}'::jsonb, array['subject'], null, null)), true);
select * from public.record_decision(current_setting('t.a1')::uuid, current_setting('t.adam')::uuid,
  'approved', null, null, 'del-key-adam-0001');
select * from public.record_decision(current_setting('t.a2')::uuid, current_setting('t.mia')::uuid,
  'rejected', null, 'not now', 'del-key-mia-00001');

-- Pete's workspace must be untouched by everything below.
select set_config('t.pete_agent', (public.create_agent(current_setting('t.pete')::uuid, 'Pete agent', 'make',
  'https://pete.example/cb', 'whsec_pete_inbound_secret_0123456789abcde')).id::text, true);
select public.record_action_inbound(
  current_setting('t.pete_agent')::uuid, 'pete-1', 'email', 'Pete action', null,
  '{"subject":"Hi"}'::jsonb, array['subject'], null, null);

-- ---------------------------------------------------------------------------
-- Privileges: nobody but the erasure function can mutate audit_entry
-- ---------------------------------------------------------------------------
select has_function('public', 'delete_account_data', array['uuid'], 'delete_account_data exists');

select ok(
  not has_function_privilege('authenticated', 'public.delete_account_data(uuid)', 'execute')
  and not has_function_privilege('anon', 'public.delete_account_data(uuid)', 'execute')
  and has_function_privilege('service_role', 'public.delete_account_data(uuid)', 'execute'),
  'only service_role may execute delete_account_data');

select ok(
  not has_table_privilege('authenticated', 'public.audit_entry', 'update')
  and not has_table_privilege('authenticated', 'public.audit_entry', 'delete')
  and not has_table_privilege('anon', 'public.audit_entry', 'update')
  and not has_table_privilege('anon', 'public.audit_entry', 'delete')
  and not has_table_privilege('service_role', 'public.audit_entry', 'update')
  and not has_table_privilege('service_role', 'public.audit_entry', 'delete')
  and not has_table_privilege('service_role', 'public.audit_entry', 'truncate'),
  'no app role holds UPDATE / DELETE / TRUNCATE on audit_entry');

set local role authenticated;
select throws_ok($$delete from public.audit_entry$$, '42501', null,
  'authenticated cannot DELETE audit_entry');
select throws_ok($$update public.audit_entry set reason = 'x'$$, '42501', null,
  'authenticated cannot UPDATE audit_entry');
reset role;

set local role service_role;
select throws_ok($$delete from public.audit_entry$$, '42501', null,
  'service_role cannot DELETE audit_entry');
select throws_ok($$update public.audit_entry set actor_user_id = null$$, '42501', null,
  'service_role cannot UPDATE audit_entry');
select throws_ok(
  $$select set_config('cockpit.erasure', 'on', true); delete from public.audit_entry$$,
  '42501', null, 'the erasure flag alone opens nothing for service_role');
reset role;

-- ---------------------------------------------------------------------------
-- Approver: account removed, decisions anonymized
-- ---------------------------------------------------------------------------
select set_config('t.audit_before', (select count(*)::text from public.audit_entry
                                      where workspace_id = current_setting('t.ws')::uuid), true);

select results_eq(
  $$select outcome, role, workspace_deleted, members_moved
      from public.delete_account_data(current_setting('t.adam')::uuid)$$,
  $$values ('deleted'::text, 'approver'::text, false, 0)$$,
  'deleting an approver reports deleted / approver');

select ok(not exists (select 1 from public.app_user where id = current_setting('t.adam')::uuid),
  'the approver''s app_user row (and its FCM tokens) is gone');

select is((select count(*)::int from public.audit_entry
            where actor_user_id = current_setting('t.adam')::uuid),
  0, 'no audit entry names the approver any more');

select is((select count(*)::text from public.audit_entry
            where workspace_id = current_setting('t.ws')::uuid),
  current_setting('t.audit_before'), 'the owner''s audit trail keeps every entry');

select ok((select decided_by is null and status = 'decided' from public.action
            where id = current_setting('t.a1')::uuid),
  'the approver''s decision stays recorded, without the actor');

select results_eq(
  $$select outcome, workspace_deleted from public.delete_account_data(current_setting('t.adam')::uuid)$$,
  $$values ('already_deleted'::text, false)$$,
  'deleting the approver again is a no-op');

select throws_ok($$delete from public.audit_entry where action_id = current_setting('t.a1')::uuid$$,
  'P0001', 'audit_entry is append-only: DELETE is not allowed',
  'after the erasure, audit_entry is append-only again');

-- ---------------------------------------------------------------------------
-- Owner: workspace erased, remaining member moved
-- ---------------------------------------------------------------------------
select results_eq(
  $$select outcome, role, workspace_deleted, members_moved
      from public.delete_account_data(current_setting('t.olga')::uuid)$$,
  $$values ('deleted'::text, 'owner'::text, true, 1)$$,
  'deleting the owner erases the workspace and moves one member');

select ok(not exists (select 1 from public.app_user where id = current_setting('t.olga')::uuid),
  'the owner''s app_user row is gone');
select ok(not exists (select 1 from public.workspace where id = current_setting('t.ws')::uuid),
  'the workspace is gone');
select is((select count(*)::int from public.agent where workspace_id = current_setting('t.ws')::uuid),
  0, 'its agents are gone');
select is((select count(*)::int from public.action where workspace_id = current_setting('t.ws')::uuid),
  0, 'its actions are gone');
select is((select count(*)::int from public.audit_entry where workspace_id = current_setting('t.ws')::uuid),
  0, 'its audit entries are gone');
select is((select count(*)::int from public.agent_trigger where agent_id = current_setting('t.agent')::uuid),
  0, 'its agent trigger is gone');
select is((select count(*)::int from vault.secrets
            where id in (current_setting('t.inbound_secret')::uuid,
                         current_setting('t.trigger_secret')::uuid)),
  0, 'its Vault secrets (inbound + trigger) are gone');

select ok((select m.role = 'owner'
              and m.workspace_id <> current_setting('t.ws')::uuid
              and w.owner_user_id = m.id
             from public.app_user m join public.workspace w on w.id = m.workspace_id
            where m.id = current_setting('t.mia')::uuid),
  'the other member keeps their account, now owner of a new personal workspace');

select is((select count(*)::int from public.agent a
             join public.app_user p on p.workspace_id = a.workspace_id
            where p.id = current_setting('t.pete')::uuid),
  1, 'an unrelated workspace is untouched');

-- ---------------------------------------------------------------------------
-- Erasure log: one row per deletion, no PII
-- ---------------------------------------------------------------------------
select results_eq(
  $$select subject_hash, role, workspace_deleted, members_moved from public.account_deletion_log
     where subject_hash in (encode(sha256(convert_to(current_setting('t.adam'), 'UTF8')), 'hex'),
                            encode(sha256(convert_to(current_setting('t.olga'), 'UTF8')), 'hex'))
     order by id$$,
  $$values (encode(sha256(convert_to(current_setting('t.adam'), 'UTF8')), 'hex'), 'approver'::text, false, 0),
           (encode(sha256(convert_to(current_setting('t.olga'), 'UTF8')), 'hex'), 'owner'::text, true, 1)$$,
  'the log records each deletion by hashed id, once');

select is(
  (select array_agg(column_name::text order by ordinal_position) from information_schema.columns
    where table_schema = 'public' and table_name = 'account_deletion_log'),
  array['id', 'subject_hash', 'role', 'workspace_deleted', 'members_moved',
        'actions_deleted', 'audit_entries', 'deleted_at'],
  'the log has no column for email, name or payload');

select ok(not has_table_privilege('authenticated', 'public.account_deletion_log', 'select'),
  'clients cannot read the deletion log');

-- The flag only lets erasure shapes through: other columns stay frozen.
select set_config('cockpit.erasure', 'on', true);
select throws_ok(
  $$update public.audit_entry set reason = 'rewritten'
     where action_id in (select id from public.action where agent_id = current_setting('t.pete_agent')::uuid)$$,
  'P0001', 'audit_entry is append-only: UPDATE is not allowed',
  'even with the flag, only actor anonymization is allowed');
select set_config('cockpit.erasure', 'off', true);

select throws_ok($$select * from public.delete_account_data(null)$$, '22023', 'invalid_user',
  'a null user id is rejected');

select * from finish();
rollback;
