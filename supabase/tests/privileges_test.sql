-- pgTAP: 0009 — the exact Data API privilege matrix, per role, for every
-- public table, column, sequence and function. The local stack used to hand
-- out default grants the cloud project doesn't, which hid a missing GRANT
-- (prod sign-in: 42501 on the profile read). Any drift — a missing grant or
-- an extra one — fails here. Keep in sync with 0009's header and
-- scripts/deploy-check.ts (EXPECTED_PRIVILEGES).
begin;
create extension if not exists pgtap with schema extensions;

select plan(11);

-- The roles that matter; 'PUBLIC' is grantee 0.
create temp view app_grantee (oid, name) as
  select 0::oid, 'PUBLIC'::text
  union all select oid, rolname::text from pg_roles
   where rolname in ('anon', 'authenticated', 'service_role');

-- ---------------------------------------------------------------------------
-- Tables
-- ---------------------------------------------------------------------------
select set_eq(
  $$select c.relname::text from pg_class c join pg_namespace n on n.oid = c.relnamespace
     where n.nspname = 'public' and c.relkind in ('r', 'p', 'v', 'm', 'f')$$,
  $$values ('workspace'), ('app_user'), ('agent'), ('action'), ('audit_entry'),
           ('agent_rate'), ('agent_trigger'), ('trigger_run'),
           ('account_deletion_log'), ('reviewer_signin_guard')$$,
  'every public table and view is covered by the matrix (add new ones here and in 0009)');

select set_eq(
  $$select g.name, c.relname::text, a.privilege_type::text
      from pg_class c
      join pg_namespace n on n.oid = c.relnamespace
      cross join lateral aclexplode(coalesce(c.relacl, acldefault('r', c.relowner))) a
      join app_grantee g on g.oid = a.grantee
     where n.nspname = 'public' and c.relkind in ('r', 'p', 'v', 'm', 'f')$$,
  $$select 'service_role' as role, t as tbl, p as priv
      from unnest(array['workspace', 'app_user', 'agent', 'action', 'agent_rate',
                        'agent_trigger', 'trigger_run', 'account_deletion_log',
                        'reviewer_signin_guard']) t,
           unnest(array['SELECT', 'INSERT', 'UPDATE', 'DELETE']) p
    union all select * from (values ('service_role', 'audit_entry', 'SELECT'),
                     ('service_role', 'audit_entry', 'INSERT'),
                     ('authenticated', 'trigger_run', 'SELECT')) v(role, tbl, priv)$$,
  'table-level privileges: service_role DML (audit_entry SELECT/INSERT only), authenticated only trigger_run SELECT, anon and PUBLIC nothing');

select set_eq(
  $$select g.name, c.relname::text, att.attname::text, a.privilege_type::text
      from pg_attribute att
      join pg_class c on c.oid = att.attrelid
      join pg_namespace n on n.oid = c.relnamespace
      cross join lateral aclexplode(att.attacl) a
      join app_grantee g on g.oid = a.grantee
     where n.nspname = 'public' and att.attnum > 0 and not att.attisdropped$$,
  $$select 'authenticated' as role, t as tbl, col, 'SELECT' as priv
      from (values
        ('app_user',      array['id', 'email', 'workspace_id', 'role']),
        ('workspace',     array['id', 'plan']),
        ('agent',         array['id', 'name', 'platform', 'callback_url', 'status',
                                'secret_hint', 'last_action_at', 'created_at']),
        ('action',        array['id', 'agent_id', 'type', 'title', 'summary', 'payload',
                                'editable_fields', 'status', 'decision', 'decided_at',
                                'expires_at', 'created_at']),
        ('audit_entry',   array['id', 'action_id', 'event', 'decision', 'reason',
                                'edited_payload', 'metadata', 'created_at']),
        ('agent_trigger', array['agent_id', 'workspace_id', 'trigger_url', 'secret_hint',
                                'enabled', 'min_interval_secs', 'created_at', 'updated_at'])
      ) m(t, cols), unnest(m.cols) col$$,
  'column-level privileges: authenticated reads exactly the columns the app selects');

select is(
  (select count(*)::int
     from unnest(array['anon', 'authenticated']) r
     cross join (values ('app_user', 'fcm_tokens'), ('agent', 'inbound_secret_id'),
                        ('agent_trigger', 'trigger_secret_id'), ('action', 'callback_status')) s(t, col)
    where has_column_privilege(r, format('public.%I', s.t), s.col, 'SELECT')),
  0, 'no client role can read push tokens, Vault secret ids or callback internals');

select is(
  (select count(*)::int
     from unnest(array['anon', 'authenticated', 'service_role']) r,
          unnest(array['UPDATE', 'DELETE', 'TRUNCATE']) p
    where has_table_privilege(r, 'public.audit_entry', p)),
  0, 'audit_entry: no app role can UPDATE, DELETE or TRUNCATE');

-- ---------------------------------------------------------------------------
-- Sequences
-- ---------------------------------------------------------------------------
select is_empty(
  $$select c.relname, g.name, a.privilege_type
      from pg_class c
      join pg_namespace n on n.oid = c.relnamespace
      cross join lateral aclexplode(coalesce(c.relacl, acldefault('s', c.relowner))) a
      join app_grantee g on g.oid = a.grantee
     where n.nspname = 'public' and c.relkind = 'S'$$,
  'no app role holds any privilege on a public sequence');

-- ---------------------------------------------------------------------------
-- Functions (extension members excluded)
-- ---------------------------------------------------------------------------
select set_eq(
  $$select g.name, p.proname || '(' || oidvectortypes(p.proargtypes) || ')'
      from pg_proc p
      join pg_namespace n on n.oid = p.pronamespace
      cross join lateral aclexplode(coalesce(p.proacl, acldefault('f', p.proowner))) a
      join app_grantee g on g.oid = a.grantee
     where n.nspname = 'public'
       and not exists (select 1 from pg_depend d
                        where d.classid = 'pg_proc'::regclass and d.objid = p.oid and d.deptype = 'e')$$,
  $$values
      ('authenticated', 'current_workspace_id()'),
      ('authenticated', 'register_fcm_token(text)'),
      ('authenticated', 'unregister_fcm_token(text)'),
      ('service_role',  'register_fcm_token(text)'),
      ('service_role',  'unregister_fcm_token(text)'),
      ('service_role',  'prune_fcm_tokens(text[])'),
      ('service_role',  'create_agent(uuid, text, text, text, text)'),
      ('service_role',  'get_agent_inbound_context(uuid)'),
      ('service_role',  'record_action_inbound(uuid, text, text, text, text, jsonb, text[], text, timestamp with time zone)'),
      ('service_role',  'record_decision(uuid, uuid, text, jsonb, text, text)'),
      ('service_role',  'record_callback_result(uuid, boolean, text, integer)'),
      ('service_role',  'claim_due_callbacks(integer, integer)'),
      ('service_role',  'get_owned_agent(uuid, uuid)'),
      ('service_role',  'rotate_agent_secret(uuid, uuid, text)'),
      ('service_role',  'hit_rate_limit(uuid, integer, interval)'),
      ('service_role',  'configure_agent_trigger(uuid, uuid, text, text, integer)'),
      ('service_role',  'set_agent_trigger_enabled(uuid, uuid, boolean)'),
      ('service_role',  'begin_trigger_run(uuid, uuid)'),
      ('service_role',  'record_trigger_result(uuid, boolean, text)'),
      ('service_role',  'delete_account_data(uuid)'),
      ('service_role',  'reviewer_signin_attempt(text)')$$,
  'function EXECUTE: authenticated only the RLS helper and its two RPCs, service_role the Edge Function RPCs, anon and PUBLIC nothing');

-- ---------------------------------------------------------------------------
-- Defaults: a new object gets nothing until a migration grants it, locally
-- exactly as in the cloud.
-- ---------------------------------------------------------------------------
create table public.privileges_probe (id int primary key);
create function public.privileges_probe_fn() returns int language sql as 'select 1';

select is(
  (select count(*)::int
     from unnest(array['anon', 'authenticated', 'service_role']) r,
          unnest(array['SELECT', 'INSERT', 'UPDATE', 'DELETE', 'TRUNCATE', 'REFERENCES', 'TRIGGER']) p
    where has_table_privilege(r, 'public.privileges_probe', p)),
  0, 'a new public table grants nothing by default');

select is(
  (select count(*)::int
     from unnest(array['anon', 'authenticated', 'service_role']) r
    where has_function_privilege(r, 'public.privileges_probe_fn()', 'EXECUTE')),
  0, 'a new public function is executable by no app role by default (not even via PUBLIC)');

-- ---------------------------------------------------------------------------
-- Through PostgREST's roles: the app's reads work, anything else is refused.
-- ---------------------------------------------------------------------------
set local role anon;
select throws_ok($$select id from public.app_user$$, '42501', null,
  'anon cannot read app_user');
reset role;

set local role authenticated;
select throws_ok($$select * from public.agent$$, '42501', null,
  'select * is refused where a column is not granted (agent.inbound_secret_id)');
reset role;

select * from finish();
rollback;
