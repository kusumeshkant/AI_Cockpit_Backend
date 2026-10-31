-- 0009 — explicit Data API privileges (prod sign-in fix)
--
-- 0001–0008 relied on Supabase's default grants for the app's reads. The
-- local stack has them; the cloud project does not (`authenticated` held only
-- REFERENCES / TRIGGER / TRUNCATE on public tables), so every signed-in
-- PostgREST read failed with 42501 — first of all the profile read right
-- after sign-in. This migration states the whole privilege matrix explicitly,
-- so local and cloud end up identical whatever their defaults were.
--
-- The matrix (also asserted by supabase/tests/privileges_test.sql and checked
-- on the cloud project by scripts/deploy-check.ts — keep the three in sync):
--
--   anon           nothing on any public table, sequence or function.
--   authenticated  SELECT on exactly the columns the app reads (below), all
--                  under the existing RLS policies; table-level SELECT on
--                  trigger_run (0005, no sensitive column). No writes: the app
--                  writes only through Edge Functions and two RPCs.
--                  EXECUTE on current_workspace_id() (used by every RLS
--                  policy), register_fcm_token(text), unregister_fcm_token(text).
--   service_role   SELECT / INSERT / UPDATE / DELETE on every public table,
--                  except audit_entry: SELECT / INSERT only (append-only, 0007).
--                  EXECUTE on the RPCs the Edge Functions call.
--   PUBLIC         nothing.
--   Nobody (app roles) holds TRUNCATE, REFERENCES or TRIGGER.
--
-- Column-level, not table-level, reads on purpose: a table grant would let a
-- workspace member read other members' fcm_tokens (app_user) and the Vault
-- ids of agent / trigger secrets. RLS is unchanged.
--
-- Idempotent: it first revokes everything from the app roles, then grants the
-- matrix, so re-running it yields the same state.

-- ---------------------------------------------------------------------------
-- 1. Start from nothing for the app roles (tables, sequences, functions).
-- ---------------------------------------------------------------------------
revoke all on all tables    in schema public from public, anon, authenticated, service_role;
revoke all on all sequences in schema public from public, anon, authenticated, service_role;
revoke all on all functions in schema public from public, anon, authenticated, service_role;

-- New objects get no implicit grants either, locally or in the cloud: every
-- later migration must grant explicitly (and the matrix test catches it if
-- it doesn't).
alter default privileges for role postgres in schema public
  revoke all on tables from public, anon, authenticated, service_role;
alter default privileges for role postgres in schema public
  revoke all on sequences from public, anon, authenticated, service_role;
alter default privileges for role postgres in schema public
  revoke all on functions from public, anon, authenticated, service_role;
alter default privileges for role postgres
  revoke execute on functions from public;

-- ---------------------------------------------------------------------------
-- 2. authenticated: column reads the app makes (product/frontend/lib, *_remote_ds.dart).
-- ---------------------------------------------------------------------------
-- Profile (auth_remote_ds): app_user + embedded workspace plan; role (workspace_role_ds).
grant select (id, email, workspace_id, role)
  on public.app_user to authenticated;
grant select (id, plan)
  on public.workspace to authenticated;

-- Connections list (connections_remote_ds) and the audit feed's agent names.
grant select (id, name, platform, callback_url, status, secret_hint, last_action_at, created_at)
  on public.agent to authenticated;

-- Actions feed / detail (actions_remote_ds) and its Realtime change feed.
grant select (id, agent_id, type, title, summary, payload, editable_fields,
              status, decision, decided_at, expires_at, created_at)
  on public.action to authenticated;

-- Audit trail (audit_remote_ds).
grant select (id, action_id, event, decision, reason, edited_payload, metadata, created_at)
  on public.audit_entry to authenticated;

-- Agent Triggers (trigger_remote_ds), as in 0005: never the Vault secret id.
grant select (agent_id, workspace_id, trigger_url, secret_hint, enabled,
              min_interval_secs, created_at, updated_at)
  on public.agent_trigger to authenticated;
grant select on public.trigger_run to authenticated;

grant execute on function public.current_workspace_id()       to authenticated;
grant execute on function public.register_fcm_token(text)     to authenticated, service_role;
grant execute on function public.unregister_fcm_token(text)   to authenticated, service_role;

-- ---------------------------------------------------------------------------
-- 3. service_role: Edge Functions (RPCs) and admin scripts.
-- ---------------------------------------------------------------------------
grant select, insert, update, delete on
  public.workspace, public.app_user, public.agent, public.action,
  public.agent_rate, public.agent_trigger, public.trigger_run,
  public.account_deletion_log, public.reviewer_signin_guard
  to service_role;
-- Append-only (0001 trigger, 0007): no UPDATE / DELETE even for the service role.
grant select, insert on public.audit_entry to service_role;

grant execute on function public.prune_fcm_tokens(text[])                       to service_role;
grant execute on function public.create_agent(uuid, text, text, text, text)     to service_role;
grant execute on function public.get_agent_inbound_context(uuid)                to service_role;
grant execute on function public.record_action_inbound(uuid, text, text, text, text, jsonb, text[], text, timestamptz)
  to service_role;
grant execute on function public.record_decision(uuid, uuid, text, jsonb, text, text) to service_role;
grant execute on function public.record_callback_result(uuid, boolean, text, integer) to service_role;
grant execute on function public.claim_due_callbacks(integer, integer)          to service_role;
grant execute on function public.get_owned_agent(uuid, uuid)                    to service_role;
grant execute on function public.rotate_agent_secret(uuid, uuid, text)          to service_role;
grant execute on function public.hit_rate_limit(uuid, integer, interval)        to service_role;
grant execute on function public.configure_agent_trigger(uuid, uuid, text, text, integer) to service_role;
grant execute on function public.set_agent_trigger_enabled(uuid, uuid, boolean) to service_role;
grant execute on function public.begin_trigger_run(uuid, uuid)                  to service_role;
grant execute on function public.record_trigger_result(uuid, boolean, text)     to service_role;
grant execute on function public.delete_account_data(uuid)                      to service_role;
grant execute on function public.reviewer_signin_attempt(text)                  to service_role;

-- Not granted to anyone (run as their owner): handle_new_user and
-- audit_entry_forbid_mutation (triggers; EXECUTE is checked only when a
-- trigger is created), invoke_callbacks_retry (pg_cron, as postgres).
