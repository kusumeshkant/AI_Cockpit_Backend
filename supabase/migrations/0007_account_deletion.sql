-- =============================================================================
-- 0007_account_deletion.sql — in-app account deletion (F02)
--
-- delete_account_data(p_user_id) removes a user's data in one transaction.
-- The account-delete Edge Function calls it, then deletes the auth user with
-- the service role (sessions, refresh tokens, identities go with it).
--
--   * Approver: their app_user row (profile, role, FCM tokens) is deleted;
--     their decisions stay in the owner's audit trail with actor_user_id
--     anonymized to null.
--   * Owner: the whole workspace goes — agents (and their Vault secrets),
--     actions, audit entries, triggers, trigger runs, rate counters. Any other
--     member is moved to a fresh personal workspace as its owner (the same
--     shape sign-up creates); their account is never deleted.
--
-- Idempotent: a second call for a user with no app_user row returns
-- 'already_deleted' and changes nothing, so the Edge Function can always be
-- retried (e.g. when the auth delete failed after this commit).
--
-- audit_entry stays append-only. The trigger lets a mutation through only
-- while this function has set the transaction-local flag `cockpit.erasure`,
-- and no client or service role holds UPDATE/DELETE/TRUNCATE on the table, so
-- the flag alone opens nothing: only this SECURITY DEFINER function (owned by
-- postgres) can erase, and only the shapes it performs.
--
-- account_deletion_log keeps proof of each erasure without PII: a SHA-256 of
-- the user id, the role, and row counts. No email, name or payload.
-- =============================================================================

-- -----------------------------------------------------------------------------
-- audit_entry: no role may mutate it directly, including service_role
-- -----------------------------------------------------------------------------
revoke update, delete, truncate on public.audit_entry from service_role;

create or replace function public.audit_entry_forbid_mutation()
returns trigger
language plpgsql
as $$
begin
  if current_setting('cockpit.erasure', true) = 'on' then
    if tg_op = 'DELETE' then
      return old;
    end if;
    -- Erasure may only anonymize the actor; every other column is frozen.
    if tg_op = 'UPDATE'
       and new.actor_user_id is null
       and (to_jsonb(new) - 'actor_user_id') = (to_jsonb(old) - 'actor_user_id') then
      return new;
    end if;
  end if;
  raise exception 'audit_entry is append-only: % is not allowed', tg_op;
end;
$$;

-- -----------------------------------------------------------------------------
-- account_deletion_log — PII-free proof of erasure
-- -----------------------------------------------------------------------------
create table public.account_deletion_log (
  id                bigint generated always as identity primary key,
  subject_hash      text        not null check (subject_hash ~ '^[0-9a-f]{64}$'),
  role              text        not null check (role in ('owner', 'approver')),
  workspace_deleted boolean     not null,
  members_moved     integer     not null default 0 check (members_moved >= 0),
  actions_deleted   integer     not null default 0 check (actions_deleted >= 0),
  audit_entries     integer     not null default 0 check (audit_entries >= 0),
  deleted_at        timestamptz not null default now()
);

comment on table public.account_deletion_log is
  'One row per account deletion. No PII: subject_hash is sha256(user id); '
  'audit_entries counts rows deleted (owner) or anonymized (approver).';

alter table public.account_deletion_log enable row level security;
revoke all on public.account_deletion_log from anon, authenticated;

-- -----------------------------------------------------------------------------
-- delete_account_data
-- -----------------------------------------------------------------------------
create function public.delete_account_data(p_user_id uuid)
returns table (
  outcome           text,
  role              text,
  workspace_deleted boolean,
  members_moved     integer
)
language plpgsql
security definer
set search_path = public
as $$
declare
  v_user         public.app_user;
  v_workspace_id uuid;
  v_member       record;
  v_new_ws       uuid;
  v_moved        integer := 0;
  v_actions      integer := 0;
  v_audit        integer := 0;
begin
  if p_user_id is null then
    raise exception 'invalid_user' using errcode = '22023';
  end if;

  -- Two deletions of the same user never interleave.
  perform pg_advisory_xact_lock(hashtextextended('account_delete:' || p_user_id::text, 0));

  select * into v_user from public.app_user u where u.id = p_user_id for update;
  if not found then
    return query select 'already_deleted'::text, null::text, false, 0;
    return;
  end if;

  perform set_config('cockpit.erasure', 'on', true);

  if v_user.role = 'owner' then
    v_workspace_id := v_user.workspace_id;
    perform 1 from public.workspace w where w.id = v_workspace_id for update;

    -- Every other member keeps their account in a new personal workspace.
    for v_member in
      select m.id, m.email
        from public.app_user m
       where m.workspace_id = v_workspace_id
         and m.id <> p_user_id
       order by m.created_at, m.id
    loop
      insert into public.workspace (name)
      values (left(coalesce(nullif(split_part(v_member.email, '@', 1), ''), 'My workspace'), 120))
      returning id into v_new_ws;

      update public.app_user
         set workspace_id = v_new_ws,
             role = 'owner'
       where id = v_member.id;

      update public.workspace
         set owner_user_id = v_member.id
       where id = v_new_ws;

      v_moved := v_moved + 1;
    end loop;

    -- Vault secrets are not reachable by FK cascade.
    delete from vault.secrets s
     where s.id in (
       select a.inbound_secret_id from public.agent a
        where a.workspace_id = v_workspace_id and a.inbound_secret_id is not null
       union
       select t.trigger_secret_id from public.agent_trigger t
        where t.workspace_id = v_workspace_id
     );

    -- audit_entry has no cascade (append-only); remove it explicitly first.
    delete from public.audit_entry e where e.workspace_id = v_workspace_id;
    get diagnostics v_audit = row_count;

    select count(*)::int into v_actions from public.action a where a.workspace_id = v_workspace_id;

    delete from public.app_user u where u.id = p_user_id;
    -- Cascades: agent, action, agent_trigger, trigger_run, agent_rate.
    delete from public.workspace w where w.id = v_workspace_id;
  else
    update public.audit_entry e
       set actor_user_id = null
     where e.actor_user_id = p_user_id;
    get diagnostics v_audit = row_count;

    -- action.decided_by / trigger_run.triggered_by are ON DELETE SET NULL.
    delete from public.app_user u where u.id = p_user_id;
  end if;

  perform set_config('cockpit.erasure', 'off', true);

  insert into public.account_deletion_log
    (subject_hash, role, workspace_deleted, members_moved, actions_deleted, audit_entries)
  values (
    encode(sha256(convert_to(p_user_id::text, 'UTF8')), 'hex'),
    v_user.role,
    v_user.role = 'owner',
    v_moved,
    v_actions,
    v_audit
  );

  return query select 'deleted'::text, v_user.role, v_user.role = 'owner', v_moved;
end;
$$;

revoke all on function public.delete_account_data(uuid) from public, anon, authenticated;
grant execute on function public.delete_account_data(uuid) to service_role;
