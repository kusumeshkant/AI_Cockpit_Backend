-- =============================================================================
-- 0002_auth_bootstrap.sql — provision workspace + app_user on first sign-up
--
-- Plan: technical backend implementation plan §7. This trigger is the ONLY way
-- workspace/app_user rows are created; the app never inserts them (RLS denies
-- client writes anyway).
-- =============================================================================

create function public.handle_new_user()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
declare
  v_workspace_id uuid;
begin
  -- Idempotent: a re-fired trigger (or a pre-provisioned user) is a no-op.
  if exists (select 1 from public.app_user where id = new.id) then
    return new;
  end if;

  insert into public.workspace (name)
  values (
    left(coalesce(nullif(split_part(coalesce(new.email, ''), '@', 1), ''), 'My workspace'), 120)
  )
  returning id into v_workspace_id;

  insert into public.app_user (id, workspace_id, email, role)
  values (new.id, v_workspace_id, coalesce(new.email, ''), 'owner');

  update public.workspace
     set owner_user_id = new.id
   where id = v_workspace_id;

  return new;
end;
$$;

revoke all on function public.handle_new_user() from public, anon, authenticated;

create trigger on_auth_user_created
  after insert on auth.users
  for each row execute function public.handle_new_user();
