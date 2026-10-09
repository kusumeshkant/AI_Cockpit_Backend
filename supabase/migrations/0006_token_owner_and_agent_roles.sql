-- =============================================================================
-- 0006_token_owner_and_agent_roles.sql — one device token = one user, and
-- owner-only agent creation
--
-- F05 (push privacy): register_fcm_token used to add the token to the
-- caller's row only. A device that changed hands without a clean sign-out
-- (offline, expired session, uninstall) kept the token on the previous
-- user's row too, so that user's pushes reached the new user's phone. The
-- token now moves: it is removed from every other app_user row and added to
-- the caller's, in one statement-atomic RPC, serialised per token.
--
-- F08 (roles): create_agent had no role check, so an approver could create
-- an agent and then get 404 on every follow-up (test action, rotate secret),
-- which are owner-only. Agent management is owner-only; create_agent now
-- raises `forbidden` (42501) for a non-owner. Approvers keep everything they
-- had: reading the workspace and deciding actions (record_decision is
-- unchanged).
--
-- Both functions keep their signatures, so existing grants stay as they are.
-- =============================================================================

create or replace function public.register_fcm_token(p_token text)
returns void
language plpgsql
security definer
set search_path = public
as $$
declare
  v_max_tokens constant int := 10;
begin
  if auth.uid() is null then
    raise exception 'unauthorized' using errcode = '28000';
  end if;
  if p_token is null or length(p_token) = 0 or length(p_token) > 4096 then
    raise exception 'invalid_token' using errcode = '22023';
  end if;

  -- Two users registering the same token at once must not both keep it.
  perform pg_advisory_xact_lock(hashtextextended('fcm_token:' || p_token, 0));

  -- The device now belongs to the caller: drop it from everyone else.
  update public.app_user u
     set fcm_tokens = array_remove(u.fcm_tokens, p_token)
   where u.id <> auth.uid()
     and p_token = any (u.fcm_tokens);

  update public.app_user u
     set fcm_tokens = (
           select coalesce(array_agg(t order by ord), '{}')
             from (
               select t, ord
                 from unnest(array_append(array_remove(u.fcm_tokens, p_token), p_token))
                      with ordinality as x(t, ord)
                order by ord desc
                limit v_max_tokens
             ) newest
         )
   where u.id = auth.uid();
end;
$$;

create or replace function public.create_agent(
  p_user_id      uuid,
  p_name         text,
  p_platform     text,
  p_callback_url text,
  p_secret       text
)
returns public.agent
language plpgsql
security definer
set search_path = public
as $$
declare
  v_workspace_id uuid;
  v_role         text;
  v_agent_id     uuid := gen_random_uuid();
  v_secret_id    uuid;
  v_agent        public.agent;
begin
  select workspace_id, role into v_workspace_id, v_role
    from public.app_user
   where id = p_user_id;
  if v_workspace_id is null then
    raise exception 'workspace_not_found' using errcode = 'P0002';
  end if;
  if v_role is distinct from 'owner' then
    raise exception 'forbidden' using errcode = '42501';
  end if;
  if p_secret is null or length(p_secret) < 32 then
    raise exception 'invalid_secret' using errcode = '22023';
  end if;

  v_secret_id := vault.create_secret(
    p_secret,
    'agent_inbound_' || v_agent_id::text,
    'Cockpit agent inbound HMAC secret'
  );

  insert into public.agent
    (id, workspace_id, name, platform, callback_url, inbound_secret_id, secret_hint)
  values
    (v_agent_id, v_workspace_id, p_name, p_platform, p_callback_url, v_secret_id, right(p_secret, 4))
  returning * into v_agent;

  return v_agent;
end;
$$;
