-- =============================================================================
-- seed.sql — LOCAL DEVELOPMENT ONLY (applied by `supabase db reset`)
--
-- Creates one signed-up user (the auth trigger provisions their workspace +
-- app_user) and one agent with a fixed id and a well-known secret, so the
-- loop can be exercised with curl right after a reset.
--
--   user   : dev@cockpit.local / cockpit-dev-password
--   agent  : bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb
--   secret : whsec_local_dev_only_never_use_in_production
--   cron   : cron_local_dev_only_never_use_in_production (X-Cron-Secret)
-- =============================================================================

do $$
declare
  v_user_id  constant uuid := 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
  v_agent_id constant uuid := 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
  v_secret   constant text := 'whsec_local_dev_only_never_use_in_production';
  v_workspace_id uuid;
  v_secret_id    uuid;
begin
  insert into auth.users (
    instance_id, id, aud, role, email, encrypted_password, email_confirmed_at,
    raw_app_meta_data, raw_user_meta_data, created_at, updated_at,
    confirmation_token, email_change, email_change_token_new, recovery_token
  ) values (
    '00000000-0000-0000-0000-000000000000', v_user_id, 'authenticated', 'authenticated',
    'dev@cockpit.local', extensions.crypt('cockpit-dev-password', extensions.gen_salt('bf')), now(),
    '{"provider":"email","providers":["email"]}', '{}', now(), now(),
    '', '', '', ''
  );

  insert into auth.identities (
    id, user_id, provider_id, identity_data, provider, last_sign_in_at, created_at, updated_at
  ) values (
    gen_random_uuid(), v_user_id, v_user_id::text,
    jsonb_build_object('sub', v_user_id::text, 'email', 'dev@cockpit.local', 'email_verified', true),
    'email', now(), now(), now()
  );

  select workspace_id into v_workspace_id from public.app_user where id = v_user_id;

  v_secret_id := vault.create_secret(v_secret, 'agent_inbound_' || v_agent_id::text, 'Local dev seed');

  insert into public.agent (id, workspace_id, name, platform, callback_url, inbound_secret_id, secret_hint)
  values (v_agent_id, v_workspace_id, 'Local dev agent', 'n8n',
          'https://example.com/cockpit/callback', v_secret_id, right(v_secret, 4));
end;
$$;

-- -----------------------------------------------------------------------------
-- callbacks-retry schedule (0004). pg_cron calls invoke_callbacks_retry() every
-- minute; it POSTs this URL (Kong on the local Docker network) with this secret
-- as X-Cron-Secret. CRON_SECRET in supabase/functions/.env must match.
-- -----------------------------------------------------------------------------
select vault.create_secret(
  'http://supabase_kong_cockpit:8000/functions/v1/callbacks-retry',
  'cockpit_callbacks_retry_url',
  'Local dev: callbacks-retry endpoint for pg_cron');
select vault.create_secret(
  'cron_local_dev_only_never_use_in_production',
  'cockpit_cron_secret',
  'Local dev: X-Cron-Secret for callbacks-retry');
