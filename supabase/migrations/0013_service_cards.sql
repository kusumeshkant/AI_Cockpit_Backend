-- =============================================================================
-- 0013_service_cards.sql — agent → Cockpit cards (agent-service-inbound)
--
-- Additive on top of 0011 / 0012; ordinary agents, cards, callbacks and push
-- behave exactly as before.
--
--   agent_service.inbound_key_current_id / _next_id
--       A SECOND signing key pair (Vault), used only for agent → Cockpit
--       requests, so one leaked key never works in both directions. Not
--       readable by clients (no column grant).
--   register_agent_service (13 args, overload of the 0011 11-arg version,
--       which stays and is deprecated): a new service gets four secrets
--       (outbound + inbound pairs). Existing services get an inbound pair on
--       their next --rotate-keys.
--   get_service_inbound_keys / swap_service_inbound_keys
--   claim_gateway_nonce          replay guard: (key_id, nonce) accepted once
--   resolve_service_inbound      service + workspace by (slug, subject)
--   record_action_inbound        same signature and behaviour; for a SERVICE
--       agent the audit row keeps only the hook ({hook}), never the payload
--   record_action_update         revisioned update of a pending card
--   record_action_withdraw       pending → expired, reason code only
--
-- Privileges: EXECUTE for service_role only, one by one (0009 matrix).
-- =============================================================================

alter table public.agent_service
  add column inbound_key_current_id uuid,  -- vault.secrets.id (agent → Cockpit)
  add column inbound_key_next_id    uuid;  -- vault.secrets.id (rotation)

create index service_access_subject_idx on public.service_access (service_slug, subject);

-- -----------------------------------------------------------------------------
-- Registry: four keys
-- -----------------------------------------------------------------------------

-- The 0011 11-arg version stays (unchanged, deprecated: it creates a service
-- without inbound keys). scripts/register-service.ts calls this one.

-- As 0011, plus the inbound pair. Each pair is all-or-nothing; a new service
-- needs both pairs; all four secrets must differ. Updates keep a pair unless
-- it is given. Returns no secret and no Vault id.
create function public.register_agent_service(
  p_slug             text,
  p_display_name     text,
  p_description      text,
  p_icon             text,
  p_base_url         text,
  p_contract_version text,
  p_min_app_version  text,
  p_manifest         jsonb,
  p_status           text,
  p_signing_current  text,
  p_signing_next     text,
  p_inbound_current  text,
  p_inbound_next     text
)
returns table (slug text, status text, created boolean, keys_written boolean, inbound_keys_written boolean)
language plpgsql
security definer
set search_path = public
as $$
#variable_conflict use_column
declare
  v_existing public.agent_service;
  v_out      boolean := p_signing_current is not null or p_signing_next is not null;
  v_in       boolean := p_inbound_current is not null or p_inbound_next is not null;
  v_ids      uuid[];
begin
  if v_out and (p_signing_current is null or p_signing_next is null
                or length(p_signing_current) < 32 or length(p_signing_next) < 32) then
    raise exception 'invalid_secret' using errcode = '22023';
  end if;
  if v_in and (p_inbound_current is null or p_inbound_next is null
               or length(p_inbound_current) < 32 or length(p_inbound_next) < 32) then
    raise exception 'invalid_secret' using errcode = '22023';
  end if;
  if (select count(distinct s) <> count(s)
        from unnest(array[p_signing_current, p_signing_next, p_inbound_current, p_inbound_next]) s
       where s is not null) then
    raise exception 'invalid_secret' using errcode = '22023';
  end if;

  select * into v_existing from public.agent_service s where s.slug = p_slug for update;

  if v_existing.slug is null then
    if not (v_out and v_in) then
      raise exception 'invalid_secret' using errcode = '22023';
    end if;
    v_ids := array[
      vault.create_secret(p_signing_current, 'agent_service_' || p_slug || '_k1', 'Cockpit agent service signing key'),
      vault.create_secret(p_signing_next, 'agent_service_' || p_slug || '_k2', 'Cockpit agent service signing key (next)'),
      vault.create_secret(p_inbound_current, 'agent_service_' || p_slug || '_in1', 'Agent service inbound signing key'),
      vault.create_secret(p_inbound_next, 'agent_service_' || p_slug || '_in2', 'Agent service inbound signing key (next)')];
    insert into public.agent_service
      (slug, display_name, description, icon, base_url, status, contract_version,
       min_app_version, manifest, signing_key_current_id, signing_key_next_id,
       inbound_key_current_id, inbound_key_next_id)
    values
      (p_slug, p_display_name, coalesce(p_description, ''), p_icon, p_base_url,
       coalesce(p_status, 'draft'), coalesce(p_contract_version, '1.0'),
       p_min_app_version, p_manifest, v_ids[1], v_ids[2], v_ids[3], v_ids[4]);
  else
    if v_out then
      perform vault.update_secret(v_existing.signing_key_current_id, p_signing_current);
      perform vault.update_secret(v_existing.signing_key_next_id, p_signing_next);
    end if;
    if v_in then
      if v_existing.inbound_key_current_id is null then
        update public.agent_service s
           set inbound_key_current_id = vault.create_secret(
                 p_inbound_current, 'agent_service_' || p_slug || '_in1', 'Agent service inbound signing key'),
               inbound_key_next_id = vault.create_secret(
                 p_inbound_next, 'agent_service_' || p_slug || '_in2', 'Agent service inbound signing key (next)')
         where s.slug = p_slug;
      else
        perform vault.update_secret(v_existing.inbound_key_current_id, p_inbound_current);
        perform vault.update_secret(v_existing.inbound_key_next_id, p_inbound_next);
      end if;
    end if;
    update public.agent_service s
       set display_name = p_display_name,
           description = coalesce(p_description, ''),
           icon = p_icon,
           base_url = p_base_url,
           status = coalesce(p_status, s.status),
           contract_version = coalesce(p_contract_version, s.contract_version),
           min_app_version = p_min_app_version,
           manifest = p_manifest,
           updated_at = now()
     where s.slug = p_slug;
  end if;

  return query
    select s.slug, s.status, v_existing.slug is null, v_out, v_in
      from public.agent_service s
     where s.slug = p_slug;
end;
$$;

-- -----------------------------------------------------------------------------
-- Inbound keys + replay guard
-- -----------------------------------------------------------------------------

-- Both inbound keys of [p_slug] for verification (current first). No rows for
-- an unknown service or one without inbound keys.
create function public.get_service_inbound_keys(p_slug text)
returns table (key_id uuid, secret text, slot text)
language sql
stable
security definer
set search_path = public
as $$
  select k.id, v.decrypted_secret, k.slot
    from public.agent_service s
    cross join lateral (values (s.inbound_key_current_id, 'current', 1),
                               (s.inbound_key_next_id, 'next', 2)) k(id, slot, ord)
    join vault.decrypted_secrets v on v.id = k.id
   where s.slug = p_slug
   order by k.ord
$$;

-- Rotation: inbound next ↔ current. Returns the key ids, never a secret.
create function public.swap_service_inbound_keys(p_slug text)
returns table (current_key_id uuid, next_key_id uuid)
language plpgsql
security definer
set search_path = public
as $$
#variable_conflict use_column
begin
  update public.agent_service s
     set inbound_key_current_id = s.inbound_key_next_id,
         inbound_key_next_id = s.inbound_key_current_id,
         updated_at = now()
   where s.slug = p_slug
     and s.inbound_key_current_id is not null
     and s.inbound_key_next_id is not null;
  if not found then
    raise exception 'service_not_found' using errcode = 'P0002';
  end if;
  return query
    select s.inbound_key_current_id, s.inbound_key_next_id
      from public.agent_service s where s.slug = p_slug;
end;
$$;

-- True the first time (key_id, nonce) is seen; false for a replay.
create function public.claim_gateway_nonce(p_key_id uuid, p_nonce text)
returns boolean
language plpgsql
security definer
set search_path = public
as $$
declare
  v_fresh boolean;
begin
  if p_key_id is null or p_nonce is null or char_length(p_nonce) not between 16 and 128 then
    return false;
  end if;
  insert into public.gateway_nonce (key_id, nonce) values (p_key_id, p_nonce)
  on conflict (key_id, nonce) do nothing
  returning true into v_fresh;
  return coalesce(v_fresh, false);
end;
$$;

-- -----------------------------------------------------------------------------
-- Resolution by subject
-- -----------------------------------------------------------------------------

-- The service and the workspace that [p_subject] names for it. No row when
-- either is unknown (the caller answers a generic 401).
create function public.resolve_service_inbound(p_slug text, p_subject text)
returns table (
  workspace_id   uuid,
  service_status text,
  card_types     jsonb,
  access_state   text,
  agent_id       uuid
)
language sql
stable
security definer
set search_path = public
as $$
  select a.workspace_id, s.status, coalesce(s.manifest->'card_types', '[]'::jsonb),
         a.state, a.agent_id
    from public.agent_service s
    join public.service_access a on a.service_slug = s.slug
   where s.slug = p_slug and a.subject = p_subject
$$;

-- -----------------------------------------------------------------------------
-- Cards
-- -----------------------------------------------------------------------------

-- Same signature, behaviour and grants as 0003. Only change: for an agent
-- with platform 'service' the audit row stores {hook} instead of the payload
-- ("audit keeps hook only"); every other agent is byte-identical.
create or replace function public.record_action_inbound(
  p_agent_id        uuid,
  p_external_id     text,
  p_type            text,
  p_title           text,
  p_summary         text,
  p_payload         jsonb,
  p_editable_fields text[],
  p_callback_url    text,
  p_expires_at      timestamptz
)
returns table (action_id uuid, is_new boolean, fcm_tokens text[])
language plpgsql
security definer
set search_path = public
as $$
#variable_conflict use_column
declare
  v_workspace_id uuid;
  v_status       text;
  v_platform     text;
  v_action_id    uuid;
  v_tokens       text[];
begin
  select a.workspace_id, a.status, a.platform
    into v_workspace_id, v_status, v_platform
    from public.agent a
   where a.id = p_agent_id
     for share;

  if v_workspace_id is null then
    raise exception 'agent_not_found' using errcode = 'P0002';
  end if;
  if v_status <> 'active' then
    raise exception 'agent_disabled' using errcode = 'P0001';
  end if;

  insert into public.action
    (workspace_id, agent_id, external_id, type, title, summary, payload,
     editable_fields, callback_url, expires_at)
  values
    (v_workspace_id, p_agent_id, p_external_id, p_type, p_title, p_summary,
     coalesce(p_payload, '{}'::jsonb), coalesce(p_editable_fields, '{}'),
     p_callback_url, p_expires_at)
  on conflict (agent_id, external_id) do nothing
  returning id into v_action_id;

  if v_action_id is null then
    select id into v_action_id
      from public.action
     where agent_id = p_agent_id and external_id = p_external_id;
    return query select v_action_id, false, '{}'::text[];
    return;
  end if;

  insert into public.audit_entry (workspace_id, action_id, event, original_payload, metadata)
  values (v_workspace_id, v_action_id, 'action_received',
          case when v_platform = 'service'
               then jsonb_build_object('hook', p_payload->'hook')
               else p_payload end,
          jsonb_build_object('type', p_type));

  update public.agent set last_action_at = now() where id = p_agent_id;

  select coalesce(array_agg(distinct t), '{}')
    into v_tokens
    from public.app_user u
    cross join lateral unnest(u.fcm_tokens) t
   where u.workspace_id = v_workspace_id;

  return query select v_action_id, true, v_tokens;
end;
$$;

-- Applies a newer revision of a pending card. Outcomes:
--   updated   revision > current: title / summary / payload (/ expires_at)
--             replaced, action.revision bumped, audit 'action_updated' with
--             {revision} only
--   stale     revision <= current: nothing changes
--   noop      the card is no longer pending: nothing changes
-- Unknown card → action_not_found.
create function public.record_action_update(
  p_agent_id    uuid,
  p_external_id text,
  p_revision    integer,
  p_title       text,
  p_summary     text,
  p_payload     jsonb,
  p_expires_at  timestamptz
)
returns table (action_id uuid, outcome text, status text)
language plpgsql
security definer
set search_path = public
as $$
#variable_conflict use_column
declare
  v_action public.action;
begin
  if p_revision is null or p_revision < 1 then
    raise exception 'invalid_revision' using errcode = '22023';
  end if;

  select * into v_action
    from public.action a
   where a.agent_id = p_agent_id and a.external_id = p_external_id
     for update;
  if v_action.id is null then
    raise exception 'action_not_found' using errcode = 'P0002';
  end if;
  if v_action.status <> 'pending' then
    return query select v_action.id, 'noop'::text, v_action.status;
    return;
  end if;
  if p_revision <= v_action.revision then
    return query select v_action.id, 'stale'::text, v_action.status;
    return;
  end if;

  update public.action a
     set title = p_title,
         summary = p_summary,
         payload = coalesce(p_payload, a.payload),
         expires_at = coalesce(p_expires_at, a.expires_at),
         revision = p_revision
   where a.id = v_action.id;

  insert into public.audit_entry (workspace_id, action_id, event, metadata)
  values (v_action.workspace_id, v_action.id, 'action_updated',
          jsonb_build_object('revision', p_revision));

  return query select v_action.id, 'updated'::text, 'pending'::text;
end;
$$;

-- Withdraws a pending card (status 'expired', audit 'action_withdrawn' with
-- the reason code only). Not pending → 'noop' with the current status.
create function public.record_action_withdraw(
  p_agent_id    uuid,
  p_external_id text,
  p_reason_code text
)
returns table (action_id uuid, outcome text, status text)
language plpgsql
security definer
set search_path = public
as $$
#variable_conflict use_column
declare
  v_action public.action;
begin
  if p_reason_code is null or p_reason_code !~ '^[a-z][a-z0-9_]{0,39}$' then
    raise exception 'invalid_reason_code' using errcode = '22023';
  end if;

  select * into v_action
    from public.action a
   where a.agent_id = p_agent_id and a.external_id = p_external_id
     for update;
  if v_action.id is null then
    raise exception 'action_not_found' using errcode = 'P0002';
  end if;
  if v_action.status <> 'pending' then
    return query select v_action.id, 'noop'::text, v_action.status;
    return;
  end if;

  update public.action a set status = 'expired' where a.id = v_action.id;

  insert into public.audit_entry (workspace_id, action_id, event, metadata)
  values (v_action.workspace_id, v_action.id, 'action_withdrawn',
          jsonb_build_object('reason_code', p_reason_code));

  return query select v_action.id, 'withdrawn'::text, 'expired'::text;
end;
$$;

-- -----------------------------------------------------------------------------
-- Privileges (explicit, one by one). record_action_inbound keeps its 0009
-- grant (CREATE OR REPLACE preserves it).
-- -----------------------------------------------------------------------------

grant execute on function public.register_agent_service(text, text, text, text, text, text, text, jsonb, text, text, text, text, text)
  to service_role;
grant execute on function public.get_service_inbound_keys(text)  to service_role;
grant execute on function public.swap_service_inbound_keys(text) to service_role;
grant execute on function public.claim_gateway_nonce(uuid, text) to service_role;
grant execute on function public.resolve_service_inbound(text, text) to service_role;
grant execute on function public.record_action_update(uuid, text, integer, text, text, jsonb, timestamptz)
  to service_role;
grant execute on function public.record_action_withdraw(uuid, text, text) to service_role;
