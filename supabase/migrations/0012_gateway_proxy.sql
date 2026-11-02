-- =============================================================================
-- 0012_gateway_proxy.sql — what the agent-proxy Edge Function needs on top of
-- 0011 (additive only; 0011's tables, RPCs and policies are unchanged).
--
--   gateway_call.attempts      how many times the proxy called the agent for
--                              one request (0 = answered without calling out)
--   get_service_signing_key    the CURRENT signing key (Vault) of a service,
--                              for Cockpit-Signature v1; service role only
--   swap_service_signing_keys  rotation step: current ↔ next. Agents accept
--                              both key ids, so a swap never fails a call
--   record_gateway_outcome     one ids-only gateway_call row + first use +
--                              circuit breaker (5 consecutive agent failures
--                              → open for 30 s; a success closes it). State
--                              lives in agent_service, not isolate memory
--   prune_gateway + pg_cron    nonces > 24 h, calls > 30 days, rate windows
--                              older than a day; hourly (cockpit-gateway-prune)
--
-- Privileges follow the 0009 matrix: EXECUTE for service_role only, one by one;
-- prune_gateway runs as its owner from pg_cron and is granted to nobody.
-- =============================================================================

alter table public.gateway_call add column attempts integer not null default 1
  check (attempts between 0 and 3);

-- -----------------------------------------------------------------------------
-- Signing keys
-- -----------------------------------------------------------------------------

-- The current key of [p_slug]: its id (sent as X-Cockpit-Key-Id) and secret.
-- No row when the service is unknown or has no key.
create function public.get_service_signing_key(p_slug text)
returns table (key_id uuid, secret text)
language sql
stable
security definer
set search_path = public
as $$
  select s.signing_key_current_id, v.decrypted_secret
    from public.agent_service s
    join vault.decrypted_secrets v on v.id = s.signing_key_current_id
   where s.slug = p_slug
$$;

-- Rotation: the next key becomes current and the old current becomes next.
-- Returns the new pair of key ids (never a secret).
create function public.swap_service_signing_keys(p_slug text)
returns table (current_key_id uuid, next_key_id uuid)
language plpgsql
security definer
set search_path = public
as $$
#variable_conflict use_column
begin
  update public.agent_service s
     set signing_key_current_id = s.signing_key_next_id,
         signing_key_next_id = s.signing_key_current_id,
         updated_at = now()
   where s.slug = p_slug
     and s.signing_key_current_id is not null
     and s.signing_key_next_id is not null;
  if not found then
    raise exception 'service_not_found' using errcode = 'P0002';
  end if;
  return query
    select s.signing_key_current_id, s.signing_key_next_id
      from public.agent_service s where s.slug = p_slug;
end;
$$;

-- -----------------------------------------------------------------------------
-- Call outcome + circuit breaker
-- -----------------------------------------------------------------------------

-- [p_agent_ok]: true = the agent answered sanely (2xx or a well-formed error
-- envelope), false = network error / timeout / 5xx / invalid answer, null =
-- the agent was not called. [p_count_use]: a successful forwarded call stamps
-- service_access.first_used_at (built-in ops pass false).
create function public.record_gateway_outcome(
  p_workspace_id uuid,
  p_slug         text,
  p_op           text,
  p_status       integer,
  p_latency_ms   integer,
  p_attempts     integer,
  p_agent_ok     boolean,
  p_count_use    boolean
)
returns table (consecutive_failures integer, open_until timestamptz)
language plpgsql
security definer
set search_path = public
as $$
#variable_conflict use_column
declare
  c_threshold constant integer  := 5;
  c_open      constant interval := interval '30 seconds';
begin
  if p_op is null or p_op !~ '^[a-z][a-z0-9_.-]{0,63}$' then
    raise exception 'invalid_op' using errcode = '22023';
  end if;
  if p_status is null or p_status not between 100 and 599
     or p_latency_ms is null or p_latency_ms < 0
     or p_attempts is null or p_attempts not between 0 and 3 then
    raise exception 'invalid_gateway_call' using errcode = '22023';
  end if;

  insert into public.gateway_call (workspace_id, service_slug, op, status, latency_ms, attempts)
  values (p_workspace_id, p_slug, p_op, p_status, p_latency_ms, p_attempts);

  if coalesce(p_count_use, false) and p_status between 200 and 299 then
    update public.service_access a
       set first_used_at = now(), updated_at = now()
     where a.workspace_id = p_workspace_id and a.service_slug = p_slug
       and a.first_used_at is null;
  end if;

  if p_agent_ok is true then
    update public.agent_service s
       set consecutive_failures = 0, open_until = null
     where s.slug = p_slug and (s.consecutive_failures <> 0 or s.open_until is not null);
  elsif p_agent_ok is false then
    update public.agent_service s
       set consecutive_failures = s.consecutive_failures + 1,
           open_until = case when s.consecutive_failures + 1 >= c_threshold
                             then now() + c_open else s.open_until end
     where s.slug = p_slug;
  end if;

  return query
    select s.consecutive_failures, s.open_until
      from public.agent_service s where s.slug = p_slug;
end;
$$;

-- -----------------------------------------------------------------------------
-- Pruning (pg_cron, as in 0004)
-- -----------------------------------------------------------------------------

create function public.prune_gateway()
returns table (nonces integer, calls integer, rate_windows integer)
language plpgsql
security definer
set search_path = public
as $$
declare
  v_nonces integer;
  v_calls  integer;
  v_rates  integer;
begin
  delete from public.gateway_nonce where seen_at < now() - interval '24 hours';
  get diagnostics v_nonces = row_count;
  delete from public.gateway_call where created_at < now() - interval '30 days';
  get diagnostics v_calls = row_count;
  delete from public.gateway_rate where window_start < now() - interval '1 day';
  get diagnostics v_rates = row_count;
  return query select v_nonces, v_calls, v_rates;
end;
$$;

select cron.schedule('cockpit-gateway-prune', '17 * * * *', 'select public.prune_gateway()');

-- -----------------------------------------------------------------------------
-- Privileges (explicit, one by one)
-- -----------------------------------------------------------------------------

revoke all on function public.prune_gateway() from public, anon, authenticated, service_role;

grant execute on function public.get_service_signing_key(text)   to service_role;
grant execute on function public.swap_service_signing_keys(text) to service_role;
grant execute on function public.record_gateway_outcome(uuid, text, text, integer, integer, integer, boolean, boolean)
  to service_role;
