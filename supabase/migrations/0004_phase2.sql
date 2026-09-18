-- =============================================================================
-- 0004_phase2.sql — Phase 2 backend hardening
--
-- Spec: technical/phase2-and-fcm-plan.md (Part A).
--   * Callback retry with backoff (TR-7): action.next_attempt_at,
--     claim_due_callbacks, record_callback_result v2, pg_cron → pg_net →
--     callbacks-retry Edge Function.
--   * Secret rotation (TR-8): rotate_agent_secret.
--   * Test actions: get_owned_agent (ownership check for agents-test-action,
--     which then inserts through record_action_inbound).
--   * Inbound rate limit: agent_rate + hit_rate_limit (fixed window).
--
-- Retry policy numbers (base, cap, max attempts, jitter) live in
-- functions/_shared/retry.ts; Postgres applies the delay it is given, so the
-- state transition stays atomic here and the policy stays unit-testable.
--
-- Callback states after this migration:
--   pending    decided, first delivery not attempted yet
--   delivered  an attempt got a 2xx
--   retrying   an attempt failed; next_attempt_at says when to try again
--   failed     gave up (max attempts, blocked URL or missing secret)
-- =============================================================================

create extension if not exists pg_cron with schema pg_catalog;
create extension if not exists pg_net with schema extensions;

-- -----------------------------------------------------------------------------
-- Callback retry (TR-7)
-- -----------------------------------------------------------------------------

alter table public.action add column next_attempt_at timestamptz;

drop index public.action_callback_retry_idx;
create index action_callback_due_idx on public.action (next_attempt_at)
  where callback_status = 'retrying';

-- Phase 1 marked every failed first attempt as terminal `failed`. Give those
-- rows the retries they would have had.
update public.action
   set callback_status = 'retrying',
       next_attempt_at = now()
 where status = 'decided'
   and callback_status = 'failed'
   and callback_attempts < 8;

-- v2 adds p_retry_in_seconds and returns the resulting callback status.
drop function public.record_callback_result(uuid, boolean, text);

-- Records one delivery attempt. Outcome:
--   delivered                      → delivered, audit callback_delivered
--   failed, p_retry_in_seconds set → retrying at now() + delay,
--                                    audit callback_attempted
--   failed, p_retry_in_seconds null→ failed (terminal), audit callback_failed
-- A result for an action that is already delivered is ignored (a slow retry
-- can't overwrite a success), and returns 'delivered'.
create function public.record_callback_result(
  p_action_id         uuid,
  p_delivered         boolean,
  p_detail            text,
  p_retry_in_seconds  integer default null
)
returns text
language plpgsql
security definer
set search_path = public
as $$
declare
  v_status       text;
  v_next         timestamptz;
  v_workspace_id uuid;
  v_attempts     integer;
begin
  if p_retry_in_seconds is not null and p_retry_in_seconds < 0 then
    raise exception 'invalid_retry_delay' using errcode = '22023';
  end if;

  v_status := case
    when p_delivered then 'delivered'
    when p_retry_in_seconds is not null then 'retrying'
    else 'failed'
  end;
  if v_status = 'retrying' then
    v_next := now() + make_interval(secs => p_retry_in_seconds);
  end if;

  update public.action
     set callback_status   = v_status,
         callback_attempts = callback_attempts + 1,
         next_attempt_at   = v_next
   where id = p_action_id
     and callback_status <> 'delivered'
  returning workspace_id, callback_attempts into v_workspace_id, v_attempts;

  if v_workspace_id is null then
    if exists (select 1 from public.action where id = p_action_id) then
      return 'delivered';
    end if;
    raise exception 'action_not_found' using errcode = 'P0002';
  end if;

  insert into public.audit_entry (workspace_id, action_id, event, metadata)
  values (
    v_workspace_id,
    p_action_id,
    case v_status
      when 'delivered' then 'callback_delivered'
      when 'retrying'  then 'callback_attempted'
      else 'callback_failed'
    end,
    jsonb_build_object('detail', left(p_detail, 500), 'attempt', v_attempts)
      || case when v_next is null then '{}'::jsonb
              else jsonb_build_object('next_attempt_at', v_next) end
  );

  return v_status;
end;
$$;

-- Claims up to p_limit due retries for redelivery. Rows are locked with
-- SKIP LOCKED and leased (next_attempt_at pushed p_lease_seconds ahead), so a
-- concurrent or overlapping run can't claim the same callback: no double
-- send. If the worker dies mid-delivery the lease expires and the row is
-- retried. The stored callback payload and the decision's Idempotency-Key
-- are returned so the agent receives exactly what the first attempt sent.
create function public.claim_due_callbacks(p_limit integer, p_lease_seconds integer default 120)
returns table (
  action_id        uuid,
  agent_id         uuid,
  callback_url     text,
  callback_payload jsonb,
  idempotency_key  text,
  attempts         integer
)
language plpgsql
security definer
set search_path = public
as $$
#variable_conflict use_column
begin
  if p_limit is null or p_limit not between 1 and 100 then
    raise exception 'invalid_limit' using errcode = '22023';
  end if;
  if p_lease_seconds is null or p_lease_seconds not between 10 and 3600 then
    raise exception 'invalid_lease' using errcode = '22023';
  end if;

  return query
  with due as (
    select a.id
      from public.action a
     where a.callback_status = 'retrying'
       and a.next_attempt_at <= now()
     order by a.next_attempt_at
     limit p_limit
       for update skip locked
  ),
  leased as (
    update public.action a
       set next_attempt_at = now() + make_interval(secs => p_lease_seconds)
      from due
     where a.id = due.id
    returning a.id, a.agent_id, a.callback_url, a.callback_attempts
  )
  select l.id,
         l.agent_id,
         coalesce(l.callback_url, ag.callback_url),
         d.metadata -> 'callback_payload',
         d.idempotency_key,
         l.callback_attempts
    from leased l
    join public.agent ag on ag.id = l.agent_id
    join public.audit_entry d on d.action_id = l.id and d.event = 'decision_made';
end;
$$;

-- Called by pg_cron every minute. Skips the HTTP call when nothing is due or
-- when the endpoint / cron secret aren't configured in Vault, so the job is
-- free when idle and inert until set up. Configure with:
--   select vault.create_secret('<functions base>/callbacks-retry', 'cockpit_callbacks_retry_url');
--   select vault.create_secret('<CRON_SECRET>', 'cockpit_cron_secret');
create function public.invoke_callbacks_retry()
returns bigint
language plpgsql
security definer
set search_path = public
as $$
declare
  v_url    text;
  v_secret text;
begin
  if not exists (
    select 1 from public.action
     where callback_status = 'retrying' and next_attempt_at <= now()
  ) then
    return null;
  end if;

  select decrypted_secret into v_url
    from vault.decrypted_secrets where name = 'cockpit_callbacks_retry_url';
  select decrypted_secret into v_secret
    from vault.decrypted_secrets where name = 'cockpit_cron_secret';
  if v_url is null or v_secret is null then
    return null;
  end if;

  return net.http_post(
    url                  := v_url,
    body                 := '{}'::jsonb,
    headers              := jsonb_build_object(
                              'Content-Type', 'application/json',
                              'X-Cron-Secret', v_secret),
    timeout_milliseconds := 55000
  );
end;
$$;

select cron.schedule('cockpit-callbacks-retry', '* * * * *', 'select public.invoke_callbacks_retry()');

-- -----------------------------------------------------------------------------
-- Agent ownership + secret rotation (TR-8)
-- -----------------------------------------------------------------------------

-- The agent, if [p_user_id] is an owner of its workspace. Approvers can decide
-- actions but not manage agents (blueprint §5: agent endpoints are owner-only).
create function public.get_owned_agent(p_user_id uuid, p_agent_id uuid)
returns setof public.agent
language sql
stable
security definer
set search_path = public
as $$
  select a.*
    from public.agent a
    join public.app_user u on u.workspace_id = a.workspace_id
   where a.id = p_agent_id
     and u.id = p_user_id
     and u.role = 'owner';
$$;

-- Replaces an agent's inbound secret in Vault (same secret id) and its hint.
-- The old secret stops verifying immediately: there is one secret per agent.
create function public.rotate_agent_secret(p_user_id uuid, p_agent_id uuid, p_secret text)
returns public.agent
language plpgsql
security definer
set search_path = public
as $$
declare
  v_agent public.agent;
begin
  if p_secret is null or length(p_secret) < 32 then
    raise exception 'invalid_secret' using errcode = '22023';
  end if;

  select a.* into v_agent
    from public.agent a
    join public.app_user u on u.workspace_id = a.workspace_id
   where a.id = p_agent_id
     and u.id = p_user_id
     and u.role = 'owner'
     for update of a;
  if v_agent.id is null then
    raise exception 'agent_not_found' using errcode = 'P0002';
  end if;

  perform vault.update_secret(v_agent.inbound_secret_id, p_secret);

  update public.agent
     set secret_hint = right(p_secret, 4)
   where id = v_agent.id
  returning * into v_agent;

  return v_agent;
end;
$$;

-- -----------------------------------------------------------------------------
-- Inbound rate limit (fixed window per agent)
-- -----------------------------------------------------------------------------

create table public.agent_rate (
  agent_id     uuid        not null references public.agent (id) on delete cascade,
  window_start timestamptz not null,
  count        integer     not null default 0 check (count >= 0),
  primary key (agent_id, window_start)
);

-- Service-role only: RLS on with no policies, and no client grants.
alter table public.agent_rate enable row level security;
revoke all on public.agent_rate from anon, authenticated;

-- Counts one request for [p_agent_id] in the current window and reports
-- whether it exceeds [p_max]. The increment is a single upsert, so concurrent
-- requests can't under-count. Earlier windows for the agent are dropped.
create function public.hit_rate_limit(p_agent_id uuid, p_max integer, p_window interval)
returns table (limited boolean, hits integer, retry_after_seconds integer)
language plpgsql
security definer
set search_path = public
as $$
declare
  v_seconds double precision := extract(epoch from p_window);
  v_start   timestamptz;
  v_hits    integer;
begin
  if p_max is null or p_max < 1 or v_seconds is null or v_seconds < 1 then
    raise exception 'invalid_rate_limit' using errcode = '22023';
  end if;

  v_start := to_timestamp(floor(extract(epoch from now()) / v_seconds) * v_seconds);

  insert into public.agent_rate as r (agent_id, window_start, count)
  values (p_agent_id, v_start, 1)
  on conflict (agent_id, window_start) do update set count = r.count + 1
  returning r.count into v_hits;

  delete from public.agent_rate
   where agent_id = p_agent_id and window_start < v_start;

  return query select
    v_hits > p_max,
    v_hits,
    greatest(1, ceil(extract(epoch from (v_start + p_window - now()))))::integer;
end;
$$;

-- -----------------------------------------------------------------------------
-- Privileges (service role only)
-- -----------------------------------------------------------------------------

revoke all on function public.record_callback_result(uuid, boolean, text, integer) from public, anon, authenticated;
revoke all on function public.claim_due_callbacks(integer, integer) from public, anon, authenticated;
revoke all on function public.invoke_callbacks_retry() from public, anon, authenticated;
revoke all on function public.get_owned_agent(uuid, uuid) from public, anon, authenticated;
revoke all on function public.rotate_agent_secret(uuid, uuid, text) from public, anon, authenticated;
revoke all on function public.hit_rate_limit(uuid, integer, interval) from public, anon, authenticated;

grant execute on function public.record_callback_result(uuid, boolean, text, integer) to service_role;
grant execute on function public.claim_due_callbacks(integer, integer) to service_role;
grant execute on function public.get_owned_agent(uuid, uuid) to service_role;
grant execute on function public.rotate_agent_secret(uuid, uuid, text) to service_role;
grant execute on function public.hit_rate_limit(uuid, integer, interval) to service_role;
