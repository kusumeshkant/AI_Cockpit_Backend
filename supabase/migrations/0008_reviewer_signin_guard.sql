-- 0008 — Play review sign-in guard (reviewer-signin Edge Function).
--
-- The app signs in with an emailed code, which a Play reviewer can't read. The
-- reviewer-signin function accepts one fixed code for one allowlisted email,
-- both held in function secrets and off by default (see docs/DEPLOY.md). This
-- migration adds the brute-force guard it relies on:
--
--   * reviewer_signin_guard: a single row (id = 1) with the failure count of
--     the current 15-minute window and the lock expiry.
--   * reviewer_signin_attempt(p_outcome): called once per request, whatever
--     the request was, so the response time doesn't reveal whether the email
--     matched or the feature is on.
--       'none'    — the request wasn't a reviewer attempt; only reports the lock
--       'failure' — the reviewer email with a wrong code; 5 in 15 minutes
--                   locks sign-in for 1 hour
--       'success' — the right email and code; resets the count unless locked
--     Returns locked = true while a lock is active; the function then rejects
--     even the right code.
--
-- Only failures for the allowlisted email count, so someone who doesn't know
-- that email can neither guess the code nor lock the reviewer out.

-- -----------------------------------------------------------------------------
-- reviewer_signin_guard
-- -----------------------------------------------------------------------------

create table public.reviewer_signin_guard (
  id           smallint    primary key default 1 check (id = 1),
  failures     integer     not null default 0 check (failures >= 0),
  window_start timestamptz,
  locked_until timestamptz
);

insert into public.reviewer_signin_guard (id) values (1);

comment on table public.reviewer_signin_guard is
  'Single-row brute-force guard for reviewer-signin: failures in the current '
  '15-minute window and the lock expiry. No email or code is stored.';

-- Service-role only: RLS on with no policies, and no client grants.
alter table public.reviewer_signin_guard enable row level security;
revoke all on public.reviewer_signin_guard from anon, authenticated;

-- -----------------------------------------------------------------------------
-- reviewer_signin_attempt
-- -----------------------------------------------------------------------------

create function public.reviewer_signin_attempt(p_outcome text)
returns table (locked boolean)
language plpgsql
security definer
set search_path = public
as $$
declare
  c_max_failures constant integer  := 5;
  c_window       constant interval := interval '15 minutes';
  c_lock         constant interval := interval '1 hour';
  v_guard        public.reviewer_signin_guard%rowtype;
begin
  if p_outcome is null or p_outcome not in ('none', 'failure', 'success') then
    raise exception 'invalid_outcome' using errcode = '22023';
  end if;

  -- One row; the lock serializes concurrent attempts so none is under-counted.
  select * into v_guard from public.reviewer_signin_guard where id = 1 for update;

  if v_guard.locked_until is not null and v_guard.locked_until > now() then
    return query select true;
    return;
  end if;

  -- An expired lock or window starts over.
  if v_guard.locked_until is not null
     or v_guard.window_start is null
     or v_guard.window_start <= now() - c_window then
    v_guard.failures := 0;
    v_guard.window_start := null;
    v_guard.locked_until := null;
  end if;

  if p_outcome = 'failure' then
    v_guard.failures := v_guard.failures + 1;
    v_guard.window_start := coalesce(v_guard.window_start, now());
    if v_guard.failures >= c_max_failures then
      v_guard.locked_until := now() + c_lock;
    end if;
  elsif p_outcome = 'success' then
    v_guard.failures := 0;
    v_guard.window_start := null;
  end if;

  update public.reviewer_signin_guard
     set failures = v_guard.failures,
         window_start = v_guard.window_start,
         locked_until = v_guard.locked_until
   where id = 1;

  return query select false;
end;
$$;

comment on function public.reviewer_signin_attempt(text) is
  'reviewer-signin brute-force guard: records one attempt (none | failure | success) '
  'and returns locked. 5 failures in 15 minutes lock for 1 hour. Service role only.';

-- -----------------------------------------------------------------------------
-- Privileges (service role only)
-- -----------------------------------------------------------------------------

revoke all on function public.reviewer_signin_attempt(text) from public, anon, authenticated;
grant execute on function public.reviewer_signin_attempt(text) to service_role;
