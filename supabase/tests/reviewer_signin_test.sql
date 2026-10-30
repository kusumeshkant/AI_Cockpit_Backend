-- pgTAP: 0008 — reviewer-signin brute-force guard. Runs in one transaction
-- and is rolled back. now() is fixed inside the transaction, so expiry is
-- tested by moving the stored timestamps into the past.
begin;
create extension if not exists pgtap with schema extensions;

select plan(24);

-- ---------------------------------------------------------------------------
-- Shape and privileges
-- ---------------------------------------------------------------------------
select has_table('public', 'reviewer_signin_guard', 'guard table exists');
select is((select count(*)::integer from public.reviewer_signin_guard), 1, 'exactly one guard row');
select ok((select relrowsecurity from pg_class where oid = 'public.reviewer_signin_guard'::regclass),
  'RLS is on for the guard table');
select ok(not has_table_privilege('anon', 'public.reviewer_signin_guard', 'select'),
  'anon cannot read the guard');
select ok(not has_table_privilege('authenticated', 'public.reviewer_signin_guard', 'select'),
  'authenticated cannot read the guard');
select ok(not has_function_privilege('anon', 'public.reviewer_signin_attempt(text)', 'execute'),
  'anon cannot call the guard');
select ok(not has_function_privilege('authenticated', 'public.reviewer_signin_attempt(text)', 'execute'),
  'authenticated cannot call the guard');
select ok(has_function_privilege('service_role', 'public.reviewer_signin_attempt(text)', 'execute'),
  'service_role can call the guard');
select throws_ok($$insert into public.reviewer_signin_guard (id) values (2)$$, '23514', null,
  'a second guard row is impossible');

-- Start from a clean row whatever state the database is in.
update public.reviewer_signin_guard set failures = 0, window_start = null, locked_until = null;

-- ---------------------------------------------------------------------------
-- 'none' never counts
-- ---------------------------------------------------------------------------
select is((select locked from public.reviewer_signin_attempt('none')), false, 'none: not locked');
select is((select failures from public.reviewer_signin_guard), 0, 'none: nothing counted');

-- ---------------------------------------------------------------------------
-- 5 failures in the window lock for 1 hour
-- ---------------------------------------------------------------------------
do $$ begin perform public.reviewer_signin_attempt('failure') from generate_series(1, 4); end $$;
select is((select failures from public.reviewer_signin_guard), 4, 'four failures are counted');
select is((select locked_until from public.reviewer_signin_guard), null, 'four failures: no lock yet');

select is((select locked from public.reviewer_signin_attempt('failure')), false,
  'the fifth failure itself reports not locked (it is refused as a wrong code)');
select is((select locked_until from public.reviewer_signin_guard), now() + interval '1 hour',
  'the fifth failure locks for one hour');

select is((select locked from public.reviewer_signin_attempt('success')), true,
  'while locked even a success reports locked');
select is((select locked from public.reviewer_signin_attempt('none')), true,
  'while locked every request reports locked');
select is((select failures from public.reviewer_signin_guard), 5,
  'attempts during the lock change nothing');

-- ---------------------------------------------------------------------------
-- An expired lock starts over
-- ---------------------------------------------------------------------------
update public.reviewer_signin_guard set locked_until = now() - interval '1 second';
select is((select locked from public.reviewer_signin_attempt('success')), false,
  'after the lock expires a success is accepted');
select is((select failures from public.reviewer_signin_guard), 0, 'and the count is reset');

-- ---------------------------------------------------------------------------
-- A success resets the window; an old window starts over
-- ---------------------------------------------------------------------------
do $$ begin
  perform public.reviewer_signin_attempt('failure') from generate_series(1, 3);
  perform public.reviewer_signin_attempt('success');
end $$;
select is((select failures from public.reviewer_signin_guard), 0, 'a success resets the failures');

update public.reviewer_signin_guard
   set failures = 4, window_start = now() - interval '16 minutes', locked_until = null;
select is((select locked from public.reviewer_signin_attempt('failure')), false,
  'a failure after the 15-minute window does not lock');
select is((select failures from public.reviewer_signin_guard), 1,
  'and starts a new window at one failure');

select throws_ok($$select * from public.reviewer_signin_attempt('maybe')$$, '22023', 'invalid_outcome',
  'an unknown outcome is rejected');

select * from finish();
rollback;
