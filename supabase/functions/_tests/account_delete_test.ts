import { isAuthUserMissing } from '../_shared/account.ts';
import { fromPostgrest } from '../_shared/errors.ts';
import { AccountDeleteSchema } from '../_shared/validation.ts';
import { assert, assertEquals, assertFalse } from './test_deps.ts';
import type { PostgrestError } from '../_shared/deps.ts';

Deno.test('account-delete: only {"confirm": true} is accepted', () => {
  assert(AccountDeleteSchema.safeParse({ confirm: true }).success);
  assertFalse(AccountDeleteSchema.safeParse({}).success);
  assertFalse(AccountDeleteSchema.safeParse({ confirm: false }).success);
  assertFalse(AccountDeleteSchema.safeParse({ confirm: 'true' }).success);
  assertFalse(AccountDeleteSchema.safeParse({ confirm: true, user_id: 'x' }).success);
});

Deno.test('account-delete: a missing auth user counts as already deleted', () => {
  assert(isAuthUserMissing({ status: 404 }));
  assert(isAuthUserMissing({ code: 'user_not_found' }));
  assertFalse(isAuthUserMissing({ status: 500 }));
  assertFalse(isAuthUserMissing(null));
});

Deno.test('account-delete: invalid_user from the RPC is a validation error', () => {
  const error = { message: 'invalid_user', code: '22023', details: '', hint: '' } as PostgrestError;
  assertEquals(fromPostgrest(error).code, 'validation');
});
