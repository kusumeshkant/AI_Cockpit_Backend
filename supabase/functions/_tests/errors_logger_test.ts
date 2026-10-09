import { AppError, fromPostgrest, STATUS_BY_CODE, toAppError } from '../_shared/errors.ts';
import { errorResponse, json, parseJson } from '../_shared/http.ts';
import { redact } from '../_shared/logger.ts';
import { DecisionSchema } from '../_shared/validation.ts';
import type { PostgrestError } from '../_shared/deps.ts';
import { assertEquals, assertThrows } from './test_deps.ts';

function pg(message: string, code = 'P0001'): PostgrestError {
  return { message, code, details: '', hint: '', name: 'PostgrestError' } as PostgrestError;
}

Deno.test('error codes map to HTTP statuses', () => {
  assertEquals(new AppError('invalid_signature', 'x').status, 401);
  assertEquals(new AppError('agent_disabled', 'x').status, 403);
  assertEquals(new AppError('forbidden', 'x').status, 403);
  assertEquals(new AppError('conflict', 'x').status, 409);
  assertEquals(new AppError('expired', 'x').status, 410);
  assertEquals(new AppError('validation', 'x').status, 422);
  assertEquals(STATUS_BY_CODE.server, 500);
});

Deno.test('unknown errors become a generic server error', () => {
  const error = toAppError(new Error('connection string with password'));
  assertEquals(error.code, 'server');
  assertEquals(error.message, 'Internal error');
});

Deno.test('RPC errors map by raised message and SQLSTATE', () => {
  assertEquals(fromPostgrest(pg('agent_disabled')).code, 'agent_disabled');
  assertEquals(fromPostgrest(pg('forbidden', '42501')).code, 'forbidden');
  assertEquals(fromPostgrest(pg('agent_not_found', 'P0002')).code, 'not_found');
  assertEquals(fromPostgrest(pg('workspace_not_found', 'P0002')).code, 'unauthorized');
  assertEquals(fromPostgrest(pg('new row violates check', '23514')).code, 'validation');
  assertEquals(fromPostgrest(pg('boom', 'XX000')).code, 'server');
});

Deno.test('envelopes have the documented shape', async () => {
  const ok = json({ action_id: 'a' }, 200);
  assertEquals(await ok.json(), { ok: true, data: { action_id: 'a' } });

  const failed = errorResponse(new AppError('conflict', 'Already decided'));
  assertEquals(failed.status, 409);
  assertEquals(await failed.json(), {
    ok: false,
    error: { code: 'conflict', message: 'Already decided' },
  });
});

Deno.test('parseJson reports validation issues with paths', () => {
  const error = assertThrows(
    () => parseJson('{"action_id":"nope","decision":"approved"}', DecisionSchema),
    AppError,
  );
  assertEquals(error.code, 'validation');
  assertEquals((error.details as Array<{ path: string }>)[0].path, 'action_id');
  assertEquals(assertThrows(() => parseJson('{', DecisionSchema), AppError).code, 'validation');
});

Deno.test('logger redacts secrets, tokens and payloads at any depth', () => {
  const out = redact({
    action_id: 'a1',
    signing_secret: 'whsec_x',
    headers: { Authorization: 'Bearer t', 'X-Cockpit-Signature': 'sha256=abc' },
    nested: { payload: { to: 'priya@example.com' }, fcm_tokens: ['t1'] },
    items: [{ token: 't2', id: 1 }],
  }) as Record<string, unknown>;

  assertEquals(out, {
    action_id: 'a1',
    signing_secret: '[redacted]',
    headers: { Authorization: '[redacted]', 'X-Cockpit-Signature': '[redacted]' },
    nested: { payload: '[redacted]', fcm_tokens: '[redacted]' },
    items: [{ token: '[redacted]', id: 1 }],
  });
});
