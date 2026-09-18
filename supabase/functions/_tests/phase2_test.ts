import { isAuthorizedCron } from '../_shared/cron.ts';
import { AppError } from '../_shared/errors.ts';
import { errorResponse } from '../_shared/http.ts';
import { enforceRateLimit, type RateLimitVerdict } from '../_shared/rate_limit.ts';
import {
  MAX_CALLBACK_ATTEMPTS,
  RETRY_BASE_SECONDS,
  retryDelaySeconds,
} from '../_shared/retry.ts';
import { assert, assertEquals, assertFalse, assertThrows } from './test_deps.ts';

// ---------------------------------------------------------------------------
// Backoff
// ---------------------------------------------------------------------------

const noJitter = () => 0;

Deno.test('retryDelaySeconds doubles from base · 2^attempts', () => {
  const delays = [1, 2, 3, 4, 5, 6, 7].map((n) => retryDelaySeconds(n, noJitter));
  assertEquals(delays, [30, 60, 120, 240, 480, 960, 1920]);
  assertEquals(retryDelaySeconds(1, noJitter), RETRY_BASE_SECONDS * 2);
});

Deno.test('retryDelaySeconds gives up after MAX_CALLBACK_ATTEMPTS', () => {
  assertEquals(MAX_CALLBACK_ATTEMPTS, 8);
  assert(retryDelaySeconds(MAX_CALLBACK_ATTEMPTS - 1, noJitter) !== null);
  assertEquals(retryDelaySeconds(MAX_CALLBACK_ATTEMPTS, noJitter), null);
  assertEquals(retryDelaySeconds(MAX_CALLBACK_ATTEMPTS + 3, noJitter), null);
});

Deno.test('retryDelaySeconds jitter adds at most 10%', () => {
  assertEquals(retryDelaySeconds(3, () => 0.999_999), 132);
  const delay = retryDelaySeconds(3)!;
  assert(delay >= 120 && delay <= 132, `delay ${delay} outside [120, 132]`);
});

Deno.test('retryDelaySeconds rejects a non-positive attempt count', () => {
  assertThrows(() => retryDelaySeconds(0), RangeError);
  assertThrows(() => retryDelaySeconds(1.5), RangeError);
});

// ---------------------------------------------------------------------------
// Cron guard
// ---------------------------------------------------------------------------

const withHeader = (value?: string) =>
  new Request('http://local/callbacks-retry', {
    method: 'POST',
    headers: value === undefined ? {} : { 'X-Cron-Secret': value },
  });

Deno.test('isAuthorizedCron accepts only the configured secret', () => {
  assert(isAuthorizedCron(withHeader('cron-secret-123'), 'cron-secret-123'));
  assertFalse(isAuthorizedCron(withHeader('cron-secret-124'), 'cron-secret-123'));
  assertFalse(isAuthorizedCron(withHeader('cron-secret'), 'cron-secret-123'));
  assertFalse(isAuthorizedCron(withHeader(''), 'cron-secret-123'));
  assertFalse(isAuthorizedCron(withHeader(), 'cron-secret-123'));
});

Deno.test('isAuthorizedCron rejects everything when no secret is configured', () => {
  assertFalse(isAuthorizedCron(withHeader('anything'), null));
  assertFalse(isAuthorizedCron(withHeader(''), ''));
});

// ---------------------------------------------------------------------------
// Rate limiter
// ---------------------------------------------------------------------------

function fakeClient(verdict: RateLimitVerdict | null, error: unknown = null) {
  const calls: Array<{ fn: string; args: Record<string, unknown> }> = [];
  const client = {
    rpc: (fn: string, args: Record<string, unknown>) => {
      calls.push({ fn, args });
      return { single: () => Promise.resolve({ data: verdict, error }) };
    },
  };
  // deno-lint-ignore no-explicit-any -- minimal stand-in for SupabaseClient.rpc
  return { client: client as any, calls };
}

Deno.test('enforceRateLimit passes the agent, limit and window to hit_rate_limit', async () => {
  const { client, calls } = fakeClient({ limited: false, hits: 3, retry_after_seconds: 40 });
  const verdict = await enforceRateLimit(client, 'agent-1', 60);
  assertEquals(verdict.hits, 3);
  assertEquals(calls, [{
    fn: 'hit_rate_limit',
    args: { p_agent_id: 'agent-1', p_max: 60, p_window: '60 seconds' },
  }]);
});

Deno.test('enforceRateLimit throws rate_limited (429) with retry_after_seconds', async () => {
  const { client } = fakeClient({ limited: true, hits: 61, retry_after_seconds: 17 });
  let caught: unknown;
  try {
    await enforceRateLimit(client, 'agent-1', 60);
  } catch (error) {
    caught = error;
  }
  assert(caught instanceof AppError);
  assertEquals(caught.code, 'rate_limited');
  assertEquals(caught.status, 429);
  assertEquals(caught.details, { retry_after_seconds: 17 });
});

Deno.test('enforceRateLimit maps an RPC error through fromPostgrest', async () => {
  const { client } = fakeClient(null, { message: 'invalid_rate_limit', code: '22023' });
  let caught: unknown;
  try {
    await enforceRateLimit(client, 'agent-1', 0);
  } catch (error) {
    caught = error;
  }
  assert(caught instanceof AppError);
  assertEquals(caught.code, 'validation');
});

Deno.test('a rate_limited response carries Retry-After', async () => {
  const response = errorResponse(
    new AppError('rate_limited', 'slow down', { retry_after_seconds: 17 }),
  );
  assertEquals(response.status, 429);
  assertEquals(response.headers.get('Retry-After'), '17');
  const body = await response.json();
  assertEquals(body.error.code, 'rate_limited');
});

Deno.test('other errors carry no Retry-After', () => {
  const response = errorResponse(new AppError('validation', 'bad'));
  assertEquals(response.headers.get('Retry-After'), null);
});
