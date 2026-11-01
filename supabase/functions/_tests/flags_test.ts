// _shared/flags.ts (0010): DB row is the source of truth, env only for a
// missing row, failed reads fail closed, values cached ≤ CACHE_TTL_MS.
import {
  CACHE_TTL_MS,
  createFeatureFlags,
  envFallbackName,
  type FeatureRow,
} from '../_shared/flags.ts';
import { assert, assertEquals } from './test_deps.ts';

function setup(options: {
  rows?: FeatureRow[];
  fail?: boolean;
  env?: Record<string, string>;
} = {}) {
  let reads = 0;
  let clock = 1_000_000;
  let rows = options.rows ?? [];
  let fail = options.fail ?? false;
  const flags = createFeatureFlags({
    read: () => {
      reads++;
      return fail ? Promise.reject(new Error('db down')) : Promise.resolve(rows);
    },
    envValue: (name) => options.env?.[name] ?? null,
    now: () => clock,
  });
  return {
    flags,
    reads: () => reads,
    advance: (ms: number) => (clock += ms),
    setRows: (next: FeatureRow[]) => (rows = next),
    setFail: (next: boolean) => (fail = next),
  };
}

Deno.test('flags: cache TTL is at most 30 s', () => {
  assert(CACHE_TTL_MS <= 30_000);
});

Deno.test('flags: env fallback names', () => {
  assertEquals(envFallbackName('agent_triggers'), 'FEATURE_AGENT_TRIGGERS');
  assertEquals(envFallbackName('agent_services'), 'FEATURE_AGENT_SERVICES');
});

Deno.test('flags: the DB row decides, and wins over the env variable', async () => {
  const on = setup({ rows: [{ key: 'agent_triggers', enabled: true }] });
  assertEquals(await on.flags.isEnabled('agent_triggers'), true);

  const off = setup({
    rows: [{ key: 'agent_triggers', enabled: false }],
    env: { FEATURE_AGENT_TRIGGERS: 'true' },
  });
  assertEquals(await off.flags.isEnabled('agent_triggers'), false);
});

Deno.test('flags: a missing row falls back to the env variable (exactly "true")', async () => {
  const t = setup({ rows: [], env: { FEATURE_AGENT_SERVICES: 'true', FEATURE_AGENT_TRIGGERS: 'TRUE' } });
  assertEquals(await t.flags.isEnabled('agent_services'), true);
  assertEquals(await t.flags.isEnabled('agent_triggers'), false);
  assertEquals(await setup().flags.isEnabled('agent_triggers'), false);
});

Deno.test('flags: a failed read fails closed, even with the env variable on', async () => {
  const t = setup({ fail: true, env: { FEATURE_AGENT_TRIGGERS: 'true' } });
  assertEquals(await t.flags.isEnabled('agent_triggers'), false);
});

Deno.test('flags: one read serves every key until the TTL expires', async () => {
  const t = setup({ rows: [{ key: 'agent_triggers', enabled: true }] });
  await t.flags.isEnabled('agent_triggers');
  await t.flags.isEnabled('agent_services');
  t.advance(CACHE_TTL_MS - 1);
  t.setRows([{ key: 'agent_triggers', enabled: false }]);
  assertEquals(await t.flags.isEnabled('agent_triggers'), true, 'still cached');
  assertEquals(t.reads(), 1);

  t.advance(1);
  assertEquals(await t.flags.isEnabled('agent_triggers'), false, 'refreshed after the TTL');
  assertEquals(t.reads(), 2);
});

Deno.test('flags: a failure after expiry drops the cache (closed) and is retried next call', async () => {
  const t = setup({ rows: [{ key: 'agent_triggers', enabled: true }] });
  assertEquals(await t.flags.isEnabled('agent_triggers'), true);
  t.advance(CACHE_TTL_MS);
  t.setFail(true);
  assertEquals(await t.flags.isEnabled('agent_triggers'), false, 'no stale on after a failed read');
  assertEquals(await t.flags.isEnabled('agent_triggers'), false);
  assertEquals(t.reads(), 3, 'failures are not cached');
  t.setFail(false);
  assertEquals(await t.flags.isEnabled('agent_triggers'), true);
  assertEquals(t.reads(), 4);
});
