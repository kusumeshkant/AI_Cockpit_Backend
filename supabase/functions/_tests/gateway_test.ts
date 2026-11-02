// agent-proxy rules (_shared/gateway.ts) and handler (agent-proxy/handler.ts):
// versions, roles, retry rules, size caps, answer mapping, redaction, and the
// order of checks with a stubbed database and agent.
// deno-lint-ignore-file no-explicit-any -- stubbed RPC rows / bodies are ad hoc JSON.
import { createProxyHandler, type ProxyDeps } from '../agent-proxy/handler.ts';
import {
  callAgent,
  isTransient,
  mapOutcome,
  maxAttempts,
  needsAppUpdate,
  parseSemver,
  pickMeta,
  readCapped,
  roleAllowed,
} from '../_shared/gateway.ts';
import { V1_HEADERS, verifyV1 } from '../_shared/hmac.ts';
import { REDACTED_KEYS, redact } from '../_shared/logger.ts';
import { opTimeoutMs } from '../_shared/service_manifest.ts';
import { assert, assertEquals, assertFalse } from './test_deps.ts';

// ---------------------------------------------------------------------------
// Pure rules
// ---------------------------------------------------------------------------

Deno.test('semver: parse, compare and the app-update rule', () => {
  assertEquals(parseSemver('1.2.3'), [1, 2, 3]);
  assertEquals(parseSemver('0.1.1+2'), [0, 1, 1]);
  assertEquals(parseSemver('1.2'), null);
  assertFalse(needsAppUpdate(null, null), 'no min version → never');
  assertFalse(needsAppUpdate('0.0.1', null));
  assert(needsAppUpdate(null, '0.2.0'), 'missing header counts as too old when a min is set');
  assert(needsAppUpdate('garbage', '0.2.0'));
  assert(needsAppUpdate('0.1.9', '0.2.0'));
  assertFalse(needsAppUpdate('0.2.0', '0.2.0'));
  assertFalse(needsAppUpdate('0.10.0', '0.9.9'), 'numeric, not lexical');
});

Deno.test('roles and retry rules per op class', () => {
  assert(roleAllowed({ roles: ['owner', 'approver'] }, 'approver'));
  assertFalse(roleAllowed({ roles: ['owner'] }, 'approver'));
  assertEquals([maxAttempts('read'), maxAttempts('write'), maxAttempts('destructive')], [2, 2, 1]);
  assert(isTransient({ kind: 'network' }));
  assert(isTransient({ kind: 'timeout' }));
  for (const status of [502, 503, 504]) assert(isTransient({ kind: 'response', status, body: null }));
  for (const status of [200, 400, 409, 500]) assertFalse(isTransient({ kind: 'response', status, body: null }));
  assertEquals(opTimeoutMs({ class: 'read', roles: ['owner'], max_request_bytes: 1, max_response_bytes: 1 }), 8000);
  assertEquals(opTimeoutMs({ class: 'write', roles: ['owner'], max_request_bytes: 1, max_response_bytes: 1 }), 10000);
  assertEquals(
    opTimeoutMs({ class: 'read', roles: ['owner'], timeout_ms: 1234, max_request_bytes: 1, max_response_bytes: 1 }),
    1234,
  );
});

Deno.test('readCapped stops past the cap (declared or streamed)', async () => {
  assertEquals(await readCapped(new Response('abc'), 3), 'abc');
  assertEquals(await readCapped(new Response('abcd'), 3), null);
  const stream = new ReadableStream({
    start(c) {
      c.enqueue(new TextEncoder().encode('ab'));
      c.enqueue(new TextEncoder().encode('cd'));
      c.close();
    },
  });
  assertEquals(await readCapped(new Response(stream), 3), null);
});

const DECLARED = { errors: ['validation', 'conflict', 'quota_reached', 'trial_ended', 'agent_paused', 'idea_final'] as any };
const resp = (status: number, body: unknown, problem?: 'oversize' | 'invalid_json') =>
  ({ kind: 'response', status, body, ...(problem ? { problem } : {}) }) as const;

Deno.test('mapping: success envelopes, 202 and meta filtering', () => {
  const ok = mapOutcome(resp(201, { ok: true, result: { a: 1 }, meta: { version: 'v2', extra: 'x' } }), DECLARED);
  assertEquals(ok, { kind: 'ok', status: 200, result: { a: 1 }, meta: { version: 'v2' }, agentOk: true });
  const accepted = mapOutcome(resp(202, { ok: true, result: { job_id: 'j' }, meta: { poll_after_ms: 500 } }), DECLARED);
  assertEquals(accepted.kind === 'ok' && accepted.status, 202);
  assertEquals(
    pickMeta({ usage: { used: 3, limit: 10, trial_ends_at: null }, poll_after_ms: -1, version: 7 }),
    { usage: { used: 3, limit: 10, trial_ends_at: null } },
  );
  assertEquals(pickMeta({ usage: { used: 'x', limit: 1, trial_ends_at: null } }), {});
});

Deno.test('mapping: failures and agent error codes', () => {
  const code = (m: ReturnType<typeof mapOutcome>) => (m.kind === 'error' ? m.error.code : 'ok');
  const network = mapOutcome({ kind: 'network' }, DECLARED);
  assertEquals(code(network), 'agent_unavailable');
  assertEquals(network.kind === 'error' && [network.error.status, network.agentOk], [503, false]);
  assertEquals(code(mapOutcome({ kind: 'timeout' }, DECLARED)), 'agent_timeout');
  assertEquals(code(mapOutcome(resp(200, null, 'oversize'), DECLARED)), 'agent_error');
  assertEquals(code(mapOutcome(resp(200, null, 'invalid_json'), DECLARED)), 'agent_error');
  assertEquals(code(mapOutcome(resp(200, { result: 1 }), DECLARED)), 'agent_error', 'missing ok');
  assertEquals(code(mapOutcome(resp(503, 'down'), DECLARED)), 'agent_unavailable');
  assertEquals(code(mapOutcome(resp(500, 'boom'), DECLARED)), 'agent_error');

  const quota = mapOutcome(resp(403, { ok: false, error: { code: 'quota_reached', message: 'secret text' } }), DECLARED);
  assertEquals(code(quota), 'quota_reached');
  assertEquals(quota.kind === 'error' && quota.error.message, 'The usage limit has been reached', 'agent text dropped');
  assertEquals(code(mapOutcome(resp(403, { ok: false, error: { code: 'trial_ended' } }), DECLARED)), 'trial_ended');
  assertEquals(code(mapOutcome(resp(503, { ok: false, error: { code: 'agent_paused' } }), DECLARED)), 'agent_paused');
  const final = mapOutcome(resp(409, { ok: false, error: { code: 'idea_final' } }), DECLARED);
  assertEquals(final.kind === 'error' && [final.error.code, final.error.details], ['conflict', { code: 'idea_final' }]);

  for (const hidden of ['unsupported_contract', 'request_id_reuse', 'invalid_signature', 'not_found']) {
    const m = mapOutcome(resp(401, { ok: false, error: { code: hidden, message: 'agent detail' } }), DECLARED);
    assertEquals(code(m), 'agent_error', hidden);
    assertEquals(m.kind === 'error' && m.error.details, undefined, 'no agent detail reaches the app');
  }
  assertEquals(code(mapOutcome(resp(400, { ok: false, error: { code: 'validation' } }), { errors: [] })), 'agent_error',
    'undeclared codes are hidden');
});

Deno.test('logger redacts gateway content fields', () => {
  for (const key of ['params', 'result', 'caption', 'hook', 'outline', 'hashtags', 'brand', 'facts', 'niche', 'audience', 'tone', 'samples', 'signature', 'secret']) {
    assert(REDACTED_KEYS.has(key), key);
  }
  assertEquals(redact({ op: 'x', params: { brand: 'CANARY' } }), { op: 'x', params: '[redacted]' });
});

// ---------------------------------------------------------------------------
// callAgent: signing and retries
// ---------------------------------------------------------------------------

const SECRET = 'svcsig_gateway_unit_secret_0123456789abcdefghijk';
const OP = { class: 'write', roles: ['owner'], max_request_bytes: 1024, max_response_bytes: 1024 } as const;

function scripted(statuses: number[]) {
  const seen: Request[] = [];
  const fetchFn = (input: RequestInfo | URL, init?: RequestInit) => {
    seen.push(new Request(input, init));
    const status = statuses[Math.min(seen.length - 1, statuses.length - 1)];
    return Promise.resolve(Response.json(status < 300 ? { ok: true, result: { n: seen.length } } : { ok: false, error: { code: 'x' } }, { status }));
  };
  return { seen, fetchFn: fetchFn as typeof fetch };
}

let n = 0;
const io = (fetchFn: typeof fetch) => ({
  fetchFn,
  nowSeconds: () => 1_800_000_000,
  sleep: () => Promise.resolve(),
  nonce: () => `nonce-${++n}`,
});
const call = (op: any = OP) => ({
  url: 'https://agent.example/cockpit/v1/ops/brand.save',
  body: '{"params":{"brand":"x"}}',
  keyId: 'k1',
  secret: SECRET,
  contractVersion: '1.0',
  workspace: 'ws',
  user: 'u',
  requestId: 'req-1',
  op,
  timeoutMs: 1000,
});

Deno.test('callAgent: a write retries a 503 once with the same request id and a new nonce, both signed', async () => {
  const { seen, fetchFn } = scripted([503, 200]);
  const { outcome, attempts } = await callAgent(call(), io(fetchFn));
  assertEquals(attempts, 2);
  assertEquals(outcome.kind === 'response' && outcome.status, 200);
  const ids = seen.map((r) => r.headers.get(V1_HEADERS.requestId));
  const nonces = seen.map((r) => r.headers.get(V1_HEADERS.nonce));
  assertEquals(ids, ['req-1', 'req-1']);
  assert(nonces[0] !== nonces[1]);
  for (const r of seen) {
    assertEquals(r.redirect, 'manual');
    const verdict = await verifyV1({
      headers: r.headers,
      method: 'POST',
      path: new URL(r.url).pathname,
      body: await r.text(),
      secrets: { k1: SECRET },
      now: 1_800_000_000,
    });
    assert(verdict.ok);
  }
});

Deno.test('callAgent: no retry for destructive ops or non-transient answers', async () => {
  const destructive = scripted([503, 200]);
  assertEquals((await callAgent(call({ ...OP, class: 'destructive' }), io(destructive.fetchFn))).attempts, 1);
  const conflict = scripted([409, 200]);
  assertEquals((await callAgent(call(), io(conflict.fetchFn))).attempts, 1);
  const down = scripted([503, 503, 503]);
  assertEquals((await callAgent(call(), io(down.fetchFn))).attempts, 2, 'at most one retry');
});

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

const MANIFEST = {
  ui: 'native',
  ui_schema_version: 1,
  ops: {
    'ideas.list': { class: 'read', roles: ['owner', 'approver'], max_request_bytes: 4096, max_response_bytes: 4096 },
    'idea.generate': { class: 'write', roles: ['owner'], max_request_bytes: 64, max_response_bytes: 4096 },
  },
  data_categories: ['content'],
  deletion_op: 'subject.delete',
  errors: ['conflict'],
};
// deletion_op must exist and be destructive.
(MANIFEST.ops as any)['subject.delete'] = {
  class: 'destructive', roles: ['owner'], max_request_bytes: 64, max_response_bytes: 64,
};

function setup(overrides: { resolve?: Record<string, unknown>; flag?: boolean; limited?: boolean; agent?: (r: Request) => Response } = {}) {
  const rpcs: { fn: string; args: Record<string, unknown> }[] = [];
  const agentCalls: Request[] = [];
  let clientCreated = false;
  let authed = false;
  const resolve = {
    workspace_id: 'ws-1', role: 'owner', slug: 'stub', status: 'active', base_url: 'https://agent.example',
    contract_version: '1.0', min_app_version: null, manifest: MANIFEST, open_until: null,
    access_state: 'active', subject: 'ws-1', ...overrides.resolve,
  };
  const rows: Record<string, unknown> = {
    resolve_service_access: resolve,
    hit_gateway_rate: { limited: overrides.limited ?? false, retry_after_seconds: 42 },
    get_service_signing_key: { key_id: 'k1', secret: SECRET },
    enable_service: { state: 'active', consent_version: 'v1', consented_at: 't', changed: true, agent_id: 'secret-agent-id' },
    record_gateway_outcome: { consecutive_failures: 0, open_until: null },
  };
  const client = {
    rpc: (fn: string, args: Record<string, unknown>) => {
      rpcs.push({ fn, args });
      const result = Promise.resolve({ data: rows[fn] ?? null, error: null });
      return Object.assign(result, { single: () => result, maybeSingle: () => result });
    },
  };
  const deps: ProxyDeps = {
    env: { allowInsecureServices: false, gatewayRates: { read: 120, write: 30, destructive: 5 } },
    flags: { isEnabled: () => Promise.resolve(overrides.flag ?? true) },
    client: () => {
      clientCreated = true;
      return client as any;
    },
    userId: () => {
      authed = true;
      return Promise.resolve('user-1');
    },
    fetchFn: ((input: RequestInfo | URL, init?: RequestInit) => {
      const r = new Request(input, init);
      agentCalls.push(r);
      return Promise.resolve(overrides.agent?.(r) ?? Response.json({ ok: true, result: { ideas: ['CANARY-RESULT'] } }));
    }) as typeof fetch,
    sleep: () => Promise.resolve(),
    uuid: () => crypto.randomUUID(),
  };
  return {
    handle: createProxyHandler(deps),
    rpcs,
    agentCalls,
    state: () => ({ clientCreated, authed }),
  };
}

const proxy = (body: unknown, headers: Record<string, string> = {}) =>
  new Request('http://local/agent-proxy', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Authorization: 'Bearer jwt', ...headers },
    body: JSON.stringify(body),
  });

async function send(t: ReturnType<typeof setup>, body: unknown, headers: Record<string, string> = {}) {
  const response = await t.handle(proxy(body, headers));
  return { status: response.status, body: await response.json(), headers: response.headers };
}

Deno.test('proxy: flag off → 404 feature_disabled with no auth, client or agent call', async () => {
  const t = setup({ flag: false });
  const r = await send(t, { service: 'stub', op: 'ideas.list' });
  assertEquals([r.status, r.body.error.code], [404, 'feature_disabled']);
  assertEquals(t.state(), { clientCreated: false, authed: false });
  assertEquals(t.agentCalls.length, 0);
});

Deno.test('proxy: a read is forwarded, signed and answered with result + request id; one ids-only record', async () => {
  const t = setup();
  const r = await send(t, { service: 'stub', op: 'ideas.list', params: { niche: 'CANARY-PARAM' } });
  assertEquals(r.status, 200);
  assertEquals(r.body.data.result, { ideas: ['CANARY-RESULT'] });
  assert(typeof r.body.data.meta.request_id === 'string');
  assertEquals(t.agentCalls.length, 1);
  assertEquals(new URL(t.agentCalls[0].url).pathname, '/cockpit/v1/ops/ideas.list');
  assertEquals(t.agentCalls[0].headers.get(V1_HEADERS.workspace), 'ws-1');
  const records = t.rpcs.filter((c) => c.fn === 'record_gateway_outcome');
  assertEquals(records.length, 1);
  assertEquals(records[0].args.p_status, 200);
  assertEquals(records[0].args.p_attempts, 1);
  assertEquals(records[0].args.p_agent_ok, true);
  assertFalse(JSON.stringify(t.rpcs).includes('CANARY'), 'no params / result in any RPC');
});

Deno.test('proxy: checks run in order and refuse without calling the agent', async () => {
  const cases: [Record<string, unknown>, unknown, Record<string, string>, number, string][] = [
    [{ status: 'draft' }, { service: 'stub', op: 'ideas.list' }, {}, 404, 'service_not_found'],
    [{ status: 'paused' }, { service: 'stub', op: 'ideas.list' }, {}, 503, 'agent_paused'],
    [{ access_state: 'blocked' }, { service: 'stub', op: 'ideas.list' }, {}, 403, 'service_not_enabled'],
    [{ access_state: null }, { service: 'stub', op: 'ideas.list' }, {}, 403, 'service_not_enabled'],
    [{ min_app_version: '0.2.0' }, { service: 'stub', op: 'ideas.list' }, { 'X-App-Version': '0.1.9' }, 426, 'app_update_required'],
    [{}, { service: 'stub', op: 'subject.drop' }, {}, 422, 'unsupported_op'],
    [{ role: 'approver' }, { service: 'stub', op: 'idea.generate' }, { 'Idempotency-Key': 'key-12345678' }, 403, 'forbidden'],
    [{}, { service: 'stub', op: 'idea.generate' }, {}, 422, 'validation'],
    [{}, { service: 'stub', op: 'idea.generate', params: { x: 'y'.repeat(80) } }, { 'Idempotency-Key': 'key-12345678' }, 413, 'payload_too_large'],
    [{ open_until: new Date(Date.now() + 10_000).toISOString() }, { service: 'stub', op: 'ideas.list' }, {}, 503, 'agent_unavailable'],
    [{ base_url: 'http://127.0.0.1:9' }, { service: 'stub', op: 'ideas.list' }, {}, 502, 'agent_error'],
    [{ manifest: { ui: 'native' } }, { service: 'stub', op: 'ideas.list' }, {}, 502, 'agent_error'],
  ];
  for (const [resolve, body, headers, status, code] of cases) {
    const t = setup({ resolve });
    const r = await send(t, body, headers);
    assertEquals([r.status, r.body.error?.code], [status, code], JSON.stringify(resolve));
    assertEquals(t.agentCalls.length, 0, code);
  }
});

Deno.test('proxy: rate limited → 429 with Retry-After', async () => {
  const t = setup({ limited: true });
  const r = await send(t, { service: 'stub', op: 'ideas.list' });
  assertEquals([r.status, r.body.error.code, r.headers.get('Retry-After')], [429, 'rate_limited', '42']);
  assertEquals(t.agentCalls.length, 0);
});

Deno.test('proxy: built-in service.enable is owner-only, not forwarded, and bypasses the access check', async () => {
  const t = setup({ resolve: { access_state: null } });
  const r = await send(t, { service: 'stub', op: 'service.enable', params: { consent_version: 'v1' } });
  assertEquals(r.status, 200);
  assertEquals(r.body.data.result, { state: 'active', consent_version: 'v1', consented_at: 't', changed: true });
  assertEquals(t.agentCalls.length, 0);
  assertEquals(t.rpcs.find((c) => c.fn === 'record_gateway_outcome')?.args.p_count_use, false);
  const approver = setup({ resolve: { role: 'approver' } });
  assertEquals((await send(approver, { service: 'stub', op: 'service.enable', params: { consent_version: 'v1' } })).body.error.code, 'forbidden');
  const missing = setup();
  assertEquals((await send(missing, { service: 'stub', op: 'service.enable' })).body.error.code, 'validation');
});

Deno.test('proxy: agent 202 passes through; agent errors map without agent detail', async () => {
  const accepted = setup({ agent: () => Response.json({ ok: true, result: { job_id: 'j1' }, meta: { poll_after_ms: 300 } }, { status: 202 }) });
  const r = await send(accepted, { service: 'stub', op: 'idea.generate' }, { 'Idempotency-Key': 'key-12345678' });
  assertEquals([r.status, r.body.data.result, r.body.data.meta.poll_after_ms, r.body.data.meta.request_id], [202, { job_id: 'j1' }, 300, 'key-12345678']);
  assertEquals(accepted.agentCalls[0].headers.get(V1_HEADERS.requestId), 'key-12345678');

  const reuse = setup({ agent: () => Response.json({ ok: false, error: { code: 'request_id_reuse', message: 'AGENT-DETAIL' } }, { status: 409 }) });
  const e = await send(reuse, { service: 'stub', op: 'ideas.list' });
  assertEquals([e.status, e.body.error.code], [502, 'agent_error']);
  assertFalse(JSON.stringify(e.body).includes('AGENT-DETAIL'));
});
