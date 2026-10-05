import { createTriggerHandler, type TriggerDeps } from '../agents-trigger/handler.ts';
import { computeSignature, verifySignature } from '../_shared/hmac.ts';
import { REDACTED_KEYS } from '../_shared/logger.ts';
import {
  buildTriggerPayload,
  deliverTrigger,
  generateTriggerSecret,
  TRIGGER_SIGNATURE_HEADER,
} from '../_shared/trigger.ts';
import { ConfigureTriggerSchema, TriggerSchema } from '../_shared/validation.ts';
import { assert, assertEquals, assertFalse, assertMatch } from './test_deps.ts';

const SECRET = 'whtrig_test_secret_0123456789abcdefghijklmnop';
const AGENT = '11111111-1111-4111-8111-111111111111';
const RUN = '22222222-2222-4222-8222-222222222222';
const USER = '33333333-3333-4333-8333-333333333333';

// ---------------------------------------------------------------------------
// Signing, payload, secret
// ---------------------------------------------------------------------------

Deno.test('trigger signature round-trips over the exact body and rejects tampering', async () => {
  const body = JSON.stringify(buildTriggerPayload(RUN, AGENT, new Date(0), 'nonce-1'));
  const signature = await computeSignature(body, SECRET);
  assert(await verifySignature(body, signature, SECRET));
  assertFalse(await verifySignature(body.replace('nonce-1', 'nonce-2'), signature, SECRET));
  assertFalse(await verifySignature(body, signature, `${SECRET}x`));
});

Deno.test('buildTriggerPayload has the documented shape', () => {
  assertEquals(buildTriggerPayload(RUN, AGENT, new Date('2026-09-19T10:00:00Z'), 'n'), {
    trigger_id: RUN,
    agent_id: AGENT,
    triggered_at: '2026-09-19T10:00:00.000Z',
    nonce: 'n',
  });
  const a = buildTriggerPayload(RUN, AGENT);
  const b = buildTriggerPayload(RUN, AGENT);
  assert(a.nonce !== b.nonce, 'a fresh nonce per payload');
});

Deno.test('generateTriggerSecret: whtrig_ + 32 random bytes base64url', () => {
  const secret = generateTriggerSecret();
  assertMatch(secret, /^whtrig_[A-Za-z0-9_-]{43}$/);
  assert(secret !== generateTriggerSecret());
});

Deno.test('deliverTrigger signs the POST it sends and reports failures', async () => {
  let sent: Request | null = null;
  const ok = await deliverTrigger(
    'https://agent.example/trigger',
    buildTriggerPayload(RUN, AGENT),
    SECRET,
    (input, init) => {
      sent = new Request(input, init);
      return Promise.resolve(new Response('ok'));
    },
  );
  assertEquals(ok, { delivered: true, detail: 'http_200' });
  const request = sent as unknown as Request;
  assertEquals(request.method, 'POST');
  assertEquals(request.redirect, 'manual');
  const body = await request.text();
  assert(await verifySignature(body, request.headers.get(TRIGGER_SIGNATURE_HEADER), SECRET));

  const failed = await deliverTrigger('https://agent.example/t', buildTriggerPayload(RUN, AGENT), SECRET, () =>
    Promise.resolve(new Response('no', { status: 500 })));
  assertEquals(failed, { delivered: false, detail: 'http_500' });

  const unreachable = await deliverTrigger('https://agent.example/t', buildTriggerPayload(RUN, AGENT), SECRET, () =>
    Promise.reject(new TypeError('connection refused')));
  assertEquals(unreachable, { delivered: false, detail: 'network_error' });
});

Deno.test('request schemas', () => {
  assert(TriggerSchema.safeParse({ agent_id: AGENT }).success);
  assertFalse(TriggerSchema.safeParse({ agent_id: 'nope' }).success);
  assertFalse(TriggerSchema.safeParse({ agent_id: AGENT, extra: 1 }).success);
  assert(ConfigureTriggerSchema.safeParse({
    action: 'configure',
    agent_id: AGENT,
    trigger_url: 'https://n8n.example/webhook/x',
    min_interval_secs: 60,
  }).success);
  assertFalse(ConfigureTriggerSchema.safeParse({
    action: 'configure',
    agent_id: AGENT,
    trigger_url: 'https://x.example',
    min_interval_secs: 0,
  }).success);
  assert(ConfigureTriggerSchema.safeParse({ action: 'set_enabled', agent_id: AGENT, enabled: false }).success);
});

Deno.test('logs redact trigger secrets and URLs', () => {
  for (const key of ['trigger', 'trigger_secret', 'trigger_url']) assert(REDACTED_KEYS.has(key), key);
});

// ---------------------------------------------------------------------------
// agents-trigger handler
// ---------------------------------------------------------------------------

type Rpc = { fn: string; args: Record<string, unknown> };

function stubClient(rows: Record<string, unknown>) {
  const calls: Rpc[] = [];
  const client = {
    rpc: (fn: string, args: Record<string, unknown>) => {
      calls.push({ fn, args });
      const result = Promise.resolve({ data: rows[fn] ?? null, error: null });
      return Object.assign(result, { single: () => result });
    },
  };
  // deno-lint-ignore no-explicit-any -- minimal stand-in for SupabaseClient.rpc
  return { client: client as any, calls };
}

const request = (body: unknown = { agent_id: AGENT }) =>
  new Request('http://local/agents-trigger', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Authorization: 'Bearer user-jwt' },
    body: JSON.stringify(body),
  });

function deps(overrides: Partial<TriggerDeps> & { rows?: Record<string, unknown> } = {}) {
  const { client, calls } = stubClient(overrides.rows ?? {});
  let fetched = 0;
  const d: TriggerDeps = {
    env: { featureAgentTriggers: true, allowInsecureTriggers: false },
    client: () => client,
    userId: () => Promise.resolve(USER),
    fetchFn: () => {
      fetched++;
      return Promise.resolve(new Response('ok'));
    },
    ...overrides,
  };
  return { d, calls, fetched: () => fetched };
}

Deno.test('agents-trigger: feature flag off → 404 feature_disabled, no DB, no I/O', async () => {
  let clientCreated = false;
  let authed = false;
  let fetched = false;
  const handle = createTriggerHandler({
    env: { featureAgentTriggers: false, allowInsecureTriggers: false },
    client: () => {
      clientCreated = true;
      throw new Error('must not touch the database');
    },
    userId: () => {
      authed = true;
      return Promise.resolve(USER);
    },
    fetchFn: () => {
      fetched = true;
      return Promise.resolve(new Response('ok'));
    },
  });

  const response = await handle(request());
  assertEquals(response.status, 404);
  assertEquals((await response.json()).error.code, 'feature_disabled');
  assertFalse(clientCreated);
  assertFalse(authed);
  assertFalse(fetched);
});

for (const [outcome, status, code] of [
  ['not_found', 404, 'not_found'],
  ['not_configured', 404, 'not_found'],
  ['disabled', 409, 'trigger_disabled'],
  ['rate_limited', 429, 'rate_limited'],
] as const) {
  Deno.test(`agents-trigger: begin_trigger_run ${outcome} → ${status} ${code}, nothing sent`, async () => {
    const { d, calls, fetched } = deps({
      rows: { begin_trigger_run: { outcome, retry_after_seconds: outcome === 'rate_limited' ? 17 : null } },
    });
    const response = await createTriggerHandler(d)(request());
    assertEquals(response.status, status);
    assertEquals((await response.json()).error.code, code);
    if (outcome === 'rate_limited') assertEquals(response.headers.get('Retry-After'), '17');
    assertEquals(fetched(), 0);
    assertEquals(calls.map((c) => c.fn), ['begin_trigger_run']);
  });
}

Deno.test('agents-trigger: ok → signed POST, result recorded, 200', async () => {
  let sent: Request | null = null;
  const { d, calls } = deps({
    rows: {
      begin_trigger_run: {
        outcome: 'ok',
        trigger_run_id: RUN,
        trigger_url: 'https://agent.example/trigger',
        trigger_secret: SECRET,
      },
      record_trigger_result: 'sent',
    },
    fetchFn: (input, init) => {
      sent = new Request(input, init);
      return Promise.resolve(new Response('ok'));
    },
  });

  const response = await createTriggerHandler(d)(request());
  assertEquals(response.status, 200);
  assertEquals((await response.json()).data, { run_id: RUN, delivered: true, detail: 'http_200' });

  const post = sent as unknown as Request;
  const body = await post.text();
  assert(await verifySignature(body, post.headers.get(TRIGGER_SIGNATURE_HEADER), SECRET));
  assertEquals(JSON.parse(body).trigger_id, RUN);
  assertEquals(calls.map((c) => c.fn), ['begin_trigger_run', 'record_trigger_result']);
  assertEquals(calls[0].args, { p_agent_id: AGENT, p_actor_user_id: USER });
  assertEquals(calls[1].args, { p_trigger_run_id: RUN, p_delivered: true, p_detail: 'http_200' });
});

Deno.test('agents-trigger: http trigger_url is blocked unless ALLOW_INSECURE_TRIGGERS', async () => {
  const rows = {
    begin_trigger_run: {
      outcome: 'ok',
      trigger_run_id: RUN,
      trigger_url: 'http://127.0.0.1:9999/trigger',
      trigger_secret: SECRET,
    },
  };
  const blocked = deps({ rows });
  const response = await createTriggerHandler(blocked.d)(request());
  assertEquals((await response.json()).data.detail, 'trigger_url_blocked');
  assertEquals(blocked.fetched(), 0);
  assertEquals(blocked.calls[1].args.p_delivered, false);

  const allowed = deps({ rows, env: { featureAgentTriggers: true, allowInsecureTriggers: true } });
  const ok = await createTriggerHandler(allowed.d)(request());
  assertEquals((await ok.json()).data.delivered, true);
  assertEquals(allowed.fetched(), 1);
});

Deno.test('agents-trigger: invalid body → 422 before any RPC', async () => {
  const { d, calls } = deps();
  const response = await createTriggerHandler(d)(request({ agent_id: 'not-a-uuid' }));
  assertEquals(response.status, 422);
  assertEquals(calls.length, 0);
});
