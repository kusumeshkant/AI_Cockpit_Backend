// agent-service-inbound (0013): card schema, expiry, push text, inbound
// vectors, and the handler with a stubbed database (generic 401s, states,
// persist-before-push, no card text in logs).
// deno-lint-ignore-file no-explicit-any -- stubbed RPC rows are ad hoc JSON.
import { createInboundHandler, type InboundDeps } from '../agent-service-inbound/handler.ts';
import { signedHeadersV1, signV1, V1_INBOUND_CARD_PATH, type V1Fields } from '../_shared/hmac.ts';
import { pushMessage } from '../_shared/push.ts';
import { cardExpiry, parseServiceCard } from '../_shared/validation.ts';
import { assert, assertEquals, assertFalse, assertThrows } from './test_deps.ts';
import vectors from './vectors/signature_v1_inbound.json' with { type: 'json' };

const SERVICE = 'content-creator';
const card = (over: Record<string, unknown> = {}, payload: Record<string, unknown> = {}) => ({
  type: 'social_post_draft',
  title: 'Post idea: TOPIC-CANARY',
  summary: 'HOOK-CANARY',
  payload: {
    schema: 1, service: SERVICE, idea_id: 'idea_1', format: 'reel', topic: 'TOPIC-CANARY', hook: 'HOOK-CANARY',
    findings: { blocking: 0, to_fix: 0, warnings: 1 }, revision: 1, ...payload,
  },
  ...over,
});

// ---------------------------------------------------------------------------
// Schema, expiry, push
// ---------------------------------------------------------------------------

Deno.test('social_post_draft: a valid card parses; editable_fields defaults to []', () => {
  const parsed = parseServiceCard(card(), SERVICE, ['social_post_draft']);
  assertEquals(parsed.editable_fields, []);
  assertEquals(parsed.payload.format, 'reel');
});

Deno.test('social_post_draft: unknown keys, oversize, URLs, edits and foreign types are refused', () => {
  const bad = (c: Record<string, unknown>, allowed = ['social_post_draft']) =>
    assertThrows(() => parseServiceCard(c, SERVICE, allowed));
  bad(card({ caption: 'full caption' }));
  bad(card({}, { hashtags: ['#x'] }));
  bad(card({}, { image_url: 'x' }));
  bad(card({ title: 'x'.repeat(81) }));
  bad(card({ summary: 'y'.repeat(141) }));
  bad(card({}, { hook: 'see https://evil.example' }));
  bad(card({}, { topic: 'visit www.example.com' }));
  bad(card({}, { hook: 'https://x.com' }));
  bad(card({}, { hook: 'www.x.com' }));
  bad(card({ title: 'Post idea: HTTP://X.COM' }));
  bad(card({ editable_fields: ['hook'] }));
  bad(card({}, { format: 'video' }));
  bad(card({}, { findings: { blocking: 100, to_fix: 0, warnings: 0 } }));
  bad(card({}, { service: 'other-svc' }), ['social_post_draft']);
  bad(card(), ['something_else']);
  bad({ ...card(), type: 'email' });
});

Deno.test('social_post_draft: words with dots are text, not links', () => {
  for (const text of ['Mornings.In summer', 'Node.js tips', 'Plan for 2026.Q1', 'x.com is not a link without a scheme']) {
    const parsed = parseServiceCard(card({ summary: text }, { hook: text, topic: text.slice(0, 80) }), SERVICE, ['social_post_draft']);
    assertEquals(parsed.payload.hook, text);
  }
});

Deno.test('card expiry: default 7 days, capped at 30, past refused', () => {
  const now = Date.parse('2026-11-02T00:00:00Z');
  assertEquals(cardExpiry(undefined, now), '2026-11-09T00:00:00.000Z');
  assertEquals(cardExpiry('2027-06-01T00:00:00Z', now), '2026-12-02T00:00:00.000Z');
  assertEquals(cardExpiry('2026-11-05T00:00:00Z', now), '2026-11-05T00:00:00.000Z');
  assertThrows(() => cardExpiry('2026-11-01T00:00:00Z', now));
});

Deno.test('push: service cards use fixed text; other types are unchanged', () => {
  const service = pushMessage({ actionId: 'a1', title: 'Post idea: SECRET', summary: 'SECRET hook', tokens: [], type: 'social_post_draft' });
  assertEquals(service, {
    title: 'AI Cockpit',
    body: 'A post idea is ready for review',
    data: { type: 'action', action_id: 'a1', kind: 'service_card' },
  });
  assertEquals(pushMessage({ actionId: 'a2', title: 'Reply to Priya', summary: 'Refund', tokens: [] }), {
    title: 'Reply to Priya',
    body: 'Refund',
    data: { type: 'action', action_id: 'a2' },
  });
  assertEquals(pushMessage({ actionId: 'a3', title: 'T', summary: null, tokens: [], type: 'email' }).body, '');
});

Deno.test('inbound vectors reproduce over the canonical path', async () => {
  assertEquals(vectors.canonical_path, V1_INBOUND_CARD_PATH);
  for (const v of vectors.vectors) {
    const fields: V1Fields = {
      keyId: v.input.key_id, timestamp: v.input.timestamp, nonce: v.input.nonce, method: v.input.method,
      path: v.input.path, workspace: v.input.workspace, user: v.input.user, requestId: v.input.request_id,
    };
    assertEquals((await signV1(fields, v.input.body, vectors.secret)).signature, v.expected.signature, v.name);
  }
});

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

const KEY_ID = '11111111-2222-4333-8444-555555555555';
const SECRET = 'svcsig_inbound_unit_secret_0123456789abcdefghi';
const WS = 'aaaaaaaa-1111-4aaa-8aaa-aaaaaaaaaaaa';
const NOW = 1_800_000_000_000;

function setup(over: { target?: Record<string, unknown> | null; flag?: boolean; nonceFresh?: boolean; rows?: Record<string, unknown> } = {}) {
  const rpcs: { fn: string; args: any }[] = [];
  const pushes: any[] = [];
  let clientCreated = false;
  const target = over.target === null ? null : {
    workspace_id: WS, service_status: 'active', card_types: ['social_post_draft'], access_state: 'active',
    agent_id: 'agent-svc', ...over.target,
  };
  const rows: Record<string, unknown> = {
    get_service_inbound_keys: [{ key_id: KEY_ID, secret: SECRET, slot: 'current' }],
    claim_gateway_nonce: over.nonceFresh ?? true,
    resolve_service_inbound: target,
    hit_rate_limit: { limited: false, hits: 1, retry_after_seconds: 1 },
    record_action_inbound: { action_id: 'act-1', is_new: true, fcm_tokens: ['t1'] },
    record_action_update: { action_id: 'act-1', outcome: 'updated', status: 'pending' },
    record_action_withdraw: { action_id: 'act-1', outcome: 'withdrawn', status: 'expired' },
    ...over.rows,
  };
  const client = {
    rpc: (fn: string, args: any) => {
      rpcs.push({ fn, args });
      const result = Promise.resolve({ data: rows[fn] ?? null, error: null });
      return Object.assign(result, { single: () => result, maybeSingle: () => result });
    },
  };
  const deps: InboundDeps = {
    env: { inboundRateLimitPerMinute: 60 },
    flags: { isEnabled: () => Promise.resolve(over.flag ?? true) },
    client: () => {
      clientCreated = true;
      return client as any;
    },
    notify: (_c, push) => {
      pushes.push({ push, rpcsBefore: rpcs.map((r) => r.fn) });
      return Promise.resolve();
    },
    nowMs: () => NOW,
  };
  return { handle: createInboundHandler(deps), rpcs, pushes, clientCreated: () => clientCreated };
}

async function signed(body: unknown, opts: { secret?: string; timestamp?: number; workspace?: string; contract?: string; path?: string } = {}) {
  const raw = typeof body === 'string' ? body : JSON.stringify(body);
  const fields: V1Fields = {
    keyId: KEY_ID, timestamp: opts.timestamp ?? NOW / 1000, nonce: crypto.randomUUID(), method: 'POST',
    path: opts.path ?? V1_INBOUND_CARD_PATH, workspace: opts.workspace ?? WS, user: 'system', requestId: 'r-1',
  };
  return new Request('http://local/agent-service-inbound', {
    method: 'POST',
    headers: await signedHeadersV1(fields, raw, opts.secret ?? SECRET, opts.contract ?? '1.0'),
    body: raw,
  });
}

async function send(t: ReturnType<typeof setup>, req: Request) {
  const response = await t.handle(req);
  return { status: response.status, body: await response.json() };
}

const create = (c: unknown = card()) => ({ service: SERVICE, op: 'create', external_id: 'idea_1', card: c });

Deno.test('inbound: flag off → feature_disabled before any client / RPC', async () => {
  const t = setup({ flag: false });
  const r = await send(t, await signed(create()));
  assertEquals([r.status, r.body.error.code], [404, 'feature_disabled']);
  assertFalse(t.clientCreated());
});

Deno.test('inbound: every authenticity failure is the same 401', async () => {
  const bodies: string[] = [];
  const cases: [ReturnType<typeof setup>, Request][] = [
    [setup(), await signed(create(), { secret: 'svcsig_wrong_secret_0123456789abcdefghijk' })],
    [setup(), await signed(create(), { timestamp: NOW / 1000 - 61 })],
    [setup(), await signed(create(), { path: '/functions/v1/agent-service-inbound' })],
    [setup({ nonceFresh: false }), await signed(create())],
    [setup({ target: null }), await signed(create(), { workspace: 'someone-else' })],
    [setup({ rows: { get_service_inbound_keys: [] } }), await signed(create())],
    [setup(), await signed({ ...create(), service: 'BAD SLUG' })],
  ];
  for (const [t, req] of cases) {
    const r = await send(t, req);
    assertEquals(r.status, 401);
    bodies.push(JSON.stringify(r.body));
    assertFalse(t.rpcs.some((c) => c.fn.startsWith('record_')), 'nothing recorded');
  }
  assertEquals(new Set(bodies).size, 1, 'indistinguishable');
  assertEquals(JSON.parse(bodies[0]).error.code, 'unauthorized');
});

Deno.test('inbound: create persists, then pushes with the type (fixed text); answers created', async () => {
  const t = setup();
  const r = await send(t, await signed(create()));
  assertEquals([r.status, r.body.data], [200, { result: 'created', action_id: 'act-1' }]);
  const call = t.rpcs.find((c) => c.fn === 'record_action_inbound')!;
  assertEquals(call.args.p_type, 'social_post_draft');
  assertEquals(call.args.p_editable_fields, []);
  assertEquals(call.args.p_callback_url, null);
  assertEquals(call.args.p_expires_at, new Date(NOW + 7 * 86_400_000).toISOString());
  assertEquals(t.pushes.length, 1);
  assert(t.pushes[0].rpcsBefore.includes('record_action_inbound'), 'push after persist');
  assertEquals(t.pushes[0].push.type, 'social_post_draft');
  assertEquals(t.rpcs.find((c) => c.fn === 'hit_rate_limit')?.args.p_agent_id, 'agent-svc');
});

Deno.test('inbound: duplicate create answers duplicate and does not push', async () => {
  const t = setup({ rows: { record_action_inbound: { action_id: 'act-1', is_new: false, fcm_tokens: [] } } });
  const r = await send(t, await signed(create()));
  assertEquals(r.body.data.result, 'duplicate');
  assertEquals(t.pushes.length, 0);
});

Deno.test('inbound: state rules for create / update / withdraw', async () => {
  const update = { service: SERVICE, op: 'update', external_id: 'idea_1', revision: 2, card: card({}, { revision: 2 }) };
  const withdraw = { service: SERVICE, op: 'withdraw', external_id: 'idea_1', reason_code: 'regenerated' };
  const cases: [Record<string, unknown>, unknown, number, string][] = [
    [{ service_status: 'paused' }, create(), 503, 'agent_paused'],
    [{ access_state: 'disabled' }, create(), 403, 'service_not_enabled'],
    [{ access_state: 'blocked' }, create(), 403, 'service_not_enabled'],
    [{ agent_id: null }, create(), 403, 'service_not_enabled'],
    [{ service_status: 'retired' }, create(), 404, 'service_not_found'],
    [{ service_status: 'paused' }, update, 200, 'updated'],
    [{ access_state: 'blocked' }, update, 403, 'service_not_enabled'],
    [{ access_state: 'disabled' }, update, 403, 'service_not_enabled'],
    [{ access_state: 'disabled' }, withdraw, 200, 'withdrawn'],
    [{ access_state: 'blocked' }, withdraw, 200, 'withdrawn'],
    [{ service_status: 'retired' }, withdraw, 200, 'withdrawn'],
    [{ card_types: [] }, create(), 422, 'validation'],
  ];
  for (const [target, body, status, expected] of cases) {
    const t = setup({ target });
    const r = await send(t, await signed(body));
    assertEquals([r.status, r.body.data?.result ?? r.body.error?.code], [status, expected], JSON.stringify(target));
  }
});

Deno.test('inbound: update needs matching revisions; stale / noop pass through', async () => {
  const mismatch = { service: SERVICE, op: 'update', external_id: 'idea_1', revision: 3, card: card({}, { revision: 2 }) };
  assertEquals((await send(setup(), await signed(mismatch))).body.error.code, 'validation');
  const t = setup({ rows: { record_action_update: { action_id: 'act-1', outcome: 'stale', status: 'pending' } } });
  const ok = { service: SERVICE, op: 'update', external_id: 'idea_1', revision: 2, card: card({}, { revision: 2 }) };
  assertEquals((await send(t, await signed(ok))).body.data.result, 'stale');
  assertEquals(t.pushes.length, 0, 'updates never push');
});

Deno.test('inbound: body cap, unknown fields, contract version', async () => {
  assertEquals((await send(setup(), await signed({ ...create(), pad: 'x'.repeat(17 * 1024) }))).status, 413);
  assertEquals((await send(setup(), await signed({ ...create(), extra: 1 }))).body.error.code, 'validation');
  assertEquals((await send(setup(), await signed(create(), { contract: '2.0' }))).body.error.code, 'validation');
});

Deno.test('inbound: card text never reaches a log line', async () => {
  const lines: string[] = [];
  const orig = { log: console.log, warn: console.warn, error: console.error };
  console.log = console.warn = console.error = (...args: unknown[]) => lines.push(args.join(' '));
  try {
    const t = setup();
    await send(t, await signed(create()));
    await send(t, await signed({ ...create(), extra: 'TOPIC-CANARY' }));
    await send(setup({ nonceFresh: false }), await signed(create()));
  } finally {
    Object.assign(console, orig);
  }
  assert(lines.some((l) => l.includes('service_card')), 'logs captured');
  assertFalse(lines.some((l) => l.includes('TOPIC-CANARY') || l.includes('HOOK-CANARY')));
});
