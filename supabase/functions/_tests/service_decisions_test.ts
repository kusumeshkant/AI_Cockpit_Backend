// 0014: decisions on service cards (_shared/service_decision.ts), service
// delivery classification + retry bookkeeping (_shared/delivery.ts) and the
// service-deletions-retry handler — with a stubbed database and agent.
// deno-lint-ignore-file no-explicit-any -- stubbed RPC rows / bodies are ad hoc JSON.
import { classifyDeletion, createDeletionsHandler } from '../service-deletions-retry/handler.ts';
import {
  attemptServiceDelivery,
  classifyServiceDelivery,
  decisionApplyParams,
  type ServiceDecisionPayload,
} from '../_shared/delivery.ts';
import { V1_HEADERS } from '../_shared/hmac.ts';
import { MAX_CALLBACK_ATTEMPTS } from '../_shared/retry.ts';
import { type ActionServiceRow, decideServiceAction } from '../_shared/service_decision.ts';
import { ServiceDecisionSchema } from '../_shared/validation.ts';
import { assert, assertEquals, assertFalse, assertRejects } from './test_deps.ts';

const MANIFEST = {
  ui: 'native',
  ui_schema_version: 1,
  ops: {
    'decision.apply': { class: 'write', roles: ['owner', 'approver'], max_request_bytes: 2048, max_response_bytes: 2048 },
    'subject.delete': { class: 'destructive', roles: ['owner'], max_request_bytes: 64, max_response_bytes: 1024 },
  },
  data_categories: ['content'],
  deletion_op: 'subject.delete',
  errors: ['conflict', 'idea_final', 'not_found', 'approval_blocked'],
};

type Agent = (r: Request, body: any) => Response | Promise<Response>;

function world(over: { agent?: Agent; rows?: Record<string, unknown>; endpoint?: Record<string, unknown> | null } = {}) {
  const rpcs: { fn: string; args: any }[] = [];
  const calls: { req: Request; body: any }[] = [];
  const rows: Record<string, unknown> = {
    get_service_endpoint: over.endpoint === null ? null : {
      slug: 'svc', status: 'active', base_url: 'https://agent.example', contract_version: '1.0',
      manifest: MANIFEST, open_until: null, ...over.endpoint,
    },
    get_service_signing_key: { key_id: 'k1', secret: 'svcsig_decisions_unit_secret_0123456789abcd' },
    record_gateway_outcome: { consecutive_failures: 0, open_until: null },
    resolve_agent_service: { workspace_id: 'ws-1', service_slug: 'svc', subject: 'ws-1' },
    record_callback_result: null,
    ...over.rows,
  };
  const client = {
    rpc: (fn: string, args: any) => {
      rpcs.push({ fn, args });
      const value = rows[fn];
      const data = typeof value === 'function' ? (value as (a: any) => unknown)(args) : value ?? null;
      const result = Promise.resolve({ data, error: null });
      return Object.assign(result, { single: () => result, maybeSingle: () => result });
    },
  };
  const fetchFn = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const req = new Request(input, init);
    const body = JSON.parse(await req.clone().text());
    calls.push({ req, body });
    return over.agent ? over.agent(req, body) : Response.json({ ok: true, result: { applied: true } });
  }) as typeof fetch;
  return { client: client as any, rpcs, calls, fetchFn, fns: () => rpcs.map((r) => r.fn) };
}

const TARGET: ActionServiceRow = {
  action_status: 'pending', expires_at: null, idea_id: 'i-1', agent_id: 'agent-svc', workspace_id: 'ws-1',
  service_slug: 'svc', subject: 'ws-1', access_state: 'active',
};
const recorded = (decision: string) => ({
  outcome: 'recorded',
  agent_id: 'agent-svc',
  callback_status: 'pending',
  callback_payload: {
    action_id: 'act-1', external_id: 'idea_i-1', idea_id: 'i-1', decision, reason: decision === 'rejected' ? 'off brand' : null,
    decided_by: 'user-1', decided_at: '2026-11-02T00:00:00Z',
  },
});
const decide = (w: ReturnType<typeof world>, body: any, target: ActionServiceRow = TARGET) =>
  decideServiceAction(
    { client: w.client, allowInsecureServices: false, fetchFn: w.fetchFn },
    { actorId: 'user-1', key: 'key-12345678', body, target },
  );
const errEnvelope = (status: number, code: string) => Response.json({ ok: false, error: { code, message: 'AGENT DETAIL' } }, { status });

// ---------------------------------------------------------------------------
// Schema + params
// ---------------------------------------------------------------------------

Deno.test('service decisions: approve / reject only, no edits', () => {
  const id = '11111111-2222-4333-8444-555555555555';
  assert(ServiceDecisionSchema.safeParse({ action_id: id, decision: 'approved', acknowledged: ['to_fix.1'] }).success);
  assert(ServiceDecisionSchema.safeParse({ action_id: id, decision: 'rejected', reason: 'off brand' }).success);
  assertFalse(ServiceDecisionSchema.safeParse({ action_id: id, decision: 'approved_with_edits' }).success);
  assertFalse(ServiceDecisionSchema.safeParse({ action_id: id, decision: 'approved', edited_payload: { a: 1 } }).success);
  assertFalse(ServiceDecisionSchema.safeParse({ action_id: id, decision: 'rejected', reason: 'x'.repeat(501) }).success);
});

Deno.test('decision.apply params: reason / acknowledged only when present', () => {
  const p = recorded('rejected').callback_payload as ServiceDecisionPayload;
  assertEquals(decisionApplyParams(p), {
    idea_id: 'i-1', action_id: 'act-1', decision: 'rejected', decided_by: 'user-1', decided_at: '2026-11-02T00:00:00Z',
    reason: 'off brand',
  });
  assertEquals(Object.keys(decisionApplyParams({ ...p, reason: null }, [])).includes('reason'), false);
  assertEquals(decisionApplyParams({ ...p, reason: null }, ['a']).acknowledged, ['a']);
});

// ---------------------------------------------------------------------------
// Approve: agent first
// ---------------------------------------------------------------------------

Deno.test('approve: agent first, then record + delivered; the request id is the Idempotency-Key', async () => {
  const w = world({ rows: { record_decision: recorded('approved') } });
  const r = await decide(w, { action_id: 'act-1', decision: 'approved', acknowledged: ['to_fix.1'] });
  assertEquals(r, { decision_recorded: true, duplicate: false, callback_delivered: true });
  assertEquals(w.calls.length, 1);
  assertEquals(new URL(w.calls[0].req.url).pathname, '/cockpit/v1/ops/decision.apply');
  assertEquals(w.calls[0].req.headers.get(V1_HEADERS.requestId), 'key-12345678');
  assertEquals(w.calls[0].body.params.decision, 'approved');
  assertEquals(w.calls[0].body.params.acknowledged, ['to_fix.1']);
  const order = w.fns();
  assert(order.indexOf('record_gateway_outcome') < order.indexOf('record_decision'), 'agent before record');
  assertEquals(w.rpcs.find((c) => c.fn === 'record_callback_result')?.args, {
    p_action_id: 'act-1', p_delivered: true, p_detail: 'agent_applied', p_retry_in_seconds: null,
  });
});

Deno.test('approve: agent refusal / failure records nothing and maps safely', async () => {
  const cases: [Agent, string][] = [
    [() => errEnvelope(422, 'approval_blocked'), 'approval_blocked'],
    [() => errEnvelope(409, 'idea_final'), 'conflict'],
    [() => Promise.reject(new TypeError('refused')), 'agent_unavailable'],
    [() => errEnvelope(409, 'request_id_reuse'), 'agent_error'],
  ];
  for (const [agent, code] of cases) {
    const w = world({ agent, rows: { record_decision: recorded('approved') } });
    const e = await assertRejects(() => decide(w, { action_id: 'act-1', decision: 'approved' }));
    assertEquals((e as any).code, code);
    assertFalse(w.fns().includes('record_decision'), `${code}: card stays pending`);
    assertFalse(JSON.stringify((e as any).details ?? null).includes('AGENT DETAIL'));
  }
});

Deno.test('approve: retired service / closed access refuse before calling; decided cards skip the agent', async () => {
  const retired = world({ endpoint: { status: 'retired' } });
  assertEquals(((await assertRejects(() => decide(retired, { action_id: 'act-1', decision: 'approved' }))) as any).code, 'service_not_found');
  assertEquals(retired.calls.length, 0);
  const disabled = world();
  const e = await assertRejects(() => decide(disabled, { action_id: 'act-1', decision: 'approved' }, { ...TARGET, access_state: 'disabled' }));
  assertEquals((e as any).code, 'service_not_enabled');
  assertEquals(disabled.calls.length, 0);
  const replay = world({ rows: { record_decision: { outcome: 'duplicate', agent_id: 'agent-svc', callback_status: 'delivered', callback_payload: null } } });
  const r = await decide(replay, { action_id: 'act-1', decision: 'approved' }, { ...TARGET, action_status: 'decided' });
  assertEquals(r, { decision_recorded: true, duplicate: true, callback_delivered: true });
  assertEquals(replay.calls.length, 0, 'a replayed key never calls the agent again');
});

// ---------------------------------------------------------------------------
// Reject: record first, then deliver
// ---------------------------------------------------------------------------

Deno.test('reject: recorded first, then delivered via decision.apply (with reason)', async () => {
  const w = world({ rows: { record_decision: recorded('rejected') } });
  const r = await decide(w, { action_id: 'act-1', decision: 'rejected', reason: 'off brand' });
  assertEquals(r, { decision_recorded: true, duplicate: false, callback_delivered: true });
  const order = w.fns();
  assert(order.indexOf('record_decision') < order.indexOf('get_service_endpoint'), 'record before deliver');
  assertEquals(w.rpcs.find((c) => c.fn === 'record_decision')?.args.p_reason, 'off brand');
  assertEquals(w.calls[0].body.params.decision, 'rejected');
  assertEquals(w.calls[0].body.params.reason, 'off brand');
  assertEquals(w.calls[0].req.headers.get(V1_HEADERS.user), 'user-1');
});

Deno.test('reject delivery: terminal success, retries and fail-closed bookkeeping', async () => {
  const payload = recorded('rejected').callback_payload as ServiceDecisionPayload;
  const run = async (agent: Agent, attemptsMade = 0, rows: Record<string, unknown> = {}) => {
    const w = world({ agent, rows });
    const result = await attemptServiceDelivery(w.client, { agentId: 'agent-svc', payload, idempotencyKey: 'key-12345678', attemptsMade }, {
      allowInsecureServices: false,
      fetchFn: w.fetchFn,
    });
    return { result, args: w.rpcs.find((c) => c.fn === 'record_callback_result')!.args, calls: w.calls.length };
  };
  for (const code of ['idea_final', 'conflict', 'not_found']) {
    const r = await run(() => errEnvelope(409, code));
    assertEquals([r.args.p_delivered, r.args.p_detail, r.args.p_retry_in_seconds], [true, `agent_${code}`, null], code);
  }
  const down = await run(() => Promise.reject(new TypeError('down')));
  assertEquals([down.args.p_delivered, down.args.p_detail], [false, 'network']);
  assert(down.args.p_retry_in_seconds >= 30, 'backoff scheduled');
  assertEquals(down.calls, 1, 'one call per attempt (no proxy-level retry)');
  const reuse = await run(() => errEnvelope(409, 'request_id_reuse'));
  assertEquals([reuse.args.p_delivered, reuse.args.p_detail], [false, 'agent_request_id_reuse']);
  const last = await run(() => errEnvelope(401, 'invalid_signature'), MAX_CALLBACK_ATTEMPTS - 1);
  assertEquals(last.args.p_retry_in_seconds, null, 'after the last attempt it fails closed');
  const gone = await run(() => Response.json({}), 0, { resolve_agent_service: null });
  assertEquals([gone.args.p_delivered, gone.args.p_detail, gone.args.p_retry_in_seconds, gone.calls], [false, 'service_not_found', null, 0]);
});

Deno.test('delivery classification', () => {
  assertEquals(classifyServiceDelivery({ kind: 'refused', error: null as any, detail: 'breaker_open' }).permanent, false);
  assertEquals(classifyServiceDelivery({ kind: 'refused', error: null as any, detail: 'service_not_found' }).permanent, true);
});

// ---------------------------------------------------------------------------
// service-deletions-retry
// ---------------------------------------------------------------------------

function deletions(over: { flag?: boolean; authorized?: boolean; agent?: Agent; jobs?: unknown[] } = {}) {
  const w = world({
    agent: over.agent,
    rows: {
      claim_due_deletion_jobs: over.jobs ?? [{ id: 'job-1', service_slug: 'svc', subject: 'ws-gone', attempts: 0 }],
      record_deletion_job_result: (a: any) => (a.p_done ? 'done' : a.p_retry_in_seconds === null ? 'failed' : 'pending'),
    },
  });
  let created = false;
  const handle = createDeletionsHandler({
    env: { allowInsecureServices: false },
    flags: { isEnabled: () => Promise.resolve(over.flag ?? true) },
    authorized: () => over.authorized ?? true,
    client: () => {
      created = true;
      return w.client;
    },
    fetchFn: w.fetchFn,
  });
  return { w, handle, created: () => created };
}
const post = () => new Request('http://local/service-deletions-retry', { method: 'POST', body: '{}' });

Deno.test('deletions: flag off → feature_disabled with no client; no cron secret → 401', async () => {
  const off = deletions({ flag: false });
  const r = await off.handle(post());
  assertEquals([r.status, (await r.json()).error.code], [404, 'feature_disabled']);
  assertFalse(off.created());
  const anon = deletions({ authorized: false });
  assertEquals((await anon.handle(post())).status, 401);
  assertFalse(anon.created());
});

Deno.test('deletions: the deletion op is called once per job as `system` for the subject; done / not_found / retry', async () => {
  const ok = deletions();
  const body = await (await ok.handle(post())).json();
  assertEquals(body.data, { claimed: 1, done: 1, rescheduled: 0, failed: 0 });
  const call = ok.w.calls[0];
  assertEquals(new URL(call.req.url).pathname, '/cockpit/v1/ops/subject.delete');
  assertEquals([call.req.headers.get(V1_HEADERS.workspace), call.req.headers.get(V1_HEADERS.user), call.req.headers.get(V1_HEADERS.requestId)],
    ['ws-gone', 'system', 'job-1']);
  assertFalse(ok.w.fns().includes('record_gateway_outcome'), 'no gateway_call row (the workspace is gone)');

  const gone = deletions({ agent: () => errEnvelope(404, 'not_found') });
  assertEquals((await (await gone.handle(post())).json()).data.done, 1, 'not_found counts as done');
  const down = deletions({ agent: () => Promise.reject(new TypeError('down')) });
  assertEquals((await (await down.handle(post())).json()).data.rescheduled, 1);
  assertEquals(down.w.calls.length, 1, 'destructive: no proxy-level retry');
  const last = deletions({ agent: () => errEnvelope(500, 'boom'), jobs: [{ id: 'j', service_slug: 'svc', subject: 's', attempts: MAX_CALLBACK_ATTEMPTS - 1 }] });
  assertEquals((await (await last.handle(post())).json()).data.failed, 1, 'terminal after N attempts');
});

Deno.test('deletion classification', () => {
  assertEquals(classifyDeletion({ kind: 'refused', error: null as any, detail: 'breaker_open' }), { done: false, detail: 'breaker_open' });
});
