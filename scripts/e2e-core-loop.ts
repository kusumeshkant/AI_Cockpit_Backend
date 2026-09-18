// deno-lint-ignore-file no-explicit-any -- responses are untyped JSON inspected ad hoc by assertions.
// End-to-end test of the core loop (Phase 1) and Phase 2 hardening (callback
// retry, test actions, secret rotation, inbound rate limit) against a local
// stack.
//
// Prerequisites (see README):
//   supabase start && supabase db reset
//   supabase functions serve --no-verify-jwt --env-file supabase/functions/.env
//
// Env (exported by scripts/e2e-core-loop.sh from `supabase status -o env` and
// supabase/functions/.env):
//   API_URL, ANON_KEY, SERVICE_ROLE_KEY, CRON_SECRET
//   INBOUND_RATE_LIMIT_PER_MINUTE (optional, default 60 — must match the functions)
// Optional: CALLBACK_PORT (default 8787), RETRY_CALLBACK_PORT (default 8788),
//   CALLBACK_HOST (default host.docker.internal — how the edge-runtime
//   container reaches this host).
import { computeSignature, verifySignature } from '../supabase/functions/_shared/hmac.ts';

const API_URL = required('API_URL').replace(/\/+$/, '');
const ANON_KEY = required('ANON_KEY');
const SERVICE_ROLE_KEY = required('SERVICE_ROLE_KEY');
const CALLBACK_PORT = Number(Deno.env.get('CALLBACK_PORT') ?? '8787');
const RETRY_CALLBACK_PORT = Number(Deno.env.get('RETRY_CALLBACK_PORT') ?? '8788');
const CALLBACK_HOST = Deno.env.get('CALLBACK_HOST') ?? 'host.docker.internal';
const CRON_SECRET = required('CRON_SECRET');
const RATE_LIMIT = Number(Deno.env.get('INBOUND_RATE_LIMIT_PER_MINUTE') ?? '60');
const FUNCTIONS = `${API_URL}/functions/v1`;
const EDGE_CONTAINER = 'supabase_edge_runtime_cockpit';

function required(name: string): string {
  const value = Deno.env.get(name);
  if (!value) throw new Error(`Missing env ${name} — run via scripts/e2e-core-loop.sh`);
  return value;
}

// ---------------------------------------------------------------------------
// Tiny assertion/reporting helpers
// ---------------------------------------------------------------------------
let passed = 0;
function check(condition: unknown, label: string, detail?: unknown): void {
  if (!condition) {
    console.error(`  ✗ ${label}`);
    if (detail !== undefined) console.error('    ', JSON.stringify(detail));
    throw new Error(`E2E failed: ${label}`);
  }
  passed++;
  console.log(`  ✓ ${label}`);
}

function step(title: string): void {
  console.log(`\n▸ ${title}`);
}

async function call(
  url: string,
  init: RequestInit & { json?: unknown } = {},
): Promise<{ status: number; body: any }> {
  const headers = new Headers(init.headers);
  let body = init.body;
  if (init.json !== undefined) {
    headers.set('Content-Type', 'application/json');
    body = JSON.stringify(init.json);
  }
  const response = await fetch(url, { ...init, headers, body });
  const text = await response.text();
  let parsed: unknown = text;
  try {
    parsed = text ? JSON.parse(text) : null;
  } catch {
    // keep text
  }
  return { status: response.status, body: parsed };
}

const serviceHeaders = { apikey: SERVICE_ROLE_KEY, Authorization: `Bearer ${SERVICE_ROLE_KEY}` };

async function rest(path: string): Promise<any[]> {
  const { status, body } = await call(`${API_URL}/rest/v1/${path}`, { headers: serviceHeaders });
  if (status !== 200) throw new Error(`REST ${path} → ${status} ${JSON.stringify(body)}`);
  return body as any[];
}

async function patch(path: string, json: unknown): Promise<void> {
  const { status, body } = await call(`${API_URL}/rest/v1/${path}`, {
    method: 'PATCH',
    headers: { ...serviceHeaders, Prefer: 'return=minimal' },
    json,
  });
  if (status !== 204) throw new Error(`PATCH ${path} → ${status} ${JSON.stringify(body)}`);
}

const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

/** Polls [read] until [done] holds (pg_cron may be processing retries too). */
async function waitFor<T>(
  read: () => Promise<T>,
  done: (value: T) => boolean,
  timeoutMs = 20000,
): Promise<T> {
  const deadline = Date.now() + timeoutMs;
  let value = await read();
  while (!done(value) && Date.now() < deadline) {
    await sleep(500);
    value = await read();
  }
  return value;
}

// ---------------------------------------------------------------------------
// Local callback receiver (stands in for an n8n Wait node)
// ---------------------------------------------------------------------------
interface ReceivedCallback {
  body: string;
  signature: string | null;
  idempotencyKey: string | null;
}
const received: ReceivedCallback[] = [];
const receiver = Deno.serve(
  { hostname: '0.0.0.0', port: CALLBACK_PORT, onListen: () => {} },
  async (req) => {
    received.push({
      body: await req.text(),
      signature: req.headers.get('x-cockpit-signature'),
      idempotencyKey: req.headers.get('idempotency-key'),
    });
    return new Response('ok');
  },
);

const secretsSeen: string[] = [];

try {
  // -------------------------------------------------------------------------
  step('Preflight');
  const ping = await call(`${FUNCTIONS}/actions-inbound`, { method: 'GET' });
  check(
    ping.status === 405,
    'functions are being served (actions-inbound rejects GET with 405)',
    ping,
  );

  // -------------------------------------------------------------------------
  step('Auth bootstrap');
  const stamp = Date.now();
  const email = `e2e+${stamp}@cockpit.local`;
  const password = `e2e-${crypto.randomUUID()}`;
  const created = await call(`${API_URL}/auth/v1/admin/users`, {
    method: 'POST',
    headers: serviceHeaders,
    json: { email, password, email_confirm: true },
  });
  check(created.status === 200, 'admin API creates a user', created.body);
  const userId: string = created.body.id;

  const appUsers = await rest(`app_user?id=eq.${userId}&select=workspace_id,role`);
  check(appUsers.length === 1 && appUsers[0].role === 'owner', 'trigger provisioned app_user (owner)');
  const workspaceId: string = appUsers[0].workspace_id;

  const session = await call(`${API_URL}/auth/v1/token?grant_type=password`, {
    method: 'POST',
    headers: { apikey: ANON_KEY },
    json: { email, password },
  });
  check(session.status === 200 && session.body.access_token, 'user signs in with a password');
  const userJwt: string = session.body.access_token;
  const userHeaders = { apikey: ANON_KEY, Authorization: `Bearer ${userJwt}` };

  // -------------------------------------------------------------------------
  step('agents-create');
  const noAuth = await call(`${FUNCTIONS}/agents-create`, {
    method: 'POST',
    headers: { apikey: ANON_KEY, Authorization: `Bearer ${ANON_KEY}` },
    json: { name: 'x', platform: 'n8n', callback_url: 'https://example.com/cb' },
  });
  check(noAuth.status === 401, 'rejects a request without a user session', noAuth.body);

  const insecure = await call(`${FUNCTIONS}/agents-create`, {
    method: 'POST',
    headers: userHeaders,
    json: { name: 'x', platform: 'n8n', callback_url: 'http://example.com/cb' },
  });
  check(insecure.status === 422, 'rejects a non-https agent callback_url', insecure.body);

  const agentResponse = await call(`${FUNCTIONS}/agents-create`, {
    method: 'POST',
    headers: userHeaders,
    json: { name: 'E2E email agent', platform: 'n8n', callback_url: 'https://example.com/cockpit' },
  });
  check(agentResponse.status === 201 && agentResponse.body.ok, 'creates an agent', agentResponse.body);
  const agent = agentResponse.body.data.agent;
  const secret: string = agentResponse.body.data.signing_secret;
  secretsSeen.push(secret);
  check(/^whsec_[A-Za-z0-9_-]{43}$/.test(secret), 'returns a whsec_ signing secret once');
  check(
    String(agentResponse.body.data.inbound_url).endsWith('/actions-inbound'),
    'returns the inbound URL',
  );

  const agentRow = (await rest(`agent?id=eq.${agent.id}&select=*`))[0];
  check(agentRow.workspace_id === workspaceId, 'agent belongs to the caller\'s workspace');
  check(agentRow.secret_hint === secret.slice(-4), 'only the secret hint is stored on the row');
  check(!JSON.stringify(agentRow).includes(secret), 'plaintext secret is not in the agent row');

  // -------------------------------------------------------------------------
  step('actions-inbound (HMAC, TR-1 / TR-2)');
  const externalId = `n8n-exec-${stamp}`;
  const callbackUrl = `http://${CALLBACK_HOST}:${CALLBACK_PORT}/callback`;
  const inboundBody = JSON.stringify({
    agent_id: agent.id,
    external_id: externalId,
    type: 'email',
    title: 'Reply to Priya — refund request',
    summary: 'Approve a ₹2,400 refund',
    payload: { to: 'priya.k@example.com', subject: 'Re: Refund', body: 'Hi Priya…' },
    editable_fields: ['subject', 'body'],
    callback_url: callbackUrl,
  });
  const signature = await computeSignature(inboundBody, secret);
  const inbound = (sig: string | null, body = inboundBody) =>
    call(`${FUNCTIONS}/actions-inbound`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', ...(sig ? { 'X-Cockpit-Signature': sig } : {}) },
      body,
    });

  const unsigned = await inbound(null);
  check(unsigned.status === 401, 'rejects a missing signature', unsigned.body);

  const forged = await inbound(await computeSignature(inboundBody, 'whsec_wrong'));
  check(forged.status === 401, 'rejects a signature made with the wrong secret', forged.body);

  const tampered = await inbound(signature, inboundBody.replace('₹2,400', '₹24,000'));
  check(tampered.status === 401, 'rejects a tampered body', tampered.body);

  const unknownAgentBody = inboundBody.replace(agent.id, crypto.randomUUID());
  const unknownAgent = await inbound(await computeSignature(unknownAgentBody, secret), unknownAgentBody);
  check(
    unknownAgent.status === 401 && unknownAgent.body.error.code === 'invalid_signature',
    'unknown agent gets the same 401 (no id probing)',
    unknownAgent.body,
  );

  const first = await inbound(signature);
  check(first.status === 200 && first.body.data.duplicate === false, 'accepts a signed action', first.body);
  const actionId: string = first.body.data.action_id;

  const action = (await rest(`action?id=eq.${actionId}&select=*`))[0];
  check(action.status === 'pending' && action.callback_url === callbackUrl, 'action stored as pending');

  const retry = await inbound(signature);
  check(
    retry.status === 200 && retry.body.data.duplicate === true && retry.body.data.action_id === actionId,
    'duplicate inbound returns the same action as duplicate',
    retry.body,
  );
  const sameExternal = await rest(`action?agent_id=eq.${agent.id}&external_id=eq.${externalId}&select=id`);
  check(sameExternal.length === 1, 'duplicate inbound did not create a second action');
  const received1 = await rest(`audit_entry?action_id=eq.${actionId}&event=eq.action_received&select=id`);
  check(received1.length === 1, 'exactly one action_received audit row');

  // -------------------------------------------------------------------------
  step('register_fcm_token (app RPC)');
  for (let i = 0; i < 2; i++) {
    const registered = await call(`${API_URL}/rest/v1/rpc/register_fcm_token`, {
      method: 'POST',
      headers: userHeaders,
      json: { p_token: 'e2e-device-token' },
    });
    check(registered.status === 204 || registered.status === 200, `token registration #${i + 1} succeeds`, registered.body);
  }
  const tokens = (await rest(`app_user?id=eq.${userId}&select=fcm_tokens`))[0].fcm_tokens;
  check(JSON.stringify(tokens) === '["e2e-device-token"]', 'token stored once');

  // -------------------------------------------------------------------------
  step('RLS from the app\'s point of view');
  const visible = await call(`${API_URL}/rest/v1/action?select=id`, { headers: userHeaders });
  check(
    visible.status === 200 && visible.body.length === 1 && visible.body[0].id === actionId,
    'user sees exactly their own action',
    visible.body,
  );
  const clientInsert = await call(`${API_URL}/rest/v1/audit_entry`, {
    method: 'POST',
    headers: userHeaders,
    json: { workspace_id: workspaceId, action_id: actionId, event: 'decision_made' },
  });
  check(clientInsert.status === 401 || clientInsert.status === 403, 'user cannot write audit rows directly', clientInsert.body);

  // -------------------------------------------------------------------------
  step('actions-decision (TR-3 / TR-6 / TR-7)');
  const idempotencyKey = `e2e-${crypto.randomUUID()}`;
  const decide = (key: string | null, json: unknown) =>
    call(`${FUNCTIONS}/actions-decision`, {
      method: 'POST',
      headers: { ...userHeaders, ...(key ? { 'Idempotency-Key': key } : {}) },
      json,
    });
  const decision = {
    action_id: actionId,
    decision: 'approved_with_edits',
    edited_payload: { subject: 'Re: Refund — approved' },
  };

  const noKey = await decide(null, decision);
  check(noKey.status === 422, 'requires an Idempotency-Key header', noKey.body);

  const badEdit = await decide(`e2e-${crypto.randomUUID()}`, {
    ...decision,
    edited_payload: { to: 'attacker@example.com' },
  });
  check(badEdit.status === 422, 'refuses edits to non-editable fields', badEdit.body);

  const decided = await decide(idempotencyKey, decision);
  check(
    decided.status === 200 && decided.body.data.decision_recorded && decided.body.data.duplicate === false,
    'records the decision',
    decided.body,
  );
  check(decided.body.data.callback_delivered === true, 'delivers the callback to the agent', decided.body);

  check(received.length === 1, 'receiver got exactly one callback', received.length);
  const callbackBody = JSON.parse(received[0].body);
  check(await verifySignature(received[0].body, received[0].signature, secret), 'callback is signed with the agent secret');
  check(received[0].idempotencyKey === idempotencyKey, 'callback carries the Idempotency-Key');
  check(
    callbackBody.action_id === actionId &&
      callbackBody.external_id === externalId &&
      callbackBody.decision === 'approved_with_edits' &&
      callbackBody.payload.subject === 'Re: Refund — approved' &&
      callbackBody.payload.to === 'priya.k@example.com',
    'callback payload has ids, decision and merged edits',
    callbackBody,
  );

  const decidedRow = (await rest(`action?id=eq.${actionId}&select=status,decision,callback_status,callback_attempts,decided_by`))[0];
  check(
    decidedRow.status === 'decided' &&
      decidedRow.decision === 'approved_with_edits' &&
      decidedRow.decided_by === userId &&
      decidedRow.callback_status === 'delivered' &&
      decidedRow.callback_attempts === 1,
    'action row: decided, delivered, 1 attempt',
    decidedRow,
  );

  const replay = await decide(idempotencyKey, decision);
  check(
    replay.status === 200 && replay.body.data.duplicate === true && replay.body.data.callback_delivered === true,
    'same Idempotency-Key replays as duplicate',
    replay.body,
  );
  check(received.length === 1, 'replay did not re-send an already-delivered callback', received.length);

  const conflicting = await decide(`e2e-${crypto.randomUUID()}`, { action_id: actionId, decision: 'rejected' });
  check(conflicting.status === 409, 'a new key on a decided action returns 409', conflicting.body);

  const audit = await rest(`audit_entry?action_id=eq.${actionId}&select=event,decision,idempotency_key&order=id.asc`);
  check(
    JSON.stringify(audit.map((row) => row.event)) ===
      JSON.stringify(['action_received', 'decision_made', 'callback_delivered']),
    'audit trail: action_received → decision_made → callback_delivered',
    audit,
  );

  // -------------------------------------------------------------------------
  step('Failed callback is scheduled for retry (TR-7)');
  const retryUrl = `http://${CALLBACK_HOST}:${RETRY_CALLBACK_PORT}/callback`;
  const retryBody = JSON.stringify({
    agent_id: agent.id,
    external_id: `${externalId}-retry`,
    type: 'escalation',
    title: 'Escalate ticket #4821',
    payload: { ticket: 4821 },
    callback_url: retryUrl,
  });
  const retryInbound = await inbound(await computeSignature(retryBody, secret), retryBody);
  check(retryInbound.status === 200, 'accepts an action whose agent is down', retryInbound.body);
  const retryId: string = retryInbound.body.data.action_id;
  const retryKey = `e2e-${crypto.randomUUID()}`;
  const rejected = await decide(retryKey, { action_id: retryId, decision: 'rejected', reason: 'too risky' });
  check(
    rejected.status === 200 && rejected.body.data.decision_recorded && rejected.body.data.callback_delivered === false,
    'decision still succeeds when the agent is unreachable',
    rejected.body,
  );
  const retryRow = (await rest(`action?id=eq.${retryId}&select=status,callback_status,callback_attempts,next_attempt_at`))[0];
  check(
    retryRow.status === 'decided' && retryRow.callback_status === 'retrying' && retryRow.callback_attempts === 1,
    'failed first attempt → retrying, 1 attempt',
    retryRow,
  );
  const firstRetryIn = (Date.parse(retryRow.next_attempt_at) - Date.now()) / 1000;
  check(firstRetryIn > 15 && firstRetryIn <= 40, 'next attempt scheduled ~30s out (backoff step 1)', firstRetryIn);

  const replayRetry = await decide(retryKey, { action_id: retryId, decision: 'rejected', reason: 'too risky' });
  const afterReplay = (await rest(`action?id=eq.${retryId}&select=callback_attempts`))[0];
  check(
    replayRetry.status === 200 && replayRetry.body.data.duplicate === true && afterReplay.callback_attempts === 1,
    'a duplicate decision leaves redelivery to the scheduler',
    { replay: replayRetry.body, afterReplay },
  );

  // -------------------------------------------------------------------------
  step('callbacks-retry (X-Cron-Secret)');
  const runRetry = (secretHeader: string | null) =>
    call(`${FUNCTIONS}/callbacks-retry`, {
      method: 'POST',
      headers: secretHeader === null ? {} : { 'X-Cron-Secret': secretHeader },
      json: {},
    });
  const noCron = await runRetry(null);
  check(noCron.status === 401, 'rejects a request without X-Cron-Secret', noCron.body);
  const badCron = await runRetry('not-the-cron-secret');
  check(badCron.status === 401, 'rejects a wrong X-Cron-Secret', badCron.body);
  const userCron = await call(`${FUNCTIONS}/callbacks-retry`, { method: 'POST', headers: userHeaders, json: {} });
  check(userCron.status === 401, 'a user JWT is not enough', userCron.body);

  const retryReceived: ReceivedCallback[] = [];
  const retryReceiver = Deno.serve(
    { hostname: '0.0.0.0', port: RETRY_CALLBACK_PORT, onListen: () => {} },
    async (req) => {
      retryReceived.push({
        body: await req.text(),
        signature: req.headers.get('x-cockpit-signature'),
        idempotencyKey: req.headers.get('idempotency-key'),
      });
      return new Response('ok');
    },
  );
  try {
    await patch(`action?id=eq.${retryId}`, { next_attempt_at: new Date(Date.now() - 1000).toISOString() });
    const run = await runRetry(CRON_SECRET);
    check(run.status === 200 && typeof run.body.data.claimed === 'number', 'runs with the cron secret', run.body);
    const deliveredRow = await waitFor(
      async () => (await rest(`action?id=eq.${retryId}&select=callback_status,callback_attempts,next_attempt_at`))[0],
      (row) => row.callback_status === 'delivered',
    );
    check(
      deliveredRow.callback_status === 'delivered' && deliveredRow.callback_attempts >= 2 &&
        deliveredRow.next_attempt_at === null,
      'retry delivers once the agent is reachable',
      deliveredRow,
    );
    check(retryReceived.length === 1, 'the agent received the retried callback exactly once', retryReceived.length);
    const retried = JSON.parse(retryReceived[0].body);
    check(
      (await verifySignature(retryReceived[0].body, retryReceived[0].signature, secret)) &&
        retryReceived[0].idempotencyKey === retryKey &&
        retried.action_id === retryId && retried.decision === 'rejected' && retried.reason === 'too risky',
      'retried callback: signed, original Idempotency-Key, stored payload',
      retried,
    );
    const again = await runRetry(CRON_SECRET);
    check(again.status === 200 && retryReceived.length === 1, 'a delivered callback is not sent again', again.body);
  } finally {
    await retryReceiver.shutdown();
  }
  const retryAudit = (await rest(`audit_entry?action_id=eq.${retryId}&select=event&order=id.asc`)).map((r) => r.event);
  check(
    retryAudit[0] === 'action_received' && retryAudit[1] === 'decision_made' &&
      retryAudit.includes('callback_attempted') && retryAudit.at(-1) === 'callback_delivered',
    'audit: action_received → decision_made → callback_attempted… → callback_delivered',
    retryAudit,
  );

  // -------------------------------------------------------------------------
  step('Retries give up after the last attempt');
  const deadBody = JSON.stringify({
    agent_id: agent.id,
    external_id: `${externalId}-dead`,
    type: 'escalation',
    title: 'Escalate ticket #4822',
    payload: { ticket: 4822 },
    callback_url: `http://${CALLBACK_HOST}:1/unreachable`,
  });
  const deadInbound = await inbound(await computeSignature(deadBody, secret), deadBody);
  const deadId: string = deadInbound.body.data.action_id;
  await decide(`e2e-${crypto.randomUUID()}`, { action_id: deadId, decision: 'approved' });
  await patch(`action?id=eq.${deadId}`, {
    callback_attempts: 7,
    next_attempt_at: new Date(Date.now() - 1000).toISOString(),
  });
  await runRetry(CRON_SECRET);
  const deadRow = await waitFor(
    async () => (await rest(`action?id=eq.${deadId}&select=callback_status,callback_attempts,next_attempt_at`))[0],
    (row) => row.callback_status === 'failed',
  );
  check(
    deadRow.callback_status === 'failed' && deadRow.callback_attempts === 8 && deadRow.next_attempt_at === null,
    '8th failed attempt → terminal failed',
    deadRow,
  );
  const deadAudit = (await rest(`audit_entry?action_id=eq.${deadId}&select=event&order=id.asc`)).map((r) => r.event);
  check(deadAudit.at(-1) === 'callback_failed', 'terminal failure audited as callback_failed', deadAudit);

  // -------------------------------------------------------------------------
  step('agents-test-action');
  const testAction = (agentId: string, headers: Record<string, string> = userHeaders) =>
    call(`${FUNCTIONS}/agents-test-action`, { method: 'POST', headers, json: { agent_id: agentId } });
  const testNoAuth = await testAction(agent.id, { apikey: ANON_KEY, Authorization: `Bearer ${ANON_KEY}` });
  check(testNoAuth.status === 401, 'requires a user session', testNoAuth.body);
  const testUnknown = await testAction(crypto.randomUUID());
  check(testUnknown.status === 404, 'another / unknown agent is 404', testUnknown.body);
  const testSent = await testAction(agent.id);
  check(testSent.status === 201 && testSent.body.data.action_id, 'creates a sample action', testSent.body);
  const sample = (await rest(`action?id=eq.${testSent.body.data.action_id}&select=*`))[0];
  check(
    sample.status === 'pending' && sample.agent_id === agent.id && sample.external_id.startsWith('test-') &&
      sample.type === 'email' && JSON.stringify(sample.editable_fields) === '["subject","body"]',
    'sample is a pending email action with editable subject/body',
    sample,
  );
  const sampleAudit = await rest(`audit_entry?action_id=eq.${sample.id}&event=eq.action_received&select=id`);
  check(sampleAudit.length === 1, 'sample went through record_action_inbound (audited)');

  // -------------------------------------------------------------------------
  step('agents-rotate-secret (TR-8)');
  const rotateBody = JSON.stringify({
    agent_id: agent.id,
    external_id: `${externalId}-rotate`,
    type: 'email',
    title: 'Before and after rotation',
    payload: { subject: 'x' },
  });
  const rotateNoAuth = await call(`${FUNCTIONS}/agents-rotate-secret`, {
    method: 'POST',
    headers: { apikey: ANON_KEY, Authorization: `Bearer ${ANON_KEY}` },
    json: { agent_id: agent.id },
  });
  check(rotateNoAuth.status === 401, 'requires a user session', rotateNoAuth.body);
  const rotated = await call(`${FUNCTIONS}/agents-rotate-secret`, {
    method: 'POST',
    headers: userHeaders,
    json: { agent_id: agent.id },
  });
  check(rotated.status === 200 && rotated.body.ok, 'rotates the secret', rotated.body);
  const newSecret: string = rotated.body.data.signing_secret;
  secretsSeen.push(newSecret);
  check(
    /^whsec_[A-Za-z0-9_-]{43}$/.test(newSecret) && newSecret !== secret &&
      rotated.body.data.agent.secret_hint === newSecret.slice(-4),
    'returns a new secret once, with its hint',
  );
  const oldSecretCall = await inbound(await computeSignature(rotateBody, secret), rotateBody);
  check(oldSecretCall.status === 401, 'the old secret is rejected immediately', oldSecretCall.body);
  const newSecretCall = await inbound(await computeSignature(rotateBody, newSecret), rotateBody);
  check(newSecretCall.status === 200, 'the new secret is accepted', newSecretCall.body);

  // -------------------------------------------------------------------------
  step(`Inbound rate limit (${RATE_LIMIT}/min per agent)`);
  const busyAgent = await call(`${FUNCTIONS}/agents-create`, {
    method: 'POST',
    headers: userHeaders,
    json: { name: 'E2E busy agent', platform: 'custom', callback_url: 'https://example.com/busy' },
  });
  check(busyAgent.status === 201, 'creates a second agent', busyAgent.body);
  const busyId: string = busyAgent.body.data.agent.id;
  const busySecret: string = busyAgent.body.data.signing_secret;
  secretsSeen.push(busySecret);
  const pingBody = (external: string) =>
    JSON.stringify({ agent_id: busyId, external_id: external, type: 'ping', title: 'Ping', payload: {} });
  // Fixed one-minute windows: start the burst early in a window.
  const secondOfMinute = new Date().getUTCSeconds();
  if (secondOfMinute > 35) await sleep((61 - secondOfMinute) * 1000);
  let accepted = 0;
  for (let n = 1; n <= RATE_LIMIT; n++) {
    const body = pingBody(`burst-${stamp}-${n}`);
    if ((await inbound(await computeSignature(body, busySecret), body)).status === 200) accepted++;
  }
  check(accepted === RATE_LIMIT, `the first ${RATE_LIMIT} requests in the window are accepted`, accepted);
  const overBody = pingBody('over-the-limit');
  const over = await fetch(`${FUNCTIONS}/actions-inbound`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-Cockpit-Signature': await computeSignature(overBody, busySecret) },
    body: overBody,
  });
  const overJson = await over.json();
  check(
    over.status === 429 && overJson.error.code === 'rate_limited' && Number(over.headers.get('retry-after')) >= 1,
    `request ${RATE_LIMIT + 1} → 429 rate_limited with Retry-After`,
    { status: over.status, body: overJson },
  );
  const overStored = await rest(`action?agent_id=eq.${busyId}&external_id=eq.over-the-limit&select=id`);
  check(overStored.length === 0, 'a limited request stores nothing');

  // -------------------------------------------------------------------------
  step('No secrets in logs');
  const logs = new Deno.Command('docker', { args: ['logs', EDGE_CONTAINER], stdout: 'piped', stderr: 'piped' });
  const { stdout, stderr, success } = await logs.output();
  check(success, `read ${EDGE_CONTAINER} logs`);
  const logText = new TextDecoder().decode(stdout) + new TextDecoder().decode(stderr);
  check(logText.includes('action_inbound'), 'function logs are being captured');
  const sensitive: Array<[string, string]> = [
    ...secretsSeen.map((value): [string, string] => ['the signing secret', value]),
    ['the user JWT', userJwt],
    ['the request signature', signature],
    ['payload content', 'priya.k@example.com'],
    ['the device token', 'e2e-device-token'],
    ['the cron secret', CRON_SECRET],
  ];
  for (const [label, value] of sensitive) {
    check(!logText.includes(value), `logs do not contain ${label}`);
  }

  console.log(`\nPASS — ${passed} checks`);
} catch (error) {
  console.error(`\nFAIL after ${passed} passing checks: ${error instanceof Error ? error.message : error}`);
  Deno.exitCode = 1;
} finally {
  await receiver.shutdown();
}
