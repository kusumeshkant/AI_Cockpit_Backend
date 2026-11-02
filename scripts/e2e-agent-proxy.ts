// deno-lint-ignore-file no-explicit-any -- responses are untyped JSON inspected ad hoc by assertions.
// End-to-end test of agent-proxy (0012) + Cockpit-Signature v1 against the
// local stack and the in-process stub agent (scripts/stub-agent.ts).
// Run through scripts/e2e-agent-proxy.sh, which sets the agent_services flag
// and serves the functions (PROXY_FLAG=off, then on).
//
// Env: API_URL, ANON_KEY, SERVICE_ROLE_KEY, PROXY_FLAG=on|off
// Optional: STUB_PORT (default 8792; must match the registered base_url).
import { startStub, type StubHandle } from './stub-agent.ts';

const API_URL = required('API_URL').replace(/\/+$/, '');
const ANON_KEY = required('ANON_KEY');
const SERVICE_ROLE_KEY = required('SERVICE_ROLE_KEY');
const FLAG = required('PROXY_FLAG');
const STUB_PORT = Number(Deno.env.get('STUB_PORT') ?? '8792');
const FUNCTIONS = `${API_URL}/functions/v1`;
const EDGE_CONTAINER = 'supabase_edge_runtime_cockpit';
const SLUG = 'stub-agent';
const SERVICE_FILE = new URL('./examples/stub-agent.service.json', import.meta.url);
const APP_VERSION = '0.1.1';
const CANARY = `CANARY-${crypto.randomUUID()}`;

function required(name: string): string {
  const value = Deno.env.get(name);
  if (!value) throw new Error(`Missing env ${name} — run via scripts/e2e-agent-proxy.sh`);
  return value;
}

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

async function call(url: string, init: RequestInit & { json?: unknown } = {}) {
  const headers = new Headers(init.headers);
  let body = init.body;
  if (init.json !== undefined) {
    headers.set('Content-Type', 'application/json');
    body = JSON.stringify(init.json);
  }
  const response = await fetch(url, { ...init, headers, body });
  const text = await response.text();
  let parsed: any = text;
  try {
    parsed = text ? JSON.parse(text) : null;
  } catch {
    // keep text
  }
  return { status: response.status, body: parsed, headers: response.headers };
}

const serviceHeaders = { apikey: SERVICE_ROLE_KEY, Authorization: `Bearer ${SERVICE_ROLE_KEY}` };

async function rest(path: string, init: RequestInit & { json?: unknown } = {}): Promise<any> {
  const r = await call(`${API_URL}/rest/v1/${path}`, {
    ...init,
    headers: { ...serviceHeaders, Prefer: 'return=representation', ...(init.headers ?? {}) },
  });
  if (r.status < 200 || r.status >= 300) throw new Error(`REST ${path} → ${r.status} ${JSON.stringify(r.body)}`);
  return r.body;
}

async function signedInUser(tag: string) {
  const email = `e2e-proxy-${tag}-${Date.now()}@cockpit.local`;
  const password = `e2e-${crypto.randomUUID()}`;
  const created = await call(`${API_URL}/auth/v1/admin/users`, {
    method: 'POST',
    headers: serviceHeaders,
    json: { email, password, email_confirm: true },
  });
  if (created.status !== 200) throw new Error(`create user ${tag}: ${created.status}`);
  const session = await call(`${API_URL}/auth/v1/token?grant_type=password`, {
    method: 'POST',
    headers: { apikey: ANON_KEY },
    json: { email, password },
  });
  if (session.status !== 200) throw new Error(`sign in ${tag}: ${session.status}`);
  return {
    userId: created.body.id as string,
    jwt: session.body.access_token as string,
    headers: { apikey: ANON_KEY, Authorization: `Bearer ${session.body.access_token}` } as Record<string, string>,
  };
}

type User = Awaited<ReturnType<typeof signedInUser>>;

const proxy = (
  user: { headers: Record<string, string> } | null,
  op: string,
  params: Record<string, unknown> = {},
  extra: Record<string, string> = {},
  service = SLUG,
) =>
  call(`${FUNCTIONS}/agent-proxy`, {
    method: 'POST',
    headers: { ...(user?.headers ?? { apikey: ANON_KEY }), 'X-App-Version': APP_VERSION, ...extra },
    json: { service, op, params },
  });

const key = () => ({ 'Idempotency-Key': `e2e-${crypto.randomUUID()}` });

/** Runs register-service.ts; returns the printed key ids and secrets (never printed here). */
async function registerStub(args: string[]): Promise<Record<string, string>> {
  const out = await new Deno.Command(Deno.execPath(), {
    args: ['run', '--allow-net', '--allow-env', '--allow-read', new URL('./register-service.ts', import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, '$1'), SERVICE_FILE.pathname.replace(/^\/([A-Za-z]:)/, '$1'), ...args],
    env: { API_URL, SERVICE_ROLE_KEY },
    stdout: 'piped',
    stderr: 'piped',
  }).output();
  const text = new TextDecoder().decode(out.stdout);
  if (!out.success) throw new Error(`register-service failed: ${new TextDecoder().decode(out.stderr).split('\n')[0]}`);
  const keys: Record<string, string> = {};
  for (const match of text.matchAll(/^\s+(?:current|next):\s+([0-9a-f-]{36})\s+(svcsig_\S+)$/gm)) keys[match[1]] = match[2];
  return keys;
}

const code = (r: { body: any }) => r.body?.error?.code;
const gatewayCalls = async () => (await rest(`gateway_call?service_slug=eq.${SLUG}&select=*`)) as any[];

// ---------------------------------------------------------------------------

async function flagOff(): Promise<void> {
  const owner = await signedInUser('off');
  const before = (await gatewayCalls()).length;
  step('flag off');
  const r = await proxy(owner, 'ideas.list');
  check(r.status === 404 && code(r) === 'feature_disabled', 'agent-proxy → 404 feature_disabled', r.body);
  const anon = await proxy(null, 'service.enable', { consent_version: 'v1' });
  check(anon.status === 404 && code(anon) === 'feature_disabled', 'even unauthenticated calls get feature_disabled');
  check((await gatewayCalls()).length === before, 'nothing was recorded (no RPC ran)');
}

async function flagOn(): Promise<void> {
  const owner = await signedInUser('owner');
  const approver = await signedInUser('approver');
  const [ownerRow] = await rest(`app_user?id=eq.${owner.userId}&select=workspace_id`);
  const workspace = ownerRow.workspace_id as string;
  await rest(`app_user?id=eq.${approver.userId}`, {
    method: 'PATCH',
    json: { workspace_id: workspace, role: 'approver' },
  });

  step('registry: draft, then active');
  const keys = await registerStub(['--status', 'draft', '--rotate-keys']);
  check(Object.keys(keys).length === 2, 'register-service printed two key ids with secrets');
  const stub: StubHandle = startStub({ port: STUB_PORT, keys });
  try {
    const draft = await proxy(owner, 'service.enable', { consent_version: 'v1' });
    check(draft.status === 404 && code(draft) === 'service_not_found', 'draft service → service_not_found', draft.body);
    await registerStub(['--status', 'active']);
    const [svc] = await rest(`agent_service?slug=eq.${SLUG}&select=status,open_until,consecutive_failures`);
    check(svc.status === 'active', 'service is active');
    await rest(`agent_service?slug=eq.${SLUG}`, { method: 'PATCH', json: { open_until: null, consecutive_failures: 0, min_app_version: null } });

    step('enable (owner only) and first use');
    const notYet = await proxy(owner, 'ideas.list');
    check(notYet.status === 403 && code(notYet) === 'service_not_enabled', 'before enabling → service_not_enabled', notYet.body);
    const approverEnable = await proxy(approver, 'service.enable', { consent_version: 'v1' });
    check(approverEnable.status === 403 && code(approverEnable) === 'forbidden', 'an approver cannot enable', approverEnable.body);
    const enabled = await proxy(owner, 'service.enable', { consent_version: 'v1' });
    check(enabled.status === 200 && enabled.body.data.result.state === 'active', 'the owner enables the service', enabled.body);
    check(typeof enabled.body.data.meta.request_id === 'string', 'built-in answers carry a request id');
    check(stub.seen.length === 0, 'built-in ops are not forwarded');
    const again = await proxy(owner, 'service.enable', { consent_version: 'v1' });
    check(again.status === 200 && again.body.data.result.changed === false, 'enable is idempotent');
    const list = await proxy(owner, 'ideas.list');
    check(list.status === 200 && Array.isArray(list.body.data.result.ideas), 'owner ideas.list → 200', list.body);
    const [access] = await rest(`service_access?workspace_id=eq.${workspace}&service_slug=eq.${SLUG}&select=first_used_at`);
    check(access.first_used_at !== null, 'the first forwarded success stamps first_used_at');

    step('generate (202) and poll to done');
    const approverGen = await proxy(approver, 'idea.generate', { topic: 'x' }, key());
    check(approverGen.status === 403 && code(approverGen) === 'forbidden', 'an approver cannot generate', approverGen.body);
    const noKey = await proxy(owner, 'idea.generate', { topic: CANARY });
    check(noKey.status === 422 && code(noKey) === 'validation', 'a write without Idempotency-Key → 422', noKey.body);
    const genKey = key();
    const gen = await proxy(owner, 'idea.generate', { topic: CANARY }, genKey);
    check(gen.status === 202 && typeof gen.body.data.result.job_id === 'string', 'idea.generate → 202 + job_id', gen.body);
    check(gen.body.data.meta.request_id === genKey['Idempotency-Key'], 'the Idempotency-Key is the request id');
    check(gen.body.data.meta.poll_after_ms === 100 && gen.body.data.meta.usage?.used >= 1, 'meta: poll_after_ms + usage');
    let status = '';
    let ideas: any[] = [];
    for (let i = 0; i < 6 && status !== 'done'; i++) {
      const poll = await proxy(owner, 'job.poll', { job_id: gen.body.data.result.job_id });
      status = poll.body?.data?.result?.status;
      ideas = poll.body?.data?.result?.ideas ?? [];
    }
    check(status === 'done' && ideas.length === 1, 'job.poll goes queued → running → done');
    const ideaId = ideas[0].id;

    step('decisions (approver allowed) and idea_final');
    const approve = await proxy(approver, 'decision.apply', { idea_id: ideaId, decision: 'approved' }, key());
    check(approve.status === 200 && approve.body.data.result.idea.status === 'approved', 'an approver can decision.apply', approve.body);
    const final = await proxy(owner, 'decision.apply', { idea_id: ideaId, decision: 'rejected' }, key());
    check(
      final.status === 409 && code(final) === 'conflict' && final.body.error.details?.code === 'idea_final',
      'a decided idea → 409 conflict (details.code idea_final)',
      final.body,
    );

    step('request ids: replay and reuse');
    const saveKey = key();
    const save1 = await proxy(owner, 'brand.save', { brand: { name: CANARY } }, saveKey);
    const save2 = await proxy(owner, 'brand.save', { brand: { name: CANARY } }, saveKey);
    check(save1.status === 200 && save2.status === 200, 'same request id + same body → 200 twice');
    check(stub.seen.at(-1)?.deduped === true, 'the stub answered the repeat from its idempotency store');
    const reuse = await proxy(owner, 'brand.save', { brand: { name: 'other' } }, saveKey);
    check(reuse.status === 502 && code(reuse) === 'agent_error', 'same request id + other body → agent_error', reuse.body);
    check(!JSON.stringify(reuse.body).includes('stub detail'), 'no agent detail reaches the app');

    step('manifest-only ops, size caps, app version');
    const unknown = await proxy(owner, 'ideas.drop');
    check(unknown.status === 422 && code(unknown) === 'unsupported_op', 'an op outside the manifest → unsupported_op');
    const big = await proxy(owner, 'brand.save', { brand: { blob: 'x'.repeat(3000) } }, key());
    check(big.status === 413 && code(big) === 'payload_too_large', 'over the op max_request_bytes → 413', big.body);
    const huge = await proxy(owner, 'brand.save', { brand: { blob: 'x'.repeat(70 * 1024) } }, key());
    check(huge.status === 413, 'over the proxy 64 KB cap → 413');
    await rest(`agent_service?slug=eq.${SLUG}`, { method: 'PATCH', json: { min_app_version: '9.0.0' } });
    const old = await proxy(owner, 'ideas.list');
    check(old.status === 426 && code(old) === 'app_update_required', 'below min_app_version → 426 app_update_required');
    await rest(`agent_service?slug=eq.${SLUG}`, { method: 'PATCH', json: { min_app_version: null } });

    step('retries: same request id, new nonce');
    stub.clearLog();
    stub.failNext(1, 503);
    const retried = await proxy(owner, 'brand.get');
    check(retried.status === 200 && retried.body.data.result.brand?.name === CANARY, 'a read survives one transient 503');
    check(
      stub.seen.length === 2 && stub.seen[0].requestId === stub.seen[1].requestId && stub.seen[0].nonce !== stub.seen[1].nonce,
      'the retry reused the request id with a fresh nonce',
      stub.seen,
    );
    stub.clearLog();
    stub.failNext(1, 502);
    const writeRetry = await proxy(owner, 'brand.save', { brand: { name: CANARY, v: 2 } }, key());
    check(writeRetry.status === 200 && stub.seen.length === 2 && stub.seen[0].requestId === stub.seen[1].requestId,
      'a write retries once on 502 with the same request id');
    const recorded = (await gatewayCalls()).filter((c) => c.op === 'brand.save' && c.attempts === 2);
    check(recorded.length >= 1, 'gateway_call records 2 attempts');

    step('replayed nonce is rejected by the stub');
    const raw = stub.lastRaw!;
    const replay = await fetch(`http://127.0.0.1:${STUB_PORT}${raw.path}`, { method: 'POST', headers: raw.headers, body: raw.body });
    const replayBody = await replay.json();
    check(replay.status === 401 && replayBody.error.code === 'replayed_nonce', 'replaying a signed request → replayed_nonce');

    step('key rotation overlap');
    const [before] = await rest(`agent_service?slug=eq.${SLUG}&select=signing_key_current_id,signing_key_next_id`);
    stub.clearLog();
    await rest('rpc/swap_service_signing_keys', { method: 'POST', json: { p_slug: SLUG } });
    const rotated = await proxy(owner, 'ideas.list');
    check(rotated.status === 200 && stub.seen[0]?.keyId === before.signing_key_next_id, 'after a swap the proxy signs with the former next key, no failure');
    await rest('rpc/swap_service_signing_keys', { method: 'POST', json: { p_slug: SLUG } });
    check((await proxy(owner, 'ideas.list')).status === 200, 'swapping back works too');

    const healthy = async (label: string) => {
      const r = await proxy(owner, 'ideas.list');
      check(r.status === 200, `healthy again after ${label}`, r.body);
    };

    step('agent failures map to safe codes');
    await stub.stop();
    const down = await proxy(owner, 'ideas.list');
    check(down.status === 503 && code(down) === 'agent_unavailable' && down.headers.get('Retry-After') !== null,
      'stub down → 503 agent_unavailable + Retry-After', down.body);
    stub.start();
    await healthy('down');
    stub.setMode('slow');
    const slow = await proxy(owner, 'usage.get');
    check(slow.status === 504 && code(slow) === 'agent_timeout', 'slow agent → 504 agent_timeout', slow.body);
    stub.setMode('normal');
    await healthy('slow');
    for (const [mode, label] of [['error500', '500'], ['malformed', 'malformed envelope'], ['oversize', 'oversized response']] as const) {
      stub.setMode(mode);
      const r = await proxy(owner, 'ideas.list');
      check(r.status === 502 && code(r) === 'agent_error', `${label} → 502 agent_error`, r.body);
      stub.setMode('normal');
      await healthy(label);
    }
    stub.setQuota(0);
    const quota = await proxy(owner, 'idea.generate', { topic: 'q' }, key());
    check(quota.status === 403 && code(quota) === 'quota_reached', 'quota_reached passes through', quota.body);
    stub.setQuota(5);
    stub.setMode('trial_ended');
    const trial = await proxy(owner, 'usage.get');
    check(trial.status === 403 && code(trial) === 'trial_ended', 'trial_ended passes through', trial.body);
    stub.setMode('agent_paused');
    const agentPaused = await proxy(owner, 'usage.get');
    check(agentPaused.status === 503 && code(agentPaused) === 'agent_paused', 'agent-side agent_paused passes through');
    stub.setMode('unsupported_contract');
    const contract = await proxy(owner, 'usage.get');
    check(contract.status === 502 && code(contract) === 'agent_error' && !JSON.stringify(contract.body).includes('stub detail'),
      'unsupported_contract → agent_error without detail', contract.body);
    stub.setMode('normal');
    stub.setKeys({ [Object.keys(keys)[0]]: 'svcsig_wrong_secret_0123456789abcdefghijklmnopq' });
    const badSig = await proxy(owner, 'usage.get');
    check(badSig.status === 502 && code(badSig) === 'agent_error' && !JSON.stringify(badSig.body).includes('stub detail'),
      'a signature the agent rejects → agent_error without detail', badSig.body);
    stub.setKeys(keys);
    await healthy('bad signature');

    step('registry paused, disabled, blocked');
    await registerStub(['--status', 'paused']);
    const paused = await proxy(owner, 'ideas.list');
    check(paused.status === 503 && code(paused) === 'agent_paused', 'registry paused → agent_paused');
    const disablePaused = await proxy(owner, 'service.disable');
    check(disablePaused.status === 200 && disablePaused.body.data.result.state === 'disabled', 'service.disable works while paused');
    await registerStub(['--status', 'active']);
    const disabled = await proxy(owner, 'ideas.list');
    check(disabled.status === 403 && code(disabled) === 'service_not_enabled', 'disabled → service_not_enabled');
    await proxy(owner, 'service.enable', { consent_version: 'v1' });
    await rest(`service_access?workspace_id=eq.${workspace}&service_slug=eq.${SLUG}`, { method: 'PATCH', json: { state: 'blocked' } });
    const blocked = await proxy(owner, 'ideas.list');
    check(blocked.status === 403 && code(blocked) === 'service_not_enabled' && blocked.body.error.message === disabled.body.error.message,
      'blocked looks exactly like disabled');
    const blockedEnable = await proxy(owner, 'service.enable', { consent_version: 'v2' });
    check(code(blockedEnable) === 'service_not_enabled', 'a blocked service cannot be re-enabled by the owner', blockedEnable.body);
    await rest(`service_access?workspace_id=eq.${workspace}&service_slug=eq.${SLUG}`, { method: 'PATCH', json: { state: 'active' } });

    step('circuit breaker');
    await stub.stop();
    for (let i = 0; i < 5; i++) await proxy(owner, 'ideas.list');
    const [open] = await rest(`agent_service?slug=eq.${SLUG}&select=consecutive_failures,open_until`);
    check(open.consecutive_failures >= 5 && open.open_until !== null, 'five failures open the breaker (state in the table)', open);
    stub.start();
    stub.clearLog();
    const shortCircuit = await proxy(owner, 'ideas.list');
    check(shortCircuit.status === 503 && code(shortCircuit) === 'agent_unavailable' && stub.seen.length === 0,
      'while open the proxy answers agent_unavailable without calling out');
    await rest(`agent_service?slug=eq.${SLUG}`, { method: 'PATCH', json: { open_until: new Date(Date.now() - 1000).toISOString() } });
    await healthy('the breaker cooled down');
    const [closed] = await rest(`agent_service?slug=eq.${SLUG}&select=consecutive_failures,open_until`);
    check(closed.consecutive_failures === 0 && closed.open_until === null, 'a success closes and resets it');

    step('rate limit (destructive: 5/min)');
    let limited: Awaited<ReturnType<typeof proxy>> | null = null;
    for (let i = 0; i < 6; i++) {
      const r = await proxy(owner, 'subject.delete', {}, key());
      if (r.status === 429) {
        limited = r;
        break;
      }
    }
    check(limited !== null && code(limited) === 'rate_limited' && limited.headers.get('Retry-After') !== null,
      'the 6th destructive call in a minute → 429 rate_limited + Retry-After');

    step('redaction canary');
    const rows = await gatewayCalls();
    check(rows.length > 0 && !JSON.stringify(rows).includes(CANARY), 'gateway_call rows hold no params / results');
    check(!JSON.stringify(rows).includes(SERVICE_ROLE_KEY), 'gateway_call rows hold no keys');
    const logs = await new Deno.Command('docker', { args: ['logs', EDGE_CONTAINER], stdout: 'piped', stderr: 'piped' }).output();
    const logText = new TextDecoder().decode(logs.stdout) + new TextDecoder().decode(logs.stderr);
    check(logText.includes('agent_call'), 'function logs are being captured');
    check(!logText.includes(CANARY), 'no function log line contains params or agent results');
    for (const secret of Object.values(keys)) check(!logText.includes(secret), 'logs never contain a signing secret');
    check(!logText.includes(owner.jwt), 'logs never contain the user JWT');
  } finally {
    await stub.stop();
  }
}

try {
  const ping = await call(`${FUNCTIONS}/actions-inbound`, { method: 'GET' });
  check(ping.status === 405, 'functions are being served');
  const [row] = await rest('feature_setting?key=eq.agent_services&select=enabled');
  check(row?.enabled === (FLAG === 'on'), `feature_setting agent_services is ${FLAG}`, row);
  if (FLAG === 'on') await flagOn();
  else await flagOff();
  console.log(`\nPASS (flag ${FLAG}) — ${passed} checks`);
} catch (error) {
  console.error(`\nFAIL (flag ${FLAG}) after ${passed} passing checks: ${error instanceof Error ? error.message : error}`);
  Deno.exitCode = 1;
}
