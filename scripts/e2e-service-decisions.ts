// deno-lint-ignore-file no-explicit-any -- responses are untyped JSON inspected ad hoc by assertions.
// End-to-end test of 0014: decisions on service cards through the gateway,
// reject delivery + callbacks-retry, and the account-deletion fan-out via
// service-deletions-retry — against the local stack and the in-process stub.
// Run through scripts/e2e-service-decisions.sh (flag on, then off).
//
// Env: API_URL, ANON_KEY, SERVICE_ROLE_KEY, CRON_SECRET (LOCAL seed value),
//      DECISIONS_FLAG=on|off, DECISIONS_STATE (file shared between the runs)
import { postCard, socialPostDraft, startStub, type StubHandle } from './stub-agent.ts';

const API_URL = required('API_URL').replace(/\/+$/, '');
const ANON_KEY = required('ANON_KEY');
const SERVICE_ROLE_KEY = required('SERVICE_ROLE_KEY');
const CRON_SECRET = required('CRON_SECRET');
const FLAG = required('DECISIONS_FLAG');
const STATE = required('DECISIONS_STATE');
const STUB_PORT = Number(Deno.env.get('STUB_PORT') ?? '8792');
const FUNCTIONS = `${API_URL}/functions/v1`;
const EDGE_CONTAINER = 'supabase_edge_runtime_cockpit';
const SLUG = 'stub-agent';
const SERVICE_FILE = new URL('./examples/stub-agent.service.json', import.meta.url);
const REASON = `REASON-${crypto.randomUUID().slice(0, 8)}`;

function required(name: string): string {
  const value = Deno.env.get(name);
  if (!value) throw new Error(`Missing env ${name} — run via scripts/e2e-service-decisions.sh`);
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
const step = (title: string) => console.log(`\n▸ ${title}`);

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
  return { status: response.status, body: parsed };
}

const serviceHeaders = { apikey: SERVICE_ROLE_KEY, Authorization: `Bearer ${SERVICE_ROLE_KEY}` };
async function rest(path: string, init: RequestInit & { json?: unknown } = {}): Promise<any> {
  const r = await call(`${API_URL}/rest/v1/${path}`, {
    ...init,
    headers: { ...serviceHeaders, Prefer: 'return=representation', ...(init.headers ?? {}) },
  });
  if (r.status < 200 || r.status >= 300) throw new Error(`REST ${path} → ${r.status}`);
  return r.body;
}

async function signedInUser(tag: string) {
  const email = `e2e-dec-${tag}-${Date.now()}@cockpit.local`;
  const password = `e2e-${crypto.randomUUID()}`;
  const created = await call(`${API_URL}/auth/v1/admin/users`, { method: 'POST', headers: serviceHeaders, json: { email, password, email_confirm: true } });
  if (created.status !== 200) throw new Error(`create user ${tag}: ${created.status}`);
  const session = await call(`${API_URL}/auth/v1/token?grant_type=password`, { method: 'POST', headers: { apikey: ANON_KEY }, json: { email, password } });
  if (session.status !== 200) throw new Error(`sign in ${tag}: ${session.status}`);
  const [row] = await rest(`app_user?id=eq.${created.body.id}&select=workspace_id`);
  return {
    userId: created.body.id as string,
    workspace: row.workspace_id as string,
    headers: { apikey: ANON_KEY, Authorization: `Bearer ${session.body.access_token}` } as Record<string, string>,
  };
}
type User = Awaited<ReturnType<typeof signedInUser>>;

async function registerStub(args: string[]) {
  const path = (u: URL) => u.pathname.replace(/^\/([A-Za-z]:)/, '$1');
  const out = await new Deno.Command(Deno.execPath(), {
    args: ['run', '--allow-net', '--allow-env', '--allow-read', path(new URL('./register-service.ts', import.meta.url)), path(SERVICE_FILE), ...args],
    env: { API_URL, SERVICE_ROLE_KEY },
    stdout: 'piped',
    stderr: 'piped',
  }).output();
  if (!out.success) throw new Error('register-service failed');
  const text = new TextDecoder().decode(out.stdout);
  const pick = (dir: string) =>
    [...text.matchAll(new RegExp(`^\\s+${dir} (?:current|next):\\s+([0-9a-f-]{36})\\s+(svcsig_\\S+)$`, 'gm'))].map((m) => [m[1], m[2]] as [string, string]);
  return { outbound: pick('outbound'), inbound: pick('inbound') };
}

const decide = (user: { headers: Record<string, string> }, body: Record<string, unknown>, key = `e2e-${crypto.randomUUID()}`) =>
  call(`${FUNCTIONS}/actions-decision`, { method: 'POST', headers: { ...user.headers, 'Idempotency-Key': key }, json: body });
const proxy = (user: User, op: string, params: Record<string, unknown> = {}) =>
  call(`${FUNCTIONS}/agent-proxy`, { method: 'POST', headers: { ...user.headers, 'X-App-Version': '0.1.1' }, json: { service: SLUG, op, params } });
const cron = (fn: string) => call(`${FUNCTIONS}/${fn}`, { method: 'POST', headers: { 'X-Cron-Secret': CRON_SECRET }, json: {} });
const actionRow = async (id: string) =>
  (await rest(`action?id=eq.${id}&select=status,decision,callback_status,callback_attempts`))[0];
const code = (r: { body: any }) => r.body?.error?.code;

// ---------------------------------------------------------------------------

async function flagOn(): Promise<void> {
  const owner = await signedInUser('owner');
  const approver = await signedInUser('approver');
  const outsider = await signedInUser('outsider');
  await rest(`app_user?id=eq.${approver.userId}`, { method: 'PATCH', json: { workspace_id: owner.workspace, role: 'approver' } });

  step('setup: register, stub, enable');
  const keys = await registerStub(['--status', 'active', '--rotate-keys']);
  check(keys.outbound.length === 2 && keys.inbound.length === 2, 'four keys printed');
  await rest(`agent_service?slug=eq.${SLUG}`, { method: 'PATCH', json: { open_until: null, consecutive_failures: 0, min_app_version: null } });
  const stub: StubHandle = startStub({ port: STUB_PORT, keys: Object.fromEntries(keys.outbound) });
  try {
    check((await proxy(owner, 'service.enable', { consent_version: 'v1' })).status === 200, 'the owner enables the service');
    const [inId, inSecret] = keys.inbound[0];
    let n = 0;
    const card = async (workspace = owner.workspace, ideaId = `idea-${++n}-${crypto.randomUUID().slice(0, 6)}`) => {
      stub.seedIdea(workspace, ideaId);
      const r = await postCard({
        url: `${FUNCTIONS}/agent-service-inbound`, keyId: inId, secret: inSecret, workspace,
        body: { service: SLUG, op: 'create', external_id: `card_${crypto.randomUUID().slice(0, 8)}`, card: socialPostDraft(SLUG, ideaId, { topic: 'Morning routines', hook: 'Save an hour' }) },
      });
      if (r.body?.data?.result !== 'created') throw new Error(`card create failed: ${r.status}`);
      return { actionId: r.body.data.action_id as string, ideaId };
    };

    step('approve: agent first, synchronous');
    const a = await card();
    const approved = await decide(owner, { action_id: a.actionId, decision: 'approved', acknowledged: ['to_fix.1'] });
    check(approved.status === 200 && approved.body.data.callback_delivered === true, 'approve → 200, delivered', approved.body);
    check(stub.ideaStatus(owner.workspace, a.ideaId) === 'approved', 'the agent applied the approval');
    const aRow = await actionRow(a.actionId);
    check(aRow.status === 'decided' && aRow.decision === 'approved' && aRow.callback_status === 'delivered', 'the card is closed and the delivery done');

    step('approve refused by the agent leaves the card pending');
    const b = await card();
    stub.setMode('approval_blocked');
    const blocked = await decide(owner, { action_id: b.actionId, decision: 'approved' });
    check(blocked.status === 422 && code(blocked) === 'approval_blocked', 'approval_blocked → 422', blocked.body);
    stub.setMode('normal');
    check((await actionRow(b.actionId)).status === 'pending', 'still pending, nothing recorded');
    const audit = await rest(`audit_entry?action_id=eq.${b.actionId}&event=eq.decision_made&select=id`);
    check(audit.length === 0, 'no decision audit row');

    step('agent down on approve, then the same key succeeds');
    const c = await card();
    const key = `e2e-heal-${crypto.randomUUID()}`;
    await stub.stop();
    const down = await decide(owner, { action_id: c.actionId, decision: 'approved' }, key);
    check(down.status === 503 && code(down) === 'agent_unavailable', 'agent down → 503 agent_unavailable', down.body);
    check((await actionRow(c.actionId)).status === 'pending', 'still pending');
    stub.start();
    stub.clearLog();
    const healed = await decide(owner, { action_id: c.actionId, decision: 'approved' }, key);
    check(healed.status === 200 && healed.body.data.decision_recorded === true, 'retrying with the same key succeeds');
    check(stub.seen.some((s) => s.op === 'decision.apply' && s.requestId === key), 'the agent saw the same request id');
    const replay = await decide(owner, { action_id: c.actionId, decision: 'approved' }, key);
    check(replay.status === 200 && replay.body.data.duplicate === true, 'a third call is a duplicate');
    check(stub.seen.filter((s) => s.op === 'decision.apply').length === 1, 'the replay did not call the agent again');

    step('reject while the agent is down: recorded, delivered later by callbacks-retry');
    const d = await card();
    await stub.stop();
    const rejected = await decide(owner, { action_id: d.actionId, decision: 'rejected', reason: REASON });
    check(rejected.status === 200 && rejected.body.data.decision_recorded && rejected.body.data.callback_delivered === false,
      'reject → recorded, not yet delivered', rejected.body);
    check((await actionRow(d.actionId)).callback_status === 'retrying', 'callback_status retrying');
    stub.start();
    await rest(`action?id=eq.${d.actionId}`, { method: 'PATCH', json: { next_attempt_at: new Date().toISOString() } });
    const retry = await cron('callbacks-retry');
    check(retry.status === 200 && retry.body.data.delivered >= 1, 'callbacks-retry delivered it', retry.body);
    check((await actionRow(d.actionId)).callback_status === 'delivered', 'callback_status delivered');
    check(stub.ideaStatus(owner.workspace, d.ideaId) === 'rejected', 'the agent applied the rejection');

    step('reject on an already-final idea is terminal');
    const e1 = await card();
    check((await decide(owner, { action_id: e1.actionId, decision: 'approved' })).status === 200, 'idea approved via card 1');
    const e2 = await card(owner.workspace, e1.ideaId);
    const late = await decide(owner, { action_id: e2.actionId, decision: 'rejected' });
    check(late.status === 200 && late.body.data.callback_delivered === true, 'idea_final from the agent counts as delivered');
    const e2Row = await actionRow(e2.actionId);
    check(e2Row.callback_status === 'delivered' && e2Row.callback_attempts === 1, 'one attempt, no retries');

    step('roles and members');
    const g = await card();
    check((await decide(approver, { action_id: g.actionId, decision: 'approved' })).status === 200, 'an approver can decide');
    const h = await card();
    const foreign = await decide(outsider, { action_id: h.actionId, decision: 'approved' });
    check(foreign.status === 404 && code(foreign) === 'not_found', 'a non-member gets 404');
    const edits = await decide(owner, { action_id: h.actionId, decision: 'approved_with_edits', edited_payload: { hook: 'x' } });
    check(edits.status === 422 && code(edits) === 'validation', 'approved_with_edits on a service card → validation');

    step('retired service: approve refused, reject still clears the card');
    const r1 = await card();
    const r2 = await card();
    await registerStub(['--status', 'retired']);
    const retiredApprove = await decide(owner, { action_id: r1.actionId, decision: 'approved' });
    check(retiredApprove.status === 404 && code(retiredApprove) === 'service_not_found', 'retired: approve → service_not_found');
    const retiredReject = await decide(owner, { action_id: r2.actionId, decision: 'rejected' });
    check(retiredReject.status === 200 && retiredReject.body.data.decision_recorded === true, 'retired: reject records');
    check((await actionRow(r2.actionId)).callback_status === 'failed', 'its delivery ends failed without calling out');
    await registerStub(['--status', 'active']);

    step('account deletion fans out to the service');
    const owner2 = await signedInUser('owner2');
    check((await proxy(owner2, 'service.enable', { consent_version: 'v1' })).status === 200, 'second workspace enables the service');
    await card(owner2.workspace);
    check(stub.hasWorkspace(owner2.workspace), 'the agent holds data for it');
    const deleted = await call(`${FUNCTIONS}/account-delete`, { method: 'POST', headers: owner2.headers, json: { confirm: true } });
    check(deleted.status === 200, 'the owner deletes their account', deleted.body);
    const [job] = await rest(`service_deletion_job?subject=eq.${owner2.workspace}&select=id,status,service_slug`);
    check(job?.status === 'pending' && job.service_slug === SLUG, 'a deletion job is queued for the subject');
    const [log] = await rest(`account_deletion_log?order=deleted_at.desc&limit=1&select=service_jobs`);
    check(log.service_jobs === 1, 'account_deletion_log counts it');
    await rest(`service_deletion_job?id=eq.${job.id}`, { method: 'PATCH', json: { next_attempt_at: new Date().toISOString() } });
    const run = await cron('service-deletions-retry');
    check(run.status === 200 && run.body.data.done >= 1, 'service-deletions-retry ran the deletion op', run.body);
    check(!stub.hasWorkspace(owner2.workspace), 'the agent forgot the subject');
    check((await rest(`service_deletion_job?id=eq.${job.id}&select=status`))[0].status === 'done', 'the job is done');
    check((await cron('service-deletions-retry')).body.data.claimed === 0, 'nothing left to claim');
    const noCron = await call(`${FUNCTIONS}/service-deletions-retry`, { method: 'POST', json: {} });
    check(noCron.status === 401, 'service-deletions-retry refuses callers without the cron secret');

    step('a pending card for the flag-off run');
    const left = await card();
    await Deno.writeTextFile(STATE, JSON.stringify({ headers: owner.headers, actionId: left.actionId }));

    step('redaction canary');
    const calls = await rest(`gateway_call?service_slug=eq.${SLUG}&select=*`);
    check(!JSON.stringify(calls).includes(REASON), 'gateway_call rows hold no reason text');
    const logs = await new Deno.Command('docker', { args: ['logs', EDGE_CONTAINER], stdout: 'piped', stderr: 'piped' }).output();
    const logText = new TextDecoder().decode(logs.stdout) + new TextDecoder().decode(logs.stderr);
    check(logText.includes('service_decision_delivery'), 'function logs are being captured');
    check(!logText.includes(REASON), 'no function log line contains the reject reason');
    for (const [, secret] of [...keys.outbound, ...keys.inbound]) check(!logText.includes(secret), 'no log contains a key');
  } finally {
    await stub.stop();
  }
}

async function flagOff(): Promise<void> {
  const state = JSON.parse(await Deno.readTextFile(STATE)) as { headers: Record<string, string>; actionId: string };
  step('flag off');
  const r = await decide({ headers: state.headers }, { action_id: state.actionId, decision: 'approved' });
  check(r.status === 404 && code(r) === 'feature_disabled', 'a service decision → feature_disabled', r.body);
  check((await actionRow(state.actionId)).status === 'pending', 'the card stays pending');
  const run = await call(`${FUNCTIONS}/service-deletions-retry`, { method: 'POST', json: {} });
  check(run.status === 404 && code(run) === 'feature_disabled', 'service-deletions-retry → feature_disabled (before the cron check)');
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
