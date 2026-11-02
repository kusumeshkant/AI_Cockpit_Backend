// deno-lint-ignore-file no-explicit-any -- responses are untyped JSON inspected ad hoc by assertions.
// End-to-end test of agent-service-inbound (0013): the stub agent posts
// social_post_draft cards signed with the service's INBOUND keys.
// Run through scripts/e2e-service-cards.sh (flag off, then on).
//
// Env: API_URL, ANON_KEY, SERVICE_ROLE_KEY, CARDS_FLAG=on|off
import { postCard, socialPostDraft } from './stub-agent.ts';

const API_URL = required('API_URL').replace(/\/+$/, '');
const ANON_KEY = required('ANON_KEY');
const SERVICE_ROLE_KEY = required('SERVICE_ROLE_KEY');
const FLAG = required('CARDS_FLAG');
const FUNCTIONS = `${API_URL}/functions/v1`;
const INBOUND = `${FUNCTIONS}/agent-service-inbound`;
const EDGE_CONTAINER = 'supabase_edge_runtime_cockpit';
const SLUG = 'stub-agent';
const SERVICE_FILE = new URL('./examples/stub-agent.service.json', import.meta.url);
const TOPIC = `TOPIC-${crypto.randomUUID().slice(0, 8)}`;
const HOOK = `HOOK-${crypto.randomUUID().slice(0, 8)}`;

function required(name: string): string {
  const value = Deno.env.get(name);
  if (!value) throw new Error(`Missing env ${name} — run via scripts/e2e-service-cards.sh`);
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
  const email = `e2e-cards-${tag}-${Date.now()}@cockpit.local`;
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
    headers: { apikey: ANON_KEY, Authorization: `Bearer ${session.body.access_token}` } as Record<string, string>,
  };
}

type Keys = { outbound: [string, string][]; inbound: [string, string][] };

/** Runs register-service.ts; returns the printed key ids + secrets (never printed here). */
async function registerStub(args: string[]): Promise<Keys> {
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
    [...text.matchAll(new RegExp(`^\\s+${dir} (?:current|next):\\s+([0-9a-f-]{36})\\s+(svcsig_\\S+)$`, 'gm'))]
      .map((m) => [m[1], m[2]] as [string, string]);
  return { outbound: pick('outbound'), inbound: pick('inbound') };
}

const proxy = (user: { headers: Record<string, string> }, op: string, params: Record<string, unknown> = {}) =>
  call(`${FUNCTIONS}/agent-proxy`, {
    method: 'POST',
    headers: { ...user.headers, 'X-App-Version': '0.1.1' },
    json: { service: SLUG, op, params },
  });

// ---------------------------------------------------------------------------

async function flagOff(): Promise<void> {
  step('flag off');
  const before = (await rest('gateway_nonce?select=nonce')).length;
  const r = await postCard({
    url: INBOUND,
    keyId: crypto.randomUUID(),
    secret: 'svcsig_any_secret_0123456789abcdefghijklmnopq',
    workspace: crypto.randomUUID(),
    body: { service: SLUG, op: 'create', external_id: 'idea_off', card: socialPostDraft(SLUG, 'off', { topic: 'x', hook: 'y' }) },
  });
  check(r.status === 404 && r.body?.error?.code === 'feature_disabled', 'agent-service-inbound → 404 feature_disabled', r.body);
  check((await rest('gateway_nonce?select=nonce')).length === before, 'no RPC ran (no nonce claimed)');
}

async function flagOn(): Promise<void> {
  const owner = await signedInUser('owner');
  const [row] = await rest(`app_user?id=eq.${owner.userId}&select=workspace_id`);
  const workspace = row.workspace_id as string;

  step('register (four keys) and enable');
  const keys = await registerStub(['--status', 'active', '--rotate-keys']);
  check(keys.outbound.length === 2 && keys.inbound.length === 2, 'register-service printed outbound and inbound pairs');
  check(keys.inbound.every(([id]) => !keys.outbound.some(([o]) => o === id)), 'the inbound pair is a separate key pair');
  await rest(`agent_service?slug=eq.${SLUG}`, { method: 'PATCH', json: { open_until: null, consecutive_failures: 0, min_app_version: null } });
  const enabled = await proxy(owner, 'service.enable', { consent_version: 'v1' });
  check(enabled.status === 200, 'the owner enables the service', enabled.body);
  const [inId, inSecret] = keys.inbound[0];
  const post = (body: Record<string, unknown> | string, extra: Partial<Parameters<typeof postCard>[0]> = {}) =>
    postCard({ url: INBOUND, keyId: inId, secret: inSecret, workspace, body, ...extra });
  const create = (id: string, opts: { topic?: string; hook?: string; expiresAt?: string } = {}) =>
    ({ service: SLUG, op: 'create', external_id: `idea_${id}`, card: socialPostDraft(SLUG, id, { topic: opts.topic ?? TOPIC, hook: opts.hook ?? HOOK, expiresAt: opts.expiresAt }) });
  const update = (id: string, revision: number, topic = `${TOPIC} v${revision}`) =>
    ({ service: SLUG, op: 'update', external_id: `idea_${id}`, revision, card: socialPostDraft(SLUG, id, { topic, hook: HOOK, revision }) });
  const withdraw = (id: string) => ({ service: SLUG, op: 'withdraw', external_id: `idea_${id}`, reason_code: 'regenerated' });
  const ownerAction = async (id: string) =>
    (await call(`${API_URL}/rest/v1/action?id=eq.${id}&select=id,type,title,summary,status,expires_at,editable_fields`, { headers: owner.headers })).body[0];

  step('create, duplicate');
  const c1 = await post(create('1'));
  check(c1.status === 200 && c1.body.data.result === 'created', 'create → created', c1.body);
  const a1 = c1.body.data.action_id;
  const seen = await ownerAction(a1);
  check(seen?.type === 'social_post_draft' && seen.status === 'pending' && seen.summary === HOOK, "the card is in the workspace's actions (owner JWT, RLS)", seen);
  check(seen.editable_fields.length === 0, 'no editable fields');
  const ttl = Date.parse(seen.expires_at) - Date.now();
  check(ttl > 6.9 * 86_400_000 && ttl <= 7 * 86_400_000 + 60_000, 'default expiry ≈ 7 days');
  const dup = await post(create('1'));
  check(dup.body.data?.result === 'duplicate' && dup.body.data.action_id === a1, 'the same external_id → duplicate, same action');

  step('update ordering, withdraw');
  check((await post(update('1', 2))).body.data?.result === 'updated', 'revision 2 → updated');
  check((await ownerAction(a1)).title === `Post idea: ${TOPIC} v2`, 'the owner sees the new revision');
  check((await post(update('1', 2))).body.data?.result === 'stale', 'revision 2 again → stale');
  check((await post(update('1', 1))).body.data?.result === 'stale', 'revision 1 → stale');
  const w1 = await post(withdraw('1'));
  check(w1.body.data?.result === 'withdrawn' && (await ownerAction(a1)).status === 'expired', 'withdraw → expired');
  check((await post(withdraw('1'))).body.data?.result === 'noop', 'withdraw again → noop');
  check((await post(update('1', 3))).body.data?.result === 'noop', 'no update after withdraw');
  const far = await post(create('2', { expiresAt: new Date(Date.now() + 60 * 86_400_000).toISOString() }));
  const exp2 = Date.parse((await ownerAction(far.body.data.action_id)).expires_at) - Date.now();
  check(exp2 <= 30 * 86_400_000 + 60_000 && exp2 > 29.9 * 86_400_000, 'a requested 60 days is capped at 30');

  step('service states');
  await registerStub(['--status', 'paused']);
  const paused = await post(create('3'));
  check(paused.status === 503 && paused.body.error.code === 'agent_paused', 'paused: create → agent_paused');
  check((await post(update('2', 2))).body.data?.result === 'updated', 'paused: fixes (update) still apply');
  await registerStub(['--status', 'active']);
  await proxy(owner, 'service.disable');
  const disabled = await post(create('4'));
  check(disabled.status === 403 && disabled.body.error.code === 'service_not_enabled', 'disabled: create → service_not_enabled');
  check((await post(update('2', 3))).body.error?.code === 'service_not_enabled', 'disabled: update → service_not_enabled');
  await proxy(owner, 'service.enable', { consent_version: 'v1' });
  const dots = await post(create('11', { hook: 'Mornings.In summer' }));
  check(dots.body.data?.result === 'created', '"Mornings.In summer" is text, not a link');
  check((await post(create('12', { hook: 'see www.x.com' }))).status === 422, '"www.x.com" is refused');
  check((await post(create('12', { hook: 'https://x.com' }))).status === 422, '"https://x.com" is refused');
  await rest(`service_access?workspace_id=eq.${workspace}&service_slug=eq.${SLUG}`, { method: 'PATCH', json: { state: 'blocked' } });
  check((await post(create('5'))).body.error?.code === 'service_not_enabled', 'blocked: create → service_not_enabled');
  check((await post(update('2', 3))).body.error?.code === 'service_not_enabled', 'blocked: update → service_not_enabled');
  check((await post(withdraw('2'))).body.data?.result === 'withdrawn', 'blocked: withdraw still works');
  await rest(`service_access?workspace_id=eq.${workspace}&service_slug=eq.${SLUG}`, { method: 'PATCH', json: { state: 'active' } });

  step('authenticity: every failure is the same 401');
  const fresh = await post(create('6'));
  check(fresh.body.data?.result === 'created', 'a valid card is accepted');
  const failures = [
    await post(create('7'), { fault: 'bad_signature' }),
    await post(create('6'), { nonce: fresh.nonce }),
    await post(create('7'), { workspace: crypto.randomUUID() }),
    await post(create('7'), { timestamp: Math.floor(Date.now() / 1000) - 120 }),
    await post({ ...create('7'), service: 'nope-svc' }),
    await post(create('7'), { keyId: keys.outbound[0][0], secret: keys.outbound[0][1] }),
    await post(create('7'), { fault: 'sign_actual_path' }),
  ];
  const labels = ['bad signature', 'replayed nonce', 'wrong workspace', 'expired timestamp', 'unknown service', 'outbound key used inbound', 'signed over the URL path'];
  failures.forEach((r, i) => check(r.status === 401 && r.body.error.code === 'unauthorized', `${labels[i]} → 401 unauthorized`, r.body));
  check(new Set(failures.map((r) => JSON.stringify(r.body))).size === 1, 'all 401 bodies are identical');

  step('validation');
  const big = await post({ ...create('8'), pad: 'x'.repeat(17 * 1024) });
  check(big.status === 413, 'body over 16 KB → 413');
  const extra = await post({ ...create('8'), card: { ...create('8').card as any, caption: 'full caption' } });
  check(extra.status === 422 && extra.body.error.code === 'validation', 'unknown card field → validation');
  const foreign = await post({ ...create('8'), card: { ...create('8').card as any, type: 'email' } });
  check(foreign.status === 422, 'a type outside the manifest → validation');
  const url = await post(create('8', { hook: 'read https://example.invalid/x' }));
  check(url.status === 422, 'a URL in the hook → validation');

  step('inbound key rotation');
  await rest('rpc/swap_service_inbound_keys', { method: 'POST', json: { p_slug: SLUG } });
  const [nextId, nextSecret] = keys.inbound[1];
  const rotated = await postCard({ url: INBOUND, keyId: nextId, secret: nextSecret, workspace, body: create('9') });
  check(rotated.body.data?.result === 'created', 'the next key works after a swap');
  check((await post(create('10'))).body.data?.result === 'created', 'the former current key still works (overlap)');
  await rest('rpc/swap_service_inbound_keys', { method: 'POST', json: { p_slug: SLUG } });

  step('card text stays out of logs and the audit');
  const audit = await rest(`audit_entry?workspace_id=eq.${workspace}&select=event,original_payload,metadata`) as any[];
  check(audit.length > 0 && !JSON.stringify(audit).includes(TOPIC), 'no audit row contains the topic');
  const withHook = audit.filter((e) => JSON.stringify(e).includes(HOOK));
  check(
    withHook.length > 0 && withHook.every((e) => e.event === 'action_received' && Object.keys(e.original_payload ?? {}).join() === 'hook'),
    'the hook appears only as the audit hook of action_received',
  );
  check(audit.filter((e) => e.event === 'action_updated').every((e) => Object.keys(e.metadata).join() === 'revision'),
    'action_updated holds the revision only');
  const logs = await new Deno.Command('docker', { args: ['logs', EDGE_CONTAINER], stdout: 'piped', stderr: 'piped' }).output();
  const logText = new TextDecoder().decode(logs.stdout) + new TextDecoder().decode(logs.stderr);
  check(logText.includes('service_card'), 'function logs are being captured');
  check(!logText.includes(TOPIC) && !logText.includes(HOOK), 'no function log line contains card text (incl. push)');
  for (const [, secret] of [...keys.inbound, ...keys.outbound]) check(!logText.includes(secret), 'no log contains a key');
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
