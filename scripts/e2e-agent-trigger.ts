// deno-lint-ignore-file no-explicit-any -- responses are untyped JSON inspected ad hoc by assertions.
// End-to-end test of Agent Triggers (app → agent) against the local stack.
// Run through scripts/e2e-agent-trigger.sh, which serves the functions twice
// (flag on, then off) and sets TRIGGER_FLAG accordingly.
//
// Env: API_URL, ANON_KEY, SERVICE_ROLE_KEY, TRIGGER_FLAG=on|off
// Optional: TRIGGER_PORT (default 8790), CALLBACK_HOST (default
//   host.docker.internal — how the edge-runtime container reaches this host).
import { verifySignature } from '../supabase/functions/_shared/hmac.ts';

const API_URL = required('API_URL').replace(/\/+$/, '');
const ANON_KEY = required('ANON_KEY');
const SERVICE_ROLE_KEY = required('SERVICE_ROLE_KEY');
const FLAG = required('TRIGGER_FLAG');
const TRIGGER_PORT = Number(Deno.env.get('TRIGGER_PORT') ?? '8790');
const CALLBACK_HOST = Deno.env.get('CALLBACK_HOST') ?? 'host.docker.internal';
const FUNCTIONS = `${API_URL}/functions/v1`;
const EDGE_CONTAINER = 'supabase_edge_runtime_cockpit';
const SIGNATURE_HEADER = 'x-cockpit-trigger-signature';

function required(name: string): string {
  const value = Deno.env.get(name);
  if (!value) throw new Error(`Missing env ${name} — run via scripts/e2e-agent-trigger.sh`);
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

async function call(
  url: string,
  init: RequestInit & { json?: unknown } = {},
): Promise<{ status: number; body: any; headers: Headers }> {
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
  return { status: response.status, body: parsed, headers: response.headers };
}

const serviceHeaders = { apikey: SERVICE_ROLE_KEY, Authorization: `Bearer ${SERVICE_ROLE_KEY}` };

async function rest(path: string): Promise<any[]> {
  const { status, body } = await call(`${API_URL}/rest/v1/${path}`, { headers: serviceHeaders });
  if (status !== 200) throw new Error(`REST ${path} → ${status} ${JSON.stringify(body)}`);
  return body as any[];
}

/** A fresh signed-in owner with one agent. */
async function ownerWithAgent(tag: string) {
  const email = `e2e-trigger-${tag}-${Date.now()}@cockpit.local`;
  const password = `e2e-${crypto.randomUUID()}`;
  const created = await call(`${API_URL}/auth/v1/admin/users`, {
    method: 'POST',
    headers: serviceHeaders,
    json: { email, password, email_confirm: true },
  });
  check(created.status === 200, `admin API creates a user (${tag})`, created.body);
  const session = await call(`${API_URL}/auth/v1/token?grant_type=password`, {
    method: 'POST',
    headers: { apikey: ANON_KEY },
    json: { email, password },
  });
  const jwt: string = session.body.access_token;
  const headers = { apikey: ANON_KEY, Authorization: `Bearer ${jwt}` };
  const agent = await call(`${FUNCTIONS}/agents-create`, {
    method: 'POST',
    headers,
    json: { name: `Trigger E2E ${tag}`, platform: 'n8n', callback_url: 'https://example.com/cb' },
  });
  check(agent.status === 201, `creates an agent (${tag})`, agent.body);
  return { headers, jwt, agentId: agent.body.data.agent.id as string };
}

const trigger = (headers: Record<string, string>, agentId: string) =>
  call(`${FUNCTIONS}/agents-trigger`, { method: 'POST', headers, json: { agent_id: agentId } });

const configure = (headers: Record<string, string>, json: unknown) =>
  call(`${FUNCTIONS}/agents-configure-trigger`, { method: 'POST', headers, json });

async function flagOn(): Promise<void> {
  const secretsSeen: string[] = [];
  const { headers, jwt, agentId } = await ownerWithAgent('on');

  step('agents-configure-trigger');
  const noAuth = await configure(
    { apikey: ANON_KEY, Authorization: `Bearer ${ANON_KEY}` },
    { action: 'configure', agent_id: agentId, trigger_url: 'https://x.example/t' },
  );
  check(noAuth.status === 401, 'requires a user session', noAuth.body);

  const notYet = await trigger(headers, agentId);
  check(notYet.status === 404 && notYet.body.error.code === 'not_found', 'unconfigured agent → 404', notYet.body);

  const triggerUrl = `http://${CALLBACK_HOST}:${TRIGGER_PORT}/trigger`;
  const configured = await configure(headers, {
    action: 'configure',
    agent_id: agentId,
    trigger_url: triggerUrl,
    min_interval_secs: 30,
  });
  check(configured.status === 200 && configured.body.ok, 'configures the trigger', configured.body);
  const secret: string = configured.body.data.trigger_secret;
  secretsSeen.push(secret);
  check(/^whtrig_[A-Za-z0-9_-]{43}$/.test(secret), 'returns a whtrig_ secret once');
  check(
    configured.body.data.trigger.secret_hint === secret.slice(-4) &&
      !('trigger_secret_id' in configured.body.data.trigger),
    'the stored config exposes only the hint',
    configured.body.data.trigger,
  );
  const row = (await rest(`agent_trigger?agent_id=eq.${agentId}&select=*`))[0];
  check(row && !JSON.stringify(row).includes(secret), 'plaintext secret is not in the agent_trigger row');

  step('agents-trigger → signed POST to the agent');
  const received: Array<{ body: string; signature: string | null }> = [];
  const receiver = Deno.serve(
    { hostname: '0.0.0.0', port: TRIGGER_PORT, onListen: () => {} },
    async (req) => {
      received.push({ body: await req.text(), signature: req.headers.get(SIGNATURE_HEADER) });
      return new Response('ok');
    },
  );
  try {
    const fired = await trigger(headers, agentId);
    check(fired.status === 200 && fired.body.data.delivered === true, 'trigger delivered (200)', fired.body);
    const runId: string = fired.body.data.run_id;
    check(received.length === 1, 'the agent received exactly one POST', received.length);
    check(
      await verifySignature(received[0].body, received[0].signature, secret),
      'X-Cockpit-Trigger-Signature verifies with the trigger secret',
    );
    const payload = JSON.parse(received[0].body);
    check(
      payload.trigger_id === runId && payload.agent_id === agentId &&
        typeof payload.nonce === 'string' && !Number.isNaN(Date.parse(payload.triggered_at)),
      'payload: trigger_id, agent_id, triggered_at, nonce',
      payload,
    );
    const run = (await rest(`trigger_run?id=eq.${runId}&select=status,triggered_by`))[0];
    check(run.status === 'sent', "trigger_run = 'sent'", run);
    const fired1 = await rest(
      `audit_entry?event=eq.trigger_fired&metadata->>trigger_run_id=eq.${runId}&select=id,action_id`,
    );
    check(fired1.length === 1 && fired1[0].action_id === null, "audit 'trigger_fired' recorded");

    step('min_interval_secs');
    const again = await trigger(headers, agentId);
    check(
      again.status === 429 && again.body.error.code === 'rate_limited' &&
        Number(again.headers.get('retry-after')) >= 1,
      'a second call within the interval → 429 rate_limited + Retry-After',
      again.body,
    );
    const runs = await rest(`trigger_run?agent_id=eq.${agentId}&select=status`);
    check(
      runs.length === 1 && runs[0].status === 'sent' && received.length === 1,
      'exactly one run sent, nothing else delivered',
      runs,
    );

    step('enable / disable');
    const off = await configure(headers, { action: 'set_enabled', agent_id: agentId, enabled: false });
    check(off.status === 200 && off.body.data.trigger.enabled === false, 'disables the trigger', off.body);
    const disabled = await trigger(headers, agentId);
    check(
      disabled.status === 409 && disabled.body.error.code === 'trigger_disabled',
      'a disabled trigger → 409 trigger_disabled',
      disabled.body,
    );
    const on = await configure(headers, { action: 'set_enabled', agent_id: agentId, enabled: true });
    check(on.status === 200 && on.body.data.trigger.enabled === true, 're-enables the trigger', on.body);
  } finally {
    await receiver.shutdown();
  }

  step('isolation');
  const other = await ownerWithAgent('other');
  const foreign = await trigger(other.headers, agentId);
  check(foreign.status === 404, "another workspace can't fire the trigger", foreign.body);
  const foreignConfig = await configure(other.headers, {
    action: 'configure',
    agent_id: agentId,
    trigger_url: 'https://x.example/t',
  });
  check(foreignConfig.status === 404, "another workspace can't configure it", foreignConfig.body);

  step('No secrets in logs');
  const logs = new Deno.Command('docker', { args: ['logs', EDGE_CONTAINER], stdout: 'piped', stderr: 'piped' });
  const { stdout, stderr, success } = await logs.output();
  check(success, `read ${EDGE_CONTAINER} logs`);
  const logText = new TextDecoder().decode(stdout) + new TextDecoder().decode(stderr);
  check(logText.includes('trigger_run'), 'function logs are being captured');
  for (const value of secretsSeen) check(!logText.includes(value), 'logs do not contain the trigger secret');
  check(!logText.includes(jwt), 'logs do not contain the user JWT');
  check(!logText.includes(triggerUrl), 'logs do not contain the trigger URL');
}

async function flagOff(): Promise<void> {
  const { headers, agentId } = await ownerWithAgent('off');
  const before = {
    triggers: (await rest('agent_trigger?select=agent_id')).length,
    runs: (await rest('trigger_run?select=id')).length,
    audits: (await rest('audit_entry?event=in.(trigger_configured,trigger_fired,trigger_failed)&select=id')).length,
  };

  step('flag off');
  const fired = await trigger(headers, agentId);
  check(
    fired.status === 404 && fired.body.error.code === 'feature_disabled',
    'agents-trigger → 404 feature_disabled',
    fired.body,
  );
  const configured = await configure(headers, {
    action: 'configure',
    agent_id: agentId,
    trigger_url: 'https://x.example/t',
  });
  check(
    configured.status === 404 && configured.body.error.code === 'feature_disabled',
    'agents-configure-trigger → 404 feature_disabled',
    configured.body,
  );
  const anon = await trigger({ apikey: ANON_KEY }, agentId);
  check(anon.status === 404 && anon.body.error.code === 'feature_disabled', 'even unauthenticated calls get feature_disabled');

  const after = {
    triggers: (await rest('agent_trigger?select=agent_id')).length,
    runs: (await rest('trigger_run?select=id')).length,
    audits: (await rest('audit_entry?event=in.(trigger_configured,trigger_fired,trigger_failed)&select=id')).length,
  };
  check(JSON.stringify(after) === JSON.stringify(before), 'nothing was written', { before, after });
}

try {
  const ping = await call(`${FUNCTIONS}/actions-inbound`, { method: 'GET' });
  check(ping.status === 405, 'functions are being served');
  if (FLAG === 'on') await flagOn();
  else await flagOff();
  console.log(`\nPASS (flag ${FLAG}) — ${passed} checks`);
} catch (error) {
  console.error(`\nFAIL (flag ${FLAG}) after ${passed} passing checks: ${error instanceof Error ? error.message : error}`);
  Deno.exitCode = 1;
}
