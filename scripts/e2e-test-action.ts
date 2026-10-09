// deno-lint-ignore-file no-explicit-any -- responses are untyped JSON inspected ad hoc by assertions.
// End-to-end test of agents-test-action's access rules against the local
// stack. The happy path is also covered by e2e-core-loop.ts; this file adds
// the cross-workspace, approver and disabled-agent cases. Run through
// scripts/e2e-test-action.sh.
//
// Current contract (documented here on purpose): the function is OWNER-ONLY.
// It looks the agent up with get_owned_agent, so an approver in the agent's
// own workspace gets the same 404 not_found as a stranger.
//
// Env: API_URL, ANON_KEY, SERVICE_ROLE_KEY

const API_URL = required('API_URL').replace(/\/+$/, '');
const ANON_KEY = required('ANON_KEY');
const SERVICE_ROLE_KEY = required('SERVICE_ROLE_KEY');
const FUNCTIONS = `${API_URL}/functions/v1`;

function required(name: string): string {
  const value = Deno.env.get(name);
  if (!value) throw new Error(`Missing env ${name} — run via scripts/e2e-test-action.sh`);
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

async function rest(path: string, init: RequestInit & { json?: unknown } = {}): Promise<any[]> {
  const { status, body } = await call(`${API_URL}/rest/v1/${path}`, {
    ...init,
    headers: { ...serviceHeaders, Prefer: 'return=representation', ...(init.headers ?? {}) },
  });
  if (status < 200 || status >= 300) {
    throw new Error(`REST ${path} → ${status} ${JSON.stringify(body)}`);
  }
  return body as any[];
}

/** A fresh signed-in user (bootstrapped as owner of their own workspace). */
async function signedInUser(tag: string) {
  const email = `e2e-test-action-${tag}-${Date.now()}@cockpit.local`;
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
  check(session.status === 200, `user signs in (${tag})`, session.body);
  return {
    userId: created.body.id as string,
    headers: { apikey: ANON_KEY, Authorization: `Bearer ${session.body.access_token}` },
  };
}

async function createAgent(headers: Record<string, string>, tag: string): Promise<string> {
  const agent = await call(`${FUNCTIONS}/agents-create`, {
    method: 'POST',
    headers,
    json: {
      name: `Test action E2E ${tag}`,
      platform: 'n8n',
      callback_url: 'https://example.com/cb',
    },
  });
  check(agent.status === 201, `creates an agent (${tag})`, agent.body);
  return agent.body.data.agent.id as string;
}

const testAction = (headers: Record<string, string>, agentId: string) =>
  call(`${FUNCTIONS}/agents-test-action`, { method: 'POST', headers, json: { agent_id: agentId } });

const isNotFound = (r: { status: number; body: any }) =>
  r.status === 404 && r.body?.error?.code === 'not_found';

async function main(): Promise<void> {
  step('setup: two workspaces');
  const owner = await signedInUser('owner');
  const ownAgent = await createAgent(owner.headers, 'own');
  const stranger = await signedInUser('stranger');
  const foreignAgent = await createAgent(stranger.headers, 'foreign');

  step('authentication');
  const noJwt = await testAction(
    { apikey: ANON_KEY, Authorization: `Bearer ${ANON_KEY}` },
    ownAgent,
  );
  check(noJwt.status === 401, 'no user session → 401', noJwt.body);

  step('ownership (no info leak)');
  const foreign = await testAction(owner.headers, foreignAgent);
  check(isNotFound(foreign), "another workspace's agent → 404 not_found", foreign.body);
  const unknown = await testAction(owner.headers, crypto.randomUUID());
  check(isNotFound(unknown), 'unknown agent → 404 not_found', unknown.body);
  check(
    JSON.stringify(foreign.body.error) === JSON.stringify(unknown.body.error),
    'foreign and unknown agents are indistinguishable',
    { foreign: foreign.body, unknown: unknown.body },
  );
  const foreignActions = await rest(`action?agent_id=eq.${foreignAgent}&select=id`);
  check(foreignActions.length === 0, 'no action was created on the foreign agent', foreignActions);

  step('approver in the same workspace (owner-only today)');
  const approver = await signedInUser('approver');
  const [ownerRow] = await rest(`app_user?id=eq.${owner.userId}&select=workspace_id`);
  const moved = await rest(`app_user?id=eq.${approver.userId}`, {
    method: 'PATCH',
    json: { workspace_id: ownerRow.workspace_id, role: 'approver' },
  });
  check(
    moved.length === 1 && moved[0].role === 'approver' &&
      moved[0].workspace_id === ownerRow.workspace_id,
    "approver joins the owner's workspace",
    moved,
  );
  const byApprover = await testAction(approver.headers, ownAgent);
  check(
    isNotFound(byApprover),
    'approver → 404 not_found (function is owner-only)',
    byApprover.body,
  );

  step('owner happy path');
  const sent = await testAction(owner.headers, ownAgent);
  check(
    sent.status === 201 && typeof sent.body?.data?.action_id === 'string',
    'owner → 201 with action_id',
    sent.body,
  );
  const [row] = await rest(
    `action?id=eq.${sent.body.data.action_id}&select=status,agent_id,external_id`,
  );
  check(
    row?.status === 'pending' && row.agent_id === ownAgent &&
      String(row.external_id).startsWith('test-'),
    'action is pending on the own agent with a test- external_id',
    row,
  );

  step('disabled agent');
  await rest(`agent?id=eq.${ownAgent}`, { method: 'PATCH', json: { status: 'disabled' } });
  const disabled = await testAction(owner.headers, ownAgent);
  check(
    disabled.status === 403 && disabled.body?.error?.code === 'agent_disabled',
    'disabled agent → 403 agent_disabled',
    disabled.body,
  );

  console.log(`\nPASS — agents-test-action e2e (${passed} checks)`);
}

await main();
