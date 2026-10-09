// deno-lint-ignore-file no-explicit-any -- responses are untyped JSON inspected ad hoc by assertions.
// End-to-end test of migration 0006 against the local stack:
//   F05 — a device token belongs to one user: when user B registers a token
//         user A had, it leaves A's row, so A's pushes no longer reach it.
//   F08 — agent creation is owner-only: an approver gets 403 `forbidden`
//         from agents-create, and can still decide actions.
// Run through scripts/e2e-push-roles.sh.
//
// Env: API_URL, ANON_KEY, SERVICE_ROLE_KEY

const API_URL = required('API_URL').replace(/\/+$/, '');
const ANON_KEY = required('ANON_KEY');
const SERVICE_ROLE_KEY = required('SERVICE_ROLE_KEY');
const FUNCTIONS = `${API_URL}/functions/v1`;

function required(name: string): string {
  const value = Deno.env.get(name);
  if (!value) throw new Error(`Missing env ${name} — run via scripts/e2e-push-roles.sh`);
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
  const email = `e2e-push-roles-${tag}-${Date.now()}@cockpit.local`;
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
      name: `Push/roles E2E ${tag}`,
      platform: 'n8n',
      callback_url: 'https://example.com/cb',
    },
  });
  check(agent.status === 201, `creates an agent (${tag})`, agent.body);
  return agent.body.data.agent.id as string;
}

const registerToken = (headers: Record<string, string>, token: string) =>
  call(`${API_URL}/rest/v1/rpc/register_fcm_token`, {
    method: 'POST',
    headers,
    json: { p_token: token },
  });

async function tokensOf(userId: string): Promise<string[]> {
  const [row] = await rest(`app_user?id=eq.${userId}&select=fcm_tokens`);
  return row.fcm_tokens as string[];
}

async function main(): Promise<void> {
  step('setup');
  const owner = await signedInUser('owner');
  const agentId = await createAgent(owner.headers, 'owner');
  const approver = await signedInUser('approver');
  const [ownerRow] = await rest(`app_user?id=eq.${owner.userId}&select=workspace_id`);
  const moved = await rest(`app_user?id=eq.${approver.userId}`, {
    method: 'PATCH',
    json: { workspace_id: ownerRow.workspace_id, role: 'approver' },
  });
  check(moved[0]?.role === 'approver', "approver joins the owner's workspace", moved);
  const stranger = await signedInUser('stranger');

  step('F08: agent creation is owner-only');
  const byApprover = await call(`${FUNCTIONS}/agents-create`, {
    method: 'POST',
    headers: approver.headers,
    json: { name: 'Approver agent', platform: 'n8n', callback_url: 'https://example.com/cb' },
  });
  check(
    byApprover.status === 403 && byApprover.body?.error?.code === 'forbidden',
    'approver → 403 forbidden (not 404)',
    byApprover.body,
  );
  const agents = await rest(`agent?workspace_id=eq.${ownerRow.workspace_id}&select=id`);
  check(agents.length === 1, 'no agent was created by the approver', agents);

  const sent = await call(`${FUNCTIONS}/agents-test-action`, {
    method: 'POST',
    headers: owner.headers,
    json: { agent_id: agentId },
  });
  check(sent.status === 201, 'owner sends a test action', sent.body);
  const decided = await call(`${FUNCTIONS}/actions-decision`, {
    method: 'POST',
    headers: { ...approver.headers, 'Idempotency-Key': crypto.randomUUID() },
    json: { action_id: sent.body.data.action_id, decision: 'approved' },
  });
  check(
    decided.status === 200 && decided.body?.ok,
    'approver can still decide actions',
    decided.body,
  );

  step('F05: one device token = one user');
  const phone = `e2e-phone-${crypto.randomUUID()}`;
  const tablet = `e2e-tablet-${crypto.randomUUID()}`;
  check(
    (await registerToken(owner.headers, phone)).status === 204,
    'owner registers the phone token',
  );
  check(
    (await registerToken(owner.headers, tablet)).status === 204,
    'owner registers a tablet token',
  );
  check(
    JSON.stringify(await tokensOf(owner.userId)) === JSON.stringify([phone, tablet]),
    'owner holds both tokens',
  );

  // Same phone, another account (no clean sign-out on the phone).
  check(
    (await registerToken(stranger.headers, phone)).status === 204,
    'another user registers the same phone',
  );
  const ownerTokens = await tokensOf(owner.userId);
  check(!ownerTokens.includes(phone), "the phone token left the owner's row", ownerTokens);
  check(ownerTokens.includes(tablet), "the owner's tablet token is untouched", ownerTokens);
  check(
    JSON.stringify(await tokensOf(stranger.userId)) === JSON.stringify([phone]),
    'the phone token now belongs to the new user',
  );
  const holders = await rest(`app_user?fcm_tokens=cs.{${phone}}&select=id`);
  check(
    holders.length === 1 && holders[0].id === stranger.userId,
    'exactly one user holds the phone token',
    holders,
  );

  // The owner's next push targets only the tablet.
  const after = await call(`${FUNCTIONS}/agents-test-action`, {
    method: 'POST',
    headers: owner.headers,
    json: { agent_id: agentId },
  });
  check(after.status === 201, "a new action in the owner's workspace is created", after.body);
  const [workspaceTokens] = await rest(
    `app_user?workspace_id=eq.${ownerRow.workspace_id}&select=fcm_tokens&role=eq.owner`,
  );
  check(
    !workspaceTokens.fcm_tokens.includes(phone),
    "the owner's push targets exclude the handed-over phone",
  );

  console.log(`
PASS — push token + roles e2e (${passed} checks)`);
}

await main();
