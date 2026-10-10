// deno-lint-ignore-file no-explicit-any -- responses are untyped JSON inspected ad hoc by assertions.
// End-to-end test of account deletion (F02: migration 0007 + account-delete)
// against the local stack:
//   * bad method / missing JWT / missing confirm are rejected with clear errors
//   * approver: account and auth user gone, decisions kept but anonymized,
//     the old JWT no longer works
//   * owner: workspace, agents, actions and audit gone; the remaining member
//     is moved to a new personal workspace as its owner and keeps working
//   * retry after a failed auth delete: data already gone -> `already_deleted`
//     and the auth user is removed
//   * the deletion log has one PII-free row per deletion
// Run through scripts/e2e-account-delete.sh. Prints no token, email or secret.
//
// Env: API_URL, ANON_KEY, SERVICE_ROLE_KEY

const API_URL = required('API_URL').replace(/\/+$/, '');
const ANON_KEY = required('ANON_KEY');
const SERVICE_ROLE_KEY = required('SERVICE_ROLE_KEY');
const FUNCTIONS = `${API_URL}/functions/v1`;

function required(name: string): string {
  const value = Deno.env.get(name);
  if (!value) throw new Error(`Missing env ${name} — run via scripts/e2e-account-delete.sh`);
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
    throw new Error(`REST ${path.split('?')[0]} → ${status}`);
  }
  return body as any[];
}

/** A fresh signed-in user (bootstrapped as owner of their own workspace). */
async function signedInUser(tag: string) {
  const email = `e2e-account-delete-${tag}-${Date.now()}@cockpit.local`;
  const password = `e2e-${crypto.randomUUID()}`;
  const created = await call(`${API_URL}/auth/v1/admin/users`, {
    method: 'POST',
    headers: serviceHeaders,
    json: { email, password, email_confirm: true },
  });
  check(created.status === 200, `admin API creates a user (${tag})`);
  const session = await call(`${API_URL}/auth/v1/token?grant_type=password`, {
    method: 'POST',
    headers: { apikey: ANON_KEY },
    json: { email, password },
  });
  check(session.status === 200, `user signs in (${tag})`);
  return {
    userId: created.body.id as string,
    headers: { apikey: ANON_KEY, Authorization: `Bearer ${session.body.access_token}` },
  };
}

const deleteAccount = (
  headers: Record<string, string> | undefined,
  json?: unknown,
  method = 'POST',
) =>
  call(`${FUNCTIONS}/account-delete`, {
    method,
    headers: headers ?? {},
    ...(json === undefined ? {} : { json }),
  });

async function authUserExists(userId: string): Promise<boolean> {
  const { status } = await call(`${API_URL}/auth/v1/admin/users/${userId}`, {
    headers: serviceHeaders,
  });
  return status === 200;
}

async function sha256Hex(text: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text));
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

async function main(): Promise<void> {
  step('setup: owner + two approvers, an agent, a decided action');
  const owner = await signedInUser('owner');
  const leaver = await signedInUser('approver-leaves');
  const stayer = await signedInUser('approver-stays');
  const [ownerRow] = await rest(`app_user?id=eq.${owner.userId}&select=workspace_id`);
  const workspaceId = ownerRow.workspace_id as string;
  for (const member of [leaver, stayer]) {
    const moved = await rest(`app_user?id=eq.${member.userId}`, {
      method: 'PATCH',
      json: { workspace_id: workspaceId, role: 'approver' },
    });
    check(moved[0]?.role === 'approver', "an approver joins the owner's workspace");
  }
  const agent = await call(`${FUNCTIONS}/agents-create`, {
    method: 'POST',
    headers: owner.headers,
    json: { name: 'Deletion E2E', platform: 'n8n', callback_url: 'https://example.com/cb' },
  });
  check(agent.status === 201, 'owner creates an agent', agent.body?.error);
  const agentId = agent.body.data.agent.id as string;
  const sent = await call(`${FUNCTIONS}/agents-test-action`, {
    method: 'POST',
    headers: owner.headers,
    json: { agent_id: agentId },
  });
  check(sent.status === 201, 'owner sends a test action', sent.body?.error);
  const actionId = sent.body.data.action_id as string;
  const decided = await call(`${FUNCTIONS}/actions-decision`, {
    method: 'POST',
    headers: { ...leaver.headers, 'Idempotency-Key': crypto.randomUUID() },
    json: { action_id: actionId, decision: 'approved' },
  });
  check(decided.status === 200, 'the leaving approver decides it', decided.body?.error);
  const token = `e2e-del-${crypto.randomUUID()}`;
  const registered = await call(`${API_URL}/rest/v1/rpc/register_fcm_token`, {
    method: 'POST',
    headers: leaver.headers,
    json: { p_token: token },
  });
  check(registered.status === 204, 'the leaving approver registers a device token');

  step('rejections');
  const viaGet = await deleteAccount(leaver.headers, undefined, 'GET');
  check(
    viaGet.status === 405 && viaGet.body?.error?.code === 'method_not_allowed',
    'GET → 405 method_not_allowed',
  );
  const noJwt = await deleteAccount(undefined, { confirm: true });
  check(
    noJwt.status === 401 && noJwt.body?.error?.code === 'unauthorized',
    'no JWT → 401 unauthorized',
  );
  const empty = await deleteAccount(leaver.headers, {});
  check(
    empty.status === 422 && empty.body?.error?.code === 'validation',
    'missing confirm → 422 validation',
  );
  const falsy = await deleteAccount(leaver.headers, { confirm: false });
  check(falsy.status === 422, 'confirm: false → 422');
  const extra = await deleteAccount(leaver.headers, { confirm: true, user_id: owner.userId });
  check(extra.status === 422, 'unknown fields (e.g. another user id) → 422');
  check(await authUserExists(leaver.userId), 'nothing was deleted by the rejected calls');

  step('approver deletes their account');
  const first = await deleteAccount(leaver.headers, { confirm: true });
  check(
    first.status === 200 && first.body?.data?.outcome === 'deleted' &&
      first.body.data.workspace_deleted === false,
    'approver → 200 deleted, workspace kept',
    first.body?.error,
  );
  check(
    (await rest(`app_user?id=eq.${leaver.userId}&select=id`)).length === 0,
    'their app_user row is gone',
  );
  check(!(await authUserExists(leaver.userId)), 'their auth user is gone');
  check(
    (await rest(`app_user?fcm_tokens=cs.{${token}}&select=id`)).length === 0,
    'their device token is gone',
  );
  const audit = await rest(
    `audit_entry?action_id=eq.${actionId}&event=eq.decision_made&select=actor_user_id`,
  );
  check(
    audit.length === 1 && audit[0].actor_user_id === null,
    'their decision stays in the audit, anonymized',
  );
  const again = await deleteAccount(leaver.headers, { confirm: true });
  check(again.status === 401, 'the old JWT no longer works (401)');

  step('owner deletes their account');
  const second = await deleteAccount(owner.headers, { confirm: true });
  check(
    second.status === 200 && second.body?.data?.outcome === 'deleted' &&
      second.body.data.workspace_deleted === true && second.body.data.members_moved === 1,
    'owner → 200 deleted, workspace erased, 1 member moved',
    second.body?.error,
  );
  check(!(await authUserExists(owner.userId)), "the owner's auth user is gone");
  check(
    (await rest(`workspace?id=eq.${workspaceId}&select=id`)).length === 0,
    'the workspace is gone',
  );
  check((await rest(`agent?id=eq.${agentId}&select=id`)).length === 0, 'its agent is gone');
  check((await rest(`action?id=eq.${actionId}&select=id`)).length === 0, 'its actions are gone');
  check(
    (await rest(`audit_entry?workspace_id=eq.${workspaceId}&select=id`)).length === 0,
    'its audit entries are gone',
  );
  const [stayerRow] = await rest(`app_user?id=eq.${stayer.userId}&select=role,workspace_id`);
  check(
    stayerRow?.role === 'owner' && stayerRow.workspace_id !== workspaceId,
    'the other approver keeps their account, as owner of a new workspace',
  );
  const own = await call(`${FUNCTIONS}/agents-create`, {
    method: 'POST',
    headers: stayer.headers,
    json: { name: 'Moved member agent', platform: 'n8n', callback_url: 'https://example.com/cb' },
  });
  check(
    own.status === 201,
    'the moved member keeps working (creates an agent as owner)',
    own.body?.error,
  );

  step('retry after a failed auth delete');
  const retry = await signedInUser('retry');
  // Simulate the first attempt: the data RPC committed, the auth delete did not.
  const rpc = await call(`${API_URL}/rest/v1/rpc/delete_account_data`, {
    method: 'POST',
    headers: serviceHeaders,
    json: { p_user_id: retry.userId },
  });
  check(rpc.status === 200, 'data RPC runs alone (auth user left behind)');
  check(await authUserExists(retry.userId), 'the auth user still exists');
  const third = await deleteAccount(retry.headers, { confirm: true });
  check(
    third.status === 200 && third.body?.data?.outcome === 'already_deleted',
    'retry → 200 already_deleted (no app_user needed)',
    third.body?.error,
  );
  check(!(await authUserExists(retry.userId)), 'the retry removes the auth user');

  step('deletion log');
  const hashes = await Promise.all([leaver, owner, retry].map((u) => sha256Hex(u.userId)));
  const entries = await rest(
    `account_deletion_log?subject_hash=in.(${hashes.join(',')})&select=*`,
  );
  check(entries.length === 3, 'one log row per deletion', entries.length);
  check(!JSON.stringify(entries).includes('@'), 'the log holds no email address');
  const asUser = await call(`${API_URL}/rest/v1/account_deletion_log?select=id`, {
    headers: stayer.headers,
  });
  check(
    asUser.status !== 200 || (Array.isArray(asUser.body) && asUser.body.length === 0),
    'a signed-in user cannot read the deletion log',
  );

  console.log(`\nPASS — account deletion e2e (${passed} checks)`);
}

await main();
