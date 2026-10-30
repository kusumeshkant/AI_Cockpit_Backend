// deno-lint-ignore-file no-explicit-any -- responses are untyped JSON inspected ad hoc by assertions.
// End-to-end test of the Play review sign-in (migration 0008 + reviewer-signin)
// against the local stack, with the function served with LOCAL ONLY reviewer
// values (REVIEWER_LOGIN_ENABLED=true, REVIEWER_EMAIL, REVIEWER_CODE):
//   * another email, a wrong code and a malformed body all get the identical
//     400 (status, headers, body)
//   * the right email + code return a token hash that GoTrue exchanges for a
//     normal session of the reviewer user, exactly once
//   * 5 wrong codes lock sign-in: the right code is then refused the same way
//     until the lock is cleared
// Run through scripts/e2e-reviewer-signin.sh. Prints no token, code or secret.
//
// Env: API_URL, ANON_KEY, SERVICE_ROLE_KEY, REVIEWER_EMAIL, REVIEWER_CODE

const API_URL = required('API_URL').replace(/\/+$/, '');
const ANON_KEY = required('ANON_KEY');
const SERVICE_ROLE_KEY = required('SERVICE_ROLE_KEY');
const REVIEWER_EMAIL = required('REVIEWER_EMAIL').trim().toLowerCase();
const REVIEWER_CODE = required('REVIEWER_CODE').trim();
const FUNCTIONS = `${API_URL}/functions/v1`;
const serviceHeaders = { apikey: SERVICE_ROLE_KEY, Authorization: `Bearer ${SERVICE_ROLE_KEY}` };

function required(name: string): string {
  const value = Deno.env.get(name);
  if (!value) throw new Error(`Missing env ${name} — run via scripts/e2e-reviewer-signin.sh`);
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

interface Reply {
  status: number;
  headers: string;
  text: string;
  body: any;
}

async function call(url: string, init: RequestInit & { json?: unknown } = {}): Promise<Reply> {
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
  // Headers the function sets; gateway headers (date, request ids) differ per call.
  const own = ['content-type', 'retry-after', 'www-authenticate']
    .map((name) => `${name}=${response.headers.get(name) ?? ''}`)
    .join(';');
  return { status: response.status, headers: own, text, body: parsed };
}

const signin = (json: unknown) =>
  call(`${FUNCTIONS}/reviewer-signin`, { method: 'POST', headers: { apikey: ANON_KEY }, json });

const verifyTokenHash = (tokenHash: string) =>
  call(`${API_URL}/auth/v1/verify`, {
    method: 'POST',
    headers: { apikey: ANON_KEY },
    json: { type: 'email', token_hash: tokenHash },
  });

async function resetGuard(): Promise<void> {
  const reply = await call(`${API_URL}/rest/v1/reviewer_signin_guard?id=eq.1`, {
    method: 'PATCH',
    headers: serviceHeaders,
    json: { failures: 0, window_start: null, locked_until: null },
  });
  if (reply.status < 200 || reply.status >= 300) throw new Error(`reset guard → ${reply.status}`);
}

async function main(): Promise<void> {
  await resetGuard();

  step('Reviewer user');
  const created = await call(`${API_URL}/auth/v1/admin/users`, {
    method: 'POST',
    headers: serviceHeaders,
    json: { email: REVIEWER_EMAIL, email_confirm: true },
  });
  const userId: string | undefined = created.status === 200 ? created.body.id : undefined;
  check(created.status === 200 || created.status === 422, 'reviewer user exists', created.status);

  try {
    step('Refusals are indistinguishable');
    const otherEmail = await signin({
      email: `someone-${Date.now()}@cockpit.local`,
      code: REVIEWER_CODE,
    });
    const wrongCode = await signin({
      email: REVIEWER_EMAIL,
      code: REVIEWER_CODE === '000000' ? '111111' : '000000',
    });
    const malformed = await signin({ email: REVIEWER_EMAIL });
    check(otherEmail.status === 400, 'another email → 400', otherEmail.status);
    check(otherEmail.body?.error?.code === 'invalid_code', 'body says invalid_code');
    for (
      const [label, reply] of [['wrong code', wrongCode], ['malformed body', malformed]] as const
    ) {
      check(
        reply.status === otherEmail.status && reply.headers === otherEmail.headers &&
          reply.text === otherEmail.text,
        `${label} → identical to another email`,
        { status: reply.status, headers: reply.headers },
      );
    }
    await resetGuard();

    step('The right email and code sign in');
    const ok = await signin({ email: ` ${REVIEWER_EMAIL.toUpperCase()} `, code: REVIEWER_CODE });
    check(ok.status === 200, 'right email + code → 200', ok.status);
    const tokenHash: string = ok.body?.data?.token_hash ?? '';
    check(tokenHash.length > 10, 'a token hash is returned');

    const session = await verifyTokenHash(tokenHash);
    check(
      session.status === 200 && session.body?.access_token,
      'GoTrue exchanges it for a session',
      session.status,
    );
    check(
      String(session.body?.user?.email ?? '').toLowerCase() === REVIEWER_EMAIL,
      'the session belongs to the reviewer',
    );
    const me = await call(`${API_URL}/rest/v1/app_user?select=role`, {
      headers: { apikey: ANON_KEY, Authorization: `Bearer ${session.body.access_token}` },
    });
    check(
      me.status === 200 && Array.isArray(me.body) && me.body.length === 1,
      'the reviewer can read their own profile',
    );

    const reused = await verifyTokenHash(tokenHash);
    check(reused.status !== 200, 'the token hash works only once', reused.status);

    step('Five wrong codes lock sign-in');
    for (let i = 0; i < 5; i++) {
      await signin({
        email: REVIEWER_EMAIL,
        code: REVIEWER_CODE === '000000' ? '111111' : '000000',
      });
    }
    const whileLocked = await signin({ email: REVIEWER_EMAIL, code: REVIEWER_CODE });
    check(
      whileLocked.status === otherEmail.status && whileLocked.headers === otherEmail.headers &&
        whileLocked.text === otherEmail.text,
      'while locked the right code is refused identically',
      whileLocked.status,
    );

    await resetGuard();
    const afterReset = await signin({ email: REVIEWER_EMAIL, code: REVIEWER_CODE });
    check(
      afterReset.status === 200,
      'after the lock is cleared the right code works again',
      afterReset.status,
    );
  } finally {
    await resetGuard();
    if (userId) {
      await call(`${API_URL}/auth/v1/admin/users/${userId}`, {
        method: 'DELETE',
        headers: serviceHeaders,
      });
    }
  }

  console.log(`\n${passed} checks passed`);
}

await main();
