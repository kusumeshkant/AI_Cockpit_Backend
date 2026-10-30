import {
  classifyAttempt,
  handleReviewerSignin,
  MAX_REVIEWER_SIGNIN_BYTES,
  REJECTION_BODY,
  REJECTION_STATUS,
  type ReviewerConfig,
  reviewerConfig,
  type ReviewerOutcome,
  timingSafeEqual,
} from '../_shared/reviewer.ts';
import { assert, assertEquals, assertFalse } from './test_deps.ts';

const EMAIL = 'reviewer@test.dev';
const CODE = '246810';
const CONFIG: ReviewerConfig = { email: EMAIL, code: CODE };

function env(values: Record<string, string>): (name: string) => string | undefined {
  return (name) => values[name];
}

const ON = { REVIEWER_LOGIN_ENABLED: 'true', REVIEWER_EMAIL: EMAIL, REVIEWER_CODE: CODE };

// ---------------------------------------------------------------------------
// reviewerConfig: off unless exactly "true" and fully configured
// ---------------------------------------------------------------------------

Deno.test('reviewer-signin: config is on only when enabled and fully configured', () => {
  assertEquals(reviewerConfig(env(ON)), CONFIG);
  assertEquals(
    reviewerConfig(
      env({ ...ON, REVIEWER_EMAIL: '  Reviewer@Test.DEV ', REVIEWER_CODE: ' 246810 ' }),
    ),
    CONFIG,
  );
});

Deno.test('reviewer-signin: config is off by default and for any other flag value', () => {
  assertEquals(reviewerConfig(env({})), null);
  for (const flag of ['', 'false', 'TRUE', 'True', '1', 'yes', ' true']) {
    assertEquals(reviewerConfig(env({ ...ON, REVIEWER_LOGIN_ENABLED: flag })), null, flag);
  }
  const { REVIEWER_LOGIN_ENABLED: _, ...noFlag } = ON;
  assertEquals(reviewerConfig(env(noFlag)), null);
});

Deno.test('reviewer-signin: config is off without a usable email or a 6-digit code', () => {
  for (const email of ['', '   ', 'not-an-email']) {
    assertEquals(reviewerConfig(env({ ...ON, REVIEWER_EMAIL: email })), null, email);
  }
  for (const code of ['', '12345', '1234567', 'abcdef', '12 345', '１２３４５６']) {
    assertEquals(reviewerConfig(env({ ...ON, REVIEWER_CODE: code })), null, code);
  }
});

// ---------------------------------------------------------------------------
// timingSafeEqual / classifyAttempt
// ---------------------------------------------------------------------------

Deno.test('reviewer-signin: timingSafeEqual compares whole strings', () => {
  assert(timingSafeEqual('246810', '246810'));
  assert(timingSafeEqual('', ''));
  assertFalse(timingSafeEqual('246810', '246811'));
  assertFalse(timingSafeEqual('246810', '24681'));
  assertFalse(timingSafeEqual('24681', '246810'));
  assertFalse(timingSafeEqual('', '246810'));
  assertFalse(timingSafeEqual('é', 'e'));
});

Deno.test('reviewer-signin: classifyAttempt', () => {
  assertEquals(classifyAttempt(null, EMAIL, CODE), 'none');
  assertEquals(classifyAttempt(CONFIG, 'someone@else.dev', CODE), 'none');
  assertEquals(classifyAttempt(CONFIG, 'someone@else.dev', '000000'), 'none');
  assertEquals(classifyAttempt(CONFIG, EMAIL, CODE), 'success');
  assertEquals(classifyAttempt(CONFIG, ' REVIEWER@test.dev ', ` ${CODE} `), 'success');
  assertEquals(classifyAttempt(CONFIG, EMAIL, '000000'), 'failure');
  assertEquals(classifyAttempt(CONFIG, EMAIL, ''), 'failure');
});

// ---------------------------------------------------------------------------
// handleReviewerSignin with fake I/O
// ---------------------------------------------------------------------------

interface Fake {
  attempts: ReviewerOutcome[];
  issued: string[];
  run: (req: Request) => Promise<Response>;
}

function fake(
  options: {
    config?: ReviewerConfig | null;
    locked?: boolean;
    guardFails?: boolean;
    issueFails?: boolean;
  } = {},
): Fake {
  const attempts: ReviewerOutcome[] = [];
  const issued: string[] = [];
  const config = options.config === undefined ? CONFIG : options.config;
  return {
    attempts,
    issued,
    run: (req) =>
      handleReviewerSignin(req, {
        config: () => config,
        attempt: (outcome) => {
          attempts.push(outcome);
          if (options.guardFails) return Promise.reject(new Error('db down'));
          return Promise.resolve(options.locked ?? false);
        },
        issueTokenHash: (email) => {
          issued.push(email);
          if (options.issueFails) return Promise.reject(new Error('auth down'));
          return Promise.resolve('hash_0123456789');
        },
      }),
  };
}

function post(body: unknown, init: RequestInit = {}): Request {
  return new Request('http://localhost/reviewer-signin', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: typeof body === 'string' ? body : JSON.stringify(body),
    ...init,
  });
}

interface Snapshot {
  status: number;
  headers: [string, string][];
  body: string;
}

async function snapshot(response: Response): Promise<Snapshot> {
  return {
    status: response.status,
    headers: [...response.headers.entries()].sort(([a], [b]) => a.localeCompare(b)),
    body: await response.text(),
  };
}

const REJECTED: Snapshot = {
  status: REJECTION_STATUS,
  headers: [['content-type', 'application/json; charset=utf-8']],
  body: REJECTION_BODY,
};

Deno.test('reviewer-signin: the right email and code return a token hash', async () => {
  const f = fake();
  const response = await f.run(post({ email: ' Reviewer@Test.dev ', code: CODE }));
  assertEquals(response.status, 200);
  assertEquals(await response.json(), { ok: true, data: { token_hash: 'hash_0123456789' } });
  assertEquals(f.attempts, ['success']);
  assertEquals(f.issued, [EMAIL]);
});

Deno.test('reviewer-signin: off → refused, guard still called once, nothing issued', async () => {
  const f = fake({ config: null });
  assertEquals(await snapshot(await f.run(post({ email: EMAIL, code: CODE }))), REJECTED);
  assertEquals(f.attempts, ['none']);
  assertEquals(f.issued, []);
});

Deno.test('reviewer-signin: another email is refused without counting a failure', async () => {
  const f = fake();
  assertEquals(await snapshot(await f.run(post({ email: 'a@b.dev', code: CODE }))), REJECTED);
  assertEquals(f.attempts, ['none']);
  assertEquals(f.issued, []);
});

Deno.test('reviewer-signin: a wrong code for the reviewer counts a failure', async () => {
  const f = fake();
  assertEquals(await snapshot(await f.run(post({ email: EMAIL, code: '135790' }))), REJECTED);
  assertEquals(f.attempts, ['failure']);
  assertEquals(f.issued, []);
});

Deno.test('reviewer-signin: while locked even the right code is refused', async () => {
  const f = fake({ locked: true });
  assertEquals(await snapshot(await f.run(post({ email: EMAIL, code: CODE }))), REJECTED);
  assertEquals(f.attempts, ['success']);
  assertEquals(f.issued, []);
});

Deno.test('reviewer-signin: malformed requests are refused the same way', async () => {
  const requests: Request[] = [
    post('not json'),
    post('null'),
    post({ email: EMAIL }),
    post({ code: CODE }),
    post({ email: EMAIL, code: CODE, extra: true }),
    post({ email: 42, code: CODE }),
    post({ email: EMAIL, code: CODE, pad: 'x'.repeat(MAX_REVIEWER_SIGNIN_BYTES) }),
    new Request('http://localhost/reviewer-signin', { method: 'GET' }),
    new Request('http://localhost/reviewer-signin', { method: 'PUT', body: '{}' }),
  ];
  for (const req of requests) {
    const f = fake();
    assertEquals(await snapshot(await f.run(req)), REJECTED, `${req.method}`);
    assertEquals(f.attempts, ['none']);
    assertEquals(f.issued, []);
  }
});

Deno.test('reviewer-signin: guard or token errors are refused, not 500', async () => {
  const guard = fake({ guardFails: true });
  assertEquals(await snapshot(await guard.run(post({ email: EMAIL, code: CODE }))), REJECTED);
  assertEquals(guard.issued, []);

  const issue = fake({ issueFails: true });
  assertEquals(await snapshot(await issue.run(post({ email: EMAIL, code: CODE }))), REJECTED);
  assertEquals(issue.issued, [EMAIL]);
});

Deno.test('reviewer-signin: every refusal is byte-for-byte identical', async () => {
  const cases: Array<[string, Fake, Request]> = [
    ['off', fake({ config: null }), post({ email: EMAIL, code: CODE })],
    ['other email', fake(), post({ email: 'a@b.dev', code: CODE })],
    ['wrong code', fake(), post({ email: EMAIL, code: '000000' })],
    ['locked', fake({ locked: true }), post({ email: EMAIL, code: CODE })],
    ['malformed', fake(), post('{')],
    ['guard error', fake({ guardFails: true }), post({ email: EMAIL, code: CODE })],
  ];
  const snapshots: Snapshot[] = [];
  for (const [, f, req] of cases) snapshots.push(await snapshot(await f.run(req)));
  for (let i = 1; i < snapshots.length; i++) {
    assertEquals(snapshots[i], snapshots[0], `${cases[i][0]} vs ${cases[0][0]}`);
  }
  // And each request made exactly one guard call, so none is faster for skipping it.
  for (const [label, f] of cases) assertEquals(f.attempts.length, 1, label);
});

Deno.test('reviewer-signin: logs never contain the email, code or token hash', async () => {
  const lines: string[] = [];
  const original = { log: console.log, warn: console.warn, error: console.error };
  const capture = (...args: unknown[]) => lines.push(args.map(String).join(' '));
  console.log = capture;
  console.warn = capture;
  console.error = capture;
  try {
    await fake().run(post({ email: EMAIL, code: CODE }));
    await fake().run(post({ email: EMAIL, code: '000000' }));
    await fake({ locked: true }).run(post({ email: EMAIL, code: CODE }));
    await fake({ guardFails: true }).run(post({ email: EMAIL, code: CODE }));
    await fake({ issueFails: true }).run(post({ email: EMAIL, code: CODE }));
  } finally {
    Object.assign(console, original);
  }
  assert(lines.length > 0);
  for (const line of lines) {
    assertFalse(line.toLowerCase().includes(EMAIL), line);
    assertFalse(line.includes(CODE), line);
    assertFalse(line.includes('000000'), line);
    assertFalse(line.includes('hash_0123456789'), line);
  }
});
