// Cockpit-Signature v1 (_shared/hmac.ts): published vectors, tampering, clock
// skew boundary, key overlap, and that the legacy sha256= helpers still work.
import {
  computeSignature,
  signedHeadersV1,
  signV1,
  type V1Fields,
  verifyV1,
  verifySignature,
} from '../_shared/hmac.ts';
import { assert, assertEquals } from './test_deps.ts';
import vectors from './vectors/signature_v1.json' with { type: 'json' };

const fieldsOf = (input: (typeof vectors.vectors)[number]['input']): V1Fields => ({
  keyId: input.key_id,
  timestamp: input.timestamp,
  nonce: input.nonce,
  method: input.method,
  path: input.path,
  workspace: input.workspace,
  user: input.user,
  requestId: input.request_id,
});

Deno.test('v1: every published vector reproduces exactly', async () => {
  for (const v of vectors.vectors) {
    const signed = await signV1(fieldsOf(v.input), v.input.body, vectors.secret);
    assertEquals(signed.contentSha256, v.expected.body_sha256, v.name);
    assertEquals(signed.stringToSign, v.expected.string_to_sign, v.name);
    assertEquals(signed.signature, v.expected.signature, v.name);
  }
});

const SECRET = 'svcsig_unit_test_secret_0123456789abcdefghijklmn';
const NEXT = 'svcsig_unit_test_next_secret_0123456789abcdefghij';
const BASE: V1Fields = {
  keyId: 'key-current',
  timestamp: 1_800_000_000,
  nonce: '4b3c2d1e-0f9a-4b8c-8d7e-6f5a4b3c2d1e',
  method: 'POST',
  path: '/cockpit/v1/ops/brand.save',
  workspace: 'ws-1',
  user: 'user-1',
  requestId: 'req-1',
};
const BODY = '{"params":{"brand":{"name":"Acme"}}}';

async function verify(
  overrides: { headers?: Record<string, string>; path?: string; body?: string; now?: number } = {},
  secrets: Record<string, string> = { 'key-current': SECRET },
  fields: V1Fields = BASE,
  signWith = SECRET,
) {
  const headers = new Headers({
    ...(await signedHeadersV1(fields, BODY, signWith, '1.0')),
    ...(overrides.headers ?? {}),
  });
  return verifyV1({
    headers,
    method: 'POST',
    path: overrides.path ?? BASE.path,
    body: overrides.body ?? BODY,
    secrets,
    now: overrides.now ?? BASE.timestamp,
  });
}

Deno.test('v1: a correctly signed request verifies', async () => {
  const result = await verify();
  assert(result.ok);
  if (result.ok) assertEquals(result.fields.requestId, 'req-1');
});

Deno.test('v1: tampering with any signed part is rejected', async () => {
  assertEquals(await verify({ body: '{"params":{"brand":{"name":"Evil"}}}' }), {
    ok: false,
    reason: 'body_hash_mismatch',
  });
  assertEquals(await verify({ path: '/cockpit/v1/ops/subject.delete' }), { ok: false, reason: 'bad_signature' });
  for (const [header, value] of [
    ['X-Cockpit-Workspace', 'ws-2'],
    ['X-Cockpit-User', 'user-2'],
    ['X-Cockpit-Request-Id', 'req-2'],
    ['X-Cockpit-Nonce', 'another-nonce'],
  ]) {
    assertEquals(await verify({ headers: { [header]: value } }), { ok: false, reason: 'bad_signature' }, header);
  }
  assertEquals(
    await verify({ headers: { 'X-Cockpit-Key-Id': 'key-next' } }, { 'key-current': SECRET, 'key-next': SECRET }),
    { ok: false, reason: 'bad_signature' },
    'key id is part of the signature',
  );
});

Deno.test('v1: clock skew boundary (59 s / 60 s ok, 61 s rejected, both directions)', async () => {
  assert((await verify({ now: BASE.timestamp + 59 })).ok);
  assert((await verify({ now: BASE.timestamp + 60 })).ok);
  assert((await verify({ now: BASE.timestamp - 59 })).ok);
  assertEquals(await verify({ now: BASE.timestamp + 61 }), { ok: false, reason: 'clock_skew' });
  assertEquals(await verify({ now: BASE.timestamp - 61 }), { ok: false, reason: 'clock_skew' });
  assertEquals(await verify({ headers: { 'X-Cockpit-Timestamp': '1.8e9' } }), { ok: false, reason: 'clock_skew' });
});

Deno.test('v1: wrong version prefix or malformed signature is rejected', async () => {
  const good = (await signV1(BASE, BODY, SECRET)).signature;
  const hex = good.slice(3);
  for (const bad of [`v2=${hex}`, `sha256=${hex}`, hex, `v1=${hex.toUpperCase()}`, `v1=${hex.slice(2)}`]) {
    assertEquals(await verify({ headers: { 'X-Cockpit-Signature': bad } }), {
      ok: false,
      reason: 'bad_signature_format',
    }, bad);
  }
});

Deno.test('v1: current and next keys both verify (rotation overlap); unknown keys do not', async () => {
  const both = { 'key-current': SECRET, 'key-next': NEXT };
  assert((await verify({}, both)).ok);
  assert((await verify({}, both, { ...BASE, keyId: 'key-next' }, NEXT)).ok);
  assertEquals(await verify({}, { 'key-next': NEXT }), { ok: false, reason: 'unknown_key' });
  // Prototype keys are not accepted key ids.
  assertEquals(await verify({}, {}, { ...BASE, keyId: 'toString' }), { ok: false, reason: 'unknown_key' });
});

Deno.test('v1: a missing header is rejected', async () => {
  const headers = new Headers(await signedHeadersV1(BASE, BODY, SECRET, '1.0'));
  headers.delete('X-Cockpit-User');
  assertEquals(
    await verifyV1({ headers, method: 'POST', path: BASE.path, body: BODY, secrets: { 'key-current': SECRET }, now: BASE.timestamp }),
    { ok: false, reason: 'missing_header' },
  );
});

Deno.test('legacy sha256= signatures are unchanged', async () => {
  const signature = await computeSignature(BODY, SECRET);
  assert(signature.startsWith('sha256='));
  assert(await verifySignature(BODY, signature, SECRET));
});
