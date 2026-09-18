import {
  computeSignature,
  generateSecret,
  parseSignatureHeader,
  SECRET_PREFIX,
  timingSafeEqual,
  verifySignature,
} from '../_shared/hmac.ts';
import { assert, assertEquals, assertFalse, assertMatch, assertNotEquals } from './test_deps.ts';

const SECRET = 'whsec_test_secret_0123456789abcdef';
const BODY = '{"agent_id":"a","external_id":"x","title":"Hi"}';

Deno.test('sign → verify round-trip succeeds', async () => {
  const signature = await computeSignature(BODY, SECRET);
  assertMatch(signature, /^sha256=[0-9a-f]{64}$/);
  assert(await verifySignature(BODY, signature, SECRET));
});

Deno.test('matches a known HMAC-SHA256 vector (RFC 4231 case 2)', async () => {
  const signature = await computeSignature('what do ya want for nothing?', 'Jefe');
  assertEquals(
    signature,
    'sha256=5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843',
  );
});

Deno.test('tampered body fails verification', async () => {
  const signature = await computeSignature(BODY, SECRET);
  assertFalse(await verifySignature(BODY.replace('Hi', 'Ha'), signature, SECRET));
});

Deno.test('whitespace-only change to the body fails (raw bytes are signed)', async () => {
  const signature = await computeSignature(BODY, SECRET);
  assertFalse(await verifySignature(`${BODY} `, signature, SECRET));
});

Deno.test('wrong secret fails verification', async () => {
  const signature = await computeSignature(BODY, SECRET);
  assertFalse(await verifySignature(BODY, signature, `${SECRET}x`));
});

Deno.test('missing or malformed headers fail', async () => {
  assertFalse(await verifySignature(BODY, null, SECRET));
  assertFalse(await verifySignature(BODY, '', SECRET));
  assertFalse(await verifySignature(BODY, 'sha1=abc', SECRET));
  assertFalse(await verifySignature(BODY, `sha256=${'0'.repeat(63)}`, SECRET));
});

Deno.test('header parsing accepts uppercase hex and surrounding whitespace', async () => {
  const signature = await computeSignature(BODY, SECRET);
  const upper = `  sha256=${signature.slice(7).toUpperCase()} `;
  assert(parseSignatureHeader(upper));
  assert(await verifySignature(BODY, upper, SECRET));
});

Deno.test('timingSafeEqual compares length and content', () => {
  assert(timingSafeEqual(new Uint8Array([1, 2]), new Uint8Array([1, 2])));
  assertFalse(timingSafeEqual(new Uint8Array([1, 2]), new Uint8Array([1, 3])));
  assertFalse(timingSafeEqual(new Uint8Array([1]), new Uint8Array([1, 2])));
});

Deno.test('generated secrets are prefixed, url-safe and unique', () => {
  const a = generateSecret();
  const b = generateSecret();
  assert(a.startsWith(SECRET_PREFIX));
  assertMatch(a, /^whsec_[A-Za-z0-9_-]{43}$/);
  assertNotEquals(a, b);
});
