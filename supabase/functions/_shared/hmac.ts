// HMAC-SHA256 signatures (TR-1): `X-Cockpit-Signature: sha256=<hex>` over the
// exact raw request body. Verification is constant-time.

const encoder = new TextEncoder();
const SIGNATURE_PATTERN = /^sha256=([0-9a-f]{64})$/i;

/** Prefix of generated inbound secrets. */
export const SECRET_PREFIX = 'whsec_';

async function hmacBytes(message: string, secret: string): Promise<Uint8Array> {
  const key = await crypto.subtle.importKey(
    'raw',
    encoder.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign'],
  );
  return new Uint8Array(await crypto.subtle.sign('HMAC', key, encoder.encode(message)));
}

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

function fromHex(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

/** Constant-time comparison of equal-length byte arrays. */
export function timingSafeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

/** Signature header value for [rawBody]: `sha256=<lowercase hex>`. */
export async function computeSignature(rawBody: string, secret: string): Promise<string> {
  return `sha256=${toHex(await hmacBytes(rawBody, secret))}`;
}

/** Extracts the 32-byte digest from a header value, or null if malformed. */
export function parseSignatureHeader(value: string | null): Uint8Array | null {
  if (!value) return null;
  const match = SIGNATURE_PATTERN.exec(value.trim());
  return match ? fromHex(match[1].toLowerCase()) : null;
}

/** True when [header] is a valid signature of [rawBody] under [secret]. */
export async function verifySignature(
  rawBody: string,
  header: string | null,
  secret: string,
): Promise<boolean> {
  const provided = parseSignatureHeader(header);
  if (!provided) return false;
  return timingSafeEqual(provided, await hmacBytes(rawBody, secret));
}

/** New inbound secret: `whsec_` + 32 random bytes, base64url. */
export function generateSecret(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  const base64 = btoa(String.fromCharCode(...bytes));
  return SECRET_PREFIX + base64.replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/, '');
}
