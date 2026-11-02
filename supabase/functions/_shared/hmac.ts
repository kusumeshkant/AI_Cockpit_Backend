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

// -----------------------------------------------------------------------------
// Cockpit-Signature v1 (agent services gateway; docs/agent-gateway-wire-v1.md).
// Cockpit → agent requests are signed over a canonical string that binds the
// key id, time, nonce, method, path, body hash, workspace, user and request
// id. The legacy `sha256=` helpers above are unchanged.
// -----------------------------------------------------------------------------

/** Header names of a v1-signed request. */
export const V1_HEADERS = {
  contractVersion: 'X-Cockpit-Contract-Version',
  keyId: 'X-Cockpit-Key-Id',
  timestamp: 'X-Cockpit-Timestamp',
  nonce: 'X-Cockpit-Nonce',
  contentSha256: 'X-Cockpit-Content-SHA256',
  requestId: 'X-Cockpit-Request-Id',
  workspace: 'X-Cockpit-Workspace',
  user: 'X-Cockpit-User',
  signature: 'X-Cockpit-Signature',
} as const;

/**
 * Canonical path signed by agents for agent → Cockpit card requests (0013),
 * whatever URL they post to. Same string-to-sign and headers otherwise.
 */
export const V1_INBOUND_CARD_PATH = '/cockpit/v1/inbound/cards';

/** Max clock difference (seconds) a verifier accepts. */
export const V1_MAX_SKEW_SECONDS = 60;

const V1_SIGNATURE_PATTERN = /^v1=([0-9a-f]{64})$/;

/** Fields that are signed (besides the body, which is signed via its hash). */
export interface V1Fields {
  keyId: string;
  /** Unix seconds. */
  timestamp: number;
  nonce: string;
  method: string;
  /** URL path of the request, e.g. `/cockpit/v1/ops/ideas.list`. */
  path: string;
  workspace: string;
  user: string;
  requestId: string;
}

/** Lowercase hex SHA-256 of [text] (UTF-8). */
export async function sha256Hex(text: string): Promise<string> {
  return toHex(new Uint8Array(await crypto.subtle.digest('SHA-256', encoder.encode(text))));
}

/** The canonical v1 string to sign. */
export function stringToSignV1(fields: V1Fields, contentSha256: string): string {
  return [
    'COCKPIT-V1',
    fields.keyId,
    String(fields.timestamp),
    fields.nonce,
    fields.method.toUpperCase(),
    fields.path,
    contentSha256,
    fields.workspace,
    fields.user,
    fields.requestId,
  ].join('\n');
}

/** Signs [body] + [fields] with [secret]; returns the values to send. */
export async function signV1(
  fields: V1Fields,
  body: string,
  secret: string,
): Promise<{ contentSha256: string; stringToSign: string; signature: string }> {
  const contentSha256 = await sha256Hex(body);
  const stringToSign = stringToSignV1(fields, contentSha256);
  return {
    contentSha256,
    stringToSign,
    signature: `v1=${toHex(await hmacBytes(stringToSign, secret))}`,
  };
}

/** The v1 headers for a signed request (Content-Type included). */
export async function signedHeadersV1(
  fields: V1Fields,
  body: string,
  secret: string,
  contractVersion: string,
): Promise<Record<string, string>> {
  const signed = await signV1(fields, body, secret);
  return {
    'Content-Type': 'application/json',
    [V1_HEADERS.contractVersion]: contractVersion,
    [V1_HEADERS.keyId]: fields.keyId,
    [V1_HEADERS.timestamp]: String(fields.timestamp),
    [V1_HEADERS.nonce]: fields.nonce,
    [V1_HEADERS.contentSha256]: signed.contentSha256,
    [V1_HEADERS.requestId]: fields.requestId,
    [V1_HEADERS.workspace]: fields.workspace,
    [V1_HEADERS.user]: fields.user,
    [V1_HEADERS.signature]: signed.signature,
  };
}

/** Why a v1 verification failed. */
export type V1Failure =
  | 'missing_header'
  | 'bad_signature_format'
  | 'unknown_key'
  | 'clock_skew'
  | 'body_hash_mismatch'
  | 'bad_signature';

/**
 * Agent-side verification of a v1 request. [secrets] maps accepted key ids
 * (current and next) to secrets. Replay (nonce) and request-id idempotency
 * are the caller's job; this checks headers, time, body hash and signature.
 */
export async function verifyV1(input: {
  headers: Headers;
  method: string;
  path: string;
  body: string;
  secrets: Record<string, string>;
  /** Unix seconds; defaults to now. */
  now?: number;
  maxSkewSeconds?: number;
}): Promise<{ ok: true; fields: V1Fields } | { ok: false; reason: V1Failure }> {
  const h = (name: string) => input.headers.get(name);
  const keyId = h(V1_HEADERS.keyId);
  const timestamp = h(V1_HEADERS.timestamp);
  const nonce = h(V1_HEADERS.nonce);
  const contentSha256 = h(V1_HEADERS.contentSha256);
  const requestId = h(V1_HEADERS.requestId);
  const workspace = h(V1_HEADERS.workspace);
  const user = h(V1_HEADERS.user);
  const signature = h(V1_HEADERS.signature);
  if (!keyId || !timestamp || !nonce || !contentSha256 || !requestId || !workspace || !user || !signature) {
    return { ok: false, reason: 'missing_header' };
  }
  const match = V1_SIGNATURE_PATTERN.exec(signature.trim());
  if (!match) return { ok: false, reason: 'bad_signature_format' };
  const secret = Object.hasOwn(input.secrets, keyId) ? input.secrets[keyId] : undefined;
  if (!secret) return { ok: false, reason: 'unknown_key' };
  if (!/^[0-9]{1,12}$/.test(timestamp)) return { ok: false, reason: 'clock_skew' };
  const now = input.now ?? Math.floor(Date.now() / 1000);
  if (Math.abs(now - Number(timestamp)) > (input.maxSkewSeconds ?? V1_MAX_SKEW_SECONDS)) {
    return { ok: false, reason: 'clock_skew' };
  }
  const actualHash = await sha256Hex(input.body);
  if (!timingSafeEqual(encoder.encode(actualHash), encoder.encode(contentSha256.toLowerCase()))) {
    return { ok: false, reason: 'body_hash_mismatch' };
  }
  const fields: V1Fields = {
    keyId,
    timestamp: Number(timestamp),
    nonce,
    method: input.method,
    path: input.path,
    workspace,
    user,
    requestId,
  };
  const expected = await hmacBytes(stringToSignV1(fields, actualHash), secret);
  if (!timingSafeEqual(fromHex(match[1]), expected)) return { ok: false, reason: 'bad_signature' };
  return { ok: true, fields };
}
