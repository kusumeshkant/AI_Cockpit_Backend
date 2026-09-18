// Firebase Cloud Messaging (HTTP v1). A service-account JWT is exchanged for
// an OAuth token (cached ~55 min); one message is sent per device token and
// tokens FCM reports as dead are returned for pruning. Without
// FCM_SERVICE_ACCOUNT_JSON every call is a logged no-op, so the loop runs
// locally without Firebase.
import { log } from './logger.ts';

/** Notification content. `data` values must be strings (FCM rule). */
export interface PushMessage {
  title: string;
  body: string;
  data: Record<string, string>;
}

/** Result of a push fan-out. */
export interface PushResult {
  skipped: boolean;
  sent: number;
  failed: number;
  invalidTokens: string[];
}

/** Subset of a Google service-account key file. */
interface ServiceAccount {
  project_id: string;
  client_email: string;
  private_key: string;
  token_uri?: string;
}

/** Options for [sendPush]; `fetchFn` / `now` are injectable for tests. */
export interface PushOptions {
  serviceAccountJson: string | null;
  fetchFn?: typeof fetch;
  now?: () => number;
}

const SCOPE = 'https://www.googleapis.com/auth/firebase.messaging';
const DEFAULT_TOKEN_URI = 'https://oauth2.googleapis.com/token';
const TOKEN_TTL_SECONDS = 3600;
const TOKEN_REFRESH_MARGIN_MS = 5 * 60 * 1000;

let cachedToken: { value: string; expiresAt: number } | null = null;

/** Clears the cached OAuth token (tests). */
export function resetFcmTokenCache(): void {
  cachedToken = null;
}

/**
 * True when an FCM v1 error response means the device token is permanently
 * invalid and should be removed.
 */
export function isInvalidTokenResponse(status: number, body: unknown): boolean {
  if (status !== 400 && status !== 404) return false;
  const error = (body as { error?: { status?: string; details?: Array<Record<string, unknown>> } })
    ?.error;
  if (!error) return status === 404;
  const codes = (error.details ?? []).map((d) => d['errorCode']);
  return (
    codes.includes('UNREGISTERED') ||
    codes.includes('INVALID_ARGUMENT') ||
    error.status === 'NOT_FOUND' ||
    (status === 400 && error.status === 'INVALID_ARGUMENT')
  );
}

function base64url(bytes: Uint8Array | string): string {
  const raw = typeof bytes === 'string' ? bytes : String.fromCharCode(...bytes);
  return btoa(raw).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/, '');
}

function pemToPkcs8(pem: string): Uint8Array<ArrayBuffer> {
  const body = atob(
    pem
      .replace(/-----BEGIN PRIVATE KEY-----/, '')
      .replace(/-----END PRIVATE KEY-----/, '')
      .replace(/\s+/g, ''),
  );
  const bytes = new Uint8Array(new ArrayBuffer(body.length));
  for (let i = 0; i < body.length; i++) bytes[i] = body.charCodeAt(i);
  return bytes;
}

async function signJwt(account: ServiceAccount, nowSeconds: number): Promise<string> {
  const header = base64url(JSON.stringify({ alg: 'RS256', typ: 'JWT' }));
  const claims = base64url(
    JSON.stringify({
      iss: account.client_email,
      scope: SCOPE,
      aud: account.token_uri ?? DEFAULT_TOKEN_URI,
      iat: nowSeconds,
      exp: nowSeconds + TOKEN_TTL_SECONDS,
    }),
  );
  const key = await crypto.subtle.importKey(
    'pkcs8',
    pemToPkcs8(account.private_key),
    { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
    false,
    ['sign'],
  );
  const signature = new Uint8Array(
    await crypto.subtle.sign('RSASSA-PKCS1-v1_5', key, new TextEncoder().encode(`${header}.${claims}`)),
  );
  return `${header}.${claims}.${base64url(signature)}`;
}

async function accessToken(account: ServiceAccount, fetchFn: typeof fetch, now: number): Promise<string> {
  if (cachedToken && cachedToken.expiresAt - TOKEN_REFRESH_MARGIN_MS > now) {
    return cachedToken.value;
  }
  const assertion = await signJwt(account, Math.floor(now / 1000));
  const response = await fetchFn(account.token_uri ?? DEFAULT_TOKEN_URI, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
      assertion,
    }),
  });
  if (!response.ok) throw new Error(`fcm_oauth_failed_${response.status}`);
  const { access_token, expires_in } = await response.json();
  cachedToken = { value: access_token, expiresAt: now + Number(expires_in ?? TOKEN_TTL_SECONDS) * 1000 };
  return access_token;
}

/** Sends [message] to each token. Never throws for per-token failures. */
export async function sendPush(
  tokens: readonly string[],
  message: PushMessage,
  options: PushOptions,
): Promise<PushResult> {
  const unique = [...new Set(tokens)];
  if (!options.serviceAccountJson || unique.length === 0) {
    log.info('push_skipped', {
      cause: options.serviceAccountJson ? 'no_tokens' : 'fcm_not_configured',
    });
    return { skipped: true, sent: 0, failed: 0, invalidTokens: [] };
  }

  const fetchFn = options.fetchFn ?? fetch;
  const now = options.now?.() ?? Date.now();
  const account = JSON.parse(options.serviceAccountJson) as ServiceAccount;
  const bearer = await accessToken(account, fetchFn, now);
  const url = `https://fcm.googleapis.com/v1/projects/${account.project_id}/messages:send`;

  const result: PushResult = { skipped: false, sent: 0, failed: 0, invalidTokens: [] };
  await Promise.all(
    unique.map(async (token) => {
      const response = await fetchFn(url, {
        method: 'POST',
        headers: { Authorization: `Bearer ${bearer}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({
          message: {
            token,
            notification: { title: message.title, body: message.body },
            data: message.data,
            android: { priority: 'high', notification: { channel_id: 'actions_high' } },
            apns: { headers: { 'apns-priority': '10' } },
          },
        }),
      });
      if (response.ok) {
        result.sent++;
        await response.body?.cancel();
        return;
      }
      result.failed++;
      const body = await response.json().catch(() => null);
      if (isInvalidTokenResponse(response.status, body)) result.invalidTokens.push(token);
    }),
  );
  log.info('push_sent', {
    sent: result.sent,
    failed: result.failed,
    pruned: result.invalidTokens.length,
  });
  return result;
}
