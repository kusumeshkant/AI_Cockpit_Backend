// Agent Triggers (app → agent). Builds and delivers the signed trigger POST.
// Mirrors callback.ts: HMAC over the exact raw body, redirects not followed
// (SSRF), time-boxed, failures reported — never thrown — because the run is
// already recorded when this is called.
import { computeSignature } from './hmac.ts';
import type { TriggerPayload } from './types.ts';

/** Header carrying `sha256=<hex hmac(rawBody, trigger secret)>`. */
export const TRIGGER_SIGNATURE_HEADER = 'X-Cockpit-Trigger-Signature';

/** Prefix of generated trigger secrets. */
export const TRIGGER_SECRET_PREFIX = 'whtrig_';

/** Trigger request timeout. */
export const TRIGGER_TIMEOUT_MS = 5000;

/** New trigger secret: `whtrig_` + 32 random bytes, base64url. */
export function generateTriggerSecret(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  const base64 = btoa(String.fromCharCode(...bytes));
  return TRIGGER_SECRET_PREFIX + base64.replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/, '');
}

/** The body sent to the agent. `nonce` lets the agent drop replays. */
export function buildTriggerPayload(
  runId: string,
  agentId: string,
  now: Date = new Date(),
  nonce: string = crypto.randomUUID(),
): TriggerPayload {
  return { trigger_id: runId, agent_id: agentId, triggered_at: now.toISOString(), nonce };
}

/** Outcome of a delivery attempt. `detail` is safe to log and audit. */
export interface TriggerOutcome {
  delivered: boolean;
  detail: string;
}

/** POSTs [payload] to [url], signed with the agent's trigger [secret]. */
export async function deliverTrigger(
  url: string,
  payload: TriggerPayload,
  secret: string,
  fetchFn: typeof fetch = fetch,
): Promise<TriggerOutcome> {
  const body = JSON.stringify(payload);
  try {
    const response = await fetchFn(url, {
      method: 'POST',
      redirect: 'manual',
      signal: AbortSignal.timeout(TRIGGER_TIMEOUT_MS),
      headers: {
        'Content-Type': 'application/json',
        'User-Agent': 'Cockpit-Trigger/1',
        [TRIGGER_SIGNATURE_HEADER]: await computeSignature(body, secret),
        'X-Cockpit-Trigger-Id': payload.trigger_id,
      },
      body,
    });
    await response.body?.cancel();
    return { delivered: response.ok, detail: `http_${response.status}` };
  } catch (error) {
    const name = error instanceof Error ? error.name : 'Error';
    return { delivered: false, detail: name === 'TimeoutError' ? 'timeout' : 'network_error' };
  }
}
