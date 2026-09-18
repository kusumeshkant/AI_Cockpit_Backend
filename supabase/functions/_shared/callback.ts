// Delivers a signed decision to the agent (blueprint §5.3). Redirects are not
// followed (SSRF) and the request is time-boxed; failures are reported, never
// thrown, because the decision is already committed when this runs.
import { computeSignature } from './hmac.ts';
import type { CallbackPayload } from './types.ts';

/** Callback request timeout. */
export const CALLBACK_TIMEOUT_MS = 5000;

/** Outcome of a delivery attempt. `detail` is safe to log and audit. */
export interface CallbackOutcome {
  delivered: boolean;
  detail: string;
}

/** POSTs [payload] to [url], signed with the agent's [secret]. */
export async function deliverCallback(
  url: string,
  payload: CallbackPayload,
  secret: string,
  idempotencyKey: string,
  fetchFn: typeof fetch = fetch,
): Promise<CallbackOutcome> {
  const body = JSON.stringify(payload);
  try {
    const response = await fetchFn(url, {
      method: 'POST',
      redirect: 'manual',
      signal: AbortSignal.timeout(CALLBACK_TIMEOUT_MS),
      headers: {
        'Content-Type': 'application/json',
        'User-Agent': 'Cockpit-Callback/1',
        'X-Cockpit-Signature': await computeSignature(body, secret),
        'X-Cockpit-Action-Id': payload.action_id,
        'Idempotency-Key': idempotencyKey,
      },
      body,
    });
    await response.body?.cancel();
    return response.ok
      ? { delivered: true, detail: `http_${response.status}` }
      : { delivered: false, detail: `http_${response.status}` };
  } catch (error) {
    const name = error instanceof Error ? error.name : 'Error';
    return { delivered: false, detail: name === 'TimeoutError' ? 'timeout' : 'network_error' };
  }
}
