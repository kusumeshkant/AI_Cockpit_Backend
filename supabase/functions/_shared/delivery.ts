// One callback delivery attempt, shared by actions-decision (first attempt)
// and callbacks-retry (later attempts): check the URL policy, sign with the
// agent's current secret, POST, then record the result with the next retry
// delay (TR-7). Never throws — the decision is already committed.
import { type CallbackOutcome, deliverCallback } from './callback.ts';
import type { SupabaseClient } from './deps.ts';
import { log } from './logger.ts';
import { retryDelaySeconds } from './retry.ts';
import type { CallbackPayload, CallbackStatus } from './types.ts';
import { isAllowedCallbackUrl } from './validation.ts';
import { getAgentInboundContext } from './vault.ts';

/** A callback to (re)deliver. */
export interface DeliveryJob {
  agentId: string;
  callbackUrl: string;
  payload: CallbackPayload;
  idempotencyKey: string;
  /** Attempts already recorded before this one. */
  attemptsMade: number;
}

/** Result of [attemptDelivery]. */
export interface DeliveryResult {
  delivered: boolean;
  /** callback_status after recording this attempt. */
  status: CallbackStatus;
  detail: string;
}

/** Outcomes that can't improve by waiting: go straight to terminal `failed`. */
const PERMANENT_DETAILS = new Set(['callback_url_blocked', 'agent_secret_missing']);

/** Attempts one delivery and records it. */
export async function attemptDelivery(
  client: SupabaseClient,
  job: DeliveryJob,
  options: { allowInsecureCallbacks: boolean; fetchFn?: typeof fetch },
): Promise<DeliveryResult> {
  let outcome: CallbackOutcome;
  if (!isAllowedCallbackUrl(job.callbackUrl, options.allowInsecureCallbacks)) {
    outcome = { delivered: false, detail: 'callback_url_blocked' };
  } else {
    const context = await getAgentInboundContext(client, job.agentId).catch(() => null);
    outcome = context?.secret
      ? await deliverCallback(
        job.callbackUrl,
        job.payload,
        context.secret,
        job.idempotencyKey,
        options.fetchFn,
      )
      : { delivered: false, detail: 'agent_secret_missing' };
  }

  const retryIn = outcome.delivered || PERMANENT_DETAILS.has(outcome.detail)
    ? null
    : retryDelaySeconds(job.attemptsMade + 1);

  const { data, error } = await client.rpc('record_callback_result', {
    p_action_id: job.payload.action_id,
    p_delivered: outcome.delivered,
    p_detail: outcome.detail,
    p_retry_in_seconds: retryIn,
  });
  if (error) {
    log.error('callback_result_not_recorded', { action_id: job.payload.action_id, code: error.code });
  }
  const status: CallbackStatus = (data as CallbackStatus | null) ??
    (outcome.delivered ? 'delivered' : retryIn === null ? 'failed' : 'retrying');

  log.info('callback_attempted', {
    action_id: job.payload.action_id,
    attempt: job.attemptsMade + 1,
    delivered: outcome.delivered,
    detail: outcome.detail,
    status,
    retry_in_seconds: retryIn,
  });
  return { delivered: outcome.delivered, status, detail: outcome.detail };
}
