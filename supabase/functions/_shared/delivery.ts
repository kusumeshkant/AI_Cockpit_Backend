// One callback delivery attempt, shared by actions-decision (first attempt)
// and callbacks-retry (later attempts): check the URL policy, sign with the
// agent's current secret, POST, then record the result with the next retry
// delay (TR-7). Never throws — the decision is already committed.
import { type CallbackOutcome, deliverCallback } from './callback.ts';
import type { SupabaseClient } from './deps.ts';
import { log } from './logger.ts';
import { retryDelaySeconds } from './retry.ts';
import { callServiceOp, type ServiceCallResult } from './service_call.ts';
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

// -----------------------------------------------------------------------------
// Service agents (0014): a decision is delivered by calling the service's
// `decision.apply` op (Cockpit-Signature v1, outbound key) instead of POSTing
// a callback URL. Same record_callback_result bookkeeping and the same 8
// attempts / backoff; ordinary agents never reach this branch.
// -----------------------------------------------------------------------------

/** Agent answers that mean "already final there": delivered, stop. */
export const SERVICE_TERMINAL_OK = new Set(['conflict', 'idea_final', 'not_found']);

/** The stored decision.apply input (record_decision, 0014). */
export interface ServiceDecisionPayload {
  action_id: string;
  external_id: string;
  idea_id: string | null;
  decision: 'approved' | 'rejected' | 'approved_with_edits';
  reason: string | null;
  decided_by: string;
  decided_at: string;
}

/** A service decision to (re)deliver. */
export interface ServiceDeliveryJob {
  agentId: string;
  payload: ServiceDecisionPayload;
  idempotencyKey: string;
  attemptsMade: number;
}

/** The params sent to decision.apply. */
export function decisionApplyParams(
  payload: ServiceDecisionPayload,
  acknowledged?: string[],
): Record<string, unknown> {
  return {
    idea_id: payload.idea_id,
    action_id: payload.action_id,
    decision: payload.decision,
    decided_by: payload.decided_by,
    decided_at: payload.decided_at,
    ...(payload.reason ? { reason: payload.reason } : {}),
    ...(acknowledged && acknowledged.length > 0 ? { acknowledged } : {}),
  };
}

/** Classifies one service call for delivery: delivered / permanent / retry. */
export function classifyServiceDelivery(result: ServiceCallResult): { delivered: boolean; permanent: boolean; detail: string } {
  if (result.kind === 'refused') {
    return { delivered: false, permanent: result.detail === 'service_not_found', detail: result.detail };
  }
  if (result.mapped.kind === 'ok') return { delivered: true, permanent: false, detail: 'agent_applied' };
  if (result.agentCode && SERVICE_TERMINAL_OK.has(result.agentCode)) {
    return { delivered: true, permanent: false, detail: `agent_${result.agentCode}` };
  }
  const o = result.outcome;
  const detail = o.kind === 'response' ? (result.agentCode ? `agent_${result.agentCode}` : `http_${o.status}`) : o.kind;
  return { delivered: false, permanent: false, detail };
}

/** One service delivery attempt, recorded. Never throws. */
export async function attemptServiceDelivery(
  client: SupabaseClient,
  job: ServiceDeliveryJob,
  options: { allowInsecureServices: boolean; fetchFn?: typeof fetch; nowMs?: () => number },
): Promise<DeliveryResult> {
  let verdict: { delivered: boolean; permanent: boolean; detail: string };
  try {
    const { data: target } = await client
      .rpc('resolve_agent_service', { p_agent_id: job.agentId })
      .maybeSingle<{ workspace_id: string; service_slug: string; subject: string }>();
    if (!target) {
      verdict = { delivered: false, permanent: true, detail: 'service_not_found' };
    } else {
      const result = await callServiceOp(
        { client, allowInsecureServices: options.allowInsecureServices, fetchFn: options.fetchFn, nowMs: options.nowMs },
        {
          slug: target.service_slug,
          op: 'decision.apply',
          params: decisionApplyParams(job.payload),
          requestId: job.idempotencyKey,
          workspaceId: target.workspace_id,
          subject: target.subject,
          user: job.payload.decided_by,
          // One call per attempt; the 8-step backoff is the retry.
          maxAttempts: 1,
        },
      );
      verdict = classifyServiceDelivery(result);
    }
  } catch {
    verdict = { delivered: false, permanent: false, detail: 'gateway_error' };
  }

  const retryIn = verdict.delivered || verdict.permanent ? null : retryDelaySeconds(job.attemptsMade + 1);
  const { data, error } = await client.rpc('record_callback_result', {
    p_action_id: job.payload.action_id,
    p_delivered: verdict.delivered,
    p_detail: verdict.detail,
    p_retry_in_seconds: retryIn,
  });
  if (error) {
    log.error('callback_result_not_recorded', { action_id: job.payload.action_id, code: error.code });
  }
  const status: CallbackStatus = (data as CallbackStatus | null) ??
    (verdict.delivered ? 'delivered' : retryIn === null ? 'failed' : 'retrying');
  log.info('service_decision_delivery', {
    action_id: job.payload.action_id,
    attempt: job.attemptsMade + 1,
    delivered: verdict.delivered,
    detail: verdict.detail,
    status,
    retry_in_seconds: retryIn,
  });
  return { delivered: verdict.delivered, status, detail: verdict.detail };
}
