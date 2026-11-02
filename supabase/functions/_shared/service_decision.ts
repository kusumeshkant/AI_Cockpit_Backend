// Decisions on SERVICE cards (actions-decision branch, 0014). Ordinary agents
// never reach this module.
//   * approved — agent first: decision.apply through the gateway (v1 signed,
//     the app's Idempotency-Key as request id, a new nonce per retry). Only on
//     success is the decision recorded and the delivery marked done. Any
//     refusal / failure leaves the card pending and records nothing. A crash
//     between the agent's yes and record_decision heals when the app retries
//     with the same key (the agent op is idempotent).
//   * rejected — recorded first (record_decision), then delivered with the
//     callback retry machinery (attemptServiceDelivery).
// Rule for service state: approve needs the service active or paused (a
// paused agent answers for itself) and the workspace's access active; a
// draft / retired / unknown service → service_not_found. Reject always
// records (so users can clear cards); its delivery to a retired / unknown
// service ends `failed` without calling out.
import type { SupabaseClient } from './deps.ts';
import { AppError, fromPostgrest } from './errors.ts';
import {
  attemptServiceDelivery,
  decisionApplyParams,
  type ServiceDecisionPayload,
} from './delivery.ts';
import { log } from './logger.ts';
import { callServiceOp } from './service_call.ts';
import type { CallbackStatus, DecisionOutcome, DecisionResponse } from './types.ts';
import type { ServiceDecision } from './validation.ts';

/** Row of `resolve_action_service`. */
export interface ActionServiceRow {
  action_status: 'pending' | 'decided' | 'expired';
  expires_at: string | null;
  idea_id: string | null;
  agent_id: string;
  workspace_id: string;
  service_slug: string;
  subject: string;
  access_state: 'active' | 'disabled' | 'blocked';
}

interface DecisionRow {
  outcome: DecisionOutcome;
  callback_payload: ServiceDecisionPayload | null;
  agent_id: string | null;
  callback_status: CallbackStatus | null;
}

/** What the branch needs; injectable for tests. */
export interface ServiceDecisionDeps {
  client: SupabaseClient;
  allowInsecureServices: boolean;
  fetchFn?: typeof fetch;
  nowMs?: () => number;
}

/** Throws the HTTP error for a record_decision refusal. */
function throwFor(outcome: DecisionOutcome): void {
  switch (outcome) {
    case 'not_found':
      throw new AppError('not_found', 'Action not found');
    case 'already_decided':
      throw new AppError('conflict', 'Action was already decided');
    case 'expired':
      throw new AppError('expired', 'Action has expired');
    case 'invalid_edit':
      throw new AppError('validation', 'edited_payload contains non-editable fields');
  }
}

async function recordDecision(
  client: SupabaseClient,
  actorId: string,
  body: ServiceDecision,
  key: string,
): Promise<DecisionRow> {
  const { data, error } = await client
    .rpc('record_decision', {
      p_action_id: body.action_id,
      p_actor_user_id: actorId,
      p_decision: body.decision,
      p_edited_payload: null,
      p_reason: body.decision === 'rejected' ? body.reason ?? null : null,
      p_idempotency_key: key,
    })
    .single<DecisionRow>();
  if (error) throw fromPostgrest(error);
  throwFor(data.outcome);
  return data;
}

/** Decides a service card. */
export async function decideServiceAction(
  deps: ServiceDecisionDeps,
  input: { actorId: string; key: string; body: ServiceDecision; target: ActionServiceRow },
): Promise<DecisionResponse> {
  const { actorId, key, body, target } = input;
  const nowMs = deps.nowMs ?? Date.now;

  if (body.decision === 'rejected') {
    const row = await recordDecision(deps.client, actorId, body, key);
    const duplicate = row.outcome === 'duplicate';
    log.info('decision_recorded', { action_id: body.action_id, decision: body.decision, duplicate, service: true });
    if (duplicate && row.callback_status !== 'pending') {
      return { decision_recorded: true, duplicate: true, callback_delivered: row.callback_status === 'delivered' };
    }
    if (!row.callback_payload || !row.agent_id) {
      return { decision_recorded: true, duplicate, callback_delivered: false };
    }
    const result = await attemptServiceDelivery(
      deps.client,
      { agentId: row.agent_id, payload: row.callback_payload, idempotencyKey: key, attemptsMade: 0 },
      { allowInsecureServices: deps.allowInsecureServices, fetchFn: deps.fetchFn, nowMs },
    );
    return { decision_recorded: true, duplicate, callback_delivered: result.delivered };
  }

  // approved: agent first, but only for a card that is still open. A decided
  // or expired card goes straight to record_decision (duplicate / 409 / 410).
  const open = target.action_status === 'pending' &&
    (target.expires_at === null || Date.parse(target.expires_at) > nowMs());
  if (open) {
    if (target.access_state !== 'active') {
      throw new AppError('service_not_enabled', 'The service is not enabled for this workspace');
    }
    const decidedAt = new Date(nowMs()).toISOString();
    const result = await callServiceOp(
      { client: deps.client, allowInsecureServices: deps.allowInsecureServices, fetchFn: deps.fetchFn, nowMs },
      {
        slug: target.service_slug,
        op: 'decision.apply',
        params: decisionApplyParams(
          {
            action_id: body.action_id,
            external_id: '',
            idea_id: target.idea_id,
            decision: 'approved',
            reason: null,
            decided_by: actorId,
            decided_at: decidedAt,
          },
          body.acknowledged,
        ),
        requestId: key,
        workspaceId: target.workspace_id,
        subject: target.subject,
        user: actorId,
      },
    );
    if (result.kind === 'refused') {
      log.info('service_approve_refused', { action_id: body.action_id, detail: result.detail });
      throw result.error;
    }
    if (result.mapped.kind === 'error') {
      log.info('service_approve_refused', {
        action_id: body.action_id,
        code: result.mapped.error.code,
        agent_code: result.agentCode ?? undefined,
      });
      throw result.mapped.error;
    }
  }

  const row = await recordDecision(deps.client, actorId, body, key);
  const duplicate = row.outcome === 'duplicate';
  log.info('decision_recorded', { action_id: body.action_id, decision: body.decision, duplicate, service: true });
  if (row.callback_status === 'pending') {
    // The agent already applied it: the delivery is done.
    const { error } = await deps.client.rpc('record_callback_result', {
      p_action_id: body.action_id,
      p_delivered: true,
      p_detail: 'agent_applied',
      p_retry_in_seconds: null,
    });
    if (error) log.error('callback_result_not_recorded', { action_id: body.action_id, code: error.code });
    return { decision_recorded: true, duplicate, callback_delivered: true };
  }
  return { decision_recorded: true, duplicate, callback_delivered: row.callback_status === 'delivered' };
}
