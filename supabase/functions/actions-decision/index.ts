// Supabase Edge Function: actions-decision  (JWT — called by the signed-in app)
//
// Flow:
//   1. Authenticate the caller; require an Idempotency-Key header.
//   2. Validate the body.
//   3. record_decision — decision + audit committed atomically and
//      idempotently (TR-3, TR-6). Outcome → HTTP:
//        not_found 404 · already_decided 409 · expired 410 · invalid_edit 422
//   4. Deliver the signed callback (only after commit). A duplicate request
//      delivers only if no attempt was recorded yet (`pending`); once one is,
//      redelivery belongs to callbacks-retry. Every send carries the
//      decision's Idempotency-Key so the agent can drop repeats.
//   5. record_callback_result — delivered, or retrying with backoff (TR-7),
//      or failed when the URL is blocked / the secret is missing.
import { attemptDelivery } from '../_shared/delivery.ts';
import { loadEnv } from '../_shared/env.ts';
import { AppError, fromPostgrest } from '../_shared/errors.ts';
import { guardMethod, handler, json, parseJson, readRawBody } from '../_shared/http.ts';
import { log } from '../_shared/logger.ts';
import { serviceClient, userIdFromReq } from '../_shared/supabase.ts';
import type {
  CallbackPayload,
  CallbackStatus,
  DecisionOutcome,
  DecisionResponse,
} from '../_shared/types.ts';
import { DecisionSchema, IdempotencyKeySchema, MAX_DECISION_BYTES } from '../_shared/validation.ts';

const env = loadEnv();

interface DecisionRow {
  outcome: DecisionOutcome;
  callback_url: string | null;
  callback_payload: CallbackPayload | null;
  agent_id: string | null;
  callback_status: CallbackStatus | null;
}

Deno.serve(
  handler('actions-decision', async (req) => {
    guardMethod(req, 'POST');
    const actorId = await userIdFromReq(req);

    const key = IdempotencyKeySchema.safeParse(req.headers.get('idempotency-key'));
    if (!key.success) {
      throw new AppError('validation', 'A valid Idempotency-Key header is required');
    }
    const body = parseJson(await readRawBody(req, MAX_DECISION_BYTES), DecisionSchema);

    const client = serviceClient();
    const { data, error } = await client
      .rpc('record_decision', {
        p_action_id: body.action_id,
        p_actor_user_id: actorId,
        p_decision: body.decision,
        p_edited_payload: body.edited_payload ?? null,
        p_reason: body.reason ?? null,
        p_idempotency_key: key.data,
      })
      .single<DecisionRow>();
    if (error) throw fromPostgrest(error);

    switch (data.outcome) {
      case 'not_found':
        throw new AppError('not_found', 'Action not found');
      case 'already_decided':
        throw new AppError('conflict', 'Action was already decided');
      case 'expired':
        throw new AppError('expired', 'Action has expired');
      case 'invalid_edit':
        throw new AppError('validation', 'edited_payload contains non-editable fields');
    }

    const duplicate = data.outcome === 'duplicate';
    log.info('decision_recorded', {
      action_id: body.action_id,
      decision: body.decision,
      duplicate,
    });

    if (duplicate && data.callback_status !== 'pending') {
      const response: DecisionResponse = {
        decision_recorded: true,
        duplicate: true,
        callback_delivered: data.callback_status === 'delivered',
      };
      return json(response);
    }

    const delivered = await deliver(data, key.data);
    const response: DecisionResponse = {
      decision_recorded: true,
      duplicate,
      callback_delivered: delivered,
    };
    return json(response);
  }),
);

/** First delivery attempt; failures are scheduled for retry. Never throws. */
async function deliver(row: DecisionRow, idempotencyKey: string): Promise<boolean> {
  const payload = row.callback_payload;
  if (!payload || !row.agent_id || !row.callback_url) return false;
  const result = await attemptDelivery(
    serviceClient(),
    {
      agentId: row.agent_id,
      callbackUrl: row.callback_url,
      payload,
      idempotencyKey,
      attemptsMade: 0,
    },
    { allowInsecureCallbacks: env.allowInsecureCallbacks },
  );
  return result.delivered;
}
