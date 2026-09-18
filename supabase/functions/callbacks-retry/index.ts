// Supabase Edge Function: callbacks-retry  (scheduler only — X-Cron-Secret)
//
// Redelivers failed callbacks with backoff (TR-7). pg_cron runs
// invoke_callbacks_retry() every minute, which POSTs here via pg_net with the
// shared secret. Flow:
//   1. Reject anything without a valid X-Cron-Secret (401); not public.
//   2. claim_due_callbacks — row-locked (SKIP LOCKED) and leased, so
//      overlapping runs never send the same callback twice.
//   3. For each: re-sign with the agent's current secret and POST the stored
//      payload with the decision's original Idempotency-Key.
//   4. record_callback_result — delivered, retrying at the next backoff step,
//      or terminal failed after MAX_CALLBACK_ATTEMPTS.
import { attemptDelivery } from '../_shared/delivery.ts';
import { isAuthorizedCron } from '../_shared/cron.ts';
import { loadEnv } from '../_shared/env.ts';
import { AppError, fromPostgrest } from '../_shared/errors.ts';
import { guardMethod, handler, json } from '../_shared/http.ts';
import { log } from '../_shared/logger.ts';
import { serviceClient } from '../_shared/supabase.ts';
import type { CallbackPayload, RetryRunResponse } from '../_shared/types.ts';

const env = loadEnv();

/** Callbacks handled per run; the rest wait for the next minute. */
const BATCH_SIZE = 25;

/** How long a claimed row is hidden from other runs. */
const LEASE_SECONDS = 120;

interface DueCallback {
  action_id: string;
  agent_id: string;
  callback_url: string;
  callback_payload: CallbackPayload | null;
  idempotency_key: string | null;
  attempts: number;
}

Deno.serve(
  handler('callbacks-retry', async (req) => {
    guardMethod(req, 'POST');
    if (!isAuthorizedCron(req, env.cronSecret)) {
      throw new AppError('unauthorized', 'Scheduler only');
    }
    await req.body?.cancel();

    const client = serviceClient();
    const { data, error } = await client.rpc('claim_due_callbacks', {
      p_limit: BATCH_SIZE,
      p_lease_seconds: LEASE_SECONDS,
    });
    if (error) throw fromPostgrest(error);
    const due = (data ?? []) as DueCallback[];

    const run: RetryRunResponse = { claimed: due.length, delivered: 0, rescheduled: 0, failed: 0 };
    // Sequential on purpose: a handful per minute, each time-boxed.
    for (const row of due) {
      if (!row.callback_payload || !row.idempotency_key) {
        // Can't happen for decisions made through record_decision; end it
        // rather than re-claiming the row forever.
        log.error('retry_missing_decision', { action_id: row.action_id });
        await client.rpc('record_callback_result', {
          p_action_id: row.action_id,
          p_delivered: false,
          p_detail: 'decision_missing',
          p_retry_in_seconds: null,
        });
        run.failed++;
        continue;
      }
      const result = await attemptDelivery(
        client,
        {
          agentId: row.agent_id,
          callbackUrl: row.callback_url,
          payload: row.callback_payload,
          idempotencyKey: row.idempotency_key,
          attemptsMade: row.attempts,
        },
        { allowInsecureCallbacks: env.allowInsecureCallbacks },
      );
      if (result.status === 'delivered') run.delivered++;
      else if (result.status === 'retrying') run.rescheduled++;
      else run.failed++;
    }

    log.info('callbacks_retry_run', { ...run });
    return json(run);
  }),
);
