// agents-trigger request handling, separated from index.ts so it can be
// unit-tested with a stub client (see _tests/agent_triggers_test.ts).
import type { SupabaseClient } from '../_shared/deps.ts';
import type { Env } from '../_shared/env.ts';
import { AppError, fromPostgrest } from '../_shared/errors.ts';
import { guardMethod, handler, json, parseJson, readRawBody } from '../_shared/http.ts';
import { log } from '../_shared/logger.ts';
import { buildTriggerPayload, deliverTrigger, type TriggerOutcome } from '../_shared/trigger.ts';
import type { TriggerRunOutcome, TriggerRunResponse } from '../_shared/types.ts';
import { isAllowedCallbackUrl, MAX_AGENT_REF_BYTES, TriggerSchema } from '../_shared/validation.ts';

/** Row returned by `begin_trigger_run`. */
interface BeginRow {
  outcome: TriggerRunOutcome;
  trigger_run_id: string | null;
  trigger_url: string | null;
  trigger_secret: string | null;
  retry_after_seconds: number | null;
}

/** What the handler needs; injectable for tests. */
export interface TriggerDeps {
  env: Pick<Env, 'featureAgentTriggers' | 'allowInsecureTriggers'>;
  /** Called lazily: the flag-off path must not create a client. */
  client: () => Pick<SupabaseClient, 'rpc'>;
  userId: (req: Request) => Promise<string>;
  fetchFn?: typeof fetch;
  now?: () => Date;
}

/** Builds the `agents-trigger` handler. */
export function createTriggerHandler(deps: TriggerDeps): (req: Request) => Promise<Response> {
  return handler('agents-trigger', async (req) => {
    // Feature flag first: no DB access and no I/O while it is off.
    if (!deps.env.featureAgentTriggers) {
      throw new AppError('feature_disabled', 'Agent triggers are not enabled');
    }

    guardMethod(req, 'POST');
    const actorId = await deps.userId(req);
    const body = parseJson(await readRawBody(req, MAX_AGENT_REF_BYTES), TriggerSchema);
    const client = deps.client();

    const { data, error } = await client
      .rpc('begin_trigger_run', { p_agent_id: body.agent_id, p_actor_user_id: actorId })
      .single<BeginRow>();
    if (error) throw fromPostgrest(error);

    switch (data.outcome) {
      case 'not_found':
      case 'not_configured':
        throw new AppError('not_found', 'No trigger configured for this agent');
      case 'disabled':
        throw new AppError('trigger_disabled', 'The trigger is disabled');
      case 'rate_limited':
        throw new AppError('rate_limited', 'Triggered too recently; try again shortly', {
          retry_after_seconds: data.retry_after_seconds ?? 1,
        });
    }

    const runId = data.trigger_run_id ?? '';
    let outcome: TriggerOutcome;
    if (
      !data.trigger_url || !isAllowedCallbackUrl(data.trigger_url, deps.env.allowInsecureTriggers)
    ) {
      outcome = { delivered: false, detail: 'trigger_url_blocked' };
    } else if (!data.trigger_secret) {
      outcome = { delivered: false, detail: 'trigger_secret_missing' };
    } else {
      const payload = buildTriggerPayload(runId, body.agent_id, deps.now?.() ?? new Date());
      outcome = await deliverTrigger(data.trigger_url, payload, data.trigger_secret, deps.fetchFn);
    }

    const recorded = await client.rpc('record_trigger_result', {
      p_trigger_run_id: runId,
      p_delivered: outcome.delivered,
      p_detail: outcome.detail,
    });
    if (recorded.error) {
      log.error('trigger_result_not_recorded', {
        trigger_run_id: runId,
        code: recorded.error.code,
      });
    }
    log.info('trigger_run', {
      trigger_run_id: runId,
      agent_id: body.agent_id,
      delivered: outcome.delivered,
      detail: outcome.detail,
    });

    const response: TriggerRunResponse = {
      run_id: runId,
      delivered: outcome.delivered,
      detail: outcome.detail,
    };
    return json(response);
  });
}
