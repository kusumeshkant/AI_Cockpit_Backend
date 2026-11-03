// service-deletions-retry request handling (unit-tested in
// _tests/service_decisions_test.ts). Asks services to forget deleted
// workspaces (jobs queued by delete_account_data, 0014):
//   1. POST, then the `agent_services` flag (cached read only), then the
//      X-Cron-Secret (scheduler only).
//   2. claim_due_deletion_jobs — leased, SKIP LOCKED.
//   3. For each job: the manifest's deletion_op through the gateway call with
//      destructive rules (one attempt; the job's own backoff is the retry),
//      X-Cockpit-Workspace = the job's subject, X-Cockpit-User = system,
//      request id = the job id.
//   4. record_deletion_job_result — done on success or `not_found`, else
//      pending with backoff, terminal failed after MAX_CALLBACK_ATTEMPTS.
// Ids-only logs; the job holds no PII.
import type { SupabaseClient } from '../_shared/deps.ts';
import type { Env } from '../_shared/env.ts';
import { AppError, fromPostgrest } from '../_shared/errors.ts';
import type { FeatureFlags } from '../_shared/flags.ts';
import { guardMethod, handler, json } from '../_shared/http.ts';
import { log } from '../_shared/logger.ts';
import { retryDelaySeconds } from '../_shared/retry.ts';
import { callServiceOp, type ServiceCallResult } from '../_shared/service_call.ts';

/** Jobs per run; the rest wait for the next run. */
export const DELETION_BATCH_SIZE = 25;

/** How long a claimed job is hidden from other runs. */
export const DELETION_LEASE_SECONDS = 120;

interface DueJob {
  id: string;
  service_slug: string;
  subject: string;
  attempts: number;
}

/** What the handler needs; injectable for tests. */
export interface DeletionDeps {
  env: Pick<Env, 'allowInsecureServices'>;
  flags: Pick<FeatureFlags, 'isEnabled'>;
  /** Constant-time X-Cron-Secret check. */
  authorized: (req: Request) => boolean;
  client: () => SupabaseClient;
  fetchFn?: typeof fetch;
  nowMs?: () => number;
}

/** done / retry for one deletion call. */
export function classifyDeletion(result: ServiceCallResult): { done: boolean; detail: string } {
  if (result.kind === 'refused') return { done: false, detail: result.detail };
  if (result.mapped.kind === 'ok') return { done: true, detail: 'agent_deleted' };
  if (result.agentCode === 'not_found') return { done: true, detail: 'agent_not_found' };
  const o = result.outcome;
  return {
    done: false,
    detail: o.kind === 'response' ? (result.agentCode ? `agent_${result.agentCode}` : `http_${o.status}`) : o.kind,
  };
}

/** Builds the `service-deletions-retry` handler. */
export function createDeletionsHandler(deps: DeletionDeps): (req: Request) => Promise<Response> {
  return handler('service-deletions-retry', async (req) => {
    guardMethod(req, 'POST');
    if (!(await deps.flags.isEnabled('agent_services'))) {
      throw new AppError('feature_disabled', 'Agent services are not enabled');
    }
    if (!deps.authorized(req)) throw new AppError('unauthorized', 'Scheduler only');
    await req.body?.cancel();

    const client = deps.client();
    const { data, error } = await client.rpc('claim_due_deletion_jobs', {
      p_limit: DELETION_BATCH_SIZE,
      p_lease_seconds: DELETION_LEASE_SECONDS,
    });
    if (error) throw fromPostgrest(error);
    const due = (data ?? []) as DueJob[];

    const run = { claimed: due.length, done: 0, rescheduled: 0, failed: 0 };
    for (const job of due) {
      let verdict: { done: boolean; detail: string };
      try {
        const result = await callServiceOp(
          { client, allowInsecureServices: deps.env.allowInsecureServices, fetchFn: deps.fetchFn, nowMs: deps.nowMs },
          {
            slug: job.service_slug,
            op: (manifest) => manifest.deletion_op,
            params: {},
            requestId: job.id,
            // The workspace is gone: no gateway_call row (it has a workspace FK).
            workspaceId: null,
            subject: job.subject,
            user: 'system',
            maxAttempts: 1,
          },
        );
        verdict = classifyDeletion(result);
      } catch {
        verdict = { done: false, detail: 'gateway_error' };
      }
      const retryIn = verdict.done ? null : retryDelaySeconds(job.attempts + 1);
      const recorded = await client.rpc('record_deletion_job_result', {
        p_job_id: job.id,
        p_done: verdict.done,
        p_detail: verdict.detail,
        p_retry_in_seconds: retryIn,
      });
      if (recorded.error) log.error('deletion_job_not_recorded', { job_id: job.id, code: recorded.error.code });
      const status = (recorded.data as string | null) ?? (verdict.done ? 'done' : retryIn === null ? 'failed' : 'pending');
      if (status === 'done') run.done++;
      else if (status === 'pending') run.rescheduled++;
      else run.failed++;
      log.info('service_deletion_attempt', {
        job_id: job.id,
        service: job.service_slug,
        attempt: job.attempts + 1,
        detail: verdict.detail,
        status,
      });
    }
    log.info('service_deletions_run', { ...run });
    return json(run);
  });
}
