// One signed call to a service op outside agent-proxy (0014): decisions
// (actions-decision, callbacks-retry) and deletion jobs
// (service-deletions-retry). Same rules as the proxy: registry status,
// manifest op only, circuit breaker, SSRF policy, Cockpit-Signature v1 with
// the current outbound key, class timeouts, answer mapping. Never logs params.
import type { SupabaseClient } from './deps.ts';
import { AppError, fromPostgrest } from './errors.ts';
import { type AttemptOutcome, callAgent, loggableCode, type Mapped, mapOutcome } from './gateway.ts';
import { log } from './logger.ts';
import { opTimeoutMs, type ServiceManifest, ServiceManifestSchema } from './service_manifest.ts';
import { isAllowedCallbackUrl } from './validation.ts';

/** Row of `get_service_endpoint`. */
interface Endpoint {
  slug: string;
  status: 'draft' | 'active' | 'paused' | 'retired';
  base_url: string;
  contract_version: string;
  manifest: unknown;
  open_until: string | null;
}

/** I/O for a service call. */
export interface ServiceCallDeps {
  client: Pick<SupabaseClient, 'rpc'>;
  allowInsecureServices: boolean;
  fetchFn?: typeof fetch;
  nowMs?: () => number;
  sleep?: (ms: number) => Promise<void>;
  uuid?: () => string;
}

/** What to call. */
export interface ServiceCallInput {
  slug: string;
  /** The op, or how to pick it from the manifest (e.g. its deletion_op). */
  op: string | ((manifest: ServiceManifest) => string);
  params: Record<string, unknown>;
  /** X-Cockpit-Request-Id (stable across retries). */
  requestId: string;
  /** For the gateway_call row + breaker; null skips recording (no workspace left). */
  workspaceId: string | null;
  /** X-Cockpit-Workspace. */
  subject: string;
  /** X-Cockpit-User: a user id or `system`. */
  user: string;
  maxAttempts?: number;
  /** Count a success as the workspace's first use. */
  countUse?: boolean;
}

/** Refused before calling out, or the agent's mapped answer. */
export type ServiceCallResult =
  | { kind: 'refused'; error: AppError; detail: string }
  | { kind: 'called'; outcome: AttemptOutcome; mapped: Mapped; attempts: number; agentCode: string | null };

const refused = (error: AppError, detail: string): ServiceCallResult => ({ kind: 'refused', error, detail });
const agentError = () => new AppError('agent_error', 'The service returned an unexpected answer');

/** The agent's raw error code, if it answered with an error envelope. */
export function rawAgentCode(outcome: AttemptOutcome): string | null {
  if (outcome.kind !== 'response' || outcome.status < 300) return null;
  const code = (outcome.body as { error?: { code?: unknown } } | null)?.error?.code;
  return typeof code === 'string' ? loggableCode(code) : null;
}

/** Calls [input.op] of [input.slug]; never throws for agent problems. */
export async function callServiceOp(deps: ServiceCallDeps, input: ServiceCallInput): Promise<ServiceCallResult> {
  const nowMs = deps.nowMs ?? Date.now;
  const uuid = deps.uuid ?? (() => crypto.randomUUID());
  const started = nowMs();

  const endpoint = await deps.client.rpc('get_service_endpoint', { p_slug: input.slug }).maybeSingle<Endpoint>();
  if (endpoint.error) throw fromPostgrest(endpoint.error);
  const e = endpoint.data;
  if (!e || e.status === 'draft' || e.status === 'retired') {
    return refused(new AppError('service_not_found', 'Service not found'), 'service_not_found');
  }
  const manifest = ServiceManifestSchema.safeParse(e.manifest);
  if (!manifest.success) return refused(agentError(), 'manifest_invalid');
  const opName = typeof input.op === 'string' ? input.op : input.op(manifest.data);
  const op = Object.hasOwn(manifest.data.ops, opName) ? manifest.data.ops[opName] : undefined;
  if (!op) return refused(new AppError('unsupported_op', 'This operation is not supported'), 'unsupported_op');
  if (e.open_until && Date.parse(e.open_until) > nowMs()) {
    return refused(
      new AppError('agent_unavailable', 'The service is unavailable', {
        retry_after_seconds: Math.max(1, Math.ceil((Date.parse(e.open_until) - nowMs()) / 1000)),
      }),
      'breaker_open',
    );
  }
  const url = `${e.base_url.replace(/\/+$/, '')}/cockpit/v1/ops/${opName}`;
  if (!isAllowedCallbackUrl(url, deps.allowInsecureServices)) return refused(agentError(), 'url_blocked');
  const key = await deps.client
    .rpc('get_service_signing_key', { p_slug: e.slug })
    .maybeSingle<{ key_id: string; secret: string }>();
  if (key.error) throw fromPostgrest(key.error);
  if (!key.data?.secret) return refused(agentError(), 'key_missing');

  const { outcome, attempts } = await callAgent(
    {
      url,
      body: JSON.stringify({ params: input.params }),
      keyId: key.data.key_id,
      secret: key.data.secret,
      contractVersion: e.contract_version,
      workspace: input.subject,
      user: input.user,
      requestId: input.requestId,
      op,
      timeoutMs: opTimeoutMs(op),
      maxAttempts: input.maxAttempts,
    },
    {
      fetchFn: deps.fetchFn ?? fetch,
      nowSeconds: () => Math.floor(nowMs() / 1000),
      sleep: deps.sleep ?? ((ms) => new Promise((resolve) => setTimeout(resolve, ms))),
      nonce: uuid,
    },
  );
  const mapped = mapOutcome(outcome, manifest.data);

  if (input.workspaceId) {
    const { error } = await deps.client.rpc('record_gateway_outcome', {
      p_workspace_id: input.workspaceId,
      p_slug: e.slug,
      p_op: opName,
      p_status: mapped.kind === 'ok' ? mapped.status : mapped.error.status,
      p_latency_ms: Math.max(0, Math.round(nowMs() - started)),
      p_attempts: attempts,
      p_agent_ok: mapped.agentOk,
      p_count_use: (input.countUse ?? false) && mapped.kind === 'ok',
    });
    if (error) {
      // Metrics only; the call itself already happened.
      log.warn('gateway_call_not_recorded', { service: e.slug, op: opName, code: error.code });
    }
  }
  return { kind: 'called', outcome, mapped, attempts, agentCode: rawAgentCode(outcome) };
}
