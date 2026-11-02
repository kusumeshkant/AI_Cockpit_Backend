// agent-proxy request handling, separated from index.ts so it can be
// unit-tested with stubs (see _tests/agent_proxy_test.ts). The app's only
// door to an agent service; order of checks:
//   1. POST, then the `agent_services` flag (cached read only; off → 404
//      feature_disabled before auth or any RPC).
//   2. Auth, body, resolve_service_access (workspace, role, registry, access).
//   3. Registry status, access state (built-in ops skip the access check).
//   4. X-App-Version vs min_app_version.
//   5. Op from the manifest only (no pass-through) + its roles.
//   6. hit_gateway_rate per user + service + op class.
//   7. Built-in ops run here; others: breaker, size cap, SSRF policy, sign
//      (v1, current key) and call with the class's timeout / retry rules.
//   8. Map the answer; 9. record one ids-only gateway_call row.
import type { SupabaseClient } from '../_shared/deps.ts';
import type { Env } from '../_shared/env.ts';
import { AppError, fromPostgrest, toAppError } from '../_shared/errors.ts';
import type { FeatureFlags } from '../_shared/flags.ts';
import {
  callAgent,
  DisableParamsSchema,
  EnableParamsSchema,
  type GatewayMeta,
  isBuiltInOp,
  loggableCode,
  mapOutcome,
  MAX_PROXY_REQ_BYTES,
  needsAppUpdate,
  ProxyRequestSchema,
  roleAllowed,
} from '../_shared/gateway.ts';
import { guardMethod, handler, json, parseJson, readRawBody } from '../_shared/http.ts';
import { log } from '../_shared/logger.ts';
import {
  opTimeoutMs,
  type ServiceManifest,
  ServiceManifestSchema,
  type ServiceOp,
} from '../_shared/service_manifest.ts';
import { IdempotencyKeySchema, isAllowedCallbackUrl } from '../_shared/validation.ts';

/** Row returned by `resolve_service_access`. */
interface ResolveRow {
  workspace_id: string;
  role: string;
  slug: string;
  status: 'draft' | 'active' | 'paused' | 'retired';
  base_url: string;
  contract_version: string;
  min_app_version: string | null;
  manifest: unknown;
  open_until: string | null;
  access_state: 'active' | 'disabled' | 'blocked' | null;
  subject: string | null;
}

/** Row returned by enable_service / disable_service. */
interface AccessRow {
  state: string;
  consent_version: string | null;
  consented_at: string | null;
  changed: boolean;
}

/** What the handler needs; injectable for tests. */
export interface ProxyDeps {
  env: Pick<Env, 'allowInsecureServices' | 'gatewayRates'>;
  flags: Pick<FeatureFlags, 'isEnabled'>;
  /** Called lazily: the flag-off path must not create a client. */
  client: () => Pick<SupabaseClient, 'rpc'>;
  userId: (req: Request) => Promise<string>;
  fetchFn?: typeof fetch;
  nowMs?: () => number;
  sleep?: (ms: number) => Promise<void>;
  uuid?: () => string;
  random?: () => number;
}

/** The success envelope's `data`. */
interface ProxyData {
  result: unknown;
  meta: GatewayMeta & { request_id: string };
}

/** Builds the `agent-proxy` handler. */
export function createProxyHandler(deps: ProxyDeps): (req: Request) => Promise<Response> {
  const nowMs = deps.nowMs ?? Date.now;
  const uuid = deps.uuid ?? (() => crypto.randomUUID());

  return handler('agent-proxy', async (req) => {
    guardMethod(req, 'POST');
    if (!(await deps.flags.isEnabled('agent_services'))) {
      throw new AppError('feature_disabled', 'Agent services are not enabled');
    }

    const started = nowMs();
    const userId = await deps.userId(req);
    const body = parseJson(await readRawBody(req, MAX_PROXY_REQ_BYTES), ProxyRequestSchema);
    const client = deps.client();

    const resolved = await client
      .rpc('resolve_service_access', { p_user_id: userId, p_slug: body.service })
      .single<ResolveRow>();
    if (resolved.error) throw fromPostgrest(resolved.error);
    const access = resolved.data;

    // Filled in while the request runs; recorded once at the end.
    const outcome = { attempts: 0, agentOk: null as boolean | null, countUse: false };
    let requestId = '';

    const record = async (status: number) => {
      const { error } = await client.rpc('record_gateway_outcome', {
        p_workspace_id: access.workspace_id,
        p_slug: access.slug,
        p_op: body.op,
        p_status: status,
        p_latency_ms: Math.max(0, Math.round(nowMs() - started)),
        p_attempts: outcome.attempts,
        p_agent_ok: outcome.agentOk,
        p_count_use: outcome.countUse,
      });
      if (error) log.error('gateway_call_not_recorded', { service: access.slug, op: body.op, code: error.code });
    };

    const run = async (): Promise<Response> => {
      // 3. Registry and access.
      if (access.status === 'draft' || access.status === 'retired') {
        throw new AppError('service_not_found', 'Service not found');
      }
      const builtIn = isBuiltInOp(body.op);
      if (!builtIn) {
        if (access.status === 'paused') throw new AppError('agent_paused', 'The service is paused');
        if (access.access_state !== 'active') {
          // Blocked looks exactly like disabled / never enabled.
          throw new AppError('service_not_enabled', 'The service is not enabled for this workspace');
        }
      }

      // 4. App version.
      if (needsAppUpdate(req.headers.get('x-app-version'), access.min_app_version)) {
        throw new AppError('app_update_required', 'Update the app to use this service');
      }

      // 5. Op + role (built-ins: owner only, rate-limited as writes).
      let op: ServiceOp;
      let manifestErrors: ServiceManifest['errors'] = [];
      if (builtIn) {
        op = { class: 'write', roles: ['owner'], max_request_bytes: 1024, max_response_bytes: 1024 };
      } else {
        const manifest = ServiceManifestSchema.safeParse(access.manifest);
        if (!manifest.success) {
          log.error('service_manifest_invalid', { service: access.slug });
          throw new AppError('agent_error', 'The service returned an unexpected answer');
        }
        const found = Object.hasOwn(manifest.data.ops, body.op) ? manifest.data.ops[body.op] : undefined;
        if (!found) throw new AppError('unsupported_op', 'This operation is not supported');
        op = found;
        manifestErrors = manifest.data.errors;
      }
      if (!roleAllowed(op, access.role)) {
        throw new AppError('forbidden', 'Your role cannot do this');
      }

      // Request id: the Idempotency-Key (required for write / destructive).
      const keyHeader = req.headers.get('idempotency-key');
      if (keyHeader !== null || (!builtIn && op.class !== 'read')) {
        const key = IdempotencyKeySchema.safeParse(keyHeader);
        if (!key.success) throw new AppError('validation', 'A valid Idempotency-Key header is required');
        requestId = key.data;
      } else {
        requestId = uuid();
      }

      // 6. Rate limit.
      const rate = await client
        .rpc('hit_gateway_rate', {
          p_user_id: userId,
          p_slug: access.slug,
          p_class: op.class,
          p_max: deps.env.gatewayRates[op.class],
          p_window: '60 seconds',
        })
        .single<{ limited: boolean; retry_after_seconds: number }>();
      if (rate.error) throw fromPostgrest(rate.error);
      if (rate.data.limited) {
        throw new AppError('rate_limited', 'Too many requests; try again shortly', {
          retry_after_seconds: rate.data.retry_after_seconds,
        });
      }

      // 7a. Built-in ops.
      if (builtIn) {
        const result = await runBuiltIn(client, userId, access.slug, body.op, body.params);
        return json<ProxyData>({ result, meta: { request_id: requestId } });
      }

      // 7b. Forwarded ops.
      if (access.open_until && Date.parse(access.open_until) > nowMs()) {
        throw new AppError('agent_unavailable', 'The service is unavailable', {
          retry_after_seconds: Math.max(1, Math.ceil((Date.parse(access.open_until) - nowMs()) / 1000)),
        });
      }
      const forward = JSON.stringify(body.if_match === undefined
        ? { params: body.params }
        : { params: body.params, if_match: body.if_match });
      if (new TextEncoder().encode(forward).byteLength > op.max_request_bytes) {
        throw new AppError('payload_too_large', `Body exceeds ${op.max_request_bytes} bytes`);
      }
      const url = `${access.base_url.replace(/\/+$/, '')}/cockpit/v1/ops/${body.op}`;
      if (!isAllowedCallbackUrl(url, deps.env.allowInsecureServices)) {
        log.error('service_url_blocked', { service: access.slug });
        throw new AppError('agent_error', 'The service returned an unexpected answer');
      }
      const key = await client
        .rpc('get_service_signing_key', { p_slug: access.slug })
        .maybeSingle<{ key_id: string; secret: string }>();
      if (key.error) throw fromPostgrest(key.error);
      if (!key.data?.secret) {
        log.error('service_signing_key_missing', { service: access.slug });
        throw new AppError('agent_error', 'The service returned an unexpected answer');
      }

      const { outcome: answer, attempts } = await callAgent(
        {
          url,
          body: forward,
          keyId: key.data.key_id,
          secret: key.data.secret,
          contractVersion: access.contract_version,
          workspace: access.subject ?? access.workspace_id,
          user: userId,
          requestId,
          op,
          timeoutMs: opTimeoutMs(op),
        },
        {
          fetchFn: deps.fetchFn ?? fetch,
          nowSeconds: () => Math.floor(nowMs() / 1000),
          sleep: deps.sleep ?? ((ms) => new Promise((resolve) => setTimeout(resolve, ms))),
          nonce: uuid,
          random: deps.random,
        },
      );
      const mapped = mapOutcome(answer, { errors: manifestErrors });
      outcome.attempts = attempts;
      outcome.agentOk = mapped.agentOk;
      outcome.countUse = mapped.kind === 'ok';
      log.info('agent_call', {
        service: access.slug,
        op: body.op,
        request_id: requestId,
        attempts,
        agent_status: answer.kind === 'response' ? answer.status : answer.kind,
        ...(mapped.kind === 'error' ? { code: mapped.error.code, agent_code: loggableCode(mapped.agentCode ?? '') } : {}),
      });
      if (mapped.kind === 'error') throw mapped.error;
      return json<ProxyData>({ result: mapped.result, meta: { ...mapped.meta, request_id: requestId } }, mapped.status);
    };

    try {
      const response = await run();
      await record(response.status);
      return response;
    } catch (error) {
      await record(toAppError(error).status);
      throw error;
    }
  });
}

/** `service.enable` / `service.disable`: owner-only, idempotent. */
async function runBuiltIn(
  client: Pick<SupabaseClient, 'rpc'>,
  userId: string,
  slug: string,
  op: string,
  params: Record<string, unknown>,
): Promise<{ state: string; consent_version: string | null; consented_at: string | null; changed: boolean }> {
  if (op === 'service.enable') {
    const parsed = EnableParamsSchema.safeParse(params);
    if (!parsed.success) throw new AppError('validation', 'consent_version is required');
    const { data, error } = await client
      .rpc('enable_service', {
        p_user_id: userId,
        p_slug: slug,
        p_consent_version: parsed.data.consent_version,
      })
      .single<AccessRow>();
    if (error) throw fromPostgrest(error);
    return pickAccess(data);
  }
  if (!DisableParamsSchema.safeParse(params).success) throw new AppError('validation', 'No params expected');
  const { data, error } = await client
    .rpc('disable_service', { p_user_id: userId, p_slug: slug })
    .maybeSingle<AccessRow>();
  if (error) throw fromPostgrest(error);
  return data ? pickAccess(data) : { state: 'disabled', consent_version: null, consented_at: null, changed: false };
}

const pickAccess = (row: AccessRow) => ({
  state: row.state,
  consent_version: row.consent_version,
  consented_at: row.consented_at,
  changed: row.changed,
});
