// Agent services gateway (agent-proxy): request schema, version / role checks,
// the agent call with Cockpit-Signature v1, retry rules and answer mapping.
// Pure helpers (fetch / sleep / clock injected) so the rules are unit-tested
// in _tests/gateway_test.ts. Wire contract: docs/agent-gateway-wire-v1.md.
import { z } from './deps.ts';
import { AppError, type ErrorCode } from './errors.ts';
import { signedHeadersV1 } from './hmac.ts';
import {
  type PASSABLE_AGENT_ERRORS,
  type ServiceManifest,
  type ServiceOp,
} from './service_manifest.ts';

/** Max raw body of an app → proxy request. */
export const MAX_PROXY_REQ_BYTES = 64 * 1024;

/** Ops the proxy answers itself (never forwarded). */
export const BUILT_IN_OPS = ['service.enable', 'service.disable'] as const;
/** A built-in op name. */
export type BuiltInOp = (typeof BUILT_IN_OPS)[number];

/** Is [op] answered by the proxy itself? */
export const isBuiltInOp = (op: string): op is BuiltInOp =>
  (BUILT_IN_OPS as readonly string[]).includes(op);

/** Default per-user limits per op class and minute (env-overridable). */
export const DEFAULT_GATEWAY_RATES = { read: 120, write: 30, destructive: 5 } as const;

/** Retry-After sent with agent_unavailable when the agent can't be reached. */
export const UNAVAILABLE_RETRY_AFTER_SECONDS = 5;

/** `agent-proxy` body. */
export const ProxyRequestSchema = z
  .object({
    service: z.string().regex(/^[a-z][a-z0-9-]{1,39}$/),
    op: z.string().regex(/^[a-z][a-z0-9_.-]{0,63}$/),
    params: z.record(z.string(), z.unknown()).default({}),
    if_match: z.string().min(1).max(200).optional(),
  })
  .strict();

/** Parsed proxy request. */
export type ProxyRequest = z.infer<typeof ProxyRequestSchema>;

/** Params of the built-in `service.enable`. */
export const EnableParamsSchema = z.object({ consent_version: z.string().min(1).max(32) }).strict();

/** Params of the built-in `service.disable`. */
export const DisableParamsSchema = z.object({}).strict();

// ---------------------------------------------------------------------------
// Versions and roles
// ---------------------------------------------------------------------------

/** `x.y.z` (optional `+build` / `-pre` ignored) → [x, y, z], or null. */
export function parseSemver(value: string | null | undefined): [number, number, number] | null {
  const match = /^(\d{1,6})\.(\d{1,6})\.(\d{1,6})(?:[+-][0-9A-Za-z.+-]*)?$/.exec((value ?? '').trim());
  return match ? [Number(match[1]), Number(match[2]), Number(match[3])] : null;
}

/** -1 / 0 / 1 comparison of two parsed versions. */
export function compareSemver(a: [number, number, number], b: [number, number, number]): number {
  for (let i = 0; i < 3; i++) if (a[i] !== b[i]) return a[i] < b[i] ? -1 : 1;
  return 0;
}

/**
 * Whether the app must update: only when [minAppVersion] is set, and then a
 * missing or unparseable `X-App-Version` counts as too old.
 */
export function needsAppUpdate(appVersion: string | null, minAppVersion: string | null): boolean {
  const min = parseSemver(minAppVersion);
  if (!min) return false;
  const have = parseSemver(appVersion);
  return !have || compareSemver(have, min) < 0;
}

/** Whether a caller with [role] may run [op]. */
export const roleAllowed = (op: Pick<ServiceOp, 'roles'>, role: string): boolean =>
  (op.roles as readonly string[]).includes(role);

// ---------------------------------------------------------------------------
// Calling the agent
// ---------------------------------------------------------------------------

/** One attempt's raw outcome. */
export type AttemptOutcome =
  | { kind: 'network' }
  | { kind: 'timeout' }
  | { kind: 'response'; status: number; body: unknown; problem?: 'oversize' | 'invalid_json' };

/** Statuses (and failures) worth one retry for read / write ops. */
export function isTransient(outcome: AttemptOutcome): boolean {
  return outcome.kind !== 'response' || [502, 503, 504].includes(outcome.status);
}

/** Attempts allowed for [cls]: read / write get one retry, destructive none. */
export const maxAttempts = (cls: ServiceOp['class']): number => (cls === 'destructive' ? 1 : 2);

/** Reads [response]'s body as text, giving up past [maxBytes]. */
export async function readCapped(response: Response, maxBytes: number): Promise<string | null> {
  const declared = Number(response.headers.get('content-length') ?? '0');
  if (declared > maxBytes) {
    await response.body?.cancel();
    return null;
  }
  if (!response.body) return '';
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > maxBytes) {
      await reader.cancel();
      return null;
    }
    chunks.push(value);
  }
  const bytes = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return new TextDecoder().decode(bytes);
}

/** Everything one forwarded call needs. */
export interface AgentCall {
  url: string;
  body: string;
  keyId: string;
  secret: string;
  contractVersion: string;
  workspace: string;
  user: string;
  requestId: string;
  op: ServiceOp;
  timeoutMs: number;
  /** Overrides the class's attempt count (deliveries / jobs retry by backoff instead). */
  maxAttempts?: number;
}

/** Injected I/O. */
export interface CallIo {
  fetchFn: typeof fetch;
  /** Unix seconds. */
  nowSeconds: () => number;
  sleep: (ms: number) => Promise<void>;
  /** A fresh nonce per attempt. */
  nonce: () => string;
  /** Jitter in [0, 1). */
  random?: () => number;
}

/** Sends [call] with the op's retry rules; returns the last outcome + attempts. */
export async function callAgent(
  call: AgentCall,
  io: CallIo,
): Promise<{ outcome: AttemptOutcome; attempts: number }> {
  const path = new URL(call.url).pathname;
  const limit = call.maxAttempts ?? maxAttempts(call.op.class);
  let outcome: AttemptOutcome = { kind: 'network' };
  let attempts = 0;
  while (attempts < limit) {
    attempts++;
    const headers = await signedHeadersV1(
      {
        keyId: call.keyId,
        timestamp: io.nowSeconds(),
        nonce: io.nonce(),
        method: 'POST',
        path,
        workspace: call.workspace,
        user: call.user,
        requestId: call.requestId,
      },
      call.body,
      call.secret,
      call.contractVersion,
    );
    outcome = await attemptOnce(call, headers, io.fetchFn);
    if (!isTransient(outcome) || attempts >= limit) break;
    await io.sleep(250 + Math.floor((io.random ?? Math.random)() * 250));
  }
  return { outcome, attempts };
}

async function attemptOnce(
  call: AgentCall,
  headers: Record<string, string>,
  fetchFn: typeof fetch,
): Promise<AttemptOutcome> {
  const signal = AbortSignal.timeout(call.timeoutMs);
  try {
    const response = await fetchFn(call.url, {
      method: 'POST',
      redirect: 'manual',
      signal,
      headers: { ...headers, 'User-Agent': 'Cockpit-Gateway/1' },
      body: call.body,
    });
    const text = await readCapped(response, call.op.max_response_bytes);
    if (text === null) return { kind: 'response', status: response.status, body: null, problem: 'oversize' };
    try {
      return { kind: 'response', status: response.status, body: text ? JSON.parse(text) : null };
    } catch {
      return { kind: 'response', status: response.status, body: null, problem: 'invalid_json' };
    }
  } catch (error) {
    const name = error instanceof Error || error instanceof DOMException ? error.name : '';
    return name === 'TimeoutError' || signal.aborted ? { kind: 'timeout' } : { kind: 'network' };
  }
}

// ---------------------------------------------------------------------------
// Mapping the agent's answer
// ---------------------------------------------------------------------------

const UsageSchema = z.object({
  used: z.number().int().min(0),
  limit: z.number().int().min(0).nullable(),
  trial_ends_at: z.string().datetime({ offset: true }).nullable(),
});

const AgentSuccessSchema = z.object({
  ok: z.literal(true),
  result: z.unknown().refine((value) => value !== undefined, 'result is required'),
  meta: z.record(z.string(), z.unknown()).optional(),
});

const AgentErrorSchema = z.object({
  ok: z.literal(false),
  error: z.object({ code: z.string().min(1).max(64) }).passthrough(),
});

/** The `meta` Cockpit passes on (type-checked; anything else is dropped). */
export interface GatewayMeta {
  usage?: z.infer<typeof UsageSchema>;
  poll_after_ms?: number;
  version?: string;
}

/** Picks the allowed, well-typed meta fields. */
export function pickMeta(meta: Record<string, unknown> | undefined): GatewayMeta {
  const out: GatewayMeta = {};
  if (!meta) return out;
  const usage = UsageSchema.safeParse(meta.usage);
  if (usage.success) out.usage = usage.data;
  const poll = meta.poll_after_ms;
  if (typeof poll === 'number' && Number.isInteger(poll) && poll >= 0 && poll <= 600_000) {
    out.poll_after_ms = poll;
  }
  const version = meta.version;
  if (typeof version === 'string' && version.length > 0 && version.length <= 200) out.version = version;
  return out;
}

/** What the proxy answers, plus what it records about the agent. */
export type Mapped =
  | { kind: 'ok'; status: 200 | 202; result: unknown; meta: GatewayMeta; agentOk: true }
  | { kind: 'error'; error: AppError; agentOk: boolean; agentCode?: string };

const MESSAGES: Record<(typeof PASSABLE_AGENT_ERRORS)[number], string> = {
  validation: 'The service rejected the input',
  not_found: 'Not found',
  conflict: 'The item changed; reload and try again',
  trial_ended: 'The trial has ended',
  quota_reached: 'The usage limit has been reached',
  approval_blocked: 'This cannot be approved yet',
  agent_paused: 'The service is paused',
  idea_final: 'This idea has already been decided',
};

/** Agent error code as logged: snake_case only, else `invalid`. */
export const loggableCode = (code: unknown): string =>
  typeof code === 'string' && /^[a-z][a-z0-9_]{0,39}$/.test(code) ? code : 'invalid';

/**
 * Maps an attempt outcome to the proxy's answer. Agent texts (message,
 * details) are never passed on; only declared codes reach the app.
 */
export function mapOutcome(outcome: AttemptOutcome, manifest: Pick<ServiceManifest, 'errors'>): Mapped {
  if (outcome.kind === 'network') {
    return {
      kind: 'error',
      agentOk: false,
      error: new AppError('agent_unavailable', 'The service is unavailable', {
        retry_after_seconds: UNAVAILABLE_RETRY_AFTER_SECONDS,
      }),
    };
  }
  if (outcome.kind === 'timeout') {
    return { kind: 'error', agentOk: false, error: new AppError('agent_timeout', 'The service took too long') };
  }
  const agentError = (agentOk: boolean, agentCode?: string): Mapped => ({
    kind: 'error',
    agentOk,
    agentCode,
    error: new AppError('agent_error', 'The service returned an unexpected answer'),
  });
  if (outcome.problem) return agentError(false, outcome.problem);

  if (outcome.status >= 200 && outcome.status < 300) {
    const parsed = AgentSuccessSchema.safeParse(outcome.body);
    if (!parsed.success) return agentError(false, 'invalid_envelope');
    return {
      kind: 'ok',
      status: outcome.status === 202 ? 202 : 200,
      result: parsed.data.result,
      meta: pickMeta(parsed.data.meta),
      agentOk: true,
    };
  }

  const parsed = AgentErrorSchema.safeParse(outcome.body);
  if (!parsed.success) {
    if (outcome.status === 503) {
      return {
        kind: 'error',
        agentOk: false,
        agentCode: 'invalid_envelope',
        error: new AppError('agent_unavailable', 'The service is unavailable', {
          retry_after_seconds: UNAVAILABLE_RETRY_AFTER_SECONDS,
        }),
      };
    }
    return agentError(false, 'invalid_envelope');
  }
  const code = parsed.data.error.code;
  const healthy = outcome.status < 500;
  if (!(manifest.errors as readonly string[]).includes(code)) {
    return agentError(healthy, loggableCode(code));
  }
  const declared = code as (typeof PASSABLE_AGENT_ERRORS)[number];
  if (declared === 'idea_final') {
    return {
      kind: 'error',
      agentOk: true,
      agentCode: code,
      error: new AppError('conflict', MESSAGES.idea_final, { code: 'idea_final' }),
    };
  }
  return {
    kind: 'error',
    agentOk: true,
    agentCode: code,
    error: new AppError(declared as ErrorCode, MESSAGES[declared]),
  };
}
