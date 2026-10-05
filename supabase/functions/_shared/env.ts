// Typed environment. Functions call loadEnv() at module load so a missing
// required variable fails the boot, not the first request.

/** Runtime configuration. */
export interface Env {
  /** Supabase API URL (auto-injected). */
  supabaseUrl: string;
  /** Service-role key (auto-injected). Never leaves the function. */
  serviceRoleKey: string;
  /** Public base for Edge Functions, used to build inbound URLs. */
  publicInboundBaseUrl: string;
  /** Firebase service account JSON; push is skipped when absent. */
  fcmServiceAccountJson: string | null;
  /** Local development only: allow http:// and private-network callbacks. */
  allowInsecureCallbacks: boolean;
  /** Shared secret callers of callbacks-retry must send; null rejects all. */
  cronSecret: string | null;
  /** Max inbound actions per agent per minute. */
  inboundRateLimitPerMinute: number;
  /** Feature flag: Agent Triggers (app starts an agent). Off unless exactly "true". */
  featureAgentTriggers: boolean;
  /** Local development only: allow http:// and private-network trigger URLs. */
  allowInsecureTriggers: boolean;
}

/** Default for INBOUND_RATE_LIMIT_PER_MINUTE. */
export const DEFAULT_INBOUND_RATE_LIMIT = 60;

/** Parses a positive integer variable, falling back to [fallback]. */
export function positiveIntEnv(name: string, fallback: number): number {
  const raw = optionalEnv(name);
  if (raw === null) return fallback;
  const value = Number(raw);
  if (!Number.isInteger(value) || value < 1) {
    throw new Error(`${name} must be a positive integer`);
  }
  return value;
}

/** Reads a required variable or throws. */
export function requireEnv(name: string): string {
  const value = Deno.env.get(name);
  if (value === undefined || value.trim() === '') {
    throw new Error(`Missing required environment variable ${name}`);
  }
  return value;
}

/** Reads an optional variable (empty → null). */
export function optionalEnv(name: string): string | null {
  const value = Deno.env.get(name);
  return value === undefined || value.trim() === '' ? null : value;
}

let cached: Env | null = null;

/** Loads and caches the environment. */
export function loadEnv(): Env {
  if (cached) return cached;
  const supabaseUrl = requireEnv('SUPABASE_URL');
  cached = {
    supabaseUrl,
    serviceRoleKey: requireEnv('SUPABASE_SERVICE_ROLE_KEY'),
    publicInboundBaseUrl: (optionalEnv('PUBLIC_INBOUND_BASE_URL') ?? `${supabaseUrl}/functions/v1`)
      .replace(/\/+$/, ''),
    fcmServiceAccountJson: optionalEnv('FCM_SERVICE_ACCOUNT_JSON'),
    allowInsecureCallbacks: optionalEnv('ALLOW_INSECURE_CALLBACKS') === 'true',
    cronSecret: optionalEnv('CRON_SECRET'),
    inboundRateLimitPerMinute: positiveIntEnv(
      'INBOUND_RATE_LIMIT_PER_MINUTE',
      DEFAULT_INBOUND_RATE_LIMIT,
    ),
    featureAgentTriggers: optionalEnv('FEATURE_AGENT_TRIGGERS') === 'true',
    allowInsecureTriggers: optionalEnv('ALLOW_INSECURE_TRIGGERS') === 'true',
  };
  return cached;
}
