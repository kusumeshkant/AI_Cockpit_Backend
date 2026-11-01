// Feature flags (0010). The `feature_setting` row is the source of truth; the
// old env variable (FEATURE_<KEY>, exactly "true" = on) is used only when the
// row is missing. A failed read fails closed: the feature is off.
//
// All rows are read in one query and cached per isolate for CACHE_TTL_MS, so a
// flag flipped with scripts/set-feature.ts takes effect within that window.
// Failures are not cached: the next call reads again.
import { optionalEnv } from './env.ts';
import { log } from './logger.ts';
import { serviceClient } from './supabase.ts';

/** Known feature keys (rows seeded by 0010). */
export type FeatureKey = 'agent_triggers' | 'agent_services';

/** Upper bound for how long a flag value is served from memory. */
export const CACHE_TTL_MS = 30_000;

/** One `feature_setting` row, as far as the server cares. */
export interface FeatureRow {
  key: string;
  enabled: boolean;
}

/** Reads every row; throws on failure. */
export type FeatureRowReader = () => Promise<FeatureRow[]>;

/** Answers whether a feature is on. */
export interface FeatureFlags {
  /** Whether [key] is enabled (false on any read failure). */
  isEnabled(key: FeatureKey): Promise<boolean>;
}

/** Name of the env fallback for [key], e.g. FEATURE_AGENT_TRIGGERS. */
export function envFallbackName(key: FeatureKey): string {
  return `FEATURE_${key.toUpperCase()}`;
}

/** Builds a cached flag reader; the parts are injectable for tests. */
export function createFeatureFlags(options: {
  read: FeatureRowReader;
  envValue?: (name: string) => string | null;
  now?: () => number;
  ttlMs?: number;
}): FeatureFlags {
  const envValue = options.envValue ?? optionalEnv;
  const now = options.now ?? Date.now;
  const ttlMs = options.ttlMs ?? CACHE_TTL_MS;
  let cache: { rows: Map<string, boolean>; at: number } | null = null;

  return {
    async isEnabled(key) {
      if (!cache || now() - cache.at >= ttlMs) {
        try {
          const rows = await options.read();
          cache = { rows: new Map(rows.map((r) => [r.key, r.enabled === true])), at: now() };
        } catch (error) {
          cache = null;
          log.error('feature_flags_unavailable', {
            key,
            error: error instanceof Error ? error.message : 'unknown',
          });
          return false;
        }
      }
      const value = cache.rows.get(key);
      if (value !== undefined) return value;
      return envValue(envFallbackName(key)) === 'true';
    },
  };
}

/** Reads `feature_setting` with the service-role client. */
export const readFeatureRows: FeatureRowReader = async () => {
  const { data, error } = await serviceClient().from('feature_setting').select('key, enabled');
  if (error) throw new Error(`feature_setting read failed (${error.code ?? 'unknown'})`);
  return (data ?? []) as FeatureRow[];
};

let shared: FeatureFlags | null = null;

/** The isolate's flag reader (service role, cached). */
export function featureFlags(): FeatureFlags {
  shared ??= createFeatureFlags({ read: readFeatureRows });
  return shared;
}

/** Shorthand for `featureFlags().isEnabled(key)`. */
export function isFeatureEnabled(key: FeatureKey): Promise<boolean> {
  return featureFlags().isEnabled(key);
}
