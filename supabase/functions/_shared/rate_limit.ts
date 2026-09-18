// Per-agent inbound rate limit. The counter is a fixed one-minute window in
// Postgres (hit_rate_limit), incremented atomically; this module turns the
// verdict into a 429 `rate_limited` error.
import type { SupabaseClient } from './deps.ts';
import { AppError, fromPostgrest } from './errors.ts';

/** Window length for the inbound limit. */
export const RATE_WINDOW_SECONDS = 60;

/** Row returned by `hit_rate_limit`. */
export interface RateLimitVerdict {
  limited: boolean;
  hits: number;
  retry_after_seconds: number;
}

/**
 * Counts one request for [agentId]; throws `rate_limited` (429) when the
 * agent has sent more than [maxPerWindow] in the current window.
 */
export async function enforceRateLimit(
  client: Pick<SupabaseClient, 'rpc'>,
  agentId: string,
  maxPerWindow: number,
  windowSeconds: number = RATE_WINDOW_SECONDS,
): Promise<RateLimitVerdict> {
  const { data, error } = await client
    .rpc('hit_rate_limit', {
      p_agent_id: agentId,
      p_max: maxPerWindow,
      p_window: `${windowSeconds} seconds`,
    })
    .single<RateLimitVerdict>();
  if (error) throw fromPostgrest(error);
  if (data.limited) {
    throw new AppError('rate_limited', 'Too many actions for this agent; slow down', {
      retry_after_seconds: data.retry_after_seconds,
    });
  }
  return data;
}
