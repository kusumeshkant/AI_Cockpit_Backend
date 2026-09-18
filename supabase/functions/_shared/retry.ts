// Callback retry policy (TR-7). Exponential backoff with a cap and a little
// jitter: after the n-th failed attempt the next one runs
// min(cap, base · 2^n) seconds later (+0–10%), until MAX_CALLBACK_ATTEMPTS.
// With the defaults: 30s, 1m, 2m, 4m, 8m, 16m, 32m, then give up (~1h total).
// Postgres applies the delay (record_callback_result); the numbers live here.

/** Base delay in seconds. */
export const RETRY_BASE_SECONDS = 15;

/** Longest wait between two attempts. */
export const RETRY_CAP_SECONDS = 6 * 60 * 60;

/** Attempts in total, first delivery included. */
export const MAX_CALLBACK_ATTEMPTS = 8;

/** Upper bound of the random jitter, as a fraction of the delay. */
export const RETRY_JITTER = 0.1;

/**
 * Seconds until the next attempt after [attemptsMade] failed attempts, or
 * null when no attempt is left (the callback becomes terminal `failed`).
 * [random] returns [0, 1) and is injectable for tests.
 */
export function retryDelaySeconds(
  attemptsMade: number,
  random: () => number = Math.random,
): number | null {
  if (!Number.isInteger(attemptsMade) || attemptsMade < 1) {
    throw new RangeError('attemptsMade must be a positive integer');
  }
  if (attemptsMade >= MAX_CALLBACK_ATTEMPTS) return null;
  const base = RETRY_BASE_SECONDS * 2 ** attemptsMade;
  const jittered = base * (1 + RETRY_JITTER * random());
  return Math.min(RETRY_CAP_SECONDS, Math.round(jittered));
}
