// Guard for scheduler-only endpoints (callbacks-retry). pg_cron sends the
// shared secret as `X-Cron-Secret`; anything else is rejected, including every
// request when CRON_SECRET isn't configured.
import { timingSafeEqual } from './hmac.ts';

/** Header carrying the scheduler secret. */
export const CRON_SECRET_HEADER = 'x-cron-secret';

const encoder = new TextEncoder();

/** True when [req] carries [secret] in `X-Cron-Secret` (constant-time). */
export function isAuthorizedCron(req: Request, secret: string | null): boolean {
  if (!secret) return false;
  const provided = req.headers.get(CRON_SECRET_HEADER);
  if (!provided) return false;
  return timingSafeEqual(encoder.encode(provided), encoder.encode(secret));
}
