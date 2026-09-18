// Supabase clients. Functions use the service-role client (bypasses RLS) and
// scope every query to the authenticated caller explicitly.
import { createClient, type SupabaseClient } from './deps.ts';
import { loadEnv } from './env.ts';
import { AppError } from './errors.ts';

let service: SupabaseClient | null = null;

/** Service-role client (memoized per isolate). */
export function serviceClient(): SupabaseClient {
  if (service) return service;
  const env = loadEnv();
  service = createClient(env.supabaseUrl, env.serviceRoleKey, {
    auth: { persistSession: false, autoRefreshToken: false },
  });
  return service;
}

/**
 * Verifies the caller's bearer JWT with Supabase Auth and returns the user id.
 * Verification happens here even when the gateway also verifies, so local
 * `functions serve --no-verify-jwt` stays secure.
 */
export async function userIdFromReq(req: Request): Promise<string> {
  const header = req.headers.get('authorization') ?? '';
  const match = /^Bearer\s+(.+)$/i.exec(header);
  if (!match) throw new AppError('unauthorized', 'Missing bearer token');

  const { data, error } = await serviceClient().auth.getUser(match[1]);
  if (error || !data.user) throw new AppError('unauthorized', 'Invalid or expired session');
  return data.user.id;
}
