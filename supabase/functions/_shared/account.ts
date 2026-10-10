// Account deletion helpers shared by account-delete and its tests.

/**
 * True when the Auth admin API reports that the user no longer exists. A
 * retried deletion treats that as done, so the call is idempotent.
 */
export function isAuthUserMissing(error: { status?: number; code?: string } | null): boolean {
  if (!error) return false;
  return error.status === 404 || error.code === 'user_not_found';
}
