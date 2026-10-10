// Supabase Edge Function: account-delete  (JWT — called by the signed-in app)
//
// Deletes the caller's account (F02). The data is removed atomically by the
// `delete_account_data` RPC (approver: own row, decisions anonymized; owner:
// the whole workspace, other members moved to new personal workspaces). This
// function only does the I/O around it: it reads the user id from the JWT —
// never from app_user, so a retry after a failed auth delete still works —
// and then deletes the auth user (sessions, refresh tokens, identities) with
// the service role. Both steps are idempotent.
//
// Never logs the JWT, email or any secret.
import { isAuthUserMissing } from '../_shared/account.ts';
import { AppError, fromPostgrest } from '../_shared/errors.ts';
import { guardMethod, handler, json, parseJson, readRawBody } from '../_shared/http.ts';
import { log } from '../_shared/logger.ts';
import { serviceClient, userIdFromReq } from '../_shared/supabase.ts';
import type { AccountDeleteResponse } from '../_shared/types.ts';
import { AccountDeleteSchema, MAX_ACCOUNT_DELETE_BYTES } from '../_shared/validation.ts';

interface DeleteAccountRow {
  outcome: 'deleted' | 'already_deleted';
  role: 'owner' | 'approver' | null;
  workspace_deleted: boolean;
  members_moved: number;
}

Deno.serve(
  handler('account-delete', async (req) => {
    guardMethod(req, 'POST');
    const userId = await userIdFromReq(req);
    parseJson(await readRawBody(req, MAX_ACCOUNT_DELETE_BYTES), AccountDeleteSchema);

    const client = serviceClient();
    const { data, error } = await client
      .rpc('delete_account_data', { p_user_id: userId })
      .single<DeleteAccountRow>();
    if (error) throw fromPostgrest(error);

    const { error: authError } = await client.auth.admin.deleteUser(userId);
    if (authError && !isAuthUserMissing(authError)) {
      // The data is already gone; the app retries and only this step reruns.
      log.error('account_auth_delete_failed', { status: authError.status ?? null });
      throw new AppError('server', 'Account data deleted; sign-in removal failed, retry');
    }

    log.info('account_deleted', {
      outcome: data.outcome,
      role: data.role,
      workspace_deleted: data.workspace_deleted,
      members_moved: data.members_moved,
    });

    const response: AccountDeleteResponse = {
      outcome: data.outcome,
      workspace_deleted: data.workspace_deleted,
      members_moved: data.members_moved,
    };
    return json(response);
  }),
);
