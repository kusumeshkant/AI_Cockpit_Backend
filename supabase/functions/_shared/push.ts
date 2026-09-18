// Push for a newly stored action (actions-inbound, agents-test-action). Best
// effort: the action is already committed (TR-2) and the app reconciles via
// Realtime + poll, so failures are logged, never thrown.
import type { SupabaseClient } from './deps.ts';
import { sendPush } from './fcm.ts';
import { log } from './logger.ts';

/** What the notification needs about the new action. */
export interface NewActionPush {
  actionId: string;
  title: string;
  summary: string | null;
  tokens: readonly string[];
}

/**
 * Notifies the workspace's devices about a new action. The data payload
 * (`type: action`, `action_id`) is what the app deep-links from.
 */
export async function notifyNewAction(
  client: Pick<SupabaseClient, 'rpc'>,
  serviceAccountJson: string | null,
  push: NewActionPush,
): Promise<void> {
  try {
    const result = await sendPush(
      push.tokens,
      {
        title: push.title,
        body: push.summary ?? '',
        data: { type: 'action', action_id: push.actionId },
      },
      { serviceAccountJson },
    );
    if (result.invalidTokens.length > 0) {
      await client.rpc('prune_fcm_tokens', { p_tokens: result.invalidTokens });
    }
  } catch (error) {
    log.warn('push_failed', {
      action_id: push.actionId,
      error: error instanceof Error ? error.message : String(error),
    });
  }
}
