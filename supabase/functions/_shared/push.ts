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
  /** Card type; types in SERVICE_CARD_PUSH get fixed text (0013). */
  type?: string;
}

/** A fixed notification: never the card's own title or summary. */
export interface PushTemplate {
  title: string;
  body: string;
}

/**
 * Service card types (agent-service-inbound) and their fixed text. Their card
 * text never leaves Cockpit in a push. Other types keep title / summary.
 */
export const SERVICE_CARD_PUSH: Readonly<Record<string, PushTemplate>> = {
  social_post_draft: { title: 'AI Cockpit', body: 'A post idea is ready for review' },
};

/** The notification for [push]: a fixed template for service cards. */
export function pushMessage(push: NewActionPush): {
  title: string;
  body: string;
  data: Record<string, string>;
} {
  const template = push.type !== undefined && Object.hasOwn(SERVICE_CARD_PUSH, push.type)
    ? SERVICE_CARD_PUSH[push.type]
    : undefined;
  if (template) {
    // `type: action` keeps the existing deep link working in current app builds.
    return {
      title: template.title,
      body: template.body,
      data: { type: 'action', action_id: push.actionId, kind: 'service_card' },
    };
  }
  return { title: push.title, body: push.summary ?? '', data: { type: 'action', action_id: push.actionId } };
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
    const result = await sendPush(push.tokens, pushMessage(push), { serviceAccountJson });
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
