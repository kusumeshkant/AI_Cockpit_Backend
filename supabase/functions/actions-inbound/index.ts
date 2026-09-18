// Supabase Edge Function: actions-inbound  (no JWT — HMAC only, TR-1)
//
// Called by agents. Flow:
//   1. Read the raw body once (the signature covers these exact bytes).
//   2. Look up the agent named in the body and its Vault secret.
//   3. Verify X-Cockpit-Signature in constant time → 401 on any doubt.
//      Unknown agents get the same 401, so agent ids can't be probed.
//   4. Reject disabled agents (403), then count the request against the
//      agent's per-minute limit (429 rate_limited, with Retry-After).
//   5. Validate the body.
//   6. record_action_inbound — persisted idempotently before any push (TR-2).
//   7. Only for a genuinely new action: best-effort FCM push.
import { loadEnv } from '../_shared/env.ts';
import { AppError, fromPostgrest } from '../_shared/errors.ts';
import { verifySignature } from '../_shared/hmac.ts';
import { guardMethod, handler, json, parseJson, readRawBody } from '../_shared/http.ts';
import { log } from '../_shared/logger.ts';
import { notifyNewAction } from '../_shared/push.ts';
import { enforceRateLimit } from '../_shared/rate_limit.ts';
import { serviceClient } from '../_shared/supabase.ts';
import type { InboundResponse } from '../_shared/types.ts';
import {
  InboundActionSchema,
  isAllowedCallbackUrl,
  MAX_INBOUND_BYTES,
} from '../_shared/validation.ts';
import { getAgentInboundContext } from '../_shared/vault.ts';

const env = loadEnv();
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

function agentIdFrom(raw: string): string | null {
  try {
    const candidate = (JSON.parse(raw) as { agent_id?: unknown })?.agent_id;
    return typeof candidate === 'string' && UUID.test(candidate) ? candidate : null;
  } catch {
    return null;
  }
}

Deno.serve(
  handler('actions-inbound', async (req) => {
    guardMethod(req, 'POST');
    const raw = await readRawBody(req, MAX_INBOUND_BYTES);
    const signature = req.headers.get('x-cockpit-signature');
    const client = serviceClient();

    const agentId = agentIdFrom(raw);
    const context = agentId ? await getAgentInboundContext(client, agentId) : null;
    const verified = context?.secret != null && (await verifySignature(raw, signature, context.secret));
    if (!agentId || !context || !verified) {
      throw new AppError('invalid_signature', 'Invalid signature');
    }
    if (context.status !== 'active') {
      throw new AppError('agent_disabled', 'Agent is disabled');
    }
    await enforceRateLimit(client, agentId, env.inboundRateLimitPerMinute);

    const body = parseJson(raw, InboundActionSchema);
    if (body.callback_url && !isAllowedCallbackUrl(body.callback_url, env.allowInsecureCallbacks)) {
      throw new AppError('validation', 'callback_url is not allowed');
    }

    const { data, error } = await client
      .rpc('record_action_inbound', {
        p_agent_id: body.agent_id,
        p_external_id: body.external_id,
        p_type: body.type,
        p_title: body.title,
        p_summary: body.summary ?? null,
        p_payload: body.payload,
        p_editable_fields: body.editable_fields,
        p_callback_url: body.callback_url ?? null,
        p_expires_at: body.expires_at ?? null,
      })
      .single<{ action_id: string; is_new: boolean; fcm_tokens: string[] }>();
    if (error) throw fromPostgrest(error);

    log.info('action_inbound', {
      action_id: data.action_id,
      agent_id: body.agent_id,
      duplicate: !data.is_new,
    });

    if (data.is_new) {
      await notifyNewAction(client, env.fcmServiceAccountJson, {
        actionId: data.action_id,
        title: body.title,
        summary: body.summary ?? null,
        tokens: data.fcm_tokens,
      });
    }

    const response: InboundResponse = { action_id: data.action_id, duplicate: !data.is_new };
    return json(response);
  }),
);
