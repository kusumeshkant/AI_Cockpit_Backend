// Supabase Edge Function: agents-test-action  (JWT — called by the signed-in app)
//
// Inserts a sample pending action for one of the caller's agents so the whole
// loop can be tried before the agent is wired up. Flow:
//   1. Authenticate; the caller must own the agent (get_owned_agent → else 404).
//   2. Count it against the agent's inbound rate limit (429 rate_limited).
//   3. record_action_inbound with external_id `test-<uuid>` and a canned email
//      payload (editable subject/body) — the same path as a real agent, so
//      it's audited, streamed to the feed and pushed.
//   4. Approving it calls back the agent's callback_url like any action.
import { loadEnv } from '../_shared/env.ts';
import { AppError, fromPostgrest } from '../_shared/errors.ts';
import { guardMethod, handler, json, parseJson, readRawBody } from '../_shared/http.ts';
import { log } from '../_shared/logger.ts';
import { notifyNewAction } from '../_shared/push.ts';
import { enforceRateLimit } from '../_shared/rate_limit.ts';
import { serviceClient, userIdFromReq } from '../_shared/supabase.ts';
import type { AgentStatus, TestActionResponse } from '../_shared/types.ts';
import { AgentRefSchema, MAX_AGENT_REF_BYTES } from '../_shared/validation.ts';

const env = loadEnv();

/** Canned action. `external_id` is added per request. */
const TEST_ACTION = {
  type: 'email',
  title: 'Test action from Cockpit',
  summary: 'A sample email so you can try approve, edit and reject.',
  payload: {
    to: 'customer@example.com',
    subject: 'Thanks for reaching out',
    body: 'Hi there,\n\nThanks for getting in touch — we will get back to you within one business day.\n\nBest regards',
  },
  editable_fields: ['subject', 'body'],
} as const;

Deno.serve(
  handler('agents-test-action', async (req) => {
    guardMethod(req, 'POST');
    const userId = await userIdFromReq(req);
    const body = parseJson(await readRawBody(req, MAX_AGENT_REF_BYTES), AgentRefSchema);
    const client = serviceClient();

    const owned = await client
      .rpc('get_owned_agent', { p_user_id: userId, p_agent_id: body.agent_id })
      .maybeSingle<{ id: string; status: AgentStatus }>();
    if (owned.error) throw fromPostgrest(owned.error);
    if (!owned.data) throw new AppError('not_found', 'Agent not found');
    if (owned.data.status !== 'active') throw new AppError('agent_disabled', 'Agent is disabled');

    await enforceRateLimit(client, body.agent_id, env.inboundRateLimitPerMinute);

    const { data, error } = await client
      .rpc('record_action_inbound', {
        p_agent_id: body.agent_id,
        p_external_id: `test-${crypto.randomUUID()}`,
        p_type: TEST_ACTION.type,
        p_title: TEST_ACTION.title,
        p_summary: TEST_ACTION.summary,
        p_payload: TEST_ACTION.payload,
        p_editable_fields: TEST_ACTION.editable_fields,
        p_callback_url: null,
        p_expires_at: null,
      })
      .single<{ action_id: string; is_new: boolean; fcm_tokens: string[] }>();
    if (error) throw fromPostgrest(error);

    log.info('test_action_sent', { action_id: data.action_id, agent_id: body.agent_id });

    await notifyNewAction(client, env.fcmServiceAccountJson, {
      actionId: data.action_id,
      title: TEST_ACTION.title,
      summary: TEST_ACTION.summary,
      tokens: data.fcm_tokens,
    });

    const response: TestActionResponse = { action_id: data.action_id };
    return json(response, 201);
  }),
);
