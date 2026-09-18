// Supabase Edge Function: agents-rotate-secret  (JWT — called by the signed-in app)
//
// Mints a new inbound HMAC secret for one of the caller's agents.
// rotate_agent_secret replaces it in Vault (same secret id) and updates the
// hint in one transaction; the old secret stops verifying immediately. The
// plaintext is returned exactly once (TR-8), in the same shape as
// agents-create so the app reuses its credentials panel.
import { loadEnv } from '../_shared/env.ts';
import { fromPostgrest } from '../_shared/errors.ts';
import { generateSecret } from '../_shared/hmac.ts';
import { guardMethod, handler, json, parseJson, readRawBody } from '../_shared/http.ts';
import { log } from '../_shared/logger.ts';
import { serviceClient, userIdFromReq } from '../_shared/supabase.ts';
import type { AgentDto, RotateSecretResponse } from '../_shared/types.ts';
import { AgentRefSchema, MAX_AGENT_REF_BYTES } from '../_shared/validation.ts';

const env = loadEnv();

Deno.serve(
  handler('agents-rotate-secret', async (req) => {
    guardMethod(req, 'POST');
    const userId = await userIdFromReq(req);
    const body = parseJson(await readRawBody(req, MAX_AGENT_REF_BYTES), AgentRefSchema);

    const secret = generateSecret();
    const { data, error } = await serviceClient()
      .rpc('rotate_agent_secret', {
        p_user_id: userId,
        p_agent_id: body.agent_id,
        p_secret: secret,
      })
      .single<AgentDto & { workspace_id: string }>();
    if (error) throw fromPostgrest(error);

    const agent: AgentDto = {
      id: data.id,
      name: data.name,
      platform: data.platform,
      callback_url: data.callback_url,
      status: data.status,
      secret_hint: data.secret_hint,
      last_action_at: data.last_action_at,
      created_at: data.created_at,
    };
    log.info('agent_secret_rotated', { agent_id: agent.id, workspace_id: data.workspace_id });

    const response: RotateSecretResponse = {
      agent,
      inbound_url: `${env.publicInboundBaseUrl}/actions-inbound`,
      signing_secret: secret,
    };
    return json(response);
  }),
);
