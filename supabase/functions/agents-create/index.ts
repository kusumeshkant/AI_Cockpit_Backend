// Supabase Edge Function: agents-create  (JWT — called by the signed-in app)
//
// Creates an agent in the caller's workspace, mints its inbound HMAC secret
// (stored in Vault by `create_agent`, atomically with the agent row) and
// returns the plaintext secret exactly once (TR-8).
import { loadEnv } from '../_shared/env.ts';
import { fromPostgrest } from '../_shared/errors.ts';
import { generateSecret } from '../_shared/hmac.ts';
import { guardMethod, handler, json, parseJson, readRawBody } from '../_shared/http.ts';
import { log } from '../_shared/logger.ts';
import { serviceClient, userIdFromReq } from '../_shared/supabase.ts';
import type { AgentDto, CreateAgentResponse } from '../_shared/types.ts';
import { CreateAgentSchema, MAX_CREATE_AGENT_BYTES } from '../_shared/validation.ts';

const env = loadEnv();

Deno.serve(
  handler('agents-create', async (req) => {
    guardMethod(req, 'POST');
    const userId = await userIdFromReq(req);
    const body = parseJson(await readRawBody(req, MAX_CREATE_AGENT_BYTES), CreateAgentSchema);

    const secret = generateSecret();
    const { data, error } = await serviceClient()
      .rpc('create_agent', {
        p_user_id: userId,
        p_name: body.name,
        p_platform: body.platform,
        p_callback_url: body.callback_url,
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
    log.info('agent_created', { agent_id: agent.id, workspace_id: data.workspace_id });

    const response: CreateAgentResponse = {
      agent,
      inbound_url: `${env.publicInboundBaseUrl}/actions-inbound`,
      signing_secret: secret,
    };
    return json(response, 201);
  }),
);
