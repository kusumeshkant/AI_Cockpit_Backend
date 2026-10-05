// Supabase Edge Function: agents-configure-trigger  (JWT — signed-in owner)
//
// Agent Triggers, behind FEATURE_AGENT_TRIGGERS (404 feature_disabled when
// off, before any DB access). Body `action`:
//   configure    { agent_id, trigger_url, min_interval_secs? } — mints a
//                'whtrig_' secret, stores it in Vault inside
//                configure_agent_trigger (same transaction) and returns the
//                plaintext exactly once. Reconfiguring rotates the secret.
//   set_enabled  { agent_id, enabled }
// trigger_url must pass the callback URL policy (https, no private hosts),
// relaxed only by ALLOW_INSECURE_TRIGGERS for local development.
import { loadEnv } from '../_shared/env.ts';
import { AppError, fromPostgrest } from '../_shared/errors.ts';
import { guardMethod, handler, json, parseJson, readRawBody } from '../_shared/http.ts';
import { log } from '../_shared/logger.ts';
import { serviceClient, userIdFromReq } from '../_shared/supabase.ts';
import { generateTriggerSecret } from '../_shared/trigger.ts';
import type { ConfigureTriggerResponse, TriggerConfigDto } from '../_shared/types.ts';
import {
  ConfigureTriggerSchema,
  isAllowedCallbackUrl,
  MAX_TRIGGER_CONFIG_BYTES,
} from '../_shared/validation.ts';

const env = loadEnv();

/** Default for min_interval_secs. */
const DEFAULT_MIN_INTERVAL_SECS = 30;

Deno.serve(
  handler('agents-configure-trigger', async (req) => {
    if (!env.featureAgentTriggers) {
      throw new AppError('feature_disabled', 'Agent triggers are not enabled');
    }

    guardMethod(req, 'POST');
    const userId = await userIdFromReq(req);
    const body = parseJson(
      await readRawBody(req, MAX_TRIGGER_CONFIG_BYTES),
      ConfigureTriggerSchema,
    );
    const client = serviceClient();

    if (body.action === 'set_enabled') {
      const { data, error } = await client
        .rpc('set_agent_trigger_enabled', {
          p_actor_user_id: userId,
          p_agent_id: body.agent_id,
          p_enabled: body.enabled,
        })
        .single<TriggerConfigDto>();
      if (error) throw fromPostgrest(error);
      log.info('trigger_enabled_set', { agent_id: body.agent_id, enabled: body.enabled });
      return json({ trigger: data });
    }

    if (!isAllowedCallbackUrl(body.trigger_url, env.allowInsecureTriggers)) {
      throw new AppError('validation', 'trigger_url is not allowed');
    }

    const secret = generateTriggerSecret();
    const { data, error } = await client
      .rpc('configure_agent_trigger', {
        p_actor_user_id: userId,
        p_agent_id: body.agent_id,
        p_trigger_url: body.trigger_url,
        p_secret: secret,
        p_min_interval: body.min_interval_secs ?? DEFAULT_MIN_INTERVAL_SECS,
      })
      .single<TriggerConfigDto>();
    if (error) throw fromPostgrest(error);

    log.info('trigger_configured', { agent_id: data.agent_id });
    const response: ConfigureTriggerResponse = { trigger: data, trigger_secret: secret };
    return json(response);
  }),
);
