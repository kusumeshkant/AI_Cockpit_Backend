// Supabase Edge Function: agents-trigger  (JWT — called by the signed-in app)
//
// Starts an agent (Agent Triggers, behind the `agent_triggers` feature_setting
// row; FEATURE_AGENT_TRIGGERS only when the row is missing). Flow:
//   1. Flag off → 404 feature_disabled; only the cached flag read happens.
//   2. Authenticate; validate { agent_id }.
//   3. begin_trigger_run — checks the workspace, that the trigger is enabled
//      and min_interval_secs, then records the run ('pending') and audits
//      'trigger_fired' before anything is sent. Outcome → HTTP:
//        not_found / not_configured 404 · disabled 409 · rate_limited 429
//   4. POST { trigger_id, agent_id, triggered_at, nonce } to trigger_url,
//      signed with X-Cockpit-Trigger-Signature (HMAC, trigger secret).
//   5. record_trigger_result — sent / failed (audited 'trigger_failed').
import { loadEnv } from '../_shared/env.ts';
import { featureFlags } from '../_shared/flags.ts';
import { serviceClient, userIdFromReq } from '../_shared/supabase.ts';
import { createTriggerHandler } from './handler.ts';

const env = loadEnv();

Deno.serve(
  createTriggerHandler({
    env,
    flags: featureFlags(),
    client: serviceClient,
    userId: userIdFromReq,
  }),
);
