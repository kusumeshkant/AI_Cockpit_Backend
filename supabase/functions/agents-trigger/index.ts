// Supabase Edge Function: agents-trigger  (JWT — called by the signed-in app)
//
// Starts an agent (Agent Triggers, behind FEATURE_AGENT_TRIGGERS). Flow:
//   1. Flag off → 404 feature_disabled, before any DB access or I/O.
//   2. Authenticate; validate { agent_id }.
//   3. begin_trigger_run — checks the workspace, that the trigger is enabled
//      and min_interval_secs, then records the run ('pending') and audits
//      'trigger_fired' before anything is sent. Outcome → HTTP:
//        not_found / not_configured 404 · disabled 409 · rate_limited 429
//   4. POST { trigger_id, agent_id, triggered_at, nonce } to trigger_url,
//      signed with X-Cockpit-Trigger-Signature (HMAC, trigger secret).
//   5. record_trigger_result — sent / failed (audited 'trigger_failed').
import { loadEnv } from '../_shared/env.ts';
import { serviceClient, userIdFromReq } from '../_shared/supabase.ts';
import { createTriggerHandler } from './handler.ts';

const env = loadEnv();

Deno.serve(createTriggerHandler({ env, client: serviceClient, userId: userIdFromReq }));
