// Supabase Edge Function: agent-proxy  (JWT — called by the signed-in app)
//
// The app's only door to an agent service (0011 / 0012). Behind the
// `agent_services` feature flag (404 feature_disabled when off, after only the
// cached flag read). Body: { service, op, params?, if_match? }; headers:
// Idempotency-Key (required for write / destructive ops), X-App-Version.
// Forwards only manifest ops, signed with Cockpit-Signature v1; built-in ops
// service.enable / service.disable are answered here. Answer:
// { ok: true, data: { result, meta: { request_id, usage?, poll_after_ms?, version? } } }.
// Wire contract: docs/agent-gateway-wire-v1.md. Logic: ./handler.ts.
import { loadEnv } from '../_shared/env.ts';
import { featureFlags } from '../_shared/flags.ts';
import { serviceClient, userIdFromReq } from '../_shared/supabase.ts';
import { createProxyHandler } from './handler.ts';

const env = loadEnv();

Deno.serve(
  createProxyHandler({
    env,
    flags: featureFlags(),
    client: serviceClient,
    userId: userIdFromReq,
  }),
);
