// Supabase Edge Function: agent-service-inbound  (no JWT — signature only)
//
// Agent services post review cards to Cockpit here (0013): create / update /
// withdraw, signed with Cockpit-Signature v1 using the service's INBOUND key
// pair over the canonical path /cockpit/v1/inbound/cards. Behind the
// `agent_services` feature flag (404 feature_disabled when off, after only the
// cached flag read). Answer: { ok: true, data: { result, action_id } }.
// Wire contract: docs/agent-gateway-wire-v1.md §6. Logic: ./handler.ts.
import { loadEnv } from '../_shared/env.ts';
import { featureFlags } from '../_shared/flags.ts';
import { notifyNewAction } from '../_shared/push.ts';
import { serviceClient } from '../_shared/supabase.ts';
import { createInboundHandler } from './handler.ts';

const env = loadEnv();

Deno.serve(
  createInboundHandler({
    env,
    flags: featureFlags(),
    client: serviceClient,
    notify: (client, push) => notifyNewAction(client, env.fcmServiceAccountJson, push),
  }),
);
