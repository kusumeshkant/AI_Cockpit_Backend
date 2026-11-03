// Supabase Edge Function: service-deletions-retry  (scheduler only — X-Cron-Secret)
//
// pg_cron (0014, cockpit-service-deletions-retry, every 5 minutes) POSTs here
// via pg_net. Behind the `agent_services` flag. Sends each due
// service_deletion_job to the service's deletion op (Cockpit-Signature v1,
// destructive rules) so a deleted workspace is forgotten by the services it
// used. Logic: ./handler.ts.
import { isAuthorizedCron } from '../_shared/cron.ts';
import { loadEnv } from '../_shared/env.ts';
import { featureFlags } from '../_shared/flags.ts';
import { serviceClient } from '../_shared/supabase.ts';
import { createDeletionsHandler } from './handler.ts';

const env = loadEnv();

Deno.serve(
  createDeletionsHandler({
    env,
    flags: featureFlags(),
    authorized: (req) => isAuthorizedCron(req, env.cronSecret),
    client: serviceClient,
  }),
);
