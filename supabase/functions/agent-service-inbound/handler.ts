// agent-service-inbound request handling (unit-tested in
// _tests/service_inbound_test.ts). Agent → Cockpit cards, signed with the
// service's INBOUND key pair (Cockpit-Signature v1 over the canonical path
// /cockpit/v1/inbound/cards). Order:
//   1. POST, then the `agent_services` flag (cached read only).
//   2. Raw body cap (16 KB) → signature (current or next inbound key, ±60 s,
//      body hash) → nonce claimed once in gateway_nonce. Any doubt — unknown
//      service, unknown key, bad signature, replay, unknown subject — is the
//      same generic 401.
//   3. Body + card schema (per type, service allow-list).
//   4. Service + workspace by (slug, X-Cockpit-Workspace subject).
//   5. hit_rate_limit on the workspace's service agent.
//   6. create (record_action_inbound, push after persist) / update (access
//      active; service active or paused) / withdraw (any state). Card text
//      is never logged.
import type { SupabaseClient } from '../_shared/deps.ts';
import type { Env } from '../_shared/env.ts';
import { AppError, fromPostgrest } from '../_shared/errors.ts';
import type { FeatureFlags } from '../_shared/flags.ts';
import { V1_HEADERS, V1_INBOUND_CARD_PATH, verifyV1 } from '../_shared/hmac.ts';
import { guardMethod, handler, json, parseJson, readRawBody } from '../_shared/http.ts';
import { log } from '../_shared/logger.ts';
import type { NewActionPush } from '../_shared/push.ts';
import { enforceRateLimit } from '../_shared/rate_limit.ts';
import {
  cardExpiry,
  MAX_SERVICE_CARD_BYTES,
  parseServiceCard,
  type ServiceInbound,
  ServiceInboundSchema,
} from '../_shared/validation.ts';

/** Answer `result` values. */
export type InboundResult = 'created' | 'duplicate' | 'updated' | 'stale' | 'withdrawn' | 'noop';

/** Row of `resolve_service_inbound`. */
interface InboundTarget {
  workspace_id: string;
  service_status: 'draft' | 'active' | 'paused' | 'retired';
  card_types: unknown;
  access_state: 'active' | 'disabled' | 'blocked';
  agent_id: string | null;
}

/** What the handler needs; injectable for tests. */
export interface InboundDeps {
  env: Pick<Env, 'inboundRateLimitPerMinute'>;
  flags: Pick<FeatureFlags, 'isEnabled'>;
  /** Called lazily: the flag-off path must not create a client. */
  client: () => Pick<SupabaseClient, 'rpc'>;
  /** Push for a new card (after it is persisted). */
  notify: (client: Pick<SupabaseClient, 'rpc'>, push: NewActionPush) => Promise<void>;
  nowMs?: () => number;
}

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const unauthorized = () => new AppError('unauthorized', 'Unauthorized');

function slugFrom(raw: string): string | null {
  try {
    const value = (JSON.parse(raw) as { service?: unknown })?.service;
    return typeof value === 'string' && /^[a-z][a-z0-9-]{1,39}$/.test(value) ? value : null;
  } catch {
    return null;
  }
}

/** Builds the `agent-service-inbound` handler. */
export function createInboundHandler(deps: InboundDeps): (req: Request) => Promise<Response> {
  const nowMs = deps.nowMs ?? Date.now;

  return handler('agent-service-inbound', async (req) => {
    guardMethod(req, 'POST');
    if (!(await deps.flags.isEnabled('agent_services'))) {
      throw new AppError('feature_disabled', 'Agent services are not enabled');
    }

    // 2. Authenticity: everything below the cap is signed.
    const raw = await readRawBody(req, MAX_SERVICE_CARD_BYTES);
    const slug = slugFrom(raw);
    if (!slug) throw unauthorized();
    const client = deps.client();

    const keys = await client.rpc('get_service_inbound_keys', { p_slug: slug });
    if (keys.error) throw fromPostgrest(keys.error);
    const secrets: Record<string, string> = {};
    for (const row of (keys.data ?? []) as { key_id: string; secret: string }[]) secrets[row.key_id] = row.secret;
    if (Object.keys(secrets).length === 0) throw unauthorized();

    const verdict = await verifyV1({
      headers: req.headers,
      method: req.method,
      path: V1_INBOUND_CARD_PATH,
      body: raw,
      secrets,
      now: Math.floor(nowMs() / 1000),
    });
    if (!verdict.ok) {
      log.warn('service_inbound_rejected', { service: slug, reason: verdict.reason });
      throw unauthorized();
    }
    const fresh = await client.rpc('claim_gateway_nonce', {
      p_key_id: verdict.fields.keyId,
      p_nonce: verdict.fields.nonce,
    });
    if (fresh.error) throw fromPostgrest(fresh.error);
    if (fresh.data !== true) {
      log.warn('service_inbound_rejected', { service: slug, reason: 'replayed_nonce' });
      throw unauthorized();
    }
    const user = verdict.fields.user;
    if (user !== 'system' && !UUID.test(user)) throw new AppError('validation', 'Invalid X-Cockpit-User');
    if (!/^1\.[0-9]+$/.test(req.headers.get(V1_HEADERS.contractVersion) ?? '')) {
      throw new AppError('validation', 'Unsupported contract version');
    }

    // 3. Body.
    const body = parseJson(raw, ServiceInboundSchema);

    // 4. Service + workspace by subject (unknown → the same 401).
    const target = await client
      .rpc('resolve_service_inbound', { p_slug: slug, p_subject: verdict.fields.workspace })
      .maybeSingle<InboundTarget>();
    if (target.error) throw fromPostgrest(target.error);
    if (!target.data) throw unauthorized();
    const t = target.data;
    const cardTypes = Array.isArray(t.card_types) ? (t.card_types as unknown[]).filter((x) => typeof x === 'string') as string[] : [];

    // 5. Rate limit on the workspace's service agent.
    if (t.agent_id) await enforceRateLimit(client, t.agent_id, deps.env.inboundRateLimitPerMinute);

    // 6. Act.
    const outcome = await act(client, deps, body, t, cardTypes, nowMs());
    log.info('service_card', {
      service: slug,
      op: body.op,
      action_id: outcome.action_id,
      result: outcome.result,
      ...(body.op === 'update' ? { revision: body.revision } : {}),
    });
    return json(outcome);
  });
}

async function act(
  client: Pick<SupabaseClient, 'rpc'>,
  deps: InboundDeps,
  body: ServiceInbound,
  t: InboundTarget,
  cardTypes: string[],
  now: number,
): Promise<{ result: InboundResult; action_id: string }> {
  if (body.op === 'withdraw') {
    // Allowed in every service / access state (the agent cleans up).
    if (!t.agent_id) throw new AppError('not_found', 'Not found');
    const { data, error } = await client
      .rpc('record_action_withdraw', {
        p_agent_id: t.agent_id,
        p_external_id: body.external_id,
        p_reason_code: body.reason_code,
      })
      .single<{ action_id: string; outcome: 'withdrawn' | 'noop' }>();
    if (error) throw fromPostgrest(error);
    return { result: data.outcome, action_id: data.action_id };
  }

  if (t.service_status === 'draft' || t.service_status === 'retired') {
    throw new AppError('service_not_found', 'Service not found');
  }

  if (body.op === 'update') {
    // Fixes are allowed while the SERVICE is paused, but only while the
    // workspace's access is active (disabled or blocked → refused).
    if (t.access_state !== 'active' || !t.agent_id) {
      throw new AppError('service_not_enabled', 'The service is not enabled for this workspace');
    }
    const card = parseServiceCard(body.card, body.service, cardTypes);
    if (card.payload.revision !== body.revision) {
      throw new AppError('validation', 'Invalid card', [{ path: 'payload.revision', message: 'must equal revision' }]);
    }
    const { data, error } = await client
      .rpc('record_action_update', {
        p_agent_id: t.agent_id,
        p_external_id: body.external_id,
        p_revision: body.revision,
        p_title: card.title,
        p_summary: card.summary,
        p_payload: card.payload,
        p_expires_at: card.expires_at === undefined ? null : cardExpiry(card.expires_at, now),
      })
      .single<{ action_id: string; outcome: 'updated' | 'stale' | 'noop' }>();
    if (error) throw fromPostgrest(error);
    return { result: data.outcome, action_id: data.action_id };
  }

  // create
  if (t.service_status === 'paused') throw new AppError('agent_paused', 'The service is paused');
  if (t.access_state !== 'active' || !t.agent_id) {
    throw new AppError('service_not_enabled', 'The service is not enabled for this workspace');
  }
  const card = parseServiceCard(body.card, body.service, cardTypes);
  const { data, error } = await client
    .rpc('record_action_inbound', {
      p_agent_id: t.agent_id,
      p_external_id: body.external_id,
      p_type: card.type,
      p_title: card.title,
      p_summary: card.summary,
      p_payload: card.payload,
      p_editable_fields: [],
      p_callback_url: null,
      p_expires_at: cardExpiry(card.expires_at, now),
    })
    .single<{ action_id: string; is_new: boolean; fcm_tokens: string[] }>();
  if (error) {
    const mapped = fromPostgrest(error);
    // A disabled service agent means access is off.
    if (mapped.code === 'agent_disabled') {
      throw new AppError('service_not_enabled', 'The service is not enabled for this workspace');
    }
    throw mapped;
  }
  if (data.is_new) {
    // Persisted first (TR-2); the push carries fixed text, never card text.
    await deps.notify(client, {
      actionId: data.action_id,
      title: card.title,
      summary: card.summary,
      tokens: data.fcm_tokens,
      type: card.type,
    });
  }
  return { result: data.is_new ? 'created' : 'duplicate', action_id: data.action_id };
}
