// Wire and domain types. Enum values match product/frontend exactly
// (DecisionWire, AgentPlatform, AgentStatus, ActionStatus).

export const DECISIONS = ['approved', 'approved_with_edits', 'rejected'] as const;
/** Human decision on an action. */
export type DecisionType = (typeof DECISIONS)[number];

export const PLATFORMS = ['n8n', 'make', 'zapier', 'custom'] as const;
/** Platform hosting an agent. */
export type AgentPlatform = (typeof PLATFORMS)[number];

/** Agent lifecycle. */
export type AgentStatus = 'active' | 'disabled';

/** Action lifecycle. */
export type ActionStatus = 'pending' | 'decided' | 'expired';

/** Callback delivery state. */
export type CallbackStatus = 'pending' | 'delivered' | 'retrying' | 'failed';

/** Outcome of `record_decision`. */
export type DecisionOutcome =
  | 'recorded'
  | 'duplicate'
  | 'already_decided'
  | 'expired'
  | 'invalid_edit'
  | 'not_found';

/** Agent as returned to the app (never includes secret material). */
export interface AgentDto {
  id: string;
  name: string;
  platform: AgentPlatform;
  callback_url: string;
  status: AgentStatus;
  secret_hint: string | null;
  last_action_at: string | null;
  created_at: string;
}

/** `agents-create` response — the only place the secret is ever returned. */
export interface CreateAgentResponse {
  agent: AgentDto;
  inbound_url: string;
  signing_secret: string;
}

/** `agents-rotate-secret` response: same shape as creation (TR-8). */
export type RotateSecretResponse = CreateAgentResponse;

/** `agents-test-action` response. */
export interface TestActionResponse {
  action_id: string;
}

/** `callbacks-retry` response (counts for this run). */
export interface RetryRunResponse {
  claimed: number;
  delivered: number;
  rescheduled: number;
  failed: number;
}

/** Agent trigger run state (mirrors `trigger_run.status`). */
export type TriggerRunStatus = 'pending' | 'sent' | 'failed';

/** Outcome of `begin_trigger_run`. */
export type TriggerRunOutcome = 'ok' | 'not_found' | 'not_configured' | 'disabled' | 'rate_limited';

/** An agent's trigger as returned to the app (never the secret or its id). */
export interface TriggerConfigDto {
  agent_id: string;
  trigger_url: string;
  secret_hint: string;
  enabled: boolean;
  min_interval_secs: number;
  updated_at: string;
}

/** `agents-configure-trigger` (configure) response — the secret, once. */
export interface ConfigureTriggerResponse {
  trigger: TriggerConfigDto;
  trigger_secret: string;
}

/** `agents-trigger` response. */
export interface TriggerRunResponse {
  run_id: string;
  delivered: boolean;
  detail: string;
}

/** Body POSTed to the agent's trigger_url. */
export interface TriggerPayload {
  trigger_id: string;
  agent_id: string;
  triggered_at: string;
  nonce: string;
}

/** `actions-inbound` response. */
export interface InboundResponse {
  action_id: string;
  duplicate: boolean;
}

/** `actions-decision` response. */
export interface DecisionResponse {
  decision_recorded: true;
  duplicate: boolean;
  callback_delivered: boolean;
}

/** Body POSTed to the agent's callback URL (blueprint §5.3). */
export interface CallbackPayload {
  action_id: string;
  external_id: string;
  decision: DecisionType;
  payload: Record<string, unknown>;
  edited_payload: Record<string, unknown> | null;
  reason: string | null;
  decided_at: string;
}

/** Response envelope shared by every function. */
export type Envelope<T> =
  | { ok: true; data: T }
  | { ok: false; error: { code: string; message: string; details?: unknown } };
