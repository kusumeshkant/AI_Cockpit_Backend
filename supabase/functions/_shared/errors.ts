// Typed errors. Codes mirror the Flutter Failure taxonomy so the app can map
// them 1:1 (AuthFailure, ServerFailure, NetworkFailure…).
import type { PostgrestError } from './deps.ts';

/** Error codes returned in the response envelope. */
export type ErrorCode =
  | 'unauthorized'
  | 'invalid_signature'
  | 'agent_disabled'
  | 'forbidden'
  | 'not_found'
  | 'conflict'
  | 'expired'
  | 'validation'
  | 'method_not_allowed'
  | 'payload_too_large'
  | 'rate_limited'
  | 'feature_disabled'
  | 'trigger_disabled'
  // Agent services gateway (0011).
  | 'agent_unavailable'
  | 'agent_timeout'
  | 'agent_error'
  | 'agent_paused'
  | 'trial_ended'
  | 'quota_reached'
  | 'approval_blocked'
  | 'unsupported_op'
  | 'app_update_required'
  | 'service_not_found'
  | 'service_not_enabled'
  | 'server';

/** HTTP status for each code. */
export const STATUS_BY_CODE: Readonly<Record<ErrorCode, number>> = {
  unauthorized: 401,
  invalid_signature: 401,
  agent_disabled: 403,
  forbidden: 403,
  not_found: 404,
  method_not_allowed: 405,
  conflict: 409,
  expired: 410,
  payload_too_large: 413,
  validation: 422,
  rate_limited: 429,
  feature_disabled: 404,
  trigger_disabled: 409,
  agent_unavailable: 503,
  agent_timeout: 504,
  agent_error: 502,
  agent_paused: 503,
  trial_ended: 403,
  quota_reached: 403,
  approval_blocked: 422,
  unsupported_op: 422,
  app_update_required: 426,
  service_not_found: 404,
  service_not_enabled: 403,
  server: 500,
};

/** An expected, client-facing error. */
export class AppError extends Error {
  readonly status: number;

  constructor(
    readonly code: ErrorCode,
    message: string,
    readonly details?: unknown,
  ) {
    super(message);
    this.name = 'AppError';
    this.status = STATUS_BY_CODE[code];
  }
}

/** Normalizes anything thrown into an AppError (unknown → server). */
export function toAppError(error: unknown): AppError {
  if (error instanceof AppError) return error;
  return new AppError('server', 'Internal error');
}

/**
 * Maps a failed RPC to an AppError. Our plpgsql functions raise with a
 * machine-readable message (e.g. `agent_disabled`).
 */
export function fromPostgrest(error: PostgrestError): AppError {
  switch (error.message) {
    case 'agent_not_found':
    case 'trigger_run_not_found':
    case 'trigger_not_found':
    case 'action_not_found':
      return new AppError('not_found', 'Not found');
    case 'workspace_not_found':
    case 'unauthorized':
      return new AppError('unauthorized', 'Unauthorized');
    case 'agent_disabled':
      return new AppError('agent_disabled', 'Agent is disabled');
    case 'forbidden':
      return new AppError('forbidden', 'Only the workspace owner can do this');
    case 'service_not_found':
      return new AppError('service_not_found', 'Service not found');
    case 'service_paused':
      return new AppError('agent_paused', 'The service is paused');
    case 'service_blocked':
      return new AppError('service_not_enabled', 'The service is not available for this workspace');
    case 'invalid_decision':
    case 'invalid_idempotency_key':
    case 'invalid_secret':
    case 'invalid_token':
    case 'invalid_limit':
    case 'invalid_lease':
    case 'invalid_rate_limit':
    case 'invalid_retry_delay':
    case 'invalid_trigger_url':
    case 'invalid_min_interval':
    case 'invalid_enabled':
    case 'invalid_user':
    case 'invalid_consent_version':
    case 'invalid_op_class':
    case 'invalid_op':
    case 'invalid_gateway_call':
    case 'invalid_revision':
    case 'invalid_reason_code':
      return new AppError('validation', error.message);
  }
  // Check-constraint / invalid-input violations are client errors.
  if (error.code === '23514' || error.code === '22023' || error.code === '22P02') {
    return new AppError('validation', 'Invalid input');
  }
  return new AppError('server', 'Database error');
}
