// Request schemas and URL policy. Unknown fields are rejected (.strict()).
import { z } from './deps.ts';
import { AppError } from './errors.ts';
import { DECISIONS, PLATFORMS } from './types.ts';

/** Max raw body sizes (bytes). */
export const MAX_INBOUND_BYTES = 256 * 1024;
export const MAX_DECISION_BYTES = 128 * 1024;
export const MAX_CREATE_AGENT_BYTES = 8 * 1024;
export const MAX_AGENT_REF_BYTES = 1024;
export const MAX_TRIGGER_CONFIG_BYTES = 4 * 1024;
export const MAX_ACCOUNT_DELETE_BYTES = 256;

const payloadObject = z.record(z.string(), z.unknown());

/** `agents-create` body. */
export const CreateAgentSchema = z
  .object({
    name: z.string().trim().min(1).max(60),
    platform: z.enum(PLATFORMS),
    callback_url: z.string().url().max(2048).refine((url) => url.startsWith('https://'), {
      message: 'callback_url must use https://',
    }),
  })
  .strict();

/**
 * `account-delete` body. `confirm: true` must be sent explicitly, so a stray or
 * empty request never deletes an account.
 */
export const AccountDeleteSchema = z
  .object({
    confirm: z.literal(true),
  })
  .strict();

/** `agents-test-action` / `agents-rotate-secret` body. */
export const AgentRefSchema = z
  .object({
    agent_id: z.string().uuid(),
  })
  .strict();

/** `agents-trigger` body. */
export const TriggerSchema = z
  .object({
    agent_id: z.string().uuid(),
  })
  .strict();

/**
 * `agents-configure-trigger` body: `action: configure` (create or
 * reconfigure, which rotates the secret) or `action: set_enabled`. The trigger URL must also pass
 * [isAllowedCallbackUrl] (https + SSRF policy, relaxed by
 * ALLOW_INSECURE_TRIGGERS locally), checked in the function.
 */
export const ConfigureTriggerSchema = z.discriminatedUnion('action', [
  z
    .object({
      action: z.literal('configure'),
      agent_id: z.string().uuid(),
      trigger_url: z.string().url().max(2048),
      min_interval_secs: z.number().int().min(1).max(86400).optional(),
    })
    .strict(),
  z
    .object({
      action: z.literal('set_enabled'),
      agent_id: z.string().uuid(),
      enabled: z.boolean(),
    })
    .strict(),
]);

/** `actions-inbound` body (blueprint §5.1). */
export const InboundActionSchema = z
  .object({
    agent_id: z.string().uuid(),
    external_id: z.string().min(1).max(200),
    type: z.string().regex(/^[a-z][a-z0-9_]{0,63}$/, 'type must be snake_case'),
    title: z.string().trim().min(1).max(200),
    summary: z.string().max(1000).optional(),
    payload: payloadObject,
    editable_fields: z.array(z.string().min(1).max(64)).max(50).default([]),
    callback_url: z.string().url().max(2048).optional(),
    expires_at: z.string().datetime({ offset: true }).optional(),
  })
  .strict()
  .superRefine((body, ctx) => {
    for (const field of body.editable_fields) {
      if (!(field in body.payload)) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ['editable_fields'],
          message: `editable field "${field}" is not in payload`,
        });
      }
    }
  });

/** `actions-decision` body (blueprint §5.2). */
export const DecisionSchema = z
  .object({
    action_id: z.string().uuid(),
    decision: z.enum(DECISIONS),
    edited_payload: payloadObject.nullish(),
    reason: z.string().max(500).nullish(),
  })
  .strict()
  .superRefine((body, ctx) => {
    const hasEdits = body.edited_payload != null && Object.keys(body.edited_payload).length > 0;
    if (body.decision === 'approved_with_edits' && !hasEdits) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['edited_payload'],
        message: 'approved_with_edits requires a non-empty edited_payload',
      });
    }
    if (body.decision !== 'approved_with_edits' && hasEdits) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['edited_payload'],
        message: 'edited_payload is only allowed with approved_with_edits',
      });
    }
  });

/** `Idempotency-Key` header. */
export const IdempotencyKeySchema = z.string().min(8).max(200).regex(/^[A-Za-z0-9._:-]+$/);

const PRIVATE_HOST_PATTERNS: readonly RegExp[] = [
  /^localhost$/i,
  /\.localhost$/i,
  /\.internal$/i,
  /\.local$/i,
  /^127\./,
  /^10\./,
  /^192\.168\./,
  /^172\.(1[6-9]|2\d|3[01])\./,
  /^169\.254\./,
  /^0\./,
  /^\[?::1\]?$/,
  /^\[?f[cd][0-9a-f]{2}:/i,
  /^\[?fe80:/i,
];

/**
 * Callback URL policy: https only, and no loopback / private / link-local
 * hosts (SSRF). [allowInsecure] relaxes both for local development.
 */
export function isAllowedCallbackUrl(value: string, allowInsecure: boolean): boolean {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    return false;
  }
  if (url.username || url.password) return false;
  if (allowInsecure) return url.protocol === 'https:' || url.protocol === 'http:';
  if (url.protocol !== 'https:') return false;
  return !PRIVATE_HOST_PATTERNS.some((pattern) => pattern.test(url.hostname));
}

// -----------------------------------------------------------------------------
// Service cards (0013, agent-service-inbound). Per-type schemas: Cockpit stores
// a SUMMARY only — no caption, hashtags, image or URL fields, and no URL text
// anywhere. Existing card types (actions-inbound) are untouched.
// -----------------------------------------------------------------------------

/** Max raw body of an agent-service-inbound request. */
export const MAX_SERVICE_CARD_BYTES = 16 * 1024;

/** Max card lifetime (agents keep their data for 30 days). */
export const MAX_CARD_TTL_DAYS = 30;

/** Card lifetime when the agent asks for none. */
export const DEFAULT_CARD_TTL_DAYS = 7;

// Links only: a scheme or a www. prefix (bare words like "Mornings.In" are text).
const URL_LIKE = /(https?:\/\/|www\.)/i;

/** A short, single-line text without anything URL-like. */
const plainText = (max: number) =>
  z.string().trim().min(1).max(max).refine((s) => !URL_LIKE.test(s), 'URLs are not allowed')
    .refine((s) => !/[\r\n]/.test(s), 'single line only');

/** `social_post_draft` (content creator): a post idea awaiting review. */
export const SocialPostDraftCardSchema = z
  .object({
    type: z.literal('social_post_draft'),
    title: plainText(80),
    summary: plainText(140),
    payload: z
      .object({
        schema: z.literal(1),
        service: z.string().regex(/^[a-z][a-z0-9-]{1,39}$/),
        idea_id: z.string().min(1).max(100).regex(/^[A-Za-z0-9._:-]+$/),
        format: z.enum(['reel', 'carousel', 'photo', 'story']),
        topic: plainText(80),
        hook: plainText(140),
        findings: z
          .object({
            blocking: z.number().int().min(0).max(99),
            to_fix: z.number().int().min(0).max(99),
            warnings: z.number().int().min(0).max(99),
          })
          .strict(),
        revision: z.number().int().min(1),
      })
      .strict(),
    editable_fields: z.array(z.string()).max(0, 'editable_fields must be empty').default([]),
    expires_at: z.string().datetime({ offset: true }).optional(),
  })
  .strict();

/** Card schemas by type. A type must also be in the service's `card_types`. */
export const SERVICE_CARD_SCHEMAS = {
  social_post_draft: SocialPostDraftCardSchema,
} as const;

/** A known service card type. */
export type ServiceCardType = keyof typeof SERVICE_CARD_SCHEMAS;

/** A parsed service card. */
export type ServiceCard = z.infer<typeof SocialPostDraftCardSchema>;

/** `agent-service-inbound` body. The card is validated per type afterwards. */
export const ServiceInboundSchema = z.discriminatedUnion('op', [
  z.object({
    service: z.string().regex(/^[a-z][a-z0-9-]{1,39}$/),
    op: z.literal('create'),
    external_id: z.string().min(1).max(200).regex(/^[A-Za-z0-9._:-]+$/),
    card: z.record(z.string(), z.unknown()),
  }).strict(),
  z.object({
    service: z.string().regex(/^[a-z][a-z0-9-]{1,39}$/),
    op: z.literal('update'),
    external_id: z.string().min(1).max(200).regex(/^[A-Za-z0-9._:-]+$/),
    revision: z.number().int().min(1),
    card: z.record(z.string(), z.unknown()),
  }).strict(),
  z.object({
    service: z.string().regex(/^[a-z][a-z0-9-]{1,39}$/),
    op: z.literal('withdraw'),
    external_id: z.string().min(1).max(200).regex(/^[A-Za-z0-9._:-]+$/),
    reason_code: z.string().regex(/^[a-z][a-z0-9_]{0,39}$/).default('withdrawn'),
  }).strict(),
]);

/** Parsed `agent-service-inbound` body. */
export type ServiceInbound = z.infer<typeof ServiceInboundSchema>;

/**
 * Validates [card] against its type's schema and the service's allow-list.
 * Throws `validation` (field paths only, never values).
 */
export function parseServiceCard(
  card: Record<string, unknown>,
  service: string,
  allowedTypes: readonly string[],
): ServiceCard {
  const type = card.type;
  if (typeof type !== 'string' || !Object.hasOwn(SERVICE_CARD_SCHEMAS, type) || !allowedTypes.includes(type)) {
    throw new AppError('validation', 'Unsupported card type');
  }
  const parsed = SERVICE_CARD_SCHEMAS[type as ServiceCardType].safeParse(card);
  if (!parsed.success) {
    throw new AppError(
      'validation',
      'Invalid card',
      parsed.error.issues.map((issue) => ({ path: issue.path.join('.'), message: issue.message })),
    );
  }
  if (parsed.data.payload.service !== service) {
    throw new AppError('validation', 'Invalid card', [{ path: 'payload.service', message: 'must match service' }]);
  }
  return parsed.data;
}

/**
 * The stored expiry: the requested time capped at now + 30 days, default
 * now + 7 days; a time in the past is invalid.
 */
export function cardExpiry(requested: string | undefined, nowMs: number): string {
  const max = nowMs + MAX_CARD_TTL_DAYS * 86_400_000;
  if (requested === undefined) return new Date(nowMs + DEFAULT_CARD_TTL_DAYS * 86_400_000).toISOString();
  const at = Date.parse(requested);
  if (!(at > nowMs)) throw new AppError('validation', 'expires_at must be in the future');
  return new Date(Math.min(at, max)).toISOString();
}
