// Agent service registry entries (0011): the JSON an operator registers with
// scripts/register-service.ts, and the manifest the future agent-proxy reads.
// The database checks only the manifest's shape (ui, ui_schema_version, ops);
// everything else is validated here.
import { z } from './deps.ts';

/** Op classes; gateway rate limits are counted per class. */
export const OP_CLASSES = ['read', 'write', 'destructive'] as const;

/** Workspace roles an op may be allowed for. */
export const SERVICE_ROLES = ['owner', 'approver'] as const;

/** Upper bound for an op's timeout. */
export const MAX_OP_TIMEOUT_MS = 30_000;

/** Upper bound for an op's request / response size caps (1 MiB). */
export const MAX_OP_BYTES = 1_048_576;

const OP_NAME = /^[a-z][a-z0-9_.-]{0,63}$/;
const IDENT = /^[a-z][a-z0-9_.-]{0,63}$/;

/** One operation a service exposes. */
export const ServiceOpSchema = z.object({
  class: z.enum(OP_CLASSES),
  roles: z.array(z.enum(SERVICE_ROLES)).min(1).refine(
    (roles) => new Set(roles).size === roles.length,
    'roles must be unique',
  ),
  timeout_ms: z.number().int().min(1).max(MAX_OP_TIMEOUT_MS),
  max_request_bytes: z.number().int().min(1).max(MAX_OP_BYTES),
  max_response_bytes: z.number().int().min(1).max(MAX_OP_BYTES),
}).strict();

/** The service manifest (agent_service.manifest). */
export const ServiceManifestSchema = z.object({
  ui: z.enum(['native', 'sdui']),
  ui_schema_version: z.number().int().min(1),
  ops: z.record(z.string().regex(OP_NAME), ServiceOpSchema).refine(
    (ops) => Object.keys(ops).length > 0,
    'at least one op',
  ),
  card_types: z.array(z.string().regex(IDENT)).default([]),
  data_categories: z.array(z.string().regex(IDENT)).min(1),
  deletion_op: z.string().regex(OP_NAME),
}).strict().superRefine((manifest, ctx) => {
  const deletion = manifest.ops[manifest.deletion_op];
  if (!deletion) {
    ctx.addIssue({ code: 'custom', path: ['deletion_op'], message: 'deletion_op must be one of ops' });
  } else if (deletion.class !== 'destructive') {
    ctx.addIssue({ code: 'custom', path: ['deletion_op'], message: 'deletion_op must be destructive' });
  }
});

/** A registry entry as stored in a *.service.json file. */
export const ServiceRegistrationSchema = z.object({
  slug: z.string().regex(/^[a-z][a-z0-9-]{1,39}$/),
  display_name: z.string().min(1).max(60),
  description: z.string().max(500).default(''),
  icon: z.string().max(200).nullable().default(null),
  base_url: z.string().url().refine(
    (url) => /^https?:\/\//.test(url),
    'base_url must be http(s)',
  ),
  contract_version: z.string().regex(/^[0-9]+\.[0-9]+$/).default('1.0'),
  min_app_version: z.string().regex(/^[0-9]+\.[0-9]+\.[0-9]+$/).nullable().default(null),
  manifest: ServiceManifestSchema,
}).strict();

/** Parsed registry entry. */
export type ServiceRegistration = z.infer<typeof ServiceRegistrationSchema>;

/** Parsed manifest. */
export type ServiceManifest = z.infer<typeof ServiceManifestSchema>;

/** New signing secret: `svcsig_` + 32 random bytes, base64url. */
export function generateServiceSigningSecret(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  const base64 = btoa(String.fromCharCode(...bytes));
  return 'svcsig_' + base64.replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/, '');
}
