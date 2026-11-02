// _shared/service_manifest.ts (0011) and the gateway error codes.
import { AppError, fromPostgrest, STATUS_BY_CODE } from '../_shared/errors.ts';
import {
  generateServiceSigningSecret,
  ServiceManifestSchema,
  ServiceRegistrationSchema,
} from '../_shared/service_manifest.ts';
import type { PostgrestError } from '../_shared/deps.ts';
import { assert, assertEquals, assertFalse, assertMatch } from './test_deps.ts';
// A static JSON import: no --allow-read needed by `deno task test`.
import example from '../../../scripts/examples/content-creator.service.json' with { type: 'json' };

// deno-lint-ignore no-explicit-any -- mutated freely to build invalid manifests.
const manifest = (): Record<string, any> => structuredClone(example.manifest);

Deno.test('the example service file is valid and defaults apply', () => {
  const parsed = ServiceRegistrationSchema.parse(example);
  assertEquals(parsed.slug, 'content-creator');
  assertEquals(parsed.manifest.deletion_op, 'subject.delete');
  const minimal = ServiceRegistrationSchema.parse({
    slug: 'svc-x',
    display_name: 'X',
    base_url: 'https://x.example',
    manifest: example.manifest,
  });
  assertEquals(minimal.contract_version, '1.0');
  assertEquals(minimal.description, '');
  assertEquals(minimal.min_app_version, null);
});

Deno.test('manifest: ui, ops and op fields are checked', () => {
  const bad = (mutate: (m: ReturnType<typeof manifest>) => void) => {
    const m = manifest();
    mutate(m);
    return ServiceManifestSchema.safeParse(m).success;
  };
  assert(bad(() => {}));
  assertFalse(bad((m) => (m.ui = 'web')), 'ui');
  assertFalse(bad((m) => (m.ops = {})), 'at least one op');
  assertFalse(bad((m) => (m.ops['drafts.list'].class = 'admin')), 'op class');
  assertFalse(bad((m) => (m.ops['drafts.list'].roles = [])), 'roles');
  assertFalse(bad((m) => (m.ops['drafts.list'].roles = ['owner', 'owner'])), 'unique roles');
  assertFalse(bad((m) => (m.ops['drafts.list'].timeout_ms = 60_000)), 'timeout cap');
  assertFalse(bad((m) => (m.ops['drafts.list'].max_response_bytes = 0)), 'size cap');
  assertFalse(bad((m) => (m.ops['Bad Op'] = m.ops['drafts.list'])), 'op name');
  assertFalse(bad((m) => (m.extra = true)), 'unknown keys');
  assertFalse(bad((m) => (m.data_categories = [])), 'data categories');
});

Deno.test('manifest: deletion_op must exist and be destructive', () => {
  const missing = manifest();
  missing.deletion_op = 'nope';
  assertFalse(ServiceManifestSchema.safeParse(missing).success);
  const wrongClass = manifest();
  wrongClass.deletion_op = 'drafts.list';
  assertFalse(ServiceManifestSchema.safeParse(wrongClass).success);
});

Deno.test('registration: slug, base_url and versions are checked', () => {
  const bad = (patch: Record<string, unknown>) =>
    ServiceRegistrationSchema.safeParse({ ...example, ...patch }).success;
  assertFalse(bad({ slug: 'Content_Creator' }));
  assertFalse(bad({ base_url: 'ftp://x.example' }));
  assertFalse(bad({ contract_version: '1' }));
  assertFalse(bad({ min_app_version: '1.2' }));
  assertFalse(bad({ secret: 'x' }), 'unknown keys (no secrets in the file)');
});

Deno.test('signing secrets: svcsig_ + 32 random bytes', () => {
  const secret = generateServiceSigningSecret();
  assertMatch(secret, /^svcsig_[A-Za-z0-9_-]{43}$/);
  assert(secret !== generateServiceSigningSecret());
});

Deno.test('gateway error codes map to their HTTP statuses', () => {
  const expected = {
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
  } as const;
  for (const [code, status] of Object.entries(expected)) {
    assertEquals(STATUS_BY_CODE[code as keyof typeof expected], status, code);
    assertEquals(new AppError(code as keyof typeof expected, 'x').status, status, code);
  }
});

Deno.test('service RPC errors map to gateway codes', () => {
  const pg = (message: string, code = 'P0001') =>
    ({ message, code, details: '', hint: '', name: 'PostgrestError' }) as PostgrestError;
  assertEquals(fromPostgrest(pg('service_not_found', 'P0002')).code, 'service_not_found');
  assertEquals(fromPostgrest(pg('service_paused')).code, 'agent_paused');
  assertEquals(fromPostgrest(pg('service_blocked', '42501')).code, 'service_not_enabled');
  assertEquals(fromPostgrest(pg('forbidden', '42501')).code, 'forbidden');
  for (const message of ['invalid_consent_version', 'invalid_op_class', 'invalid_op', 'invalid_gateway_call']) {
    assertEquals(fromPostgrest(pg(message, '22023')).code, 'validation', message);
  }
});
