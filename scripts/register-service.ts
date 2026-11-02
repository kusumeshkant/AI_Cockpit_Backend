// Registers or updates an agent service (0011) from a *.service.json file.
//
// Usage:
//   deno run --allow-net --allow-env --allow-read scripts/register-service.ts <file.json>
//     [--status draft|active|paused|retired] [--rotate-keys]
//
//   * New service: created as 'draft' (unless --status) with two fresh signing
//     secrets (current + next) written to Vault in the same transaction. The
//     secrets are printed ONCE to this terminal so you can configure the
//     service; they are never logged, written to a file, or retrievable later.
//   * Existing service: fields updated, status kept (unless --status), keys
//     kept (unless --rotate-keys, which replaces both and prints them once).
//     ⚠️ NEVER use --rotate-keys on a live service: replacing both keys at
//     once fails every call until the agent has the new pair. Live rotation
//     is the swap_service_signing_keys RPC (0012), which agents survive.
//   * Four keys (0013): `outbound current|next` (Cockpit → agent; the agent
//     verifies) and `inbound current|next` (agent → Cockpit cards; the agent
//     signs), each printed as `<key id> <secret>`. A service registered
//     before 0013 has no inbound pair until its next --rotate-keys (which,
//     again, must not be run on a live service).
//
// Env (service role; values are never printed):
//   SUPABASE_URL or API_URL                        project / local API URL
//   SUPABASE_SERVICE_ROLE_KEY or SERVICE_ROLE_KEY  service-role key
// Local stack: eval "$(supabase status -o env | grep -E '^(API_URL|SERVICE_ROLE_KEY)=' | sed 's/^/export /')"
import {
  generateServiceSigningSecret,
  ServiceRegistrationSchema,
} from '../supabase/functions/_shared/service_manifest.ts';

const STATUSES = ['draft', 'active', 'paused', 'retired'];

function fail(message: string): never {
  console.error(message);
  Deno.exit(2);
}

function env(...names: string[]): string | undefined {
  for (const name of names) {
    const value = Deno.env.get(name)?.trim();
    if (value) return value;
  }
  return undefined;
}

const args = [...Deno.args];
const file = args.shift();
let status: string | null = null;
let rotate = false;
while (args.length > 0) {
  const flag = args.shift();
  if (flag === '--status') {
    status = args.shift() ?? '';
    if (!STATUSES.includes(status)) fail(`--status must be one of ${STATUSES.join(', ')}`);
  } else if (flag === '--rotate-keys') {
    rotate = true;
  } else {
    fail(`Unknown argument ${flag}`);
  }
}
if (!file) fail('Usage: register-service.ts <file.json> [--status <s>] [--rotate-keys]');

let raw: unknown;
try {
  raw = JSON.parse(await Deno.readTextFile(file));
} catch (error) {
  fail(`Cannot read ${file}: ${(error as Error).message}`);
}
const parsed = ServiceRegistrationSchema.safeParse(raw);
if (!parsed.success) {
  fail(
    'Invalid service file:\n' +
      parsed.error.issues.map((i) => `  ${i.path.join('.') || '(root)'}: ${i.message}`).join('\n'),
  );
}
const service = parsed.data;

const apiUrl = env('SUPABASE_URL', 'API_URL')?.replace(/\/+$/, '');
const serviceKey = env('SUPABASE_SERVICE_ROLE_KEY', 'SERVICE_ROLE_KEY');
if (!apiUrl || !serviceKey) fail('Set SUPABASE_URL (or API_URL) and SUPABASE_SERVICE_ROLE_KEY (or SERVICE_ROLE_KEY)');

const headers = {
  apikey: serviceKey,
  Authorization: `Bearer ${serviceKey}`,
  'Content-Type': 'application/json',
};

// New services always get keys; existing ones only with --rotate-keys.
const existing = await fetch(
  `${apiUrl}/rest/v1/agent_service?slug=eq.${encodeURIComponent(service.slug)}&select=slug`,
  { headers },
);
if (!existing.ok) {
  await existing.body?.cancel();
  fail(`lookup failed: HTTP ${existing.status}`);
}
const isNew = ((await existing.json()) as unknown[]).length === 0;
const writeKeys = isNew || rotate;
const current = writeKeys ? generateServiceSigningSecret() : null;
const next = writeKeys ? generateServiceSigningSecret() : null;
// 0013: a separate pair for agent → Cockpit (cards), written together.
const inboundCurrent = writeKeys ? generateServiceSigningSecret() : null;
const inboundNext = writeKeys ? generateServiceSigningSecret() : null;

const response = await fetch(`${apiUrl}/rest/v1/rpc/register_agent_service`, {
  method: 'POST',
  headers,
  body: JSON.stringify({
    p_slug: service.slug,
    p_display_name: service.display_name,
    p_description: service.description,
    p_icon: service.icon,
    p_base_url: service.base_url,
    p_contract_version: service.contract_version,
    p_min_app_version: service.min_app_version,
    p_manifest: service.manifest,
    p_status: status,
    p_signing_current: current,
    p_signing_next: next,
    p_inbound_current: inboundCurrent,
    p_inbound_next: inboundNext,
  }),
});
if (!response.ok) {
  // Status (and the raised code when there is one) only: never the body.
  const code = await response.json().then((b) => (b as { message?: string }).message).catch(() => null);
  fail(`register failed: HTTP ${response.status}${code && /^[a-z_]+$/.test(code) ? ` (${code})` : ''}`);
}
const [row] = await response.json() as { slug: string; status: string; created: boolean }[];
console.log(`${row.slug}: ${row.created ? 'created' : 'updated'}, status ${row.status} (${new URL(apiUrl).host})`);
if (current && next && inboundCurrent && inboundNext) {
  // Key ids travel as X-Cockpit-Key-Id; the agent maps them to the secrets.
  const ids = await fetch(
    `${apiUrl}/rest/v1/agent_service?slug=eq.${encodeURIComponent(row.slug)}` +
      '&select=signing_key_current_id,signing_key_next_id,inbound_key_current_id,inbound_key_next_id',
    { headers },
  ).then((r) => (r.ok ? r.json() : [])) as Record<string, string>[];
  const id = (column: string) => ids[0]?.[column] ?? '?';
  console.log('\nSigning keys — secrets shown ONCE, copy them into the service now (key id, secret):');
  console.log('  Cockpit → agent (the agent VERIFIES with these):');
  console.log(`    outbound current: ${id('signing_key_current_id')} ${current}`);
  console.log(`    outbound next:    ${id('signing_key_next_id')} ${next}`);
  console.log('  agent → Cockpit cards (the agent SIGNS with these):');
  console.log(`    inbound current:  ${id('inbound_key_current_id')} ${inboundCurrent}`);
  console.log(`    inbound next:     ${id('inbound_key_next_id')} ${inboundNext}`);
} else {
  console.log('Signing keys unchanged.');
}
