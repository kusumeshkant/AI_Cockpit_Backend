// Switches a feature on or off in public.feature_setting (0010) — no app
// re-release, no function redeploy. Edge Functions pick it up within their
// flag cache (≤ 30 s); the app on its next refresh (start, resume, ~5 min).
//
// Usage:
//   deno run --allow-net --allow-env scripts/set-feature.ts <key> on|off [--note "text"]
//
// Env (service role; values are never printed):
//   SUPABASE_URL or API_URL                        project / local API URL
//   SUPABASE_SERVICE_ROLE_KEY or SERVICE_ROLE_KEY  service-role key
// Local stack: eval "$(supabase status -o env | grep -E '^(API_URL|SERVICE_ROLE_KEY)=' | sed 's/^/export /')"
//
// Prints the key, the new state and the target host only.

const KEY_PATTERN = /^[a-z][a-z0-9_]{0,62}$/;

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

const [key, state, ...rest] = Deno.args;
if (!key || !KEY_PATTERN.test(key) || (state !== 'on' && state !== 'off')) {
  fail('Usage: set-feature.ts <key> on|off [--note "text"]');
}
let note: string | undefined;
if (rest.length > 0) {
  if (rest[0] !== '--note' || rest.length !== 2) fail('Only --note "text" is accepted after on|off');
  note = rest[1];
}

const apiUrl = env('SUPABASE_URL', 'API_URL')?.replace(/\/+$/, '');
const serviceKey = env('SUPABASE_SERVICE_ROLE_KEY', 'SERVICE_ROLE_KEY');
if (!apiUrl || !serviceKey) fail('Set SUPABASE_URL (or API_URL) and SUPABASE_SERVICE_ROLE_KEY (or SERVICE_ROLE_KEY)');

const row: Record<string, unknown> = {
  key,
  enabled: state === 'on',
  updated_at: new Date().toISOString(),
};
if (note !== undefined) row.note = note;

// Upsert: creates the row if a newer key isn't seeded yet.
const response = await fetch(`${apiUrl}/rest/v1/feature_setting?on_conflict=key`, {
  method: 'POST',
  headers: {
    apikey: serviceKey,
    Authorization: `Bearer ${serviceKey}`,
    'Content-Type': 'application/json',
    Prefer: 'resolution=merge-duplicates,return=representation',
  },
  body: JSON.stringify(row),
});
if (!response.ok) {
  // Status only: the body could echo request details.
  await response.body?.cancel();
  fail(`set-feature failed: HTTP ${response.status}`);
}
const [saved] = await response.json() as { key: string; enabled: boolean }[];
console.log(`${saved.key} → ${saved.enabled ? 'on' : 'off'} (${new URL(apiUrl).host})`);
