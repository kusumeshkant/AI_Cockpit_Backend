#!/usr/bin/env bash
# End-to-end check of the core loop + Phase 2 against the local Supabase stack.
#
# Prerequisites (from product/backend/):
#   supabase start
#   supabase db reset
#   supabase functions serve --no-verify-jwt --env-file supabase/functions/.env
#
# Usage: scripts/e2e-core-loop.sh
# Uses `supabase` / `deno` from PATH, falling back to pinned npx versions.
set -euo pipefail

cd "$(dirname "$0")/.."

if command -v supabase >/dev/null 2>&1; then SUPABASE=(supabase); else SUPABASE=(npx --yes supabase@2.117.0); fi
if command -v deno >/dev/null 2>&1; then DENO=(deno); else DENO=(npx --yes deno@2.9.6); fi

# Export API_URL, ANON_KEY, SERVICE_ROLE_KEY for the test (values stay local).
eval "$("${SUPABASE[@]}" status -o env 2>/dev/null | grep -E '^(API_URL|ANON_KEY|SERVICE_ROLE_KEY)=' | sed 's/^/export /')"

# CRON_SECRET / INBOUND_RATE_LIMIT_PER_MINUTE come from the functions env file.
ENV_FILE=supabase/functions/.env
if [[ -f "$ENV_FILE" ]]; then
  for name in CRON_SECRET INBOUND_RATE_LIMIT_PER_MINUTE; do
    value="$(grep -E "^${name}=" "$ENV_FILE" | tail -1 | cut -d= -f2- || true)"
    if [[ -n "$value" && -z "${!name:-}" ]]; then export "$name=$value"; fi
  done
fi
if [[ -z "${CRON_SECRET:-}" ]]; then
  echo "CRON_SECRET is not set (add it to $ENV_FILE, see .env.example)" >&2
  exit 1
fi

if [[ -z "${API_URL:-}" ]]; then
  echo "Local Supabase is not running. Run: supabase start" >&2
  exit 1
fi

exec "${DENO[@]}" run --allow-net --allow-env --allow-read --allow-run scripts/e2e-core-loop.ts
