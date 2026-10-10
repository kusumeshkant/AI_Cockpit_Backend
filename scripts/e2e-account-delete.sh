#!/usr/bin/env bash
# End-to-end check of account deletion (migration 0007 + account-delete)
# against the local Supabase stack.
#
# Prerequisites (from product/backend/):
#   supabase start
#   supabase db reset
#   supabase functions serve --no-verify-jwt --env-file supabase/functions/.env
#
# Usage: scripts/e2e-account-delete.sh
set -euo pipefail

cd "$(dirname "$0")/.."

if command -v supabase >/dev/null 2>&1; then SUPABASE=(supabase); else SUPABASE=(npx --yes supabase@2.117.0); fi
if command -v deno >/dev/null 2>&1; then DENO=(deno); else DENO=(npx --yes deno@2.9.6); fi

# Export API_URL, ANON_KEY, SERVICE_ROLE_KEY for the test (values stay local).
eval "$("${SUPABASE[@]}" status -o env 2>/dev/null | grep -E '^(API_URL|ANON_KEY|SERVICE_ROLE_KEY)=' | sed 's/^/export /')"
if [[ -z "${API_URL:-}" ]]; then
  echo "Local Supabase is not running. Run: supabase start" >&2
  exit 1
fi

exec "${DENO[@]}" run --allow-net --allow-env scripts/e2e-account-delete.ts
