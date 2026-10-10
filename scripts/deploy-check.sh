#!/usr/bin/env bash
# Read-only check of the deployed Supabase project against this repo (F10).
# Prints check names and pass/fail only; never a secret, key or setting value.
#
# Usage (from product/backend/, after `supabase link`):
#   export SUPABASE_PROJECT_REF=<project-ref>
#   export SUPABASE_ACCESS_TOKEN=<personal access token>   # Management API checks
#   export SUPABASE_DB_URL=<postgres connection string>    # database checks
#   scripts/deploy-check.sh
#
# Each group is skipped when its inputs are missing. Exit code 1 on any failure.
# Keep these variables in your shell only; never commit or paste them.
set -euo pipefail

cd "$(dirname "$0")/.."

if command -v deno >/dev/null 2>&1; then DENO=(deno); else DENO=(npx --yes deno@2.9.6); fi

exec "${DENO[@]}" run --allow-net --allow-env --allow-read scripts/deploy-check.ts
