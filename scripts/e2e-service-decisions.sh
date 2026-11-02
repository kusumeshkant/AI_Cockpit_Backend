#!/usr/bin/env bash
# End-to-end check of 0014 — decisions on service cards through the gateway,
# reject delivery via callbacks-retry, and the account-deletion fan-out via
# service-deletions-retry — against the local stack and the in-process stub.
#
# Prerequisites (from product/backend/):
#   supabase start && supabase db reset   (or `supabase migration up`)
#   Stop any running `supabase functions serve` first: this script serves the
#   functions itself, twice, from temporary env files derived from
#   supabase/functions/.env (CRON_SECRET replaced by the LOCAL ONLY seed value):
#     on  — row on; ALLOW_INSECURE_SERVICES=true (LOCAL ONLY: http stub)
#     off — row off; checks that both paths answer feature_disabled
#   The "on" run leaves one pending card for the "off" run. The row is set back
#   to off on exit. Nothing is written to supabase/functions/.env.
#
# Usage: scripts/e2e-service-decisions.sh
set -euo pipefail

cd "$(dirname "$0")/.."

if command -v supabase >/dev/null 2>&1; then SUPABASE=(supabase); else SUPABASE=(npx --yes supabase@2.117.0); fi
if command -v deno >/dev/null 2>&1; then DENO=(deno); else DENO=(npx --yes deno@2.9.6); fi

eval "$("${SUPABASE[@]}" status -o env 2>/dev/null | grep -E '^(API_URL|ANON_KEY|SERVICE_ROLE_KEY)=' | sed 's/^/export /')"
if [[ -z "${API_URL:-}" ]]; then
  echo "Local Supabase is not running. Run: supabase start" >&2
  exit 1
fi

BASE_ENV=supabase/functions/.env
[[ -f "$BASE_ENV" ]] || { echo "Missing $BASE_ENV (copy .env.example)" >&2; exit 1; }

WORK="$(mktemp -d)"
SERVE_PID=""
KEEP_WORK=0
cleanup() {
  stop_serve
  set_flag off >/dev/null 2>&1 || true
  if [[ "$KEEP_WORK" == 1 ]]; then echo "serve logs kept in $WORK" >&2; else rm -rf "$WORK"; fi
}
trap cleanup EXIT

# Paths as the (possibly native Windows) Supabase CLI expects them.
native_path() { if command -v cygpath >/dev/null 2>&1; then cygpath -w "$1"; else echo "$1"; fi; }

strip_flags() { grep -vE '^(FEATURE_AGENT_SERVICES|ALLOW_INSECURE_SERVICES|CRON_SECRET)=' "$BASE_ENV" || true; }

# LOCAL ONLY seed value (seed.sql / .env.example), so the e2e can call the cron endpoints.
export CRON_SECRET='cron_local_dev_only_never_use_in_production'

# The DB row is the switch (service role from `supabase status`, never printed).
set_flag() { "${DENO[@]}" run --allow-net --allow-env scripts/set-feature.ts agent_services "$1"; }

is_windows() { case "$(uname -s)" in MINGW* | MSYS* | CYGWIN*) return 0 ;; *) return 1 ;; esac; }

# `serve` runs as a tree (npx → node → supabase), and killing only $SERVE_PID
# can leave the real CLI running: the next serve then never comes up.
stop_serve() {
  if [[ -n "$SERVE_PID" ]]; then
    if is_windows; then
      # $! is an MSYS pid; the CLI processes are native Windows children that
      # `kill` doesn't reach. End the whole Windows process tree.
      local winpid
      winpid="$(cat "/proc/$SERVE_PID/winpid" 2>/dev/null || true)"
      if [[ -n "$winpid" ]]; then taskkill //F //T //PID "$winpid" >/dev/null 2>&1 || true; fi
    else
      # start_serve gives serve its own process group: signal all of it.
      kill -- "-$SERVE_PID" 2>/dev/null || kill "$SERVE_PID" 2>/dev/null || true
    fi
    wait "$SERVE_PID" 2>/dev/null || true
    SERVE_PID=""
  fi
  # The CLI normally removes the runtime container on exit; make sure.
  docker rm -f supabase_edge_runtime_cockpit >/dev/null 2>&1 || true
}

start_serve() {
  local env_file="$1" log_file="$2"
  stop_serve
  set -m # own process group (POSIX), so stop_serve can end the whole tree
  "${SUPABASE[@]}" functions serve --no-verify-jwt --env-file "$(native_path "$env_file")" >"$log_file" 2>&1 &
  SERVE_PID=$!
  set +m
  for _ in $(seq 1 60); do
    if [[ "$(curl -s -o /dev/null -w '%{http_code}' "$API_URL/functions/v1/agent-service-inbound" -X GET)" =~ ^(404|405)$ ]]; then
      # Wait for the trigger function itself (not only the gateway) to answer.
      if curl -s "$API_URL/functions/v1/agent-service-inbound" -X GET | grep -q '"code"'; then return 0; fi
    fi
    sleep 2
  done
  echo "functions did not come up; see $log_file" >&2
  tail -20 "$log_file" >&2 || true
  KEEP_WORK=1
  exit 1
}

run_mode() {
  local mode="$1"
  echo
  echo "════ feature_setting agent_services: $mode ════"
  DECISIONS_FLAG="$mode" DECISIONS_STATE="$(native_path "$WORK/state.json")"     "${DENO[@]}" run --allow-net --allow-env --allow-read --allow-write --allow-run scripts/e2e-service-decisions.ts ||
    { KEEP_WORK=1; exit 1; }
}

{ strip_flags; echo "CRON_SECRET=$CRON_SECRET"; echo 'ALLOW_INSECURE_SERVICES=true'; } >"$WORK/on.env"
{ strip_flags; echo "CRON_SECRET=$CRON_SECRET"; } >"$WORK/off.env"

set_flag on
start_serve "$WORK/on.env" "$WORK/serve-on.log"
run_mode on

set_flag off
start_serve "$WORK/off.env" "$WORK/serve-off.log"
run_mode off

echo
echo "PASS — service decisions e2e (flag on + off)"
