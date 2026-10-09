# Cockpit — Backend (Supabase)

Postgres (with RLS), Supabase Auth and Deno Edge Functions implementing the agent ↔ app approval loop. **Phase 1 (core loop) and Phase 2 (callback retry, test actions, secret rotation, inbound rate limit) are implemented and verified locally.** Nothing here requires a cloud account.

Specs: [technical/04-technical-blueprint.md](../../technical/04-technical-blueprint.md) (contract) and [technical/phase2-and-fcm-plan.md](../../technical/phase2-and-fcm-plan.md) (Phase 2 + push).

## Layout

```text
product/backend/
├─ deno.json                         # lint / test / e2e tasks
├─ scripts/
│  ├─ e2e-agent-trigger.sh / .ts     # Agent Triggers e2e (serves functions flag on + off)
│  ├─ e2e-core-loop.sh               # runs the end-to-end check
│  ├─ e2e-core-loop.ts               #   (Deno: fetch, HMAC, local callback receiver)
│  └─ e2e-test-action.sh / .ts       # agents-test-action access rules (owner-only)
└─ supabase/
   ├─ config.toml                    # project "cockpit"; per-function verify_jwt
   ├─ migrations/
   │  ├─ 0001_init.sql               # 5 tables, RLS, append-only audit
   │  ├─ 0002_auth_bootstrap.sql     # auth.users → workspace + app_user
   │  ├─ 0003_functions.sql          # transactional RPCs (record_*, create_agent, fcm tokens)
   │  ├─ 0004_phase2.sql             # retry (claim_due_callbacks, pg_cron→pg_net), rotation,
   │  │                              #   get_owned_agent, agent_rate + hit_rate_limit
   │  └─ 0005_agent_triggers.sql     # agent_trigger, trigger_run, trigger RPCs (feature-flagged)
   ├─ functions/
   │  ├─ _shared/                    # library (not deployed): env, http, errors, logger,
   │  │                              #   supabase, hmac, vault, fcm, push, callback, delivery,
   │  │                              #   retry, cron, rate_limit, trigger, validation, types
   │  ├─ _tests/                     # Deno unit tests (not deployed)
   │  ├─ agents-create/index.ts      # JWT
   │  ├─ actions-inbound/index.ts    # HMAC (no JWT)
   │  ├─ actions-decision/index.ts   # JWT + Idempotency-Key
   │  ├─ agents-test-action/index.ts # JWT (owner)
   │  ├─ agents-rotate-secret/index.ts # JWT (owner)
   │  ├─ callbacks-retry/index.ts    # X-Cron-Secret (pg_cron only)
   │  ├─ agents-configure-trigger/   # JWT (owner), FEATURE_AGENT_TRIGGERS
   │  ├─ agents-trigger/             # JWT, FEATURE_AGENT_TRIGGERS (handler.ts + index.ts)
   │  └─ .env.example                # copy to .env (git-ignored)
   ├─ tests/core_loop_test.sql       # pgTAP: RLS, privileges, idempotency
   ├─ tests/phase2_test.sql          # pgTAP: retry claims/leases, rotation, rate limit
   ├─ tests/agent_triggers_test.sql  # pgTAP: trigger RPCs, rate-limit boundary, RLS
   └─ seed.sql                       # LOCAL ONLY dev user + agent + cron Vault secrets
```

## Prerequisites

- **Docker Desktop** running.
- **Supabase CLI** and **Deno**. Installing them is optional: every command below also works through pinned npx versions:
  - `supabase` → `npx --yes supabase@2.117.0`
  - `deno` → `npx --yes deno@2.9.6`

## Run locally

```bash
cd product/backend
cp supabase/functions/.env.example supabase/functions/.env   # once

supabase start -x storage-api,imgproxy,logflare,vector,supavisor   # Docker stack
supabase db reset                                                  # migrations + seed
supabase functions serve --no-verify-jwt --env-file supabase/functions/.env
```

- API: `http://127.0.0.1:54321` · Functions: `http://127.0.0.1:54321/functions/v1/<name>` · Studio: `http://127.0.0.1:54323`.
- `supabase status` prints the local anon and service-role keys.
- `--no-verify-jwt` is safe locally: the app-facing functions verify the caller's JWT themselves (`userIdFromReq`), and `callbacks-retry` checks `X-Cron-Secret`.
- `.env` needs `CRON_SECRET` (see `.env.example`); it must equal the `cockpit_cron_secret` Vault secret that `seed.sql` creates.

## Tests

```bash
deno task lint               # deno lint (functions + scripts)
deno task test               # 58 unit tests: hmac, validation, errors/logger, fcm, callback,
                             #   backoff, cron guard, rate limiter, Retry-After, agent triggers
supabase test db             # 114 pgTAP assertions: RLS, privileges, idempotency, append-only
                             #   audit, retry claims + leases, rotation, rate-limit windows,
                             #   agent triggers
scripts/e2e-core-loop.sh     # 79-check end-to-end run against the running stack
scripts/e2e-agent-trigger.sh # Agent Triggers: flag on (29 checks) + flag off (7); stop any
                             #   running `functions serve` first — it serves them itself
scripts/e2e-test-action.sh   # agents-test-action: 18 checks (foreign agent, approver,
                             #   disabled agent) against the running stack
```

The e2e script:
1. Creates a user through the admin API and checks the trigger provisioned their workspace.
2. Creates an agent via `agents-create`.
3. Sends forged, tampered and unknown-agent inbound requests (all 401), then a valid one, then a duplicate.
4. Registers a device token and checks RLS from the app's side.
5. Decides the action: missing key 422, bad edit 422, success, replay without re-sending the callback, conflicting key 409.
6. Confirms a local receiver got exactly one correctly signed callback containing the merged edits.
7. Unreachable agent → `retrying` ~30 s out; `callbacks-retry` rejects a missing/wrong cron secret and a user JWT, then redelivers once the agent is up (signed, original Idempotency-Key, exactly once); the 8th failed attempt becomes terminal `failed`.
8. `agents-test-action` seeds an audited sample action; `agents-rotate-secret` returns a new secret and the old one gets 401 immediately.
9. The rate limit accepts 60 requests in a window and returns 429 `rate_limited` with `Retry-After` for the 61st.
10. Scans the edge-runtime logs to confirm no secret, JWT, signature, token, cron secret or payload was logged.

## Try it by hand (seed data)

`supabase db reset` seeds:

| | |
|---|---|
| User | `dev@cockpit.local` / `cockpit-dev-password` |
| Agent | `bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb` |
| Secret | `whsec_local_dev_only_never_use_in_production` |

```bash
BODY='{"agent_id":"bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb","external_id":"manual-1","type":"email","title":"Hello","payload":{"subject":"Hi"},"editable_fields":["subject"]}'
SIG=$(printf '%s' "$BODY" | openssl dgst -sha256 -hmac 'whsec_local_dev_only_never_use_in_production' | sed 's/^.* /sha256=/')
curl -X POST http://127.0.0.1:54321/functions/v1/actions-inbound \
  -H 'Content-Type: application/json' -H "X-Cockpit-Signature: $SIG" --data-raw "$BODY"
```

## API

Every function responds with `{ "ok": true, "data": … }` or `{ "ok": false, "error": { "code", "message", "details?" } }`.

| Function | Auth | Request | Success |
|---|---|---|---|
| `POST agents-create` | User JWT | `{ name, platform: n8n\|make\|zapier\|custom, callback_url (https) }` | `201 { agent, inbound_url, signing_secret }`. The secret is returned **once** (TR-8). |
| `POST actions-inbound` | `X-Cockpit-Signature: sha256=<hex hmac(raw body, secret)>` | `{ agent_id, external_id, type, title, summary?, payload, editable_fields?, callback_url?, expires_at? }` | `200 { action_id, duplicate }` |
| `POST actions-decision` | User JWT + `Idempotency-Key` | `{ action_id, decision: approved\|approved_with_edits\|rejected, edited_payload?, reason? }` | `200 { decision_recorded, duplicate, callback_delivered }` |
| `POST agents-test-action` | User JWT (owner) | `{ agent_id }` | `201 { action_id }`: a sample pending email action (`external_id` `test-<uuid>`), audited and pushed like a real one |
| `POST agents-rotate-secret` | User JWT (owner) | `{ agent_id }` | `200 { agent, inbound_url, signing_secret }`: new secret **once**; the old one stops verifying immediately |
| `POST callbacks-retry` | `X-Cron-Secret` (pg_cron) | `{}` | `200 { claimed, delivered, rescheduled, failed }` |
| `rpc/register_fcm_token` | User JWT (PostgREST) | `{ p_token }` | `204` (also `unregister_fcm_token`) |

Error codes → HTTP: `unauthorized` / `invalid_signature` 401 · `agent_disabled` 403 · `not_found` 404 · `conflict` 409 · `expired` 410 · `payload_too_large` 413 · `validation` 422 · `rate_limited` 429 (with `Retry-After`) · `server` 500.

`actions-inbound` and `agents-test-action` share a per-agent limit of `INBOUND_RATE_LIMIT_PER_MINUTE` (default 60) in fixed one-minute windows, counted after HMAC verification.

**Callback to the agent** (after the decision commits): `POST callback_url` with `X-Cockpit-Signature` (same secret), `X-Cockpit-Action-Id` and `Idempotency-Key` headers. Body: `{ action_id, external_id, decision, payload (original + edits), edited_payload, reason, decided_at }`. Any 2xx counts as delivered. Redirects are not followed. Retries resend the same body and `Idempotency-Key`, re-signed with the agent's current secret.

## Callback retry (TR-7)

`callback_status`: `pending` → `delivered`, or `retrying` (with `next_attempt_at`) → … → `delivered` / `failed`. After the n-th failed attempt the next runs `min(6h, 15s · 2^n)` later (+0–10% jitter): 30s, 1m, 2m, 4m, 8m, 16m, 32m; the 8th failure is terminal `failed` (audit `callback_failed`; earlier failures are audited as `callback_attempted`). A blocked URL or missing secret fails immediately. Policy: `_shared/retry.ts`.

pg_cron runs `invoke_callbacks_retry()` every minute. It does nothing unless a retry is due and both Vault secrets exist (`cockpit_callbacks_retry_url`, `cockpit_cron_secret`); then it POSTs `callbacks-retry` through pg_net. `claim_due_callbacks` locks rows with `SKIP LOCKED` and leases them for 2 minutes, so overlapping runs never double-send. `seed.sql` configures this locally, so retries run by themselves once `functions serve` is up. To trigger a run by hand:

```bash
curl -X POST http://127.0.0.1:54321/functions/v1/callbacks-retry \
  -H 'X-Cron-Secret: cron_local_dev_only_never_use_in_production' -H 'Content-Type: application/json' -d '{}'
```

A duplicate `actions-decision` call only delivers if no attempt was recorded yet; after that, redelivery belongs to the scheduler.

## How the requirements are enforced

| TR | Where |
|---|---|
| TR-1 verify HMAC | `_shared/hmac.ts` constant-time compare over raw bytes; unknown agent → same 401 |
| TR-2 persist before push | `record_action_inbound` commits (idempotent on `agent_id, external_id`) before `sendPush`; tokens are returned only for new actions |
| TR-3 idempotent decision | unique `audit_entry.idempotency_key`; `record_decision` locks the action row, then replays duplicates |
| TR-6 audit before callback | decision + audit in one DB transaction; callback only after commit |
| TR-7 callback retry + backoff | `record_callback_result` → `retrying` / `failed`; `claim_due_callbacks` (SKIP LOCKED + lease); pg_cron → pg_net → `callbacks-retry` |
| TR-8 secret shown once | `create_agent` / `rotate_agent_secret` write Vault + agent row atomically; plaintext returned once; only `secret_hint` is readable |
| Rate limit | `hit_rate_limit`: fixed-window upsert per agent → 429 `rate_limited` |
| Logging | `_shared/logger.ts` redacts secrets, signatures, tokens, payloads, emails, reasons |
| SSRF | `isAllowedCallbackUrl`: https only, no loopback/private/link-local hosts (relaxed only by `ALLOW_INSECURE_CALLBACKS=true`, local only) |

## Push notifications

Set `FCM_SERVICE_ACCOUNT_JSON` (single-line service-account JSON) in `supabase/functions/.env` to send real FCM v1 pushes, then restart `functions serve`. Without it, pushes are skipped and logged as `push_skipped`, and the loop still works end to end. Tokens FCM reports as unregistered are pruned automatically. The app registers its token through `rpc/register_fcm_token` after sign-in (Firebase setup: [product/frontend/README.md](../frontend/README.md)).

To turn the downloaded key into a single line: `python -c "import json,sys; print(json.dumps(json.load(open(sys.argv[1]))))" key.json`.

## Deploying (later)

`supabase link --project-ref <ref>` → `supabase db push` → `supabase functions deploy` (config.toml keeps `actions-inbound` and `callbacks-retry` without JWT verification) → `supabase secrets set PUBLIC_INBOUND_BASE_URL=… FCM_SERVICE_ACCOUNT_JSON=… CRON_SECRET=<random>` → in the SQL editor: `select vault.create_secret('https://<ref>.supabase.co/functions/v1/callbacks-retry', 'cockpit_callbacks_retry_url'); select vault.create_secret('<same CRON_SECRET>', 'cockpit_cron_secret');`. **Never** set `ALLOW_INSECURE_CALLBACKS` in a deployed project, and never load `seed.sql` into one.

## Agent Triggers (feature-flagged)

The reverse direction: a signed-in user starts an agent. **Off by default.** Both functions answer `404 feature_disabled` before touching the database unless `FEATURE_AGENT_TRIGGERS=true`.

| Env | Default | Meaning |
|---|---|---|
| `FEATURE_AGENT_TRIGGERS` | unset (off) | Enables `agents-configure-trigger` and `agents-trigger`. Leave unset in committed config. |
| `ALLOW_INSECURE_TRIGGERS` | unset (off) | **Local only.** Allows `http://` and private-network trigger URLs. |

| Function | Auth | Request | Success |
|---|---|---|---|
| `POST agents-configure-trigger` | User JWT (owner) | `{ action: "configure", agent_id, trigger_url, min_interval_secs? }` | `200 { trigger, trigger_secret }`. The `whtrig_` secret is returned **once**; reconfiguring rotates it. |
| | | `{ action: "set_enabled", agent_id, enabled }` | `200 { trigger }` |
| `POST agents-trigger` | User JWT (workspace member) | `{ agent_id }` | `200 { run_id, delivered, detail }`. `not_found` 404 · `trigger_disabled` 409 · `rate_limited` 429 (+ `Retry-After`, per `min_interval_secs`) |

**What the agent receives:** `POST trigger_url` with body `{ trigger_id, agent_id, triggered_at, nonce }` and headers `X-Cockpit-Trigger-Signature: sha256=<hex hmac(raw body, trigger secret)>` and `X-Cockpit-Trigger-Id`. Redirects aren't followed, and the request times out after 5 s.

**How it works:**
- **Tables:** `agent_trigger` (one per agent) and `trigger_run` (one per attempt). Clients can read their own workspace's rows but can't write, and can't read the Vault secret id (column grants).
- **RPCs:** `configure_agent_trigger` writes the secret to Vault in the same transaction. `begin_trigger_run` records the run and audits `trigger_fired` before anything is sent, and serializes concurrent calls on the interval check. `record_trigger_result` marks the run `sent` / `failed` (`trigger_failed` audited).
- **Audit:** `audit_entry` gains `trigger_configured`, `trigger_fired` and `trigger_failed`. These carry no `action_id`; every other event still requires one.

## Not built yet

Payload retention purge, the DPDP/GDPR erasure procedure, and an app UI for secret rotation (the endpoint exists).

Back to the [repository index](../../README.md).
