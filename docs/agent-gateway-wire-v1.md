# Agent gateway wire contract v1 (as Cockpit implements it)

Cockpit's `agent-proxy` is the only caller of an agent service. This is the HTTP contract between them. Code: `supabase/functions/_shared/hmac.ts` (signing), `_shared/gateway.ts` (calls, retries, mapping), `scripts/stub-agent.ts` (a reference agent). Test vectors: `supabase/functions/_tests/vectors/signature_v1.json`.

## 1. Request: Cockpit → agent

```
POST {base_url}/cockpit/v1/ops/{op}
```

- Must be **https**. Plain http is accepted only when `ALLOW_INSECURE_SERVICES=true` on the Cockpit side (local development only). Redirects are not followed. Private / loopback hosts are refused.
- `{op}` is always an op declared in the service's manifest. Cockpit never passes through a path or a body.
- Body (the raw JSON string, exactly as sent, is what gets hashed and signed):

```json
{ "params": { ... }, "if_match": "<version>" }
```

`if_match` is present only when the app sent one.

### Headers

| Header | Value |
|---|---|
| `Content-Type` | `application/json` |
| `X-Cockpit-Contract-Version` | the registry's `contract_version`, e.g. `1.0` |
| `X-Cockpit-Key-Id` | id of the signing key used (the current key) |
| `X-Cockpit-Timestamp` | unix seconds |
| `X-Cockpit-Nonce` | uuid v4, **fresh for every attempt** |
| `X-Cockpit-Content-SHA256` | lowercase hex SHA-256 of the raw body |
| `X-Cockpit-Request-Id` | stable across retries; the idempotency key (the app's `Idempotency-Key` for write / destructive ops, a uuid for reads) |
| `X-Cockpit-Workspace` | the workspace subject (`service_access.subject`; the raw workspace id for now) |
| `X-Cockpit-User` | the acting user id (raw) |
| `X-Cockpit-Signature` | `v1=<lowercase hex HMAC>` |
| `User-Agent` | `Cockpit-Gateway/1` (not signed) |

### Signature

```
string_to_sign = "COCKPIT-V1\n" + key_id + "\n" + timestamp + "\n" + nonce + "\n"
               + "POST\n" + path + "\n" + content_sha256 + "\n"
               + workspace + "\n" + user + "\n" + request_id
signature      = "v1=" + hex(HMAC-SHA256(signing_secret, string_to_sign))
```

- `path` is the URL path as sent, e.g. `/cockpit/v1/ops/ideas.list`. If `base_url` has a path prefix, the prefix is included.
- Every string is UTF-8, there's no trailing newline, and hex is lowercase.
- Compare signatures in constant time.
- Each service has two signing keys, **current** and **next**. Cockpit signs with current. Rotation swaps them, so the agent must accept both key ids at all times. The key ids and secrets are given once at registration (`register-service.ts` prints `current: <key id> <secret>` and `next: <key id> <secret>`).
- ⚠️ **Operators: never run `register-service --rotate-keys` on a live service.** It replaces **both** keys at once, so calls fail until the agent is updated. Live rotation is `swap_service_signing_keys` (next ↔ current), which the agent survives because it accepts both ids.

## 2. What the agent must do

1. Reject if `|now − X-Cockpit-Timestamp| > 60 s`.
2. Recompute SHA-256 of the raw body and compare it with `X-Cockpit-Content-SHA256`.
3. Look up the secret for `X-Cockpit-Key-Id` (current or next); an unknown id is rejected. Then verify the signature.
4. Reject a `(key_id, nonce)` pair seen in the last **10 minutes**.
5. For writes, deduplicate on `X-Cockpit-Request-Id`, scoped to `X-Cockpit-Workspace`:
   - same id + same body → return the original answer;
   - same id + different body → error `request_id_reuse`.
6. Accept contract major version `1`; otherwise return `unsupported_contract`.
7. Trust only the signed headers. In particular, workspace and user come from the headers, never from `params`.

Signature, timestamp and nonce failures should answer 401 with an error envelope (the stub uses codes `invalid_signature` and `replayed_nonce`). Cockpit never shows these to users.

## 3. Response: agent → Cockpit

Success: HTTP 200 / 201 / 202 with

```json
{ "ok": true, "result": { ... },
  "meta": { "usage": { "used": 3, "limit": 10, "trial_ends_at": null },
            "poll_after_ms": 500, "version": "v7" } }
```

- `result` is passed to the app untouched.
- From `meta`, Cockpit passes on only `usage` (`used` int ≥ 0, `limit` int ≥ 0 or null, `trial_ends_at` ISO datetime or null), `poll_after_ms` (int, 0–600000) and `version` (string ≤ 200 chars), each only if well-typed. Everything else is dropped. Cockpit adds `meta.request_id`.
- HTTP **202** reaches the app as 202 (e.g. an accepted job; the app polls with `poll_after_ms`). 200 and 201 reach it as 200.
- The response size cap is the op's `max_response_bytes`.

Error: any non-2xx with

```json
{ "ok": false, "error": { "code": "quota_reached", "message": "…", "details": { } } }
```

Cockpit shows only these codes to users, and only when the manifest lists them in `errors`. It never passes on the agent's `message` or `details`:

| Agent code | App sees |
|---|---|
| `validation` | 422 `validation` |
| `not_found` | 404 `not_found` |
| `conflict` | 409 `conflict` |
| `trial_ended` | 403 `trial_ended` |
| `quota_reached` | 403 `quota_reached` |
| `approval_blocked` | 422 `approval_blocked` |
| `agent_paused` | 503 `agent_paused` |
| `idea_final` | 409 `conflict` with `details.code = "idea_final"` |

Anything else, an undeclared code, `unsupported_contract`, `request_id_reuse`, or any 401 / signature failure, becomes **502 `agent_error`**. Only the code is logged.

Transport failures:

| Situation | App sees |
|---|---|
| network error (refused, DNS, reset) | 503 `agent_unavailable` + `Retry-After: 5` |
| 503 without a valid envelope | 503 `agent_unavailable` |
| timeout | 504 `agent_timeout` |
| invalid JSON, wrong envelope, over the size cap, 5xx | 502 `agent_error` |

## 4. Timeouts and retries

| Op class | Default timeout | Automatic retry |
|---|---|---|
| `read` | 8 s | one, on network error / timeout / 502 / 503 / 504, after 250–500 ms |
| `write` | 10 s | one, same conditions, **same request id, new nonce** (so the agent must dedupe) |
| `destructive` | 10 s | none |

A manifest op may set `timeout_ms` (≤ 30 000). The timeout applies to each attempt and covers reading the body.

## 5. Cockpit-side guards (FYI for agent authors)

The `agent_services` flag; registry status (`draft` / `retired` → not found, `paused` → `agent_paused`); workspace access (`service_not_enabled`, blocked looks the same); `min_app_version` (`app_update_required`); manifest ops only (`unsupported_op`) and their roles; per-user rate limits per op class (read 120 / write 30 / destructive 5 per minute); a 64 KB app body cap plus the op's `max_request_bytes`; a circuit breaker (5 consecutive agent failures → no calls for 30 s, then one trial call). Built-in ops `service.enable` / `service.disable` are handled by Cockpit and never reach the agent.
