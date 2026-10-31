# Cloud deploy runbook (Supabase)

How to put the Cockpit backend on a hosted Supabase project, check it, and roll it back. **You run every cloud step yourself**; nothing in this repo creates or changes a cloud project.

> **Never** paste a secret into a commit, an issue, a chat or a log. Values below are placeholders like `<CRON_SECRET>`; keep the real ones in a password manager and in your shell only.
>
> **Never run `supabase config push`.** `supabase/config.toml` holds **local development** values (`site_url = http://127.0.0.1:3000`, `email.max_frequency = "1s"`, `email_sent = 2`/hour). Pushing it would overwrite the cloud Auth settings. Cloud Auth is set in the Dashboard (step 8).
>
> **Never load `supabase/seed.sql`** into the cloud project: it creates a dev user, a dev agent with a well-known secret and the local cron secret. (`supabase db push` does not run it.)

## Decisions this runbook assumes

| Item | Value |
|---|---|
| Region | `ap-south-1` (Mumbai) — cannot be changed later |
| Plan | **Pro** recommended (see *Free vs Pro*) |
| Auth site URL | `https://aicockpit.dqstore.in` |
| Sign-in email | code only (no link), subject "Your AI Cockpit sign-in code", valid 60 minutes |
| SMTP | Resend, sender `no-reply@auth.dqstore.in`, name "AI Cockpit" |
| Support email | `<SUPPORT_EMAIL>` (placeholder until decided) |
| Firebase | the existing project; it must list Android apps `app.aicockpit.aicockpit` and `app.aicockpit.aicockpit.dev` (register both, then download a fresh `google-services.json`) |
| Agent Triggers | **off** in the cloud (`FEATURE_AGENT_TRIGGERS` not set) |

### Free vs Pro

| | Free | Pro (~US$25/month) |
|---|---|---|
| Pausing | Paused after **7 days without activity**; the app stops working until unpaused | Never paused |
| Backups | **None** | Daily, kept 7 days; PITR is a paid add-on |
| Limits | 500 MB database, 2 active projects, Edge Function / bandwidth caps | Higher, with usage-based overage |
| Support | Community | Email |

Plan limits and prices change; check supabase.com/pricing before deciding. Free is fine for a private trial. **Upgrade to Pro before** the first real users, the Play closed test or the Play review: a paused project or a lost database without a backup would break the app for everyone. Upgrading keeps the project ref, so app builds keep working.

## Order of steps

⚠️ marks a step that is hard or impossible to undo.

| # | Step | Where |
|---|---|---|
| 1 | Turn on MFA for your Supabase account | Dashboard → Account |
| 2 | ⚠️ Create the project: region, plan, database password | Dashboard |
| 3 | Link this repo | CLI |
| 4 | ⚠️ Apply migrations 0001–0009 | CLI |
| 5 | Create the two Vault secrets | SQL editor |
| 6 | Set the function secrets | CLI |
| 7 | Deploy the Edge Functions | CLI |
| 8 | Auth settings, SMTP, email template | Dashboard + DNS |
| 9 | Run `scripts/deploy-check.sh` | CLI |
| 10 | Smoke test | App + curl |
| 11 | Prod app config and build | Frontend repo |

### 1–2. Account and project (Dashboard)

1. Account → Security → enable **MFA**.
2. New project → organisation, name `ai-cockpit`, region **ap-south-1**, plan as decided, and a long random **database password** (store it in the password manager; Supabase can't show it again, only reset it).
3. Note the **project ref** (`https://<PROJECT_REF>.supabase.co`). It ends up in every app build.

### 3. Link

From `product/backend/`:

```bash
supabase login                          # opens the browser; stores an access token locally
supabase link --project-ref <PROJECT_REF>   # asks for the database password
```

`supabase link` writes `supabase/.temp/` (git-ignored). Nothing secret is committed.

### 4. Migrations ⚠️

```bash
supabase db push --dry-run   # lists 0001…0009 (or only the new ones); check nothing unexpected
supabase db push
```

Migrations only go forward: a mistake is fixed with a new migration, never by editing an applied one. They create the tables, RLS, RPCs, the `pg_cron` / `pg_net` / `supabase_vault` extensions and the `cockpit-callbacks-retry` cron job (every minute). The job does nothing until step 5 is done.

**Grants (0009).** The app's reads only work through explicit grants: a cloud project does not hand out the default table grants the local stack has, and without them every signed-in read fails with `42501` (sign-in then looks like it fails). Migration 0009 revokes everything from `anon` / `authenticated` / `service_role` / `PUBLIC` and grants exactly the matrix in its header: `authenticated` reads only the columns the app selects (never `app_user.fcm_tokens` or Vault secret ids) under RLS, writes nothing directly, and executes only `current_workspace_id()`, `register_fcm_token`, `unregister_fcm_token`; `service_role` has DML (on `audit_entry` only SELECT / INSERT) and the Edge Functions' RPCs; `anon` has nothing; no app role holds TRUNCATE / REFERENCES / TRIGGER. It also removes the default grants for new objects, so every later migration must grant explicitly. Never grant in the Dashboard by hand: add a migration, update the matrix in `supabase/tests/privileges_test.sql` and `scripts/deploy-check.ts`, and run deploy-check after the push.

### 5. Vault secrets (SQL editor)

Generate the cron secret locally (keep it; step 6 needs the same value):

```bash
openssl rand -base64 48 | tr -d '\n'     # → <CRON_SECRET>
```

Then in Dashboard → SQL editor (replace the placeholders; don't save the query):

```sql
select vault.create_secret('https://<PROJECT_REF>.supabase.co/functions/v1/callbacks-retry', 'cockpit_callbacks_retry_url');
select vault.create_secret('<CRON_SECRET>', 'cockpit_cron_secret');
```

To rotate later: `select vault.update_secret((select id from vault.secrets where name = 'cockpit_cron_secret'), '<NEW_CRON_SECRET>');` and set the same value as `CRON_SECRET` (step 6) right after.

### 6. Function secrets

`SUPABASE_URL` and `SUPABASE_SERVICE_ROLE_KEY` are injected by Supabase; don't set them. Set the rest with the CLI (values from your password manager, typed in your shell, never committed):

```bash
supabase secrets set PUBLIC_INBOUND_BASE_URL=https://<PROJECT_REF>.supabase.co/functions/v1
supabase secrets set CRON_SECRET='<CRON_SECRET>'
supabase secrets set FCM_SERVICE_ACCOUNT_JSON="$(cat <path-to-service-account.json> | tr -d '\n')"
# optional: supabase secrets set INBOUND_RATE_LIMIT_PER_MINUTE=60
supabase secrets list   # shows names and digests only
```

| Name | Set where | Value comes from | Notes |
|---|---|---|---|
| `SUPABASE_URL`, `SUPABASE_SERVICE_ROLE_KEY` | injected | Supabase | service_role key only ever inside functions — never in the app, the repo or a log |
| `PUBLIC_INBOUND_BASE_URL` | `supabase secrets set` | `https://<PROJECT_REF>.supabase.co/functions/v1` | builds the inbound URL `agents-create` returns |
| `CRON_SECRET` | `supabase secrets set` | `openssl rand` (step 5) | must equal Vault `cockpit_cron_secret`; rotate both together |
| `FCM_SERVICE_ACCOUNT_JSON` | `supabase secrets set` | Firebase → Project settings → Service accounts → new private key (one line) | without it pushes are skipped (`push_skipped`) |
| `INBOUND_RATE_LIMIT_PER_MINUTE` | optional | default 60 | per agent, fixed one-minute window |
| `FEATURE_AGENT_TRIGGERS` | **not set** | — | Agent Triggers stay off in the cloud |
| `ALLOW_INSECURE_CALLBACKS`, `ALLOW_INSECURE_TRIGGERS` | **never set** | — | local-only; allow `http://` and private hosts |
| Vault `cockpit_callbacks_retry_url` | SQL editor (step 5) | project functions URL | |
| Vault `cockpit_cron_secret` | SQL editor (step 5) | `<CRON_SECRET>` | never the `seed.sql` value |
| Agent inbound / trigger secrets | Vault, created by the app | — | nothing to do |
| SMTP password | Dashboard → Auth → SMTP | Resend API key | |
| Database password | password manager | step 2 | |
| `REVIEWER_LOGIN_ENABLED`, `REVIEWER_EMAIL`, `REVIEWER_CODE` | `supabase secrets set`, **only while a Play review needs it** | see *Play review sign-in* | unset = off (default) |

### 7. Deploy the functions

```bash
supabase functions deploy
```

This deploys every function under `supabase/functions/` with the `verify_jwt` setting from `config.toml`: `actions-inbound` (HMAC), `callbacks-retry` (cron secret) and `reviewer-signin` (called before sign-in; off unless its secrets are set) without JWT verification, all others with it.

### 8. Auth, SMTP and the sign-in email (Dashboard + DNS)

**Authentication → URL configuration**
- Site URL: `https://aicockpit.dqstore.in`
- Redirect URLs: `https://aicockpit.dqstore.in` only. The app signs in with the emailed code, so no app deep link is needed.

**Authentication → Providers → Email**
- Email provider on; **Confirm email off** (the code is the confirmation).
- OTP length **6** and OTP expiry **3600** seconds. They must match the app's `otpLength` / `otpValidity`.

**Authentication → Rate limits**
- Emails: start at **30 per hour** with custom SMTP (the built-in mailer allows only a couple per hour); raise as usage grows.
- Minimum interval between emails to the same user (`max_frequency`): **60 seconds**. The app's resend cooldown is 60 s too.
- Token verifications / sign-ups: keep the defaults.

**Resend + DNS for `auth.dqstore.in`**
1. Resend → Domains → add `auth.dqstore.in` (a subdomain keeps sign-in mail reputation separate from marketing mail on `dqstore.in`).
2. Add the DNS records Resend shows (DKIM `resend._domainkey.auth`, the return-path MX/TXT on the `send.auth` subdomain, as listed).
3. ⚠️ **SPF: one record per name.** If the name already has an SPF `TXT` record (`v=spf1 …`), **add Resend's `include:` to that record**; never create a second SPF record. Two SPF records make SPF fail for **all** mail on that name, marketing included.
4. **DMARC:** add `_dmarc.auth.dqstore.in` `TXT` `v=DMARC1; p=none; rua=mailto:<SUPPORT_EMAIL>` to start; tighten to `quarantine` once reports look clean.
5. Wait for Resend to show the domain as **verified**.

**Authentication → SMTP settings**
- Host `smtp.resend.com`, port `465`, username `resend`, password = a Resend API key with sending access only.
- Sender email `no-reply@auth.dqstore.in`, sender name `AI Cockpit`.

**Authentication → Email templates → Magic link**
- Subject: `Your AI Cockpit sign-in code`
- Body: paste `supabase/templates/magic_link.html` from this repo. It shows `{{ .Token }}` only; there is **no** link (`{{ .ConfirmationURL }}`) on purpose.
- If "Confirm signup" is ever turned on, give that template the same code-only body.

### 9. Deploy check

Read-only; prints check names and pass/fail, never a value:

```bash
export SUPABASE_PROJECT_REF=<PROJECT_REF>
export SUPABASE_ACCESS_TOKEN=<personal access token>      # Dashboard → Account → Access tokens
export SUPABASE_DB_URL='<connection string>'              # Dashboard → Connect → session pooler URI
scripts/deploy-check.sh
unset SUPABASE_ACCESS_TOKEN SUPABASE_DB_URL
```

It checks:

- **Management API:** every function deployed and `ACTIVE` with `config.toml`'s `verify_jwt`; required secrets present by name, `ALLOW_INSECURE_*` / `FEATURE_AGENT_TRIGGERS` absent; Auth site URL, OTP length/expiry, 60 s email frequency, custom SMTP, email rate limit > 2/h, subject and code-only template.
- **Database:** migrations 0001–0009 applied, extensions, the cron job active, both Vault secrets present, the retry URL pointing at this project, the cron secret not the seed value, RLS on every public table, SELECT-only policies never for `anon`, the 0009 privilege matrix exactly (tables, columns, sequences, function EXECUTE, no default grants for new objects; a mismatch lists the role / object / privilege names), no app role able to mutate `audit_entry`, no seed user/agent.

Fix every ✗ before going on. A `!` means the API didn't report a setting; check it in the Dashboard.

### 10. Smoke test (cloud)

- [ ] `scripts/deploy-check.sh` is green.
- [ ] **Sign-in:** a real email receives the code from `no-reply@auth.dqstore.in` (not spam); resend is held for 60 s; a wrong code shows "wrong or expired".
- [ ] **Agent:** create one in the app; the inbound URL is `https://<PROJECT_REF>.supabase.co/functions/v1/actions-inbound`.
- [ ] **Inbound:** a signed request (HMAC with the agent secret) creates an action that appears in the feed; an unsigned or tampered one gets 401.
- [ ] **Push:** a real phone gets the notification (FCM).
- [ ] **Decision:** approve → the callback reaches a test receiver (e.g. a webhook.site URL as the agent's callback); with an unreachable callback the action goes `retrying` and pg_cron retries it (`select * from cron.job_run_details order by start_time desc limit 5;`).
- [ ] **Roles:** "Send a test action" works for the owner; an approver gets 403.
- [ ] **Account deletion:** delete a throwaway account; its data and auth user are gone.
- [ ] **Logs:** Edge Function logs contain no email, JWT or secret.

### 11. Prod app (frontend repo)

`env/prod.json` (git-ignored; template `env/prod.example.json`):

| Key | From |
|---|---|
| `SUPABASE_URL` | `https://<PROJECT_REF>.supabase.co` |
| `SUPABASE_ANON_KEY` | Dashboard → Project settings → API keys → publishable / anon key (public by design) |
| `TERMS_URL`, `PRIVACY_URL` | the hosted pages (https) |
| `SUPPORT_EMAIL` | `<SUPPORT_EMAIL>` |
| `SENTRY_DSN` | optional |

Prod release builds stop in Gradle without `SUPABASE_URL`, `SUPABASE_ANON_KEY`, and https `TERMS_URL` / `PRIVACY_URL`, or without the upload key (`android/key.properties`); a prod build without backend config refuses to start. `android/app/google-services.json` from the existing Firebase project.

```bash
flutter build appbundle --release --flavor prod --dart-define-from-file=env/prod.json
```

## Play review sign-in

The app signs in with an emailed code, which a Google Play reviewer can't read. `reviewer-signin` (migration 0008) accepts **one fixed 6-digit code for one allowlisted email**, so the reviewer can sign in through the normal sign-in screen. It is **off by default** and switched on only by function secrets.

How it works: when the normal code check fails, the app posts `{email, code}` to `reviewer-signin`. Only if `REVIEWER_LOGIN_ENABLED` is exactly `true` and both match `REVIEWER_EMAIL` / `REVIEWER_CODE` does it return a one-time token hash, which the app exchanges for a normal session (no email is sent). Every other request (off, another email, wrong code, locked, malformed) gets the **identical** `400 invalid_code`. Wrong codes for the reviewer email count in `reviewer_signin_guard`: **5 within 15 minutes lock it for 1 hour**. Other emails never count, so nobody who doesn't know the reviewer email can guess the code or lock it.

**Set up (once)**
1. Sign in to the prod app once with the reviewer mailbox (`kusumeshkantsharma+playreview@gmail.com`) using a real emailed code; this creates its own workspace.
2. In that account: connect a "Demo agent" (callback `https://aicockpit.dqstore.in/api/demo-callback`) and use **Send test action** two or three times so the feed has pending items.

**Turn on** (values typed in your shell, kept in the password manager, never committed):

```bash
supabase secrets set REVIEWER_EMAIL='kusumeshkantsharma+playreview@gmail.com'
supabase secrets set REVIEWER_CODE="$(LC_ALL=C tr -dc 0-9 </dev/urandom | head -c 6)"   # note it before closing the shell
supabase secrets set REVIEWER_LOGIN_ENABLED=true
```

Enter the email and code in Play Console → App content → Sign-in details. Google reviews **every** update, so either keep it on and set a new code for each submission, or turn it on before each submission and off after approval.

**Turn off:** `supabase secrets unset REVIEWER_LOGIN_ENABLED` (takes effect on the next request; no app build). To remove it completely, also unset `REVIEWER_EMAIL` and `REVIEWER_CODE` and delete the review account in the app.

**If it is locked** (5 wrong codes): wait an hour, or clear it in the SQL editor: `update public.reviewer_signin_guard set failures = 0, window_start = null, locked_until = null;`

**Check:** `scripts/deploy-check.sh` reports whether the reviewer secrets are set (names only). Logs show `reviewer_signin` with `ok` / `denied` / `locked` and never the email or code.

## Rollback

| What | How |
|---|---|
| Edge Functions | Check out the last good tag and `supabase functions deploy` again |
| A migration | Migrations don't roll back. Write a new migration that undoes the change; test it locally (`supabase db reset` + `supabase test db`) first |
| Data | Pro: restore a daily backup (Dashboard → Database → Backups). With PITR: restore to a point in time. Free: no backup exists |
| A secret | `supabase secrets set` again (and the Vault secret for `CRON_SECRET`) |
| Auth settings | Re-enter them from this runbook (they are not in `config.toml` for the cloud) |

**Before every `supabase db push`:** tag the release, make sure a recent backup exists (Pro), and run the new migration against a local reset first. Keep any manual `supabase db dump` file out of the repo; it contains user data.

## Backups and PITR

- **Free:** no backups. Don't hold real users there.
- **Pro:** daily backups, 7 days. Enough for launch.
- **PITR** (add-on): restore to any second within the retention window. Worth it once losing a day of decisions or audit would matter to customers.

## Monitoring

- **Logs:** Dashboard → Logs → Edge Functions (look for `unhandled_error`, `account_auth_delete_failed`, `request_rejected` spikes) and Postgres.
- **Cron:** `select status, return_message, start_time from cron.job_run_details where jobid = (select jobid from cron.job where jobname = 'cockpit-callbacks-retry') order by start_time desc limit 20;`
- **App:** Sentry (`SENTRY_DSN`).
- **Uptime:** follow-up — a small `health` function plus an external uptime check.
- **Usage:** Dashboard → Usage, and the plan's spend alerts.

## Cloud security checklist

- [ ] MFA on the Supabase account; long database password in a password manager.
- [ ] RLS on every public table; policies SELECT-only and never for `anon` (deploy-check).
- [ ] Privileges match the 0009 matrix: `anon` nothing; `authenticated` only the app's columns plus `current_workspace_id` / `register_fcm_token` / `unregister_fcm_token`; `audit_entry` immutable for every app role (deploy-check).
- [ ] service_role key only inside Edge Functions.
- [ ] The anon key is public: with it, anyone can request a sign-in code and read REST under RLS (nothing without a session); every app-facing function requires a JWT; `actions-inbound` needs a valid HMAC and `callbacks-retry` the cron secret.
- [ ] No CORS headers on functions: browsers can't call them (native app only). Revisit if a web client is added.
- [ ] Rate limits: inbound 60/min per agent; Auth email/verification limits as in step 8.
- [ ] Vault holds only real values; no seed data; `ALLOW_INSECURE_*` not set (deploy-check).
- [ ] Callback URL SSRF guard is hostname-based today; DNS-aware checking is a separate change (audit F17).
