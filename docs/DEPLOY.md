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
| Firebase | the existing project (it lists `app.cockpit.cockpit` and `app.cockpit.cockpit.dev`) |
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
| 4 | ⚠️ Apply migrations 0001–0007 | CLI |
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
supabase db push --dry-run   # lists 0001…0007; check nothing unexpected
supabase db push
```

Migrations only go forward: a mistake is fixed with a new migration, never by editing an applied one. They create the tables, RLS, RPCs, the `pg_cron` / `pg_net` / `supabase_vault` extensions and the `cockpit-callbacks-retry` cron job (every minute). The job does nothing until step 5 is done.

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

### 7. Deploy the functions

```bash
supabase functions deploy
```

This deploys every function under `supabase/functions/` with the `verify_jwt` setting from `config.toml`: `actions-inbound` (HMAC) and `callbacks-retry` (cron secret) without JWT verification, all others with it.

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
- **Database:** migrations 0001–0007 applied, extensions, the cron job active, both Vault secrets present, the retry URL pointing at this project, the cron secret not the seed value, RLS on every public table, SELECT-only policies never for `anon`, no extra functions executable by `anon`, no app role able to mutate `audit_entry`, no seed user/agent.

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
- [ ] `anon` executes no RPC beyond the harmless allow-list; `authenticated` only `register_fcm_token` / `unregister_fcm_token`; `audit_entry` immutable for every app role (deploy-check).
- [ ] service_role key only inside Edge Functions.
- [ ] The anon key is public: with it, anyone can request a sign-in code and read REST under RLS (nothing without a session); every app-facing function requires a JWT; `actions-inbound` needs a valid HMAC and `callbacks-retry` the cron secret.
- [ ] No CORS headers on functions: browsers can't call them (native app only). Revisit if a web client is added.
- [ ] Rate limits: inbound 60/min per agent; Auth email/verification limits as in step 8.
- [ ] Vault holds only real values; no seed data; `ALLOW_INSECURE_*` not set (deploy-check).
- [ ] Callback URL SSRF guard is hostname-based today; DNS-aware checking is a separate change (audit F17).
