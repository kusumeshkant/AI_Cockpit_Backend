// deno-lint-ignore-file no-explicit-any -- Management API / SQL rows are untyped JSON checked ad hoc.
// Read-only check of a deployed (linked) Supabase project against this repo
// (F10). Prints only check names and pass/fail — never a value: no secret,
// key, URL or setting is echoed, not even on failure.
//
// Run through scripts/deploy-check.sh. Env (all optional; a group without
// its inputs is skipped, not failed):
//   SUPABASE_PROJECT_REF   project ref (e.g. from `supabase link`)
//   SUPABASE_ACCESS_TOKEN  personal access token → Management API checks
//   SUPABASE_DB_URL        Postgres connection string → database checks
//                          (opened in a READ ONLY transaction)
//   EXPECTED_SITE_URL      Auth site URL to expect (default below)
import postgres from 'npm:postgres@3.4.5';

const EXPECTED = {
  siteUrl: Deno.env.get('EXPECTED_SITE_URL') ?? 'https://aicockpit.dqstore.in',
  otpLength: 6,
  otpExpirySeconds: 3600,
  emailMaxFrequencySeconds: 60,
  requiredSecrets: ['PUBLIC_INBOUND_BASE_URL', 'CRON_SECRET'],
  optionalSecrets: ['FCM_SERVICE_ACCOUNT_JSON'],
  // Local-only switches and the Agent Triggers flag (off in the cloud for now).
  forbiddenSecrets: [
    'ALLOW_INSECURE_CALLBACKS',
    'ALLOW_INSECURE_TRIGGERS',
    'FEATURE_AGENT_TRIGGERS',
  ],
  vaultSecrets: ['cockpit_callbacks_retry_url', 'cockpit_cron_secret'],
  extensions: ['pg_cron', 'pg_net', 'supabase_vault'],
  cronJob: 'cockpit-callbacks-retry',
  // Public functions anon may execute: harmless by design.
  anonFunctionsAllowed: ['audit_entry_forbid_mutation', 'current_workspace_id'],
  // seed.sql (LOCAL ONLY) leftovers that must never exist in the cloud.
  seedUserId: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
  seedAgentId: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',
  seedCronSecret: 'cron_local_dev_only_never_use_in_production',
};

type Status = 'pass' | 'fail' | 'warn' | 'skip';
const results: { status: Status; name: string; note?: string }[] = [];

function record(status: Status, name: string, note?: string): void {
  results.push({ status, name, note });
  const mark = { pass: '✓', fail: '✗', warn: '!', skip: '–' }[status];
  console.log(`  ${mark} ${name}${note ? ` — ${note}` : ''}`);
}

const check = (ok: boolean, name: string, failNote?: string) =>
  record(ok ? 'pass' : 'fail', name, ok ? undefined : failNote);

function section(title: string): void {
  console.log(`\n▸ ${title}`);
}

const root = new URL('..', import.meta.url);

/** Function slugs in supabase/functions (excluding _shared/_tests). */
function localFunctions(): string[] {
  const slugs: string[] = [];
  for (const entry of Deno.readDirSync(new URL('supabase/functions/', root))) {
    if (entry.isDirectory && !entry.name.startsWith('_')) slugs.push(entry.name);
  }
  return slugs.sort();
}

/** verify_jwt per function from supabase/config.toml. */
function expectedVerifyJwt(): Map<string, boolean> {
  const toml = Deno.readTextFileSync(new URL('supabase/config.toml', root));
  const map = new Map<string, boolean>();
  for (
    const match of toml.matchAll(
      /\[functions\.([a-z0-9-]+)\]\s*\n\s*verify_jwt\s*=\s*(true|false)/g,
    )
  ) {
    map.set(match[1], match[2] === 'true');
  }
  return map;
}

/** Migration versions in supabase/migrations. */
function localMigrations(): string[] {
  const versions: string[] = [];
  for (const entry of Deno.readDirSync(new URL('supabase/migrations/', root))) {
    if (entry.isFile && entry.name.endsWith('.sql')) versions.push(entry.name.split('_')[0]);
  }
  return versions.sort();
}

async function management(path: string, token: string): Promise<any> {
  const response = await fetch(`https://api.supabase.com/v1${path}`, {
    headers: { Authorization: `Bearer ${token}` },
  });
  if (!response.ok) throw new Error(`HTTP ${response.status}`);
  return response.json();
}

async function managementChecks(ref: string, token: string): Promise<void> {
  section('Edge Functions');
  try {
    const deployed = await management(`/projects/${ref}/functions`, token) as any[];
    const bySlug = new Map(deployed.map((f) => [f.slug as string, f]));
    const verify = expectedVerifyJwt();
    for (const slug of localFunctions()) {
      const fn = bySlug.get(slug);
      if (!fn) {
        record('fail', `${slug} deployed`, 'not deployed');
        continue;
      }
      check(fn.status === 'ACTIVE', `${slug} active`, 'not ACTIVE');
      const expected = verify.get(slug);
      if (expected === undefined) {
        record('warn', `${slug} verify_jwt`, 'no [functions.*] entry in config.toml');
      } else if (typeof fn.verify_jwt === 'boolean') {
        check(fn.verify_jwt === expected, `${slug} verify_jwt matches config.toml`, 'differs');
      } else {
        record('warn', `${slug} verify_jwt`, 'not reported by the API');
      }
    }
  } catch (error) {
    record('fail', 'list functions', `Management API ${(error as Error).message}`);
  }

  section('Function secrets (names only)');
  try {
    const secrets = await management(`/projects/${ref}/secrets`, token) as any[];
    const names = new Set(secrets.map((s) => s.name as string));
    for (const name of EXPECTED.requiredSecrets) {
      check(names.has(name), `${name} is set`, 'missing');
    }
    for (const name of EXPECTED.optionalSecrets) {
      record(
        names.has(name) ? 'pass' : 'warn',
        `${name} is set`,
        names.has(name) ? undefined : 'missing: push stays off',
      );
    }
    for (const name of EXPECTED.forbiddenSecrets) {
      check(!names.has(name), `${name} is not set`, 'must not be set in the cloud');
    }
  } catch (error) {
    record('fail', 'list secrets', `Management API ${(error as Error).message}`);
  }

  section('Auth settings');
  try {
    const auth = await management(`/projects/${ref}/config/auth`, token);
    const field = (key: string, name: string, ok: (value: any) => boolean) => {
      if (!(key in auth)) {
        return record('warn', name, `'${key}' not in the API response — check in the Dashboard`);
      }
      check(ok(auth[key]), name, 'differs from the runbook');
    };
    field('site_url', 'site URL is the expected one', (v) => v === EXPECTED.siteUrl);
    field(
      'mailer_otp_length',
      `OTP length ${EXPECTED.otpLength} (app otpLength)`,
      (v) => Number(v) === EXPECTED.otpLength,
    );
    field(
      'mailer_otp_exp',
      `OTP expiry ${EXPECTED.otpExpirySeconds}s (app otpValidity)`,
      (v) => Number(v) === EXPECTED.otpExpirySeconds,
    );
    field(
      'smtp_max_frequency',
      `email max frequency ${EXPECTED.emailMaxFrequencySeconds}s (app cooldown)`,
      (v) => Number(v) === EXPECTED.emailMaxFrequencySeconds,
    );
    field('smtp_host', 'custom SMTP configured', (v) => typeof v === 'string' && v.length > 0);
    field('smtp_admin_email', 'SMTP sender set', (v) => typeof v === 'string' && v.length > 0);
    field(
      'rate_limit_email_sent',
      'email rate limit raised above the default 2/h',
      (v) => Number(v) > 2,
    );
    field(
      'mailer_subjects_magic_link',
      'sign-in email subject names AI Cockpit',
      (v) => typeof v === 'string' && v.includes('AI Cockpit'),
    );
    field(
      'mailer_templates_magic_link_content',
      'sign-in email has the code and no link',
      (v) => typeof v === 'string' && v.includes('{{ .Token }}') && !v.includes('ConfirmationURL'),
    );
  } catch (error) {
    record('fail', 'read auth config', `Management API ${(error as Error).message}`);
  }
}

async function databaseChecks(url: string, ref: string | undefined): Promise<void> {
  let sql: ReturnType<typeof postgres> | undefined;
  try {
    sql = postgres(url, { max: 1, prepare: false, onnotice: () => {} });
    await sql.begin('read only', async (tx: any) => {
      section('Migrations');
      const applied = new Set(
        (await tx`select version from supabase_migrations.schema_migrations`).map((r: any) =>
          r.version
        ),
      );
      for (const version of localMigrations()) {
        check(applied.has(version), `migration ${version} applied`, 'not applied');
      }

      section('Extensions and schedule');
      const extensions = new Set(
        (await tx`select extname from pg_extension`).map((r: any) => r.extname),
      );
      for (const name of EXPECTED.extensions) {
        check(extensions.has(name), `extension ${name}`, 'not installed');
      }
      const [job] = await tx`select active from cron.job where jobname = ${EXPECTED.cronJob}`;
      check(
        job?.active === true,
        `pg_cron job ${EXPECTED.cronJob} active`,
        job ? 'inactive' : 'missing',
      );

      section('Vault (names only)');
      const vault = new Set((await tx`select name from vault.secrets`).map((r: any) => r.name));
      for (const name of EXPECTED.vaultSecrets) {
        check(vault.has(name), `Vault secret ${name}`, 'missing');
      }
      const [shape] = await tx`
        select
          bool_or(name = 'cockpit_callbacks_retry_url'
                  and decrypted_secret like ${
        ref
          ? `https://${ref}.supabase.co/functions/v1/callbacks-retry`
          : 'https://%/functions/v1/callbacks-retry'
      })
            as retry_url_ok,
          bool_or(name = 'cockpit_cron_secret' and decrypted_secret = ${EXPECTED.seedCronSecret})
            as cron_is_seed
        from vault.decrypted_secrets`;
      check(
        shape?.retry_url_ok === true,
        'retry URL points at this project’s callbacks-retry',
        'wrong or missing',
      );
      check(
        shape?.cron_is_seed !== true,
        'cron secret is not the local seed value',
        'uses the LOCAL ONLY seed secret',
      );

      section('Row-level security and grants');
      const noRls =
        await tx`select tablename from pg_tables where schemaname = 'public' and not rowsecurity`;
      check(
        noRls.length === 0,
        'RLS enabled on every public table',
        `off on: ${noRls.map((r: any) => r.tablename).join(', ')}`,
      );
      const loose = await tx`
        select tablename from pg_policies
         where schemaname = 'public'
           and (roles && array['anon','public']::name[] or cmd <> 'SELECT')`;
      check(
        loose.length === 0,
        'policies are SELECT-only and never for anon',
        `check: ${loose.map((r: any) => r.tablename).join(', ')}`,
      );
      const anonFns = (await tx`
        select p.proname from pg_proc p join pg_namespace n on n.oid = p.pronamespace
         where n.nspname = 'public' and has_function_privilege('anon', p.oid, 'execute')`)
        .map((r: any) => r.proname as string)
        .filter((name: string) => !EXPECTED.anonFunctionsAllowed.includes(name));
      check(
        anonFns.length === 0,
        'anon can execute no other public function',
        `also: ${anonFns.join(', ')}`,
      );
      const [audit] = await tx`
        select bool_or(has_table_privilege(r, 'public.audit_entry', p)) as writable
          from unnest(array['anon','authenticated','service_role']) r,
               unnest(array['UPDATE','DELETE','TRUNCATE']) p`;
      check(
        audit?.writable !== true,
        'audit_entry: no app role can UPDATE / DELETE / TRUNCATE',
        'a role can mutate it',
      );

      section('No local seed data');
      const [seed] = await tx`
        select exists (select 1 from auth.users where id = ${EXPECTED.seedUserId}::uuid) as user_present,
               exists (select 1 from public.agent where id = ${EXPECTED.seedAgentId}::uuid) as agent_present`;
      check(!seed?.user_present, 'seed dev user absent', 'seed.sql was applied');
      check(!seed?.agent_present, 'seed dev agent absent', 'seed.sql was applied');
    });
  } catch (error) {
    // Never echo the connection string or server text: it can contain the host/password.
    const code = (error as any)?.code;
    record('fail', 'database checks', `could not complete${code ? ` (${code})` : ''}`);
  } finally {
    await sql?.end({ timeout: 5 });
  }
}

const ref = Deno.env.get('SUPABASE_PROJECT_REF')?.trim() || undefined;
const token = Deno.env.get('SUPABASE_ACCESS_TOKEN')?.trim() || undefined;
const dbUrl = Deno.env.get('SUPABASE_DB_URL')?.trim() || undefined;

console.log('Cockpit deploy check (read-only; prints names, never values)');
if (ref && token) {
  await managementChecks(ref, token);
} else {
  section('Management API');
  record(
    'skip',
    'functions, secrets, auth settings',
    'set SUPABASE_PROJECT_REF and SUPABASE_ACCESS_TOKEN',
  );
}
if (dbUrl) {
  await databaseChecks(dbUrl, ref);
} else {
  section('Database');
  record('skip', 'migrations, Vault, cron, RLS, grants, seed', 'set SUPABASE_DB_URL');
}

const failed = results.filter((r) => r.status === 'fail').length;
const warned = results.filter((r) => r.status === 'warn').length;
const passed = results.filter((r) => r.status === 'pass').length;
console.log(
  `\n${failed === 0 ? 'PASS' : 'FAIL'} — ${passed} passed, ${failed} failed, ${warned} warnings`,
);
Deno.exit(failed === 0 ? 0 : 1);
