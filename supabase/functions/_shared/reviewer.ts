// Play review sign-in (reviewer-signin). The app signs in with an emailed
// code, which a Play reviewer can't read, so this accepts one fixed code for
// one allowlisted email. Off unless REVIEWER_LOGIN_ENABLED is exactly "true"
// and REVIEWER_EMAIL / REVIEWER_CODE (6 digits) are set as function secrets.
//
// Every refusal — off, malformed request, other email, wrong code, locked,
// internal error — is the same response (status, headers, body), and every
// request makes the same guard call, so a caller can't tell which it was. On
// success it returns a one-time token hash; the app exchanges it for a normal
// session with its own client (verifyOTP), so no session token passes
// through here.
//
// Never logs the email, the code or the token hash.
import { json, readRawBody } from './http.ts';
import { log } from './logger.ts';
import { z } from './deps.ts';

/** The reviewer code has the app's OTP shape: exactly 6 digits. */
export const REVIEWER_CODE_PATTERN = /^\d{6}$/;

/** Bodies larger than this are refused (an email and a code fit easily). */
export const MAX_REVIEWER_SIGNIN_BYTES = 1024;

/** The allowlisted reviewer, from function secrets. */
export interface ReviewerConfig {
  /** Normalized (trimmed, lower-case) email. */
  readonly email: string;
  readonly code: string;
}

/**
 * The reviewer config when sign-in is switched on and fully configured;
 * otherwise null (off). [read] returns a variable's value or undefined.
 */
export function reviewerConfig(read: (name: string) => string | undefined): ReviewerConfig | null {
  if (read('REVIEWER_LOGIN_ENABLED') !== 'true') return null;
  const email = normalizeEmail(read('REVIEWER_EMAIL') ?? '');
  const code = (read('REVIEWER_CODE') ?? '').trim();
  if (!email.includes('@') || !REVIEWER_CODE_PATTERN.test(code)) return null;
  return { email, code };
}

/** Trims and lower-cases an email for comparison. */
export function normalizeEmail(email: string): string {
  return email.trim().toLowerCase();
}

/**
 * Compares two strings in time that depends only on the longer length, not on
 * where they first differ.
 */
export function timingSafeEqual(a: string, b: string): boolean {
  const encoder = new TextEncoder();
  const left = encoder.encode(a);
  const right = encoder.encode(b);
  const length = Math.max(left.length, right.length);
  let diff = left.length ^ right.length;
  for (let i = 0; i < length; i++) {
    diff |= (left[i] ?? 0) ^ (right[i] ?? 0);
  }
  return diff === 0;
}

/** What one request means for the guard (see migration 0008). */
export type ReviewerOutcome = 'none' | 'failure' | 'success';

/**
 * Classifies a request: 'none' unless sign-in is on and the email is the
 * reviewer's; then 'success' or 'failure' by the code.
 */
export function classifyAttempt(
  config: ReviewerConfig | null,
  email: string,
  code: string,
): ReviewerOutcome {
  if (config === null) return 'none';
  // Both comparisons always run, so the time doesn't depend on which failed.
  const emailMatches = timingSafeEqual(normalizeEmail(email), config.email);
  const codeMatches = timingSafeEqual(code.trim(), config.code);
  if (!emailMatches) return 'none';
  return codeMatches ? 'success' : 'failure';
}

/** Status of every refusal. */
export const REJECTION_STATUS = 400;

/** Body of every refusal: the same text an invalid OTP gets in the app. */
export const REJECTION_BODY = JSON.stringify({
  ok: false,
  error: { code: 'invalid_code', message: 'Invalid or expired code' },
});

/** The one refusal response; a fresh object each time, identical content. */
export function rejection(): Response {
  return new Response(REJECTION_BODY, {
    status: REJECTION_STATUS,
    headers: { 'Content-Type': 'application/json; charset=utf-8' },
  });
}

const ReviewerSigninSchema = z.object({
  email: z.string().min(1).max(320),
  code: z.string().min(1).max(32),
}).strict();

/** I/O the handler needs; injected so tests run without a database. */
export interface ReviewerSigninDeps {
  /** Current config (null = off). */
  config: () => ReviewerConfig | null;
  /** Records one attempt in the guard; resolves to whether a lock is active. */
  attempt: (outcome: ReviewerOutcome) => Promise<boolean>;
  /** Issues a one-time token hash for [email] (no email is sent). */
  issueTokenHash: (email: string) => Promise<string>;
}

/** Success payload. */
export interface ReviewerSigninResponse {
  token_hash: string;
}

/** Handles one reviewer-signin request. Never throws. */
export async function handleReviewerSignin(
  req: Request,
  deps: ReviewerSigninDeps,
): Promise<Response> {
  let email = '';
  let code = '';
  if (req.method === 'POST') {
    try {
      const raw = await readRawBody(req, MAX_REVIEWER_SIGNIN_BYTES);
      const parsed = ReviewerSigninSchema.safeParse(JSON.parse(raw));
      if (parsed.success) ({ email, code } = parsed.data);
    } catch {
      // Malformed or oversized: refused below like any other non-match.
    }
  }

  const config = deps.config();
  const outcome = email === '' ? 'none' : classifyAttempt(config, email, code);

  let locked: boolean;
  try {
    locked = await deps.attempt(outcome);
  } catch (error) {
    log.error('reviewer_signin_guard_failed', { error: errorMessage(error) });
    return rejection();
  }

  if (outcome !== 'success' || locked || config === null) {
    if (outcome !== 'none') log.warn('reviewer_signin', { outcome: locked ? 'locked' : 'denied' });
    return rejection();
  }

  try {
    const tokenHash = await deps.issueTokenHash(config.email);
    log.info('reviewer_signin', { outcome: 'ok' });
    const response: ReviewerSigninResponse = { token_hash: tokenHash };
    return json(response);
  } catch (error) {
    log.error('reviewer_signin_issue_failed', { error: errorMessage(error) });
    return rejection();
  }
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
