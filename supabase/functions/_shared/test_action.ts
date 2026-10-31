// The canned "Send a test action" (agents-test-action) and its lifetime.
//
// A test action expires TEST_ACTION_TTL_DAYS after it is sent. Long enough
// for a Play / App Store reviewer to open the app days after the account was
// prepared and still find pending actions to approve, edit and reject; short
// enough that forgotten samples don't sit in a real feed forever.

/** Days a test action stays decidable. */
export const TEST_ACTION_TTL_DAYS = 14;

const DAY_MS = 24 * 60 * 60 * 1000;

/** Canned action. `external_id` and `expires_at` are added per request. */
export const TEST_ACTION = {
  type: 'email',
  title: 'Test action from Cockpit',
  summary: 'A sample email so you can try approve, edit and reject.',
  payload: {
    to: 'customer@example.com',
    subject: 'Thanks for reaching out',
    body: 'Hi there,\n\nThanks for getting in touch — we will get back to you within one business day.\n\nBest regards',
  },
  editable_fields: ['subject', 'body'],
} as const;

/** `expires_at` (ISO 8601, UTC) for a test action sent at [now]. */
export function testActionExpiresAt(now: Date = new Date()): string {
  return new Date(now.getTime() + TEST_ACTION_TTL_DAYS * DAY_MS).toISOString();
}
