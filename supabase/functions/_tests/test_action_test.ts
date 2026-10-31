import { TEST_ACTION, TEST_ACTION_TTL_DAYS, testActionExpiresAt } from '../_shared/test_action.ts';
import { assertEquals } from './test_deps.ts';

Deno.test('test actions expire 14 days after they are sent', () => {
  assertEquals(TEST_ACTION_TTL_DAYS, 14);
  assertEquals(
    testActionExpiresAt(new Date('2026-10-31T09:30:00.000Z')),
    '2026-11-14T09:30:00.000Z',
  );
});

Deno.test('the expiry is a UTC ISO 8601 timestamp the inbound RPC accepts', () => {
  const expiresAt = testActionExpiresAt();
  assertEquals(new Date(expiresAt).toISOString(), expiresAt);
  const days = (Date.parse(expiresAt) - Date.now()) / (24 * 60 * 60 * 1000);
  assertEquals(Math.round(days), 14);
});

Deno.test('the canned action keeps subject and body editable', () => {
  assertEquals(TEST_ACTION.type, 'email');
  assertEquals([...TEST_ACTION.editable_fields], ['subject', 'body']);
});
