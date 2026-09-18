import {
  CreateAgentSchema,
  DecisionSchema,
  IdempotencyKeySchema,
  InboundActionSchema,
  isAllowedCallbackUrl,
} from '../_shared/validation.ts';
import { assert, assertEquals, assertFalse } from './test_deps.ts';

const AGENT_ID = '5f1c2a4e-8b1d-4f3a-9d2e-0c5b7a9e1f22';
const ACTION_ID = 'a3e6b0d2-1f7c-4c55-9b0e-8d2f4a6c1e90';

const inbound = {
  agent_id: AGENT_ID,
  external_id: 'n8n-exec-48213',
  type: 'email',
  title: 'Follow-up to Priya',
  summary: 'Second follow-up',
  payload: { to: 'priya@example.com', subject: 'Hi', body: 'Hello' },
  editable_fields: ['subject', 'body'],
};

Deno.test('inbound: valid body parses and defaults editable_fields', () => {
  assert(InboundActionSchema.safeParse(inbound).success);
  const { editable_fields: _, ...withoutEditable } = inbound;
  const parsed = InboundActionSchema.parse(withoutEditable);
  assertEquals(parsed.editable_fields, []);
});

Deno.test('inbound: rejects unknown fields', () => {
  assertFalse(InboundActionSchema.safeParse({ ...inbound, extra: true }).success);
});

Deno.test('inbound: rejects bad agent id, type and empty title', () => {
  assertFalse(InboundActionSchema.safeParse({ ...inbound, agent_id: 'nope' }).success);
  assertFalse(InboundActionSchema.safeParse({ ...inbound, type: 'Email Draft' }).success);
  assertFalse(InboundActionSchema.safeParse({ ...inbound, title: '   ' }).success);
});

Deno.test('inbound: editable fields must exist in the payload', () => {
  assertFalse(
    InboundActionSchema.safeParse({ ...inbound, editable_fields: ['cc'] }).success,
  );
});

Deno.test('inbound: payload must be an object', () => {
  assertFalse(InboundActionSchema.safeParse({ ...inbound, payload: ['x'] }).success);
});

Deno.test('decision: approve / reject bodies parse', () => {
  assert(DecisionSchema.safeParse({ action_id: ACTION_ID, decision: 'approved' }).success);
  assert(
    DecisionSchema.safeParse({ action_id: ACTION_ID, decision: 'rejected', reason: 'no' }).success,
  );
});

Deno.test('decision: approved_with_edits requires non-empty edits', () => {
  assertFalse(
    DecisionSchema.safeParse({ action_id: ACTION_ID, decision: 'approved_with_edits' }).success,
  );
  assertFalse(
    DecisionSchema.safeParse({
      action_id: ACTION_ID,
      decision: 'approved_with_edits',
      edited_payload: {},
    }).success,
  );
  assert(
    DecisionSchema.safeParse({
      action_id: ACTION_ID,
      decision: 'approved_with_edits',
      edited_payload: { subject: 'New' },
    }).success,
  );
});

Deno.test('decision: edits are rejected on plain approve', () => {
  assertFalse(
    DecisionSchema.safeParse({
      action_id: ACTION_ID,
      decision: 'approved',
      edited_payload: { subject: 'New' },
    }).success,
  );
});

Deno.test('decision: unknown decision and long reason are rejected', () => {
  assertFalse(DecisionSchema.safeParse({ action_id: ACTION_ID, decision: 'maybe' }).success);
  assertFalse(
    DecisionSchema.safeParse({ action_id: ACTION_ID, decision: 'rejected', reason: 'x'.repeat(501) })
      .success,
  );
});

Deno.test('create agent: https callback required, name trimmed', () => {
  const parsed = CreateAgentSchema.parse({
    name: '  Email agent ',
    platform: 'n8n',
    callback_url: 'https://n8n.example.com/hook',
  });
  assertEquals(parsed.name, 'Email agent');
  assertFalse(
    CreateAgentSchema.safeParse({
      name: 'A',
      platform: 'n8n',
      callback_url: 'http://n8n.example.com/hook',
    }).success,
  );
  assertFalse(
    CreateAgentSchema.safeParse({ name: 'A', platform: 'ifttt', callback_url: 'https://x.io' })
      .success,
  );
});

Deno.test('idempotency key format', () => {
  assert(IdempotencyKeySchema.safeParse('9c1d7e4a-2b3f-4a6e').success);
  assertFalse(IdempotencyKeySchema.safeParse('short').success);
  assertFalse(IdempotencyKeySchema.safeParse('has spaces in it').success);
});

Deno.test('callback URL policy blocks http and private hosts in production', () => {
  assert(isAllowedCallbackUrl('https://hooks.example.com/cb', false));
  assertFalse(isAllowedCallbackUrl('http://hooks.example.com/cb', false));
  for (const host of [
    'localhost',
    '127.0.0.1',
    '10.0.0.5',
    '192.168.1.2',
    '172.20.0.1',
    '169.254.169.254',
    'host.docker.internal',
    '[::1]',
  ]) {
    assertFalse(isAllowedCallbackUrl(`https://${host}/cb`, false), host);
  }
  assertFalse(isAllowedCallbackUrl('https://user:pw@hooks.example.com/cb', false));
  assertFalse(isAllowedCallbackUrl('not a url', false));
});

Deno.test('callback URL policy relaxes for local development', () => {
  assert(isAllowedCallbackUrl('http://host.docker.internal:8787/callback', true));
  assertFalse(isAllowedCallbackUrl('ftp://host.docker.internal/cb', true));
});
