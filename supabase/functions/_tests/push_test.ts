// notifyNewAction: the push step shared by actions-inbound and
// agents-test-action. FCM is reached through a stubbed global fetch.
import { resetFcmTokenCache } from '../_shared/fcm.ts';
import { notifyNewAction } from '../_shared/push.ts';
import { assertEquals } from './test_deps.ts';

async function fakeServiceAccountJson(): Promise<string> {
  const { privateKey } = await crypto.subtle.generateKey(
    {
      name: 'RSASSA-PKCS1-v1_5',
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: 'SHA-256',
    },
    true,
    ['sign', 'verify'],
  );
  const pkcs8 = new Uint8Array(await crypto.subtle.exportKey('pkcs8', privateKey));
  const base64 = btoa(String.fromCharCode(...pkcs8));
  return JSON.stringify({
    project_id: 'cockpit-test',
    client_email: 'push@cockpit-test.iam.gserviceaccount.com',
    private_key: `-----BEGIN PRIVATE KEY-----\n${base64}\n-----END PRIVATE KEY-----\n`,
  });
}

function fakeClient(error: unknown = null) {
  const calls: Array<{ fn: string; args: Record<string, unknown> }> = [];
  const client = {
    rpc: (fn: string, args: Record<string, unknown>) => {
      calls.push({ fn, args });
      return Promise.resolve({ data: null, error });
    },
  };
  // deno-lint-ignore no-explicit-any -- minimal stand-in for SupabaseClient.rpc
  return { client: client as any, calls };
}

/** Runs [body] with global fetch answered by [respond]; returns FCM sends. */
async function withFcm(
  respond: (token: string) => Response | Promise<Response>,
  body: () => Promise<void>,
): Promise<Array<Record<string, unknown>>> {
  resetFcmTokenCache();
  const sent: Array<Record<string, unknown>> = [];
  const original = globalThis.fetch;
  globalThis.fetch = (input: RequestInfo | URL, init?: RequestInit) => {
    if (String(input).startsWith('https://oauth2.googleapis.com/token')) {
      return Promise.resolve(
        new Response(JSON.stringify({ access_token: 'ya29.test', expires_in: 3600 })),
      );
    }
    const message = JSON.parse(String(init?.body)).message;
    sent.push(message);
    return Promise.resolve(respond(message.token as string));
  };
  try {
    await body();
  } finally {
    globalThis.fetch = original;
  }
  return sent;
}

const push = {
  actionId: 'act-1',
  title: 'Test action from Cockpit',
  summary: 'A sample email',
  tokens: ['good', 'dead'],
};

Deno.test('notifyNewAction sends the deep-link payload and prunes unregistered tokens', async () => {
  const serviceAccountJson = await fakeServiceAccountJson();
  const { client, calls } = fakeClient();
  const sent = await withFcm(
    (token) =>
      token === 'dead'
        ? new Response(
          JSON.stringify({
            error: { status: 'NOT_FOUND', details: [{ errorCode: 'UNREGISTERED' }] },
          }),
          { status: 404 },
        )
        : new Response(JSON.stringify({ name: 'projects/x/messages/1' })),
    () => notifyNewAction(client, serviceAccountJson, push),
  );

  assertEquals(sent.length, 2);
  for (const message of sent) {
    assertEquals(message.notification, { title: push.title, body: push.summary });
    assertEquals((message.data as Record<string, string>).type, 'action');
    assertEquals((message.data as Record<string, string>).action_id, 'act-1');
  }
  assertEquals(calls, [{ fn: 'prune_fcm_tokens', args: { p_tokens: ['dead'] } }]);
});

Deno.test('notifyNewAction does not prune when every token is live', async () => {
  const serviceAccountJson = await fakeServiceAccountJson();
  const { client, calls } = fakeClient();
  await withFcm(
    () => new Response(JSON.stringify({ name: 'projects/x/messages/1' })),
    () => notifyNewAction(client, serviceAccountJson, push),
  );
  assertEquals(calls, []);
});

Deno.test('notifyNewAction is a no-op without a service account', async () => {
  const { client, calls } = fakeClient();
  const sent = await withFcm(
    () => new Response('{}'),
    () => notifyNewAction(client, null, push),
  );
  assertEquals(sent, []);
  assertEquals(calls, []);
});

Deno.test('notifyNewAction never throws when FCM is unreachable', async () => {
  const serviceAccountJson = await fakeServiceAccountJson();
  const { client, calls } = fakeClient();
  resetFcmTokenCache();
  const original = globalThis.fetch;
  globalThis.fetch = () => Promise.reject(new TypeError('network down'));
  try {
    await notifyNewAction(client, serviceAccountJson, push);
  } finally {
    globalThis.fetch = original;
  }
  assertEquals(calls, []);
});

Deno.test('notifyNewAction swallows a failing prune', async () => {
  const serviceAccountJson = await fakeServiceAccountJson();
  const client = {
    rpc: () => Promise.reject(new Error('db down')),
  };
  await withFcm(
    () => new Response(JSON.stringify({ error: { status: 'INVALID_ARGUMENT' } }), { status: 400 }),
    // deno-lint-ignore no-explicit-any -- minimal stand-in for SupabaseClient.rpc
    () => notifyNewAction(client as any, serviceAccountJson, push),
  );
});
