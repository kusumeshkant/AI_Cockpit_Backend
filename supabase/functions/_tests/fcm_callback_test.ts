import { deliverCallback } from '../_shared/callback.ts';
import { isInvalidTokenResponse, resetFcmTokenCache, sendPush } from '../_shared/fcm.ts';
import { verifySignature } from '../_shared/hmac.ts';
import type { CallbackPayload } from '../_shared/types.ts';
import { assert, assertEquals, assertFalse } from './test_deps.ts';

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

const message = { title: 'New action', body: 'Review it', data: { action_id: 'a1' } };

Deno.test('isInvalidTokenResponse recognises dead tokens only', () => {
  assert(
    isInvalidTokenResponse(404, {
      error: { status: 'NOT_FOUND', details: [{ errorCode: 'UNREGISTERED' }] },
    }),
  );
  assert(isInvalidTokenResponse(400, { error: { status: 'INVALID_ARGUMENT' } }));
  assertFalse(isInvalidTokenResponse(500, { error: { status: 'INTERNAL' } }));
  assertFalse(isInvalidTokenResponse(429, { error: { status: 'RESOURCE_EXHAUSTED' } }));
  assertFalse(isInvalidTokenResponse(401, null));
});

Deno.test('sendPush is a no-op without a service account', async () => {
  let calls = 0;
  const result = await sendPush(['t1'], message, {
    serviceAccountJson: null,
    fetchFn: () => {
      calls++;
      return Promise.resolve(new Response('{}'));
    },
  });
  assertEquals(result, { skipped: true, sent: 0, failed: 0, invalidTokens: [] });
  assertEquals(calls, 0);
});

Deno.test('sendPush fans out per token and collects tokens to prune', async () => {
  resetFcmTokenCache();
  const serviceAccountJson = await fakeServiceAccountJson();
  const sentTo: string[] = [];

  const respond = (input: RequestInfo | URL, init?: RequestInit): Response => {
    const url = String(input);
    if (url.startsWith('https://oauth2.googleapis.com/token')) {
      return new Response(JSON.stringify({ access_token: 'ya29.test', expires_in: 3600 }));
    }
    const token = JSON.parse(String(init?.body)).message.token as string;
    sentTo.push(token);
    if (token === 'dead') {
      return new Response(
        JSON.stringify({ error: { status: 'NOT_FOUND', details: [{ errorCode: 'UNREGISTERED' }] } }),
        { status: 404 },
      );
    }
    if (token === 'flaky') {
      return new Response(JSON.stringify({ error: { status: 'UNAVAILABLE' } }), { status: 503 });
    }
    return new Response(JSON.stringify({ name: 'projects/x/messages/1' }));
  };
  const fetchFn: typeof fetch = (input, init) => Promise.resolve(respond(input, init));

  const result = await sendPush(['good', 'dead', 'flaky', 'good'], message, {
    serviceAccountJson,
    fetchFn,
  });

  assertEquals(sentTo.sort(), ['dead', 'flaky', 'good']);
  assertEquals(result.sent, 1);
  assertEquals(result.failed, 2);
  assertEquals(result.invalidTokens, ['dead']);
});

const callbackPayload: CallbackPayload = {
  action_id: 'a1',
  external_id: 'n8n-1',
  decision: 'approved',
  payload: { subject: 'Hi' },
  edited_payload: null,
  reason: null,
  decided_at: '2026-09-15T10:00:00Z',
};

Deno.test('deliverCallback signs the exact body and reports 2xx as delivered', async () => {
  let captured: { body: string; signature: string | null; redirect?: RequestRedirect } | null = null;
  const fetchFn: typeof fetch = (_input, init) => {
    const headers = new Headers(init?.headers);
    captured = {
      body: String(init?.body),
      signature: headers.get('x-cockpit-signature'),
      redirect: init?.redirect,
    };
    return Promise.resolve(new Response('ok', { status: 202 }));
  };

  const outcome = await deliverCallback('https://agent.example/cb', callbackPayload, 'whsec_k', 'idem-key-1', fetchFn);

  assertEquals(outcome, { delivered: true, detail: 'http_202' });
  assert(captured);
  const request = captured as { body: string; signature: string | null; redirect?: RequestRedirect };
  assert(await verifySignature(request.body, request.signature, 'whsec_k'));
  assertEquals(request.redirect, 'manual');
});

Deno.test('deliverCallback reports non-2xx and network errors as not delivered', async () => {
  const failing = await deliverCallback('https://agent.example/cb', callbackPayload, 'k', 'idem-key-1', () =>
    Promise.resolve(new Response('nope', { status: 500 })));
  assertEquals(failing, { delivered: false, detail: 'http_500' });

  const redirect = await deliverCallback('https://agent.example/cb', callbackPayload, 'k', 'idem-key-1', () =>
    Promise.resolve(new Response(null, { status: 302 })));
  assertEquals(redirect.delivered, false);

  const offline = await deliverCallback('https://agent.example/cb', callbackPayload, 'k', 'idem-key-1', () =>
    Promise.reject(new TypeError('connection refused')));
  assertEquals(offline, { delivered: false, detail: 'network_error' });
});
