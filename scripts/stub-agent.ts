// LOCAL ONLY stub agent service: implements the AGENT side of
// docs/agent-gateway-wire-v1.md so agent-proxy can be proven end to end.
//
// It verifies, in order: path, contract version (major 1), Cockpit-Signature
// v1 (key id current OR next, ±60 s, body hash, HMAC), nonce replay (10 min),
// and request-id idempotency for write / destructive ops (same id + same body
// → the original answer; same id + another body → request_id_reuse).
//
// Ops: brand.get, brand.save, idea.generate (202 + job_id), job.poll
// (queued → running → done), ideas.list, usage.get (meta.usage),
// decision.apply (idea_final once decided), subject.delete.
//
// Failure injection (programmatic, used by scripts/e2e-agent-proxy.ts; or
// STUB_MODE for a standalone run): slow, error500, malformed, oversize,
// trial_ended, agent_paused, unsupported_contract; failNext(n, status) for
// transient errors; setQuota(remaining); stop()/start() for "down";
// approval_blocked (decision.apply only); seedIdea / hasWorkspace / ideaStatus.
//
// It also POSTS cards to Cockpit (agent-service-inbound) with the INBOUND
// keys: socialPostDraft() + postCard() (used by scripts/e2e-service-cards.ts).
//
// Standalone: STUB_PORT=8792 STUB_KEYS='{"<key id>":"<secret>",...}'
//   deno run --allow-net --allow-env scripts/stub-agent.ts
// deno-lint-ignore-file no-explicit-any -- card answers are untyped JSON.
import {
  sha256Hex,
  signedHeadersV1,
  V1_HEADERS,
  V1_INBOUND_CARD_PATH,
  verifyV1,
} from '../supabase/functions/_shared/hmac.ts';

/** Fault modes. */
export type StubMode =
  | 'normal'
  | 'slow'
  | 'error500'
  | 'malformed'
  | 'oversize'
  | 'trial_ended'
  | 'agent_paused'
  | 'unsupported_contract'
  | 'approval_blocked';

/** One request as the stub saw it (ids only + verdict). */
export interface SeenRequest {
  op: string;
  requestId: string | null;
  nonce: string | null;
  keyId: string | null;
  status: number;
  code?: string;
  deduped?: boolean;
}

const OPS: Record<string, 'read' | 'write' | 'destructive'> = {
  'brand.get': 'read',
  'brand.save': 'write',
  'idea.generate': 'write',
  'job.poll': 'read',
  'ideas.list': 'read',
  'usage.get': 'read',
  'decision.apply': 'write',
  'subject.delete': 'destructive',
};

const NONCE_TTL_MS = 10 * 60 * 1000;
const SLOW_MS = 4000;

interface Idea {
  id: string;
  text: string;
  status: 'pending' | 'approved' | 'rejected';
}

interface Workspace {
  brand: Record<string, unknown> | null;
  version: number;
  ideas: Idea[];
  jobs: Map<string, { polls: number; ideas: Idea[] }>;
}

/** A running stub. */
export interface StubHandle {
  readonly port: number;
  /** Requests seen since start (or the last clearLog). */
  readonly seen: SeenRequest[];
  /** The last raw signed request (for replay tests). */
  lastRaw: { path: string; headers: [string, string][]; body: string } | null;
  setKeys(keys: Record<string, string>): void;
  setMode(mode: StubMode): void;
  failNext(count: number, status?: number): void;
  setQuota(remaining: number, limit?: number): void;
  /** Adds a pending idea for [workspace] (cards posted via postCard refer to it). */
  seedIdea(workspace: string, ideaId: string): void;
  /** Whether the stub still holds any data for [workspace]. */
  hasWorkspace(workspace: string): boolean;
  /** Status of an idea (pending / approved / rejected), or null. */
  ideaStatus(workspace: string, ideaId: string): string | null;
  clearLog(): void;
  start(): void;
  stop(): Promise<void>;
}

/** Starts the stub on [port] (127.0.0.1 + reachable from Docker). */
export function startStub(options: { port: number; keys: Record<string, string>; hostname?: string }): StubHandle {
  let keys = { ...options.keys };
  let mode: StubMode = 'normal';
  let failCount = 0;
  let failStatus = 503;
  let limit = 10;
  let used = 0;
  const nonces = new Map<string, number>();
  const idempotency = new Map<string, { hash: string; status: number; body: string }>();
  const workspaces = new Map<string, Workspace>();
  let server: Deno.HttpServer | null = null;

  const ws = (id: string): Workspace => {
    let w = workspaces.get(id);
    if (!w) {
      w = { brand: null, version: 0, ideas: [], jobs: new Map() };
      workspaces.set(id, w);
    }
    return w;
  };

  const reply = (status: number, body: unknown) => ({ status, body: JSON.stringify(body) });
  const ok = (result: unknown, meta: Record<string, unknown> = {}, status = 200) =>
    reply(status, { ok: true, result, meta });
  const err = (status: number, code: string, message = code) =>
    reply(status, { ok: false, error: { code, message } });

  const handle: StubHandle = {
    port: options.port,
    seen: [],
    lastRaw: null,
    setKeys: (next) => {
      keys = { ...next };
    },
    setMode: (next) => {
      mode = next;
    },
    failNext: (count, status = 503) => {
      failCount = count;
      failStatus = status;
    },
    setQuota: (remaining, newLimit = limit) => {
      limit = newLimit;
      used = Math.max(0, newLimit - remaining);
    },
    clearLog: () => {
      handle.seen.length = 0;
    },
    seedIdea: (workspace, ideaId) => {
      ws(workspace).ideas.push({ id: ideaId, text: 'seeded idea', status: 'pending' });
    },
    hasWorkspace: (workspace) => workspaces.has(workspace),
    ideaStatus: (workspace, ideaId) => workspaces.get(workspace)?.ideas.find((i) => i.id === ideaId)?.status ?? null,
    start: () => {
      server = Deno.serve(
        { port: options.port, hostname: options.hostname ?? '0.0.0.0', onListen: () => {} },
        serve,
      );
    },
    stop: async () => {
      await server?.shutdown();
      server = null;
    },
  };

  function runOp(op: string, workspaceId: string, params: Record<string, unknown>) {
    const w = ws(workspaceId);
    switch (op) {
      case 'brand.get':
        return ok({ brand: w.brand }, { version: `v${w.version}` });
      case 'brand.save': {
        if (typeof params.brand !== 'object' || params.brand === null) return err(422, 'validation');
        w.brand = params.brand as Record<string, unknown>;
        w.version++;
        return ok({ saved: true }, { version: `v${w.version}` });
      }
      case 'idea.generate': {
        if (used >= limit) return err(403, 'quota_reached');
        used++;
        const jobId = crypto.randomUUID();
        const topic = typeof params.topic === 'string' ? params.topic : 'general';
        w.jobs.set(jobId, {
          polls: 0,
          ideas: [{ id: crypto.randomUUID(), text: `Idea about ${topic}`, status: 'pending' }],
        });
        return ok({ job_id: jobId }, { poll_after_ms: 100, usage: usage() }, 202);
      }
      case 'job.poll': {
        const job = typeof params.job_id === 'string' ? w.jobs.get(params.job_id) : undefined;
        if (!job) return err(404, 'not_found');
        job.polls++;
        if (job.polls === 1) return ok({ status: 'queued' }, { poll_after_ms: 100 });
        if (job.polls === 2) return ok({ status: 'running' }, { poll_after_ms: 100 });
        if (job.polls === 3) w.ideas.push(...job.ideas);
        return ok({ status: 'done', ideas: job.ideas });
      }
      case 'ideas.list':
        return ok({ ideas: w.ideas });
      case 'usage.get':
        return ok({}, { usage: usage() });
      case 'decision.apply': {
        const idea = w.ideas.find((i) => i.id === params.idea_id);
        if (!idea) return err(404, 'not_found');
        if (idea.status !== 'pending') return err(409, 'idea_final');
        if (params.decision !== 'approved' && params.decision !== 'rejected') return err(422, 'validation');
        idea.status = params.decision;
        return ok({ idea });
      }
      case 'subject.delete':
        return ok({ deleted: workspaces.delete(workspaceId) });
    }
    return err(404, 'unsupported_op');
  }

  const usage = () => ({ used, limit, trial_ends_at: null });

  async function serve(req: Request): Promise<Response> {
    const url = new URL(req.url);
    const body = await req.text();
    const match = /^\/cockpit\/v1\/ops\/([a-z][a-z0-9_.-]{0,63})$/.exec(url.pathname);
    const op = match?.[1] ?? '';
    const seen: SeenRequest = {
      op,
      requestId: req.headers.get(V1_HEADERS.requestId),
      nonce: req.headers.get(V1_HEADERS.nonce),
      keyId: req.headers.get(V1_HEADERS.keyId),
      status: 0,
    };
    const done = (r: { status: number; body: string }, code?: string, deduped?: boolean) => {
      seen.status = r.status;
      if (code) seen.code = code;
      if (deduped) seen.deduped = true;
      handle.seen.push(seen);
      return new Response(r.body, { status: r.status, headers: { 'Content-Type': 'application/json' } });
    };

    if (req.method !== 'POST' || !match || !(op in OPS)) return done(err(404, 'unsupported_op'), 'unsupported_op');
    handle.lastRaw = { path: url.pathname, headers: [...req.headers.entries()], body };

    // Contract version (major 1) before anything else.
    const contract = req.headers.get(V1_HEADERS.contractVersion) ?? '';
    if (mode === 'unsupported_contract' || !/^1\.[0-9]+$/.test(contract)) {
      return done(err(400, 'unsupported_contract', 'stub detail: contract ' + contract), 'unsupported_contract');
    }

    const verdict = await verifyV1({ headers: req.headers, method: req.method, path: url.pathname, body, secrets: keys });
    if (!verdict.ok) return done(err(401, 'invalid_signature', `stub detail: ${verdict.reason}`), verdict.reason);

    // Replay: a (key id, nonce) pair is accepted once within the TTL.
    const now = Date.now();
    for (const [k, at] of nonces) if (now - at > NONCE_TTL_MS) nonces.delete(k);
    const nonceKey = `${verdict.fields.keyId}:${verdict.fields.nonce}`;
    if (nonces.has(nonceKey)) return done(err(401, 'replayed_nonce'), 'replayed_nonce');
    nonces.set(nonceKey, now);

    // Idempotency for write / destructive ops, scoped by workspace.
    const cls = OPS[op];
    const idemKey = `${verdict.fields.workspace}:${verdict.fields.requestId}`;
    const bodyHash = await sha256Hex(body);
    if (cls !== 'read') {
      const prior = idempotency.get(idemKey);
      if (prior) {
        if (prior.hash !== bodyHash) return done(err(409, 'request_id_reuse', 'stub detail: reuse'), 'request_id_reuse');
        return done({ status: prior.status, body: prior.body }, undefined, true);
      }
    }

    // Faults.
    if (failCount > 0) {
      failCount--;
      return done(err(failStatus, 'transient'), 'transient');
    }
    switch (mode) {
      case 'slow':
        await new Promise((resolve) => setTimeout(resolve, SLOW_MS));
        break;
      case 'error500':
        return done({ status: 500, body: 'internal stub failure' }, 'error500');
      case 'malformed':
        return done({ status: 200, body: '{"ok": true, "result": ' }, 'malformed');
      case 'oversize':
        return done(ok({ blob: 'x'.repeat(300_000) }), 'oversize');
      case 'trial_ended':
        return done(err(403, 'trial_ended'), 'trial_ended');
      case 'agent_paused':
        return done(err(503, 'agent_paused'), 'agent_paused');
      case 'approval_blocked':
        if (op === 'decision.apply') return done(err(422, 'approval_blocked'), 'approval_blocked');
        break;
    }

    let params: Record<string, unknown> = {};
    try {
      const parsed = JSON.parse(body);
      params = typeof parsed?.params === 'object' && parsed.params !== null ? parsed.params : {};
    } catch {
      return done(err(400, 'validation'), 'validation');
    }
    const result = runOp(op, verdict.fields.workspace, params);
    if (cls !== 'read' && result.status < 500) idempotency.set(idemKey, { hash: bodyHash, ...result });
    return done(result);
  }

  handle.start();
  return handle;
}

if (import.meta.main) {
  const port = Number(Deno.env.get('STUB_PORT') ?? '8792');
  const keys = JSON.parse(Deno.env.get('STUB_KEYS') ?? '{}');
  const stub = startStub({ port, keys });
  const mode = Deno.env.get('STUB_MODE') as StubMode | undefined;
  if (mode) stub.setMode(mode);
  console.log(`stub agent listening on :${port} (${Object.keys(keys).length} key ids)`);
}

// -----------------------------------------------------------------------------
// Agent → Cockpit cards (0013): the stub as a CLIENT of agent-service-inbound,
// signing with the service's INBOUND key over the canonical path.
// -----------------------------------------------------------------------------

/** A `social_post_draft` card as the agent would send it (summary only). */
export function socialPostDraft(
  service: string,
  ideaId: string,
  options: { topic: string; hook: string; revision?: number; format?: string; expiresAt?: string },
): Record<string, unknown> {
  return {
    type: 'social_post_draft',
    title: `Post idea: ${options.topic}`.slice(0, 80),
    summary: options.hook,
    payload: {
      schema: 1,
      service,
      idea_id: ideaId,
      format: options.format ?? 'carousel',
      topic: options.topic,
      hook: options.hook,
      findings: { blocking: 0, to_fix: 1, warnings: 2 },
      revision: options.revision ?? 1,
    },
    ...(options.expiresAt ? { expires_at: options.expiresAt } : {}),
  };
}

/** One signed card request. Faults are for tests only. */
export interface CardPost {
  /** The agent-service-inbound URL. */
  url: string;
  keyId: string;
  secret: string;
  /** The service_access subject (raw workspace id). */
  workspace: string;
  /** Acting user id, or `system` for agent-initiated work. */
  user?: string;
  /** The JSON body (object) or an exact raw string. */
  body: Record<string, unknown> | string;
  nonce?: string;
  timestamp?: number;
  contractVersion?: string;
  fault?: 'bad_signature' | 'sign_actual_path';
}

/** Signs and posts a card request; returns status + parsed body. */
export async function postCard(post: CardPost): Promise<{ status: number; body: any; nonce: string }> {
  const raw = typeof post.body === 'string' ? post.body : JSON.stringify(post.body);
  const nonce = post.nonce ?? crypto.randomUUID();
  const fields = {
    keyId: post.keyId,
    timestamp: post.timestamp ?? Math.floor(Date.now() / 1000),
    nonce,
    method: 'POST',
    path: post.fault === 'sign_actual_path' ? new URL(post.url).pathname : V1_INBOUND_CARD_PATH,
    workspace: post.workspace,
    user: post.user ?? 'system',
    requestId: crypto.randomUUID(),
  };
  const headers = await signedHeadersV1(fields, raw, post.secret, post.contractVersion ?? '1.0');
  if (post.fault === 'bad_signature') headers[V1_HEADERS.signature] = `v1=${'0'.repeat(64)}`;
  const response = await fetch(post.url, { method: 'POST', headers, body: raw });
  const text = await response.text();
  let body: any = text;
  try {
    body = JSON.parse(text);
  } catch {
    // keep text
  }
  return { status: response.status, body, nonce };
}
