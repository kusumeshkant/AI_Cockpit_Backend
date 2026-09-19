// Structured JSON logs with redaction. Secrets, signatures, tokens, action
// payloads and personal data never reach the log stream.

type Level = 'info' | 'warn' | 'error';
type Fields = Record<string, unknown>;

/** Keys whose values are always replaced, at any depth (case-insensitive). */
export const REDACTED_KEYS: ReadonlySet<string> = new Set([
  'secret',
  'signing_secret',
  'decrypted_secret',
  'signature',
  'x-cockpit-signature',
  'authorization',
  'apikey',
  'token',
  'tokens',
  'fcm_tokens',
  'access_token',
  'private_key',
  'payload',
  'edited_payload',
  'original_payload',
  'callback_payload',
  'reason',
  'email',
  'body',
  'trigger',
  'trigger_secret',
  'trigger_url',
]);

const MAX_DEPTH = 6;

/** Returns a copy of [value] with sensitive keys replaced by "[redacted]". */
export function redact(value: unknown, depth = 0): unknown {
  if (depth > MAX_DEPTH || value === null || typeof value !== 'object') return value;
  if (Array.isArray(value)) return value.map((item) => redact(item, depth + 1));
  const out: Fields = {};
  for (const [key, inner] of Object.entries(value as Fields)) {
    out[key] = REDACTED_KEYS.has(key.toLowerCase()) ? '[redacted]' : redact(inner, depth + 1);
  }
  return out;
}

function emit(level: Level, event: string, fields: Fields = {}): void {
  const line = JSON.stringify({
    level,
    event,
    ts: new Date().toISOString(),
    ...(redact(fields) as Fields),
  });
  if (level === 'error') console.error(line);
  else if (level === 'warn') console.warn(line);
  else console.log(line);
}

/** Logger. Pass identifiers (action_id, agent_id), never content. */
export const log = {
  info: (event: string, fields?: Fields) => emit('info', event, fields),
  warn: (event: string, fields?: Fields) => emit('warn', event, fields),
  error: (event: string, fields?: Fields) => emit('error', event, fields),
};
