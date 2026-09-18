// Request/response helpers: method guard, size-capped body reading, schema
// parsing, and the `{ ok, data | error }` envelope.
import { AppError, toAppError } from './errors.ts';
import { log } from './logger.ts';
import type { z } from './deps.ts';

const JSON_HEADERS = { 'Content-Type': 'application/json; charset=utf-8' };

/** Throws 405 unless the request uses [method]. */
export function guardMethod(req: Request, method: string): void {
  if (req.method !== method) {
    throw new AppError('method_not_allowed', `Use ${method}`);
  }
}

/** Reads the raw body as text, rejecting bodies larger than [maxBytes]. */
export async function readRawBody(req: Request, maxBytes: number): Promise<string> {
  const declared = Number(req.headers.get('content-length') ?? '0');
  if (declared > maxBytes) {
    throw new AppError('payload_too_large', `Body exceeds ${maxBytes} bytes`);
  }
  const bytes = new Uint8Array(await req.arrayBuffer());
  if (bytes.byteLength > maxBytes) {
    throw new AppError('payload_too_large', `Body exceeds ${maxBytes} bytes`);
  }
  return new TextDecoder().decode(bytes);
}

/** Parses JSON text and validates it against [schema]. */
export function parseJson<S extends z.ZodTypeAny>(raw: string, schema: S): z.infer<S> {
  let value: unknown;
  try {
    value = JSON.parse(raw);
  } catch {
    throw new AppError('validation', 'Body must be valid JSON');
  }
  const result = schema.safeParse(value);
  if (!result.success) {
    throw new AppError(
      'validation',
      'Invalid request body',
      result.error.issues.map((issue) => ({
        path: issue.path.join('.'),
        message: issue.message,
      })),
    );
  }
  return result.data;
}

/** Success envelope. */
export function json<T>(data: T, status = 200): Response {
  return new Response(JSON.stringify({ ok: true, data }), { status, headers: JSON_HEADERS });
}

/** Error envelope. */
export function errorResponse(error: AppError): Response {
  const body = {
    ok: false,
    error: {
      code: error.code,
      message: error.message,
      ...(error.details === undefined ? {} : { details: error.details }),
    },
  };
  const retryAfter = (error.details as { retry_after_seconds?: unknown } | undefined)
    ?.retry_after_seconds;
  const headers = typeof retryAfter === 'number'
    ? { ...JSON_HEADERS, 'Retry-After': String(retryAfter) }
    : JSON_HEADERS;
  return new Response(JSON.stringify(body), { status: error.status, headers });
}

/**
 * Wraps a handler: any thrown error becomes an envelope; unexpected errors are
 * logged (without request content) and returned as a generic 500.
 */
export function handler(
  name: string,
  fn: (req: Request) => Promise<Response>,
): (req: Request) => Promise<Response> {
  return async (req) => {
    try {
      return await fn(req);
    } catch (error) {
      const appError = toAppError(error);
      if (appError.code === 'server') {
        log.error('unhandled_error', {
          function: name,
          error: error instanceof Error ? error.message : String(error),
        });
      } else {
        log.warn('request_rejected', { function: name, code: appError.code });
      }
      return errorResponse(appError);
    }
  };
}
