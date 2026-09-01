/**
 * Low-level network primitives: timeouts, response size caps, limits.
 *
 * `rawFetch` performs NO scope or SSRF validation and must only be used for
 * fixed, trusted, non-user-controlled URLs (the DoH resolver, Certificate
 * Transparency APIs, the CVE feed). All target traffic goes through
 * `guardedFetch` in ./http.ts instead.
 */

export const LIMITS = {
  REQUEST_TIMEOUT_MS: 10_000,
  SLOW_REQUEST_TIMEOUT_MS: 20_000,
  MAX_RESPONSE_BYTES: 2_000_000,
  MAX_EVIDENCE_BYTES: 8_000,
  MAX_REDIRECTS: 5,
  MAX_CONCURRENCY: 12,
  MAX_SCAN_DURATION_MS: 15 * 60_000,
} as const;

export const USER_AGENT =
  "SentinelAI/2.0 (authorized security assessment; +https://github.com/sentinelai)";

export class TimeoutError extends Error {
  constructor(url: string, ms: number) {
    super(`Request to ${url} timed out after ${ms}ms`);
    this.name = "TimeoutError";
  }
}

export async function rawFetch(
  url: string,
  init: RequestInit = {},
  timeoutMs: number = LIMITS.REQUEST_TIMEOUT_MS,
): Promise<Response> {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    return await fetch(url, {
      ...init,
      signal: ctrl.signal,
      headers: {
        "user-agent": USER_AGENT,
        ...((init.headers as Record<string, string> | undefined) ?? {}),
      },
    });
  } catch (err) {
    if (err instanceof Error && err.name === "AbortError") {
      throw new TimeoutError(url, timeoutMs);
    }
    throw err;
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Read a response body without letting a hostile target exhaust memory.
 * Returns the text plus whether it was cut short.
 */
export async function readCapped(
  res: Response,
  maxBytes: number = LIMITS.MAX_RESPONSE_BYTES,
): Promise<{ text: string; bytes: number; truncated: boolean }> {
  const declared = Number(res.headers.get("content-length") ?? "0");
  if (declared && declared > maxBytes) {
    // Do not download it at all.
    try {
      await res.body?.cancel();
    } catch {
      /* body already consumed or unavailable */
    }
    return { text: "", bytes: declared, truncated: true };
  }

  if (!res.body) {
    const text = await res.text();
    return { text: text.slice(0, maxBytes), bytes: text.length, truncated: text.length > maxBytes };
  }

  const reader = res.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  let truncated = false;
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    if (!value) continue;
    total += value.byteLength;
    if (total > maxBytes) {
      chunks.push(value.slice(0, value.byteLength - (total - maxBytes)));
      truncated = true;
      try {
        await reader.cancel();
      } catch {
        /* stream already closed */
      }
      break;
    }
    chunks.push(value);
  }

  const merged = new Uint8Array(chunks.reduce((n, c) => n + c.byteLength, 0));
  let offset = 0;
  for (const c of chunks) {
    merged.set(c, offset);
    offset += c.byteLength;
  }
  return {
    text: new TextDecoder("utf-8", { fatal: false }).decode(merged),
    bytes: total,
    truncated,
  };
}

/** Bounded-concurrency map. No artificial delays are ever inserted. */
export async function pooledMap<T, R>(
  items: T[],
  concurrency: number,
  fn: (item: T, index: number) => Promise<R>,
): Promise<R[]> {
  const results = new Array<R>(items.length);
  let cursor = 0;
  const width = Math.max(1, Math.min(concurrency, LIMITS.MAX_CONCURRENCY, items.length || 1));

  const workers = Array.from({ length: width }, async () => {
    while (true) {
      const index = cursor++;
      if (index >= items.length) return;
      results[index] = await fn(items[index]!, index);
    }
  });

  await Promise.all(workers);
  return results;
}

export function headersToObject(headers: Headers): Record<string, string> {
  const out: Record<string, string> = {};
  headers.forEach((v, k) => {
    out[k.toLowerCase()] = v;
  });
  return out;
}

/**
 * Workers folds repeated Set-Cookie into one comma-joined value. `getSetCookie`
 * is the correct API where available; fall back to a conservative split that
 * only breaks on a comma followed by a `name=` token.
 */
export function extractSetCookies(headers: Headers): string[] {
  const anyHeaders = headers as Headers & { getSetCookie?: () => string[] };
  if (typeof anyHeaders.getSetCookie === "function") {
    const list = anyHeaders.getSetCookie();
    if (Array.isArray(list) && list.length > 0) return list;
  }
  const raw = headers.get("set-cookie");
  if (!raw) return [];
  return raw.split(/,\s*(?=[A-Za-z0-9!#$%&'*+\-.^_`|~]+=)/);
}
