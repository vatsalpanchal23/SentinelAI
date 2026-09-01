/**
 * Guarded HTTP client for target traffic.
 *
 * Redirects are followed manually so that every hop can be re-validated
 * against the SSRF guard and the scope rules before it is requested.
 */

import { rawFetch, readCapped, headersToObject, extractSetCookies, LIMITS } from "./net";
import { validateUrl, BlockedRequestError, type GuardOptions } from "./guard";
import type { HttpProbe } from "./types";

export type GuardedResponse = {
  url: string;
  finalUrl: string;
  status: number;
  headers: Record<string, string>;
  setCookies: string[];
  body: string;
  bodyBytes: number;
  bodyTruncated: boolean;
  redirectChain: string[];
  responseTimeMs: number;
};

export type GuardedFetchOptions = GuardOptions & {
  method?: string;
  headers?: Record<string, string>;
  body?: string;
  timeoutMs?: number;
  /** Follow redirects (re-validating each hop). Default true. */
  followRedirects?: boolean;
  maxRedirects?: number;
  /** Skip downloading the body — useful for existence checks. */
  discardBody?: boolean;
  maxBodyBytes?: number;
};

const REDIRECT_STATUSES = new Set([301, 302, 303, 307, 308]);

export async function guardedFetch(
  url: string,
  opts: GuardedFetchOptions,
): Promise<GuardedResponse> {
  const started = Date.now();
  const chain: string[] = [];
  const maxRedirects = opts.maxRedirects ?? LIMITS.MAX_REDIRECTS;
  const follow = opts.followRedirects !== false;

  let current = url;
  let method = opts.method ?? "GET";

  for (let hop = 0; hop <= maxRedirects; hop++) {
    const verdict = await validateUrl(current, opts);
    if (!verdict.allowed) throw new BlockedRequestError(verdict);

    chain.push(current);

    const requestInit: RequestInit = { method, redirect: "manual" };
    if (opts.headers) requestInit.headers = opts.headers;
    if (opts.body !== undefined && method !== "GET" && method !== "HEAD") {
      requestInit.body = opts.body;
    }

    const res = await rawFetch(
      current,
      requestInit,
      opts.timeoutMs ?? LIMITS.REQUEST_TIMEOUT_MS,
    );

    const headers = headersToObject(res.headers);
    const setCookies = extractSetCookies(res.headers);

    if (follow && REDIRECT_STATUSES.has(res.status)) {
      const location = res.headers.get("location");
      if (location) {
        try {
          await res.body?.cancel();
        } catch {
          /* nothing to cancel */
        }
        const next = new URL(location, current).toString();
        // 303, and 301/302 on POST, degrade to GET per fetch semantics.
        if (res.status === 303 || (method !== "GET" && res.status !== 307 && res.status !== 308)) {
          method = "GET";
        }
        if (hop === maxRedirects) {
          return {
            url,
            finalUrl: current,
            status: res.status,
            headers,
            setCookies,
            body: "",
            bodyBytes: 0,
            bodyTruncated: false,
            redirectChain: [...chain, next],
            responseTimeMs: Date.now() - started,
          };
        }
        current = next;
        continue;
      }
    }

    let body = "";
    let bodyBytes = 0;
    let bodyTruncated = false;
    if (opts.discardBody) {
      try {
        await res.body?.cancel();
      } catch {
        /* nothing to cancel */
      }
      bodyBytes = Number(headers["content-length"] ?? "0");
    } else {
      const read = await readCapped(res, opts.maxBodyBytes ?? LIMITS.MAX_RESPONSE_BYTES);
      body = read.text;
      bodyBytes = read.bytes;
      bodyTruncated = read.truncated;
    }

    return {
      url,
      finalUrl: current,
      status: res.status,
      headers,
      setCookies,
      body,
      bodyBytes,
      bodyTruncated,
      redirectChain: chain,
      responseTimeMs: Date.now() - started,
    };
  }

  throw new Error(`Redirect limit of ${maxRedirects} exceeded for ${url}`);
}

export function extractTitle(html: string): string | null {
  const m = html.match(/<title[^>]*>([\s\S]{0,300}?)<\/title>/i);
  if (!m?.[1]) return null;
  const text = m[1]
    .replace(/&amp;/g, "&")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&quot;/g, '"')
    .replace(/\s+/g, " ")
    .trim();
  return text || null;
}

export function toHttpProbe(res: GuardedResponse): HttpProbe {
  return {
    url: res.url,
    finalUrl: res.finalUrl,
    status: res.status,
    redirected: res.redirectChain.length > 1,
    redirectChain: res.redirectChain,
    headers: res.headers,
    setCookies: res.setCookies,
    title: extractTitle(res.body),
    bodyBytes: res.bodyBytes,
    responseTimeMs: res.responseTimeMs,
    body: res.body,
  };
}

/** Probe a host over HTTPS then, if that fails, HTTP. Returns null if neither answers. */
export async function probeHost(
  hostname: string,
  opts: GuardOptions,
  timeoutMs = LIMITS.SLOW_REQUEST_TIMEOUT_MS,
): Promise<{ probe: HttpProbe | null; scheme: "https" | "http" | null; error: string | null }> {
  for (const scheme of ["https", "http"] as const) {
    try {
      const res = await guardedFetch(`${scheme}://${hostname}/`, { ...opts, timeoutMs });
      return { probe: toHttpProbe(res), scheme, error: null };
    } catch (err) {
      if (err instanceof BlockedRequestError) {
        return { probe: null, scheme: null, error: err.message };
      }
      if (scheme === "http") {
        return {
          probe: null,
          scheme: null,
          error: err instanceof Error ? err.message : String(err),
        };
      }
    }
  }
  return { probe: null, scheme: null, error: "No response over HTTPS or HTTP" };
}
