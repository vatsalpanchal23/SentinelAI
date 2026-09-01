/**
 * JavaScript analysis.
 *
 * Extracts endpoints, hostnames, WebSocket URLs, source-map references and
 * high-signal secret patterns from fetched script assets. Every hostname found
 * here is returned as a *candidate* — the caller must run it through scope
 * validation before any request is made to it.
 */

import { guardedFetch } from "./http";
import { pooledMap } from "./net";
import { normalizeHostname } from "./scope";
import type { ScopeRules } from "./types";

export type SecretCandidate = {
  kind: string;
  /** Redacted preview — never the full secret. */
  preview: string;
  scriptUrl: string;
  /** Entropy of the matched token; low-entropy matches are usually noise. */
  entropy: number;
};

export type JsAnalysisResult = {
  scriptsFetched: number;
  scriptsFailed: number;
  bytesAnalyzed: number;
  /** Path-like endpoints referenced in code. */
  endpoints: string[];
  /** Absolute URLs referenced in code. */
  urls: string[];
  /** Hostnames referenced. NOT validated against scope — caller must do that. */
  hostCandidates: string[];
  websockets: string[];
  sourceMaps: string[];
  secretCandidates: SecretCandidate[];
  errors: string[];
};

function shannonEntropy(s: string): number {
  const freq = new Map<string, number>();
  for (const ch of s) freq.set(ch, (freq.get(ch) ?? 0) + 1);
  let e = 0;
  for (const n of freq.values()) {
    const p = n / s.length;
    e -= p * Math.log2(p);
  }
  return e;
}

const SECRET_RULES: { kind: string; pattern: RegExp; minEntropy: number }[] = [
  { kind: "AWS access key ID", pattern: /\b(AKIA|ASIA)[0-9A-Z]{16}\b/g, minEntropy: 3 },
  { kind: "Google API key", pattern: /\bAIza[0-9A-Za-z_-]{35}\b/g, minEntropy: 3.5 },
  { kind: "Slack token", pattern: /\bxox[baprs]-[0-9A-Za-z-]{10,}\b/g, minEntropy: 3.5 },
  { kind: "Stripe live key", pattern: /\bsk_live_[0-9A-Za-z]{16,}\b/g, minEntropy: 3.5 },
  { kind: "GitHub token", pattern: /\bgh[pousr]_[0-9A-Za-z]{36}\b/g, minEntropy: 3.5 },
  { kind: "Private key block", pattern: /-----BEGIN (RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----/g, minEntropy: 0 },
  { kind: "JSON Web Token", pattern: /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g, minEntropy: 4 },
  { kind: "Generic assigned secret", pattern: /\b(?:api[_-]?key|secret|passwd|password|token)\s*[:=]\s*["']([A-Za-z0-9_\-/+]{20,})["']/gi, minEntropy: 4 },
];

function redact(token: string): string {
  if (token.length <= 10) return `${token.slice(0, 2)}${"*".repeat(Math.max(0, token.length - 2))}`;
  return `${token.slice(0, 6)}${"*".repeat(8)}${token.slice(-4)}`;
}

const ENDPOINT_PATTERN = /["'`](\/(?:api|v\d|graphql|rest|internal|admin|auth|oauth|user|users|account|upload|download|export|debug)[A-Za-z0-9_\-/.{}$:]*)["'`]/g;
const GENERIC_PATH_PATTERN = /["'`](\/[A-Za-z0-9_\-]{2,}(?:\/[A-Za-z0-9_\-.{}$:]+){1,5})["'`]/g;
const URL_PATTERN = /\bhttps?:\/\/[A-Za-z0-9.-]+(?::\d+)?(?:\/[^\s"'`<>()]*)?/g;
const WS_PATTERN = /\bwss?:\/\/[A-Za-z0-9.-]+(?::\d+)?(?:\/[^\s"'`<>()]*)?/g;
const SOURCEMAP_PATTERN = /\/\/[#@]\s*sourceMappingURL=(\S+)/g;

export function analyzeScriptSource(source: string, scriptUrl: string) {
  const endpoints = new Set<string>();
  const urls = new Set<string>();
  const hosts = new Set<string>();
  const websockets = new Set<string>();
  const sourceMaps = new Set<string>();
  const secrets: SecretCandidate[] = [];

  for (const pattern of [ENDPOINT_PATTERN, GENERIC_PATH_PATTERN]) {
    pattern.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = pattern.exec(source))) {
      const p = m[1]!;
      // Filter obvious non-endpoints: file extensions of static assets, regex fragments.
      if (/\.(png|jpe?g|gif|svg|webp|woff2?|ttf|eot|css|map|ico)$/i.test(p)) continue;
      if (/[\\^$*+?()[\]|]/.test(p)) continue;
      endpoints.add(p);
    }
  }

  URL_PATTERN.lastIndex = 0;
  let u: RegExpExecArray | null;
  while ((u = URL_PATTERN.exec(source))) {
    urls.add(u[0]);
    try {
      hosts.add(normalizeHostname(new URL(u[0]).hostname));
    } catch {
      /* not a usable URL */
    }
  }

  WS_PATTERN.lastIndex = 0;
  let w: RegExpExecArray | null;
  while ((w = WS_PATTERN.exec(source))) {
    websockets.add(w[0]);
    try {
      hosts.add(normalizeHostname(new URL(w[0].replace(/^ws/, "http")).hostname));
    } catch {
      /* not a usable URL */
    }
  }

  SOURCEMAP_PATTERN.lastIndex = 0;
  let s: RegExpExecArray | null;
  while ((s = SOURCEMAP_PATTERN.exec(source))) sourceMaps.add(s[1]!);

  for (const rule of SECRET_RULES) {
    rule.pattern.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = rule.pattern.exec(source))) {
      const token = m[1] ?? m[0];
      const entropy = shannonEntropy(token);
      if (entropy < rule.minEntropy) continue;
      secrets.push({
        kind: rule.kind,
        preview: redact(token),
        scriptUrl,
        entropy: Math.round(entropy * 100) / 100,
      });
    }
  }

  return {
    endpoints: [...endpoints],
    urls: [...urls],
    hosts: [...hosts],
    websockets: [...websockets],
    sourceMaps: [...sourceMaps],
    secrets,
  };
}

export async function analyzeScripts(
  scriptUrls: string[],
  opts: { scope: ScopeRules; concurrency: number; maxScripts: number },
): Promise<JsAnalysisResult> {
  const targets = scriptUrls.slice(0, opts.maxScripts);
  const endpoints = new Set<string>();
  const urls = new Set<string>();
  const hostCandidates = new Set<string>();
  const websockets = new Set<string>();
  const sourceMaps = new Set<string>();
  const secretCandidates: SecretCandidate[] = [];
  const errors: string[] = [];
  let scriptsFetched = 0;
  let scriptsFailed = 0;
  let bytesAnalyzed = 0;

  await pooledMap(targets, opts.concurrency, async (url) => {
    try {
      const res = await guardedFetch(url, { scope: opts.scope, timeoutMs: 12000 });
      if (res.status !== 200 || !res.body) {
        scriptsFailed++;
        return;
      }
      scriptsFetched++;
      bytesAnalyzed += res.bodyBytes;
      const a = analyzeScriptSource(res.body, url);
      a.endpoints.forEach((x) => endpoints.add(x));
      a.urls.forEach((x) => urls.add(x));
      a.hosts.forEach((x) => hostCandidates.add(x));
      a.websockets.forEach((x) => websockets.add(x));
      a.sourceMaps.forEach((x) => sourceMaps.add(x));
      secretCandidates.push(...a.secrets);
    } catch (err) {
      scriptsFailed++;
      errors.push(`${url} — ${err instanceof Error ? err.message : String(err)}`);
    }
  });

  if (scriptUrls.length > opts.maxScripts) {
    errors.push(
      `Script budget reached — analysed ${opts.maxScripts} of ${scriptUrls.length} discovered scripts`,
    );
  }

  return {
    scriptsFetched,
    scriptsFailed,
    bytesAnalyzed,
    endpoints: [...endpoints].sort(),
    urls: [...urls].sort(),
    hostCandidates: [...hostCandidates].sort(),
    websockets: [...websockets].sort(),
    sourceMaps: [...sourceMaps].sort(),
    secretCandidates,
    errors,
  };
}
