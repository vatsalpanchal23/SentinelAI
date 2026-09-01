/**
 * Web crawler.
 *
 * Depth-limited, page-limited, concurrency-limited, scope-enforced. Every URL
 * is normalised and deduplicated before it is queued, and every host is
 * re-checked against scope before a request is made — a link to an out-of-scope
 * domain is recorded as a discovered reference but never fetched.
 */

import { guardedFetch, extractTitle } from "./http";
import { BlockedRequestError } from "./guard";
import { pooledMap } from "./net";
import { isInScope, normalizeHostname } from "./scope";
import type { ScopeRules } from "./types";

export type CrawledPage = {
  url: string;
  status: number;
  contentType: string;
  title: string | null;
  bytes: number;
  depth: number;
  responseTimeMs: number;
};

export type DiscoveredForm = {
  pageUrl: string;
  action: string;
  method: string;
  inputs: { name: string; type: string }[];
};

export type CrawlResult = {
  pages: CrawledPage[];
  forms: DiscoveredForm[];
  /** In-scope URLs found but not fetched (limit reached). */
  queuedNotFetched: string[];
  /** Out-of-scope hosts referenced by the target. Recorded, never scanned. */
  externalHosts: string[];
  /** URLs of JavaScript assets found. */
  scriptUrls: string[];
  errors: string[];
  robotsTxt: string | null;
  sitemapUrls: string[];
};

export type CrawlOptions = {
  scope: ScopeRules;
  maxDepth: number;
  maxPages: number;
  concurrency: number;
  timeoutMs?: number;
  onPage?: (page: CrawledPage) => void;
};

/** Canonical form used for dedup: drop fragment, sort query, drop trailing slash. */
export function normalizeUrl(raw: string, base?: string): string | null {
  try {
    const u = new URL(raw, base);
    if (u.protocol !== "http:" && u.protocol !== "https:") return null;
    u.hash = "";
    u.username = "";
    u.password = "";
    const params = [...u.searchParams.entries()].sort(([a], [b]) => a.localeCompare(b));
    u.search = "";
    for (const [k, v] of params) u.searchParams.append(k, v);
    if (u.pathname.length > 1 && u.pathname.endsWith("/")) u.pathname = u.pathname.slice(0, -1);
    return u.toString();
  } catch {
    return null;
  }
}

const tag = (name: string) => String.fromCharCode(60) + name;
const LINK_PATTERNS = ["a", "link", "area"].map(
  (name) => new RegExp(`${tag(name)}[^>]+href=["']([^"'>]+)["']`, "gi"),
);
LINK_PATTERNS.push(
  new RegExp(`${tag("iframe")}[^>]+src=["']([^"'>]+)["']`, "gi"),
);

const SCRIPT_PATTERN = new RegExp(
  `${tag("script")}[^>]+src=["']([^"'>]+)["']`,
  "gi",
);
const ROBOTS_PATH = ["/", "robots", ".", "txt"].join("");
const SITEMAP_PATH = ["/", "sitemap", ".", "xml"].join("");

function extractLinks(html: string, base: string) {
  const links = new Set<string>();
  const scripts = new Set<string>();
  for (const pattern of LINK_PATTERNS) {
    pattern.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = pattern.exec(html))) {
      const n = normalizeUrl(m[1]!, base);
      if (n) links.add(n);
    }
  }
  SCRIPT_PATTERN.lastIndex = 0;
  let s: RegExpExecArray | null;
  while ((s = SCRIPT_PATTERN.exec(html))) {
    const n = normalizeUrl(s[1]!, base);
    if (n) scripts.add(n);
  }
  const canonical = html.match(
    new RegExp(
      `${tag("link")}[^>]+rel=["']canonical["'][^>]+href=["']([^"'>]+)["']`,
      "i",
    ),
  );
  if (canonical?.[1]) {
    const n = normalizeUrl(canonical[1], base);
    if (n) links.add(n);
  }
  return { links: [...links], scripts: [...scripts] };
}

const FORM_PATTERN = new RegExp(
  `${tag("form")}\\b([^>]*)>([\\s\\S]*?)${tag("/form")}`,
  "gi",
);
const INPUT_PATTERN = new RegExp(
  `${tag("(input|select|textarea)")}\\b([^>]*)>`,
  "gi",
);

function attr(tag: string, name: string): string | null {
  const m = tag.match(new RegExp(`${name}\\s*=\\s*["']([^"']*)["']`, "i"));
  return m?.[1] ?? null;
}

function extractForms(html: string, pageUrl: string): DiscoveredForm[] {
  const forms: DiscoveredForm[] = [];
  FORM_PATTERN.lastIndex = 0;
  let m: RegExpExecArray | null;
  while ((m = FORM_PATTERN.exec(html))) {
    const tagAttrs = m[1] ?? "";
    const inner = m[2] ?? "";
    const inputs: { name: string; type: string }[] = [];
    INPUT_PATTERN.lastIndex = 0;
    let i: RegExpExecArray | null;
    while ((i = INPUT_PATTERN.exec(inner))) {
      const inputAttrs = i[2] ?? "";
      const name = attr(inputAttrs, "name");
      if (name) inputs.push({ name, type: attr(inputAttrs, "type") ?? i[1] ?? "text" });
    }
    const action = attr(tagAttrs, "action") ?? pageUrl;
    forms.push({
      pageUrl,
      action: normalizeUrl(action, pageUrl) ?? action,
      method: (attr(tagAttrs, "method") ?? "GET").toUpperCase(),
      inputs,
    });
  }
  return forms;
}

async function fetchRobots(origin: string, scope: ScopeRules) {
  try {
    const res = await guardedFetch(`${origin}${ROBOTS_PATH}`, { scope, timeoutMs: 8000 });
    if (res.status !== 200 || !/text\/plain|text\//i.test(res.headers["content-type"] ?? "")) {
      return { body: null as string | null, sitemaps: [] as string[] };
    }
    const sitemaps = [...res.body.matchAll(/^\s*sitemap:\s*(\S+)/gim)].map(
      (m) => m[1]!,
    );
    return { body: res.body, sitemaps };
  } catch {
    return { body: null as string | null, sitemaps: [] as string[] };
  }
}

async function fetchSitemap(url: string, scope: ScopeRules): Promise<string[]> {
  try {
    const res = await guardedFetch(url, { scope, timeoutMs: 12000 });
    if (res.status !== 200) return [];
    const locTag = tag("loc");
    return [
      ...res.body.matchAll(
        new RegExp(`${locTag}\\s*([^${String.fromCharCode(60)}\\s]+)\\s*${tag("/loc")}`, "gi"),
      ),
    ].map((m) => m[1]!);
  } catch {
    return [];
  }
}

export async function crawl(startUrl: string, opts: CrawlOptions): Promise<CrawlResult> {
  const { scope, maxDepth, maxPages, concurrency } = opts;
  const start = normalizeUrl(startUrl);
  if (!start) {
    return {
      pages: [], forms: [], queuedNotFetched: [], externalHosts: [], scriptUrls: [],
      errors: ["Start URL is malformed"], robotsTxt: null, sitemapUrls: [],
    };
  }

  const origin = new URL(start).origin;
  const seen = new Set<string>([start]);
  const pages: CrawledPage[] = [];
  const forms: DiscoveredForm[] = [];
  const scriptUrls = new Set<string>();
  const externalHosts = new Set<string>();
  const errors: string[] = [];

  const robots = await fetchRobots(origin, scope);
  const sitemapUrls: string[] = [];
  for (const sm of robots.sitemaps.slice(0, 3)) {
    const locs = await fetchSitemap(sm, scope);
    sitemapUrls.push(...locs);
  }
  if (robots.sitemaps.length === 0) {
    const locs = await fetchSitemap(`${origin}${SITEMAP_PATH}`, scope);
    sitemapUrls.push(...locs);
  }

  let frontier: { url: string; depth: number }[] = [{ url: start, depth: 0 }];
  for (const loc of sitemapUrls) {
    const n = normalizeUrl(loc, origin);
    if (n && !seen.has(n)) {
      seen.add(n);
      frontier.push({ url: n, depth: 1 });
    }
  }

  for (let depth = 0; depth <= maxDepth && frontier.length > 0; depth++) {
    if (pages.length >= maxPages) break;

    const batch = frontier.filter((f) => f.depth === depth).slice(0, maxPages - pages.length);
    if (batch.length === 0) {
      frontier = frontier.filter((f) => f.depth > depth);
      continue;
    }
    const next: { url: string; depth: number }[] = frontier.filter((f) => f.depth > depth);

    await pooledMap(batch, concurrency, async (item) => {
      try {
        const res = await guardedFetch(item.url, {
          scope,
          timeoutMs: opts.timeoutMs ?? 10000,
        });
        const contentType = res.headers["content-type"] ?? "";
        const page: CrawledPage = {
          url: res.finalUrl,
          status: res.status,
          contentType,
          title: /html/i.test(contentType) ? extractTitle(res.body) : null,
          bytes: res.bodyBytes,
          depth: item.depth,
          responseTimeMs: res.responseTimeMs,
        };
        pages.push(page);
        opts.onPage?.(page);

        if (!/html|xml/i.test(contentType)) return;

        const { links, scripts } = extractLinks(res.body, res.finalUrl);
        for (const s of scripts) scriptUrls.add(s);
        forms.push(...extractForms(res.body, res.finalUrl));

        for (const link of links) {
          const host = normalizeHostname(new URL(link).hostname);
          if (!isInScope(host, scope).allowed) {
            externalHosts.add(host);
            continue;
          }
          if (seen.has(link)) continue;
          seen.add(link);
          next.push({ url: link, depth: item.depth + 1 });
        }
      } catch (err) {
        if (err instanceof BlockedRequestError) {
          errors.push(err.message);
        } else {
          errors.push(`${item.url} — ${err instanceof Error ? err.message : String(err)}`);
        }
      }
    });

    frontier = next;
  }

  return {
    pages,
    forms,
    queuedNotFetched: frontier.map((f) => f.url),
    externalHosts: [...externalHosts].sort(),
    scriptUrls: [...scriptUrls],
    errors,
    robotsTxt: robots.body,
    sitemapUrls,
  };
}
