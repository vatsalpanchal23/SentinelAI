/**
 * Endpoint, parameter and API discovery.
 *
 * Endpoint probing is a plain GET against a candidate path. A path is only
 * recorded as existing when the server actually returned a non-404 response,
 * and soft-404 detection is applied first so that sites returning 200 for
 * everything do not produce a fictional endpoint list.
 */

import { guardedFetch, extractTitle } from "./http";
import { pooledMap } from "./net";
import type { ScopeRules } from "./types";
import type { DiscoveredForm } from "./crawler";

export type DiscoveredEndpoint = {
  url: string;
  path: string;
  method: string;
  status: number;
  contentType: string;
  bytes: number;
  title: string | null;
  /** "crawl" | "wordlist" | "javascript" | "openapi" | "sitemap" | "form" */
  source: string;
};

export type DiscoveredParameter = {
  endpoint: string;
  method: string;
  name: string;
  location: "query" | "body" | "path" | "header";
  type: string;
  source: string;
};

export type ApiInventoryEntry = {
  kind: "rest" | "graphql" | "openapi" | "swagger-ui" | "postman";
  url: string;
  status: number;
  detail: string;
  /** Populated when an OpenAPI document was successfully parsed. */
  operations: { path: string; method: string; parameters: string[] }[];
};

/** High-signal paths worth checking on any web target. Not a claim they exist. */
export const COMMON_PATHS = [
  "/", "/login", "/signin", "/register", "/signup", "/admin", "/administrator",
  "/dashboard", "/api", "/api/v1", "/api/v2", "/graphql", "/graphiql",
  "/swagger", "/swagger-ui.html", "/swagger/index.html", "/openapi.json",
  "/swagger.json", "/api-docs", "/docs", "/redoc", "/upload", "/download",
  "/health", "/status", "/metrics", "/actuator", "/actuator/health", "/actuator/env",
  "/debug", "/console", "/phpinfo.php", "/server-status", "/server-info",
  "/.env", "/.git/HEAD", "/.git/config", "/.svn/entries", "/.DS_Store",
  "/config.json", "/config.php.bak", "/backup.zip", "/backup.sql", "/db.sql",
  "/wp-admin/", "/wp-login.php", "/wp-json/wp/v2/users",
  "/robots.txt", "/sitemap.xml", "/.well-known/security.txt",
  "/crossdomain.xml", "/clientaccesspolicy.xml", "/.well-known/openid-configuration",
];

/**
 * Establish how the server responds to a path that certainly does not exist.
 * Used to reject soft-404s (200 responses for missing content).
 */
export type SoftNotFoundBaseline = {
  status: number | null;
  bodyBytes: number | null;
  titleHash: string | null;
};

function hash(s: string): string {
  let h = 0;
  for (let i = 0; i < s.length; i++) h = (Math.imul(31, h) + s.charCodeAt(i)) | 0;
  return String(h);
}

export async function baselineNotFound(
  origin: string,
  scope: ScopeRules,
): Promise<SoftNotFoundBaseline> {
  const bytes = new Uint8Array(8);
  crypto.getRandomValues(bytes);
  const probe = `/sentinel-404-${Array.from(bytes, (b) => b.toString(16)).join("")}`;
  try {
    const res = await guardedFetch(`${origin}${probe}`, { scope, timeoutMs: 8000 });
    return {
      status: res.status,
      bodyBytes: res.bodyBytes,
      titleHash: hash(extractTitle(res.body) ?? ""),
    };
  } catch {
    return { status: null, bodyBytes: null, titleHash: null };
  }
}

function looksLikeSoft404(
  res: { status: number; bodyBytes: number; body: string },
  baseline: SoftNotFoundBaseline,
): boolean {
  if (baseline.status === null) return false;
  if (res.status !== baseline.status) return false;
  // Same status as a guaranteed-missing path. Compare shape.
  if (baseline.titleHash !== null && hash(extractTitle(res.body) ?? "") === baseline.titleHash) {
    return true;
  }
  if (baseline.bodyBytes !== null) {
    const delta = Math.abs(res.bodyBytes - baseline.bodyBytes);
    if (delta <= Math.max(64, baseline.bodyBytes * 0.02)) return true;
  }
  return false;
}

export async function probePaths(
  origin: string,
  paths: string[],
  opts: { scope: ScopeRules; concurrency: number; baseline: SoftNotFoundBaseline; source: string },
): Promise<{ endpoints: DiscoveredEndpoint[]; softNotFoundFiltered: number; errors: string[] }> {
  const endpoints: DiscoveredEndpoint[] = [];
  const errors: string[] = [];
  let softNotFoundFiltered = 0;

  await pooledMap(paths, opts.concurrency, async (path) => {
    try {
      const res = await guardedFetch(`${origin}${path}`, {
        scope: opts.scope,
        timeoutMs: 8000,
        followRedirects: false,
        maxBodyBytes: 200_000,
      });
      if (res.status === 404 || res.status === 410) return;
      if (looksLikeSoft404(res, opts.baseline)) {
        softNotFoundFiltered++;
        return;
      }
      endpoints.push({
        url: `${origin}${path}`,
        path,
        method: "GET",
        status: res.status,
        contentType: res.headers["content-type"] ?? "",
        bytes: res.bodyBytes,
        title: extractTitle(res.body),
        source: opts.source,
      });
    } catch (err) {
      errors.push(`${path} — ${err instanceof Error ? err.message : String(err)}`);
    }
  });

  return { endpoints, softNotFoundFiltered, errors };
}

/** Pull parameters out of already-known URLs and forms. No requests made. */
export function extractParameters(
  urls: string[],
  forms: DiscoveredForm[],
): DiscoveredParameter[] {
  const out = new Map<string, DiscoveredParameter>();

  for (const url of urls) {
    try {
      const u = new URL(url);
      for (const [name] of u.searchParams) {
        const key = `${u.origin}${u.pathname}|GET|${name}|query`;
        if (!out.has(key)) {
          out.set(key, {
            endpoint: `${u.origin}${u.pathname}`,
            method: "GET",
            name,
            location: "query",
            type: "string",
            source: "url-query",
          });
        }
      }
    } catch {
      /* skip unparseable */
    }
  }

  for (const form of forms) {
    for (const input of form.inputs) {
      const location = form.method === "GET" ? "query" : "body";
      const key = `${form.action}|${form.method}|${input.name}|${location}`;
      if (!out.has(key)) {
        out.set(key, {
          endpoint: form.action,
          method: form.method,
          name: input.name,
          location,
          type: input.type,
          source: "html-form",
        });
      }
    }
  }

  return [...out.values()];
}

type OpenApiDoc = {
  openapi?: string;
  swagger?: string;
  paths?: Record<string, Record<string, { parameters?: { name?: string }[] }>>;
  components?: { securitySchemes?: Record<string, unknown> };
  securityDefinitions?: Record<string, unknown>;
};

/** Discover and parse API surfaces from already-found endpoints. */
export async function discoverApis(
  origin: string,
  discovered: DiscoveredEndpoint[],
  opts: { scope: ScopeRules },
): Promise<{ apis: ApiInventoryEntry[]; parameters: DiscoveredParameter[]; errors: string[] }> {
  const apis: ApiInventoryEntry[] = [];
  const parameters: DiscoveredParameter[] = [];
  const errors: string[] = [];

  const openApiCandidates = discovered.filter(
    (e) =>
      /openapi\.json|swagger\.json|api-docs/i.test(e.path) &&
      e.status === 200 &&
      /json/i.test(e.contentType),
  );

  for (const candidate of openApiCandidates) {
    try {
      const res = await guardedFetch(candidate.url, { scope: opts.scope, timeoutMs: 12000 });
      const doc = JSON.parse(res.body) as OpenApiDoc;
      if (!doc.paths) continue;
      const operations: ApiInventoryEntry["operations"] = [];
      for (const [p, methods] of Object.entries(doc.paths)) {
        for (const [method, op] of Object.entries(methods)) {
          const params = (op?.parameters ?? []).map((x) => x.name ?? "").filter(Boolean);
          operations.push({ path: p, method: method.toUpperCase(), parameters: params });
          for (const name of params) {
            parameters.push({
              endpoint: `${origin}${p}`,
              method: method.toUpperCase(),
              name,
              location: "query",
              type: "string",
              source: "openapi",
            });
          }
        }
      }
      apis.push({
        kind: "openapi",
        url: candidate.url,
        status: candidate.status,
        detail: `${doc.openapi ? `OpenAPI ${doc.openapi}` : `Swagger ${doc.swagger ?? "2.0"}`} — ${operations.length} operations${
          doc.components?.securitySchemes || doc.securityDefinitions ? ", security schemes declared" : ", no security schemes declared"
        }`,
        operations,
      });
    } catch (err) {
      errors.push(`OpenAPI parse failed for ${candidate.url} — ${err instanceof Error ? err.message : String(err)}`);
    }
  }

  // GraphQL: confirm by a minimal, read-only introspection-shape query.
  const graphqlEndpoints = discovered.filter((e) => /graphql|graphiql/i.test(e.path));
  for (const gql of graphqlEndpoints) {
    try {
      const res = await guardedFetch(gql.url, {
        scope: opts.scope,
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ query: "{__typename}" }),
        timeoutMs: 10000,
      });
      const isGraphql = /"__typename"|"data"|"errors"/.test(res.body);
      if (isGraphql) {
        const introspectionOpen = /"__schema"|IntrospectionQuery/i.test(res.body);
        apis.push({
          kind: "graphql",
          url: gql.url,
          status: res.status,
          detail: introspectionOpen
            ? "GraphQL endpoint confirmed; introspection appears reachable"
            : "GraphQL endpoint confirmed via __typename response",
          operations: [],
        });
      }
    } catch (err) {
      errors.push(`GraphQL probe failed for ${gql.url} — ${err instanceof Error ? err.message : String(err)}`);
    }
  }

  for (const e of discovered) {
    if (e.status === 200 && /swagger-ui|redoc|\/docs$/i.test(e.path)) {
      apis.push({
        kind: "swagger-ui",
        url: e.url,
        status: e.status,
        detail: "Interactive API documentation UI is publicly reachable",
        operations: [],
      });
    }
  }

  return { apis, parameters, errors };
}
