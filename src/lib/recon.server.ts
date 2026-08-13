/**
 * Passive / non-intrusive reconnaissance helpers.
 *
 * Everything here uses plain HTTP(S) fetches that any browser could make:
 * DNS-over-HTTPS lookups, Certificate Transparency logs, and normal GET
 * requests against the target. No port scanning, no exploitation, no
 * brute force.
 */

export type Severity = "critical" | "high" | "medium" | "low" | "info";

export type Finding = {
  id: string;
  title: string;
  severity: Severity;
  category: string;
  evidence: string;
  recommendation: string;
};

export type DnsRecords = {
  a: string[];
  aaaa: string[];
  cname: string[];
  mx: string[];
  ns: string[];
  txt: string[];
  caa: string[];
};

export type SubdomainResult = {
  host: string;
  status: number | null;
  title: string | null;
  server: string | null;
};

export type HttpProbe = {
  url: string;
  finalUrl: string;
  status: number;
  redirected: boolean;
  headers: Record<string, string>;
  title: string | null;
  bodyBytes: number;
};

export type ScanResult = {
  target: string;
  scannedAt: string;
  durationMs: number;
  dns: DnsRecords;
  http: HttpProbe | null;
  httpPlain: { status: number; redirectsToHttps: boolean } | null;
  technologies: string[];
  subdomains: SubdomainResult[];
  exposedPaths: { path: string; status: number; note: string }[];
  cors: { reflectsArbitraryOrigin: boolean; allowCredentials: boolean; raw: string | null };
  cookies: { name: string; secure: boolean; httpOnly: boolean; sameSite: string | null }[];
  email: { spf: string | null; dmarc: string | null; dkimHint: boolean };
  findings: Finding[];
  score: number;
  grade: string;
  errors: string[];
};

const UA = "SentinelAI-PassiveRecon/1.0 (+authorized assessment)";

export function normalizeTarget(input: string): string {
  let t = input.trim().toLowerCase();
  t = t.replace(/^https?:\/\//, "").replace(/\/.*$/, "").replace(/:\d+$/, "");
  if (t.startsWith("www.")) t = t.slice(4);
  return t;
}

export function isValidHostname(host: string): boolean {
  return /^(?!-)[a-z0-9-]{1,63}(\.[a-z0-9-]{1,63})+$/.test(host) && host.length <= 253;
}

const PRIVATE_PATTERNS = [
  /^localhost$/,
  /\.local$/,
  /\.internal$/,
  /^\d+\.\d+\.\d+\.\d+$/,
];

export function isDisallowedTarget(host: string): boolean {
  return PRIVATE_PATTERNS.some((r) => r.test(host));
}

async function timedFetch(url: string, init: RequestInit = {}, ms = 8000): Promise<Response> {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), ms);
  try {
    return await fetch(url, {
      ...init,
      signal: ctrl.signal,
      headers: { "user-agent": UA, ...(init.headers as Record<string, string> | undefined) },
    });
  } finally {
    clearTimeout(timer);
  }
}

async function doh(name: string, type: string): Promise<string[]> {
  try {
    const res = await timedFetch(
      `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(name)}&type=${type}`,
      { headers: { accept: "application/dns-json" } },
      6000,
    );
    if (!res.ok) return [];
    const json = (await res.json()) as { Answer?: { type: number; data: string }[] };
    return (json.Answer ?? []).map((a) => a.data.replace(/^"|"$/g, ""));
  } catch {
    return [];
  }
}

export async function resolveDns(host: string): Promise<DnsRecords> {
  const [a, aaaa, cname, mx, ns, txt, caa] = await Promise.all([
    doh(host, "A"),
    doh(host, "AAAA"),
    doh(host, "CNAME"),
    doh(host, "MX"),
    doh(host, "NS"),
    doh(host, "TXT"),
    doh(host, "CAA"),
  ]);
  return { a, aaaa, cname, mx, ns, txt, caa };
}

function extractTitle(html: string): string | null {
  const m = html.match(/<title[^>]*>([\s\S]{0,200}?)<\/title>/i);
  return m?.[1] ? m[1].replace(/\s+/g, " ").trim() : null;
}

export async function probeHttps(host: string): Promise<HttpProbe | null> {
  try {
    const res = await timedFetch(`https://${host}/`, { redirect: "follow" }, 12000);
    const body = await res.text();
    const headers: Record<string, string> = {};
    res.headers.forEach((v, k) => {
      headers[k.toLowerCase()] = v;
    });
    return {
      url: `https://${host}/`,
      finalUrl: res.url || `https://${host}/`,
      status: res.status,
      redirected: res.redirected,
      headers,
      title: extractTitle(body),
      bodyBytes: body.length,
    };
  } catch {
    return null;
  }
}

export async function probePlainHttp(host: string) {
  try {
    const res = await timedFetch(`http://${host}/`, { redirect: "manual" }, 8000);
    const loc = res.headers.get("location") ?? "";
    return { status: res.status, redirectsToHttps: loc.startsWith("https://") };
  } catch {
    return null;
  }
}

export async function certTransparencySubdomains(host: string): Promise<string[]> {
  const set = new Set<string>();
  const addName = (raw: string) => {
    const n = raw.trim().toLowerCase().replace(/^\*\./, "");
    if (n.endsWith(`.${host}`)) set.add(n);
  };

  // Primary source: Cert Spotter (stable JSON API).
  try {
    const res = await timedFetch(
      `https://api.certspotter.com/v1/issuances?domain=${encodeURIComponent(host)}&include_subdomains=true&expand=dns_names`,
      { headers: { accept: "application/json" } },
      20000,
    );
    if (res.ok) {
      const rows = (await res.json()) as { dns_names?: string[] }[];
      for (const row of rows) for (const n of row.dns_names ?? []) addName(n);
    }
  } catch {
    /* fall through to crt.sh */
  }

  // Fallback source: crt.sh.
  if (set.size === 0) {
    try {
      const res = await timedFetch(
        `https://crt.sh/?q=%25.${encodeURIComponent(host)}&output=json`,
        { headers: { accept: "application/json" } },
        20000,
      );
      if (res.ok) {
        const rows = (await res.json()) as { name_value: string }[];
        for (const row of rows) for (const n of String(row.name_value).split("\n")) addName(n);
      }
    } catch {
      /* no CT data available */
    }
  }

  return [...set].sort();
}

export async function probeSubdomains(hosts: string[], limit = 20): Promise<SubdomainResult[]> {
  const targets = hosts.slice(0, limit);
  return Promise.all(
    targets.map(async (h) => {
      try {
        const res = await timedFetch(`https://${h}/`, { redirect: "follow" }, 7000);
        const text = await res.text();
        return {
          host: h,
          status: res.status,
          title: extractTitle(text),
          server: res.headers.get("server"),
        };
      } catch {
        return { host: h, status: null, title: null, server: null };
      }
    }),
  );
}

const SENSITIVE_PATHS: { path: string; note: string }[] = [
  { path: "/.env", note: "Environment file with credentials" },
  { path: "/.git/HEAD", note: "Exposed git repository" },
  { path: "/robots.txt", note: "Crawler policy (informational)" },
  { path: "/sitemap.xml", note: "Sitemap (informational)" },
  { path: "/.well-known/security.txt", note: "Security contact policy" },
  { path: "/server-status", note: "Apache status page" },
  { path: "/phpinfo.php", note: "PHP configuration dump" },
  { path: "/admin", note: "Admin interface" },
  { path: "/.DS_Store", note: "Directory listing artifact" },
  { path: "/backup.zip", note: "Backup archive" },
];

export async function checkExposedPaths(host: string) {
  const results = await Promise.all(
    SENSITIVE_PATHS.map(async ({ path, note }) => {
      try {
        const res = await timedFetch(`https://${host}${path}`, { redirect: "manual" }, 6000);
        return { path, status: res.status, note };
      } catch {
        return { path, status: 0, note };
      }
    }),
  );
  return results.filter((r) => r.status > 0);
}

export async function checkCors(host: string) {
  try {
    const res = await timedFetch(
      `https://${host}/`,
      { headers: { origin: "https://sentinel-probe.example" }, redirect: "follow" },
      8000,
    );
    const allow = res.headers.get("access-control-allow-origin");
    return {
      reflectsArbitraryOrigin:
        allow === "https://sentinel-probe.example" || allow === "*",
      allowCredentials: res.headers.get("access-control-allow-credentials") === "true",
      raw: allow,
    };
  } catch {
    return { reflectsArbitraryOrigin: false, allowCredentials: false, raw: null };
  }
}

export function parseCookies(headers: Record<string, string>) {
  const raw = headers["set-cookie"];
  if (!raw) return [];
  return raw.split(/,(?=[^;]+=)/).map((c) => {
    const name = c.split("=")[0]?.trim() ?? "cookie";
    const lower = c.toLowerCase();
    const sameSite = lower.match(/samesite=(lax|strict|none)/)?.[1] ?? null;
    return {
      name,
      secure: lower.includes("secure"),
      httpOnly: lower.includes("httponly"),
      sameSite,
    };
  });
}

const TECH_SIGNATURES: { name: string; header?: string; match: RegExp }[] = [
  { name: "Cloudflare", header: "server", match: /cloudflare/i },
  { name: "nginx", header: "server", match: /nginx/i },
  { name: "Apache", header: "server", match: /apache/i },
  { name: "Microsoft IIS", header: "server", match: /iis/i },
  { name: "Vercel", header: "server", match: /vercel/i },
  { name: "Netlify", header: "server", match: /netlify/i },
  { name: "PHP", header: "x-powered-by", match: /php/i },
  { name: "ASP.NET", header: "x-powered-by", match: /asp\.net/i },
  { name: "Express", header: "x-powered-by", match: /express/i },
  { name: "WordPress", header: "link", match: /wp-json/i },
  { name: "AWS", header: "server", match: /amazons3|awselb/i },
];

export function detectTechnologies(probe: HttpProbe | null): string[] {
  if (!probe) return [];
  const found = new Set<string>();
  for (const sig of TECH_SIGNATURES) {
    const value = sig.header ? probe.headers[sig.header] : undefined;
    if (value && sig.match.test(value)) found.add(sig.name);
  }
  if (probe.headers["x-drupal-cache"]) found.add("Drupal");
  if (probe.headers["x-shopify-stage"]) found.add("Shopify");
  if (probe.headers["cf-ray"]) found.add("Cloudflare");
  return [...found];
}

export async function emailPosture(host: string, txt: string[]) {
  const spf = txt.find((t) => t.toLowerCase().startsWith("v=spf1")) ?? null;
  const dmarcRecords = await doh(`_dmarc.${host}`, "TXT");
  const dmarc = dmarcRecords.find((t) => t.toLowerCase().startsWith("v=dmarc1")) ?? null;
  const dkim = await doh(`default._domainkey.${host}`, "TXT");
  return { spf, dmarc, dkimHint: dkim.length > 0 };
}

const SEVERITY_WEIGHT: Record<Severity, number> = {
  critical: 25,
  high: 15,
  medium: 8,
  low: 3,
  info: 0,
};

export function scoreFindings(findings: Finding[]) {
  const penalty = findings.reduce((sum, f) => sum + SEVERITY_WEIGHT[f.severity], 0);
  const score = Math.max(0, 100 - penalty);
  const grade =
    score >= 90 ? "A" : score >= 80 ? "B" : score >= 65 ? "C" : score >= 50 ? "D" : "F";
  return { score, grade };
}

export function analyzeFindings(input: {
  host: string;
  probe: HttpProbe | null;
  httpPlain: { status: number; redirectsToHttps: boolean } | null;
  cors: ScanResult["cors"];
  cookies: ScanResult["cookies"];
  exposedPaths: ScanResult["exposedPaths"];
  email: ScanResult["email"];
  dns: DnsRecords;
}): Finding[] {
  const findings: Finding[] = [];
  const h = input.probe?.headers ?? {};
  const add = (f: Finding) => findings.push(f);

  if (!input.probe) {
    add({
      id: "https-unreachable",
      title: "HTTPS endpoint unreachable",
      severity: "high",
      category: "Transport",
      evidence: `https://${input.host}/ did not respond to a standard GET request.`,
      recommendation: "Verify TLS is served on port 443 and the certificate chain is valid.",
    });
  }

  if (input.probe && !h["strict-transport-security"]) {
    add({
      id: "missing-hsts",
      title: "Missing Strict-Transport-Security header",
      severity: "medium",
      category: "Transport",
      evidence: "No HSTS header returned on the main response.",
      recommendation:
        "Send `Strict-Transport-Security: max-age=31536000; includeSubDomains` over HTTPS.",
    });
  }
  if (input.probe && !h["content-security-policy"]) {
    add({
      id: "missing-csp",
      title: "No Content-Security-Policy",
      severity: "medium",
      category: "Application",
      evidence: "Responses do not define a CSP, leaving XSS payloads unrestricted.",
      recommendation: "Deploy a CSP starting in report-only mode, then enforce it.",
    });
  }
  if (input.probe && !h["x-content-type-options"]) {
    add({
      id: "missing-xcto",
      title: "Missing X-Content-Type-Options",
      severity: "low",
      category: "Application",
      evidence: "MIME sniffing is not disabled.",
      recommendation: "Add `X-Content-Type-Options: nosniff`.",
    });
  }
  if (input.probe && !h["x-frame-options"] && !/frame-ancestors/i.test(h["content-security-policy"] ?? "")) {
    add({
      id: "clickjacking",
      title: "Clickjacking protection absent",
      severity: "low",
      category: "Application",
      evidence: "Neither X-Frame-Options nor CSP frame-ancestors is present.",
      recommendation: "Set `X-Frame-Options: DENY` or CSP `frame-ancestors 'none'`.",
    });
  }
  if (input.probe && !h["referrer-policy"]) {
    add({
      id: "missing-referrer-policy",
      title: "No Referrer-Policy",
      severity: "low",
      category: "Privacy",
      evidence: "Full URLs may leak to third parties via the Referer header.",
      recommendation: "Set `Referrer-Policy: strict-origin-when-cross-origin`.",
    });
  }
  if (h["server"] && /\d+\.\d+/.test(h["server"])) {
    add({
      id: "server-version-disclosure",
      title: "Server version disclosed",
      severity: "low",
      category: "Information disclosure",
      evidence: `Server: ${h["server"]}`,
      recommendation: "Suppress version numbers in the Server banner.",
    });
  }
  if (h["x-powered-by"]) {
    add({
      id: "x-powered-by",
      title: "Technology stack disclosed via X-Powered-By",
      severity: "low",
      category: "Information disclosure",
      evidence: `X-Powered-By: ${h["x-powered-by"]}`,
      recommendation: "Remove the X-Powered-By header at the web server or framework level.",
    });
  }

  if (input.httpPlain && !input.httpPlain.redirectsToHttps && input.httpPlain.status < 400) {
    add({
      id: "no-https-redirect",
      title: "Plain HTTP is served without redirect to HTTPS",
      severity: "high",
      category: "Transport",
      evidence: `http://${input.host}/ returned ${input.httpPlain.status} with no HTTPS redirect.`,
      recommendation: "Force a 301 redirect from HTTP to HTTPS on every path.",
    });
  }

  if (input.cors.reflectsArbitraryOrigin) {
    add({
      id: "cors-wildcard",
      title: input.cors.allowCredentials
        ? "CORS reflects arbitrary origins with credentials"
        : "Permissive CORS policy",
      severity: input.cors.allowCredentials ? "critical" : "medium",
      category: "Application",
      evidence: `Access-Control-Allow-Origin: ${input.cors.raw}`,
      recommendation: "Allow only an explicit allowlist of trusted origins.",
    });
  }

  for (const c of input.cookies) {
    const issues: string[] = [];
    if (!c.secure) issues.push("no Secure flag");
    if (!c.httpOnly) issues.push("no HttpOnly flag");
    if (!c.sameSite) issues.push("no SameSite attribute");
    if (issues.length) {
      add({
        id: `cookie-${c.name}`,
        title: `Cookie "${c.name}" set without full protection`,
        severity: issues.length >= 2 ? "medium" : "low",
        category: "Session",
        evidence: issues.join(", "),
        recommendation: "Set Secure, HttpOnly and SameSite=Lax/Strict on session cookies.",
      });
    }
  }

  for (const p of input.exposedPaths) {
    if (p.status !== 200) continue;
    if (p.path === "/robots.txt" || p.path === "/sitemap.xml" || p.path.includes("security.txt")) {
      add({
        id: `path${p.path}`,
        title: `${p.path} is available`,
        severity: "info",
        category: "Discovery",
        evidence: `HTTP 200 at ${p.path} — ${p.note}.`,
        recommendation: "Informational: review contents for sensitive path leakage.",
      });
      continue;
    }
    const critical = [".env", ".git", "backup.zip", "phpinfo"].some((s) => p.path.includes(s));
    add({
      id: `path${p.path}`,
      title: `Sensitive path reachable: ${p.path}`,
      severity: critical ? "critical" : "medium",
      category: "Exposure",
      evidence: `HTTP 200 at ${p.path} — ${p.note}.`,
      recommendation: "Block or remove this path from public access immediately.",
    });
  }

  if (input.dns.mx.length > 0) {
    if (!input.email.spf) {
      add({
        id: "missing-spf",
        title: "No SPF record",
        severity: "medium",
        category: "Email",
        evidence: "Domain accepts mail but publishes no v=spf1 record.",
        recommendation: "Publish an SPF record ending in -all.",
      });
    }
    if (!input.email.dmarc) {
      add({
        id: "missing-dmarc",
        title: "No DMARC policy",
        severity: "medium",
        category: "Email",
        evidence: "_dmarc TXT record is absent — spoofed mail will not be rejected.",
        recommendation: "Publish `v=DMARC1; p=quarantine; rua=mailto:...` and ramp to p=reject.",
      });
    } else if (/p=none/i.test(input.email.dmarc)) {
      add({
        id: "weak-dmarc",
        title: "DMARC policy set to p=none",
        severity: "low",
        category: "Email",
        evidence: input.email.dmarc,
        recommendation: "Move to p=quarantine and then p=reject after monitoring reports.",
      });
    }
  }

  if (input.dns.caa.length === 0) {
    add({
      id: "missing-caa",
      title: "No CAA record",
      severity: "low",
      category: "PKI",
      evidence: "Any certificate authority may issue certificates for this domain.",
      recommendation: "Publish CAA records restricting issuance to your CA.",
    });
  }

  return findings;
}

export async function runFullScan(hostInput: string): Promise<ScanResult> {
  const started = Date.now();
  const host = normalizeTarget(hostInput);
  const errors: string[] = [];

  const [dns, probe, httpPlain, ctSubs, exposedPaths, cors] = await Promise.all([
    resolveDns(host).catch(() => {
      errors.push("DNS resolution failed");
      return { a: [], aaaa: [], cname: [], mx: [], ns: [], txt: [], caa: [] } as DnsRecords;
    }),
    probeHttps(host),
    probePlainHttp(host),
    certTransparencySubdomains(host).catch(() => {
      errors.push("Certificate Transparency lookup failed");
      return [] as string[];
    }),
    checkExposedPaths(host),
    checkCors(host),
  ]);

  const [subdomains, email] = await Promise.all([
    probeSubdomains(ctSubs),
    emailPosture(host, dns.txt),
  ]);

  const cookies = parseCookies(probe?.headers ?? {});
  const technologies = detectTechnologies(probe);
  const findings = analyzeFindings({
    host,
    probe,
    httpPlain,
    cors,
    cookies,
    exposedPaths,
    email,
    dns,
  });
  const { score, grade } = scoreFindings(findings);

  return {
    target: host,
    scannedAt: new Date().toISOString(),
    durationMs: Date.now() - started,
    dns,
    http: probe,
    httpPlain,
    technologies,
    subdomains,
    exposedPaths,
    cors,
    cookies,
    email,
    findings,
    score,
    grade,
    errors,
  };
}

export async function aiAnalysis(result: ScanResult, apiKey: string): Promise<string> {
  const summary = {
    target: result.target,
    grade: result.grade,
    score: result.score,
    technologies: result.technologies,
    subdomainCount: result.subdomains.length,
    liveSubdomains: result.subdomains.filter((s) => s.status && s.status < 400).map((s) => s.host),
    findings: result.findings.map((f) => ({
      title: f.title,
      severity: f.severity,
      evidence: f.evidence,
    })),
    email: result.email,
    dnsProviders: result.dns.ns,
  };

  const baseUrl = (
    process.env["AI_BASE_URL"] ?? "https://ai.gateway.lovable.dev/v1"
  ).replace(/\/$/, "");
  const model = process.env["AI_MODEL"] ?? "google/gemini-2.5-flash";

  const res = await timedFetch(
    `${baseUrl}/chat/completions`,
    {
      method: "POST",
      headers: {
        authorization: `Bearer ${apiKey}`,
        "content-type": "application/json",
      },
      body: JSON.stringify({
        model,

        messages: [
          {
            role: "system",
            content:
              "You are a senior application security consultant. Given passive reconnaissance output, write a concise executive assessment in markdown: 1) Risk summary (2-3 sentences), 2) Top prioritized risks with why they matter to this specific stack, 3) A 30/60/90 day remediation roadmap. Be specific, no filler, no disclaimers.",
          },
          { role: "user", content: JSON.stringify(summary) },
        ],
      }),
    },
    45000,
  );

  if (res.status === 429) throw new Error("AI rate limit reached — try again shortly.");
  if (res.status === 402) throw new Error("AI credits exhausted for this workspace.");
  if (!res.ok) throw new Error(`AI gateway error ${res.status}`);

  const json = (await res.json()) as { choices?: { message?: { content?: string } }[] };
  return json.choices?.[0]?.message?.content ?? "No analysis returned.";
}
