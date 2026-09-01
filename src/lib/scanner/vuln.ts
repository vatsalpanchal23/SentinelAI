/**
 * Vulnerability assessment rules.
 *
 * Rules are deterministic and evidence-bound: every finding carries the ID of
 * the evidence record that justifies it, and a confidence level that reflects
 * how much the scanner actually proved.
 *
 * Confidence ladder:
 *   detected           — an indicator was observed, nothing was tested
 *   tested             — an active probe was sent and the response examined
 *   evidence-collected — a probe produced a response that is retained verbatim
 *   validated          — the response uniquely establishes the condition
 */

import type { Confidence, Finding, HttpProbe, Severity, DnsRecords } from "./types";
import type { EvidenceStore } from "./evidence";
import type { DiscoveredEndpoint } from "./endpoints";
import type { TechDetection } from "./tech";
import { buildFindingGuidance, type FindingGuidance } from "./guidance";

let counter = 0;
function nextId(prefix: string): string {
  return `${prefix}-${(++counter).toString(36)}-${Date.now().toString(36)}`;
}

export function resetFindingIds() {
  counter = 0;
}

type FindingInput = {
  title: string;
  severity: Severity;
  confidence: Confidence;
  category: string;
  cvss?: number | null;
  cwe?: string | null;
  owasp?: string | null;
  asset: string;
  endpoint?: string | null;
  parameter?: string | null;
  evidenceIds: string[];
  description: string;
  impact: string;
  remediation: string;
  exposureSteps?: string[];
  remediationSteps?: string[];
  references?: string[];
  module: string;
};

function make(input: FindingInput): Finding {
  const guidance: FindingGuidance = buildFindingGuidance(input);
  return {
    id: nextId("f"),
    title: input.title,
    severity: input.severity,
    confidence: input.confidence,
    category: input.category,
    cvss: input.cvss ?? null,
    cwe: input.cwe ?? null,
    owasp: input.owasp ?? null,
    asset: input.asset,
    endpoint: input.endpoint ?? null,
    parameter: input.parameter ?? null,
    evidenceIds: input.evidenceIds,
    description: input.description,
    impact: input.impact,
    remediation: input.remediation,
    exposureSteps: input.exposureSteps ?? guidance.exposureSteps,
    remediationSteps: input.remediationSteps ?? guidance.remediationSteps,
    references: input.references ?? [],
    module: input.module,
    detectedAt: new Date().toISOString(),
  };
}

// ---------------------------------------------------------------------------
// Security headers
// ---------------------------------------------------------------------------

export function analyzeSecurityHeaders(
  asset: string,
  probe: HttpProbe,
  store: EvidenceStore,
): Finding[] {
  const findings: Finding[] = [];
  const h = probe.headers;
  const evId = store.addHeaders("vuln.headers", probe);
  const MODULE = "vuln.headers";

  const isHttps = probe.finalUrl.startsWith("https://");

  if (isHttps && !h["strict-transport-security"]) {
    findings.push(make({
      title: "HTTP Strict Transport Security not enforced",
      severity: "medium",
      confidence: "validated",
      category: "Transport security",
      cwe: "CWE-319",
      owasp: "A02:2021 Cryptographic Failures",
      cvss: 5.3,
      asset,
      endpoint: probe.finalUrl,
      evidenceIds: [evId],
      description:
        "The response over HTTPS does not include a Strict-Transport-Security header, so a browser will still attempt plaintext HTTP for this origin on a first or subsequent visit.",
      impact:
        "An attacker positioned on the network can strip TLS on the initial request and intercept or modify traffic, including session cookies.",
      remediation:
        "Return `Strict-Transport-Security: max-age=31536000; includeSubDomains` on all HTTPS responses, then consider preload submission once subdomain coverage is verified.",
      references: ["https://owasp.org/www-project-secure-headers/#http-strict-transport-security"],
      module: MODULE,
    }));
  }

  const csp = h["content-security-policy"];
  if (!csp) {
    findings.push(make({
      title: "No Content-Security-Policy",
      severity: "medium",
      confidence: "validated",
      category: "Application security",
      cwe: "CWE-1021",
      owasp: "A05:2021 Security Misconfiguration",
      cvss: 5.4,
      asset,
      endpoint: probe.finalUrl,
      evidenceIds: [evId],
      description: "The application does not define a Content-Security-Policy on this response.",
      impact:
        "Any cross-site scripting flaw elsewhere in the application executes without restriction, and there is no defence-in-depth against injected script or data exfiltration.",
      remediation:
        "Deploy a CSP in report-only mode, resolve violations, then enforce. Start from `default-src 'self'` and avoid 'unsafe-inline' for scripts.",
      references: ["https://owasp.org/www-project-secure-headers/#content-security-policy"],
      module: MODULE,
    }));
  } else if (/unsafe-inline|unsafe-eval/i.test(csp)) {
    findings.push(make({
      title: "Content-Security-Policy weakened by unsafe directives",
      severity: "low",
      confidence: "validated",
      category: "Application security",
      cwe: "CWE-1021",
      owasp: "A05:2021 Security Misconfiguration",
      cvss: 3.7,
      asset,
      endpoint: probe.finalUrl,
      evidenceIds: [evId],
      description: `The policy contains unsafe directives: ${csp.slice(0, 300)}`,
      impact:
        "'unsafe-inline' and 'unsafe-eval' permit exactly the script execution CSP is intended to prevent, substantially reducing its value against XSS.",
      remediation:
        "Replace inline scripts with external files or nonce/hash-based allowances and remove 'unsafe-eval'.",
      module: MODULE,
    }));
  }

  if (!h["x-content-type-options"]) {
    findings.push(make({
      title: "MIME type sniffing not disabled",
      severity: "low",
      confidence: "validated",
      category: "Application security",
      cwe: "CWE-430",
      owasp: "A05:2021 Security Misconfiguration",
      cvss: 3.1,
      asset,
      endpoint: probe.finalUrl,
      evidenceIds: [evId],
      description: "The response omits `X-Content-Type-Options: nosniff`.",
      impact:
        "Browsers may interpret a response as a different content type than declared, which can turn an uploaded or reflected file into executable script.",
      remediation: "Add `X-Content-Type-Options: nosniff` to every response.",
      module: MODULE,
    }));
  }

  const hasFrameAncestors = /frame-ancestors/i.test(csp ?? "");
  if (!h["x-frame-options"] && !hasFrameAncestors) {
    findings.push(make({
      title: "No clickjacking protection",
      severity: "medium",
      confidence: "validated",
      category: "Application security",
      cwe: "CWE-1021",
      owasp: "A05:2021 Security Misconfiguration",
      cvss: 4.3,
      asset,
      endpoint: probe.finalUrl,
      evidenceIds: [evId],
      description:
        "Neither an X-Frame-Options header nor a CSP frame-ancestors directive is present, so the page can be embedded in a frame on any origin.",
      impact:
        "An attacker can overlay the framed application with their own interface and trick an authenticated user into performing actions they did not intend.",
      remediation:
        "Set `Content-Security-Policy: frame-ancestors 'none'` (or an explicit allowlist) and `X-Frame-Options: DENY` for older clients.",
      module: MODULE,
    }));
  }

  if (!h["referrer-policy"]) {
    findings.push(make({
      title: "No Referrer-Policy",
      severity: "low",
      confidence: "validated",
      category: "Privacy",
      cwe: "CWE-200",
      owasp: "A01:2021 Broken Access Control",
      cvss: 2.6,
      asset,
      endpoint: probe.finalUrl,
      evidenceIds: [evId],
      description: "No Referrer-Policy header is returned.",
      impact:
        "Full request URLs, including any identifiers or tokens present in the path or query string, are sent to third-party origins in the Referer header.",
      remediation: "Set `Referrer-Policy: strict-origin-when-cross-origin` or stricter.",
      module: MODULE,
    }));
  }

  const server = h["server"];
  if (server && /\d+\.\d+/.test(server)) {
    findings.push(make({
      title: "Server software version disclosed",
      severity: "low",
      confidence: "validated",
      category: "Information disclosure",
      cwe: "CWE-200",
      owasp: "A05:2021 Security Misconfiguration",
      cvss: 3.1,
      asset,
      endpoint: probe.finalUrl,
      evidenceIds: [evId],
      description: `The Server header advertises an exact version: \`${server}\`.`,
      impact:
        "An attacker can match the disclosed version directly against public vulnerability databases without needing to probe the service, shortening reconnaissance.",
      remediation:
        "Suppress version output in the web server configuration (nginx `server_tokens off`, Apache `ServerTokens Prod`).",
      module: MODULE,
    }));
  }

  if (h["x-powered-by"]) {
    findings.push(make({
      title: "Technology stack disclosed via X-Powered-By",
      severity: "low",
      confidence: "validated",
      category: "Information disclosure",
      cwe: "CWE-200",
      owasp: "A05:2021 Security Misconfiguration",
      cvss: 3.1,
      asset,
      endpoint: probe.finalUrl,
      evidenceIds: [evId],
      description: `\`X-Powered-By: ${h["x-powered-by"]}\``,
      impact: "Discloses the runtime and often its version, aiding targeted exploit selection.",
      remediation: "Remove the header at the framework or reverse-proxy layer.",
      module: MODULE,
    }));
  }

  return findings;
}

// ---------------------------------------------------------------------------
// Cookies
// ---------------------------------------------------------------------------

export type ParsedCookie = {
  name: string;
  secure: boolean;
  httpOnly: boolean;
  sameSite: string | null;
  raw: string;
};

export function parseCookies(setCookies: string[]): ParsedCookie[] {
  return setCookies.map((raw) => {
    const name = raw.split("=")[0]?.trim() ?? "cookie";
    const lower = raw.toLowerCase();
    return {
      name,
      secure: /(^|;)\s*secure\s*(;|$)/.test(lower),
      httpOnly: /(^|;)\s*httponly\s*(;|$)/.test(lower),
      sameSite: lower.match(/samesite\s*=\s*(lax|strict|none)/)?.[1] ?? null,
      raw,
    };
  });
}

const SESSION_HINT = /sess|sid|auth|token|jwt|login|remember/i;

export function analyzeCookies(
  asset: string,
  probe: HttpProbe,
  store: EvidenceStore,
): Finding[] {
  const cookies = parseCookies(probe.setCookies);
  const findings: Finding[] = [];
  const MODULE = "vuln.cookies";

  for (const c of cookies) {
    const issues: string[] = [];
    if (!c.secure) issues.push("Secure flag missing");
    if (!c.httpOnly) issues.push("HttpOnly flag missing");
    if (!c.sameSite) issues.push("SameSite attribute missing");
    if (c.sameSite === "none" && !c.secure) issues.push("SameSite=None without Secure");
    if (issues.length === 0) continue;

    const isSession = SESSION_HINT.test(c.name);
    const evId = store.add({
      module: MODULE,
      source: `Set-Cookie on ${probe.finalUrl}`,
      // Redact the value; the attributes are what matters.
      content: `${c.name}=<redacted>; ${c.raw.split(";").slice(1).join(";").trim()}`,
      contentType: "http-headers",
    });

    findings.push(make({
      title: `Cookie "${c.name}" missing protection attributes`,
      severity: isSession && issues.length >= 2 ? "medium" : "low",
      confidence: "validated",
      category: "Session management",
      cwe: c.httpOnly ? "CWE-614" : "CWE-1004",
      owasp: "A05:2021 Security Misconfiguration",
      cvss: isSession && issues.length >= 2 ? 5.3 : 3.1,
      asset,
      endpoint: probe.finalUrl,
      evidenceIds: [evId],
      description: `${issues.join("; ")}.${isSession ? " The name suggests this is a session or authentication cookie." : ""}`,
      impact: !c.httpOnly
        ? "Without HttpOnly the cookie is readable by JavaScript, so any XSS flaw yields immediate session theft. Without Secure it can be transmitted over plaintext HTTP."
        : "Without a SameSite attribute the cookie is attached to cross-site requests, enabling cross-site request forgery against state-changing endpoints.",
      remediation:
        "Set `Secure; HttpOnly; SameSite=Lax` (or `Strict`) on session cookies. Use `SameSite=None; Secure` only where genuine cross-site delivery is required.",
      module: MODULE,
    }));
  }

  return findings;
}

// ---------------------------------------------------------------------------
// Transport
// ---------------------------------------------------------------------------

export function analyzeTransport(
  asset: string,
  httpsProbe: HttpProbe | null,
  plainHttp: { status: number; redirectsToHttps: boolean; location: string | null } | null,
  store: EvidenceStore,
): Finding[] {
  const findings: Finding[] = [];
  const MODULE = "vuln.transport";

  if (!httpsProbe) {
    const evId = store.add({
      module: MODULE,
      source: `https://${asset}/`,
      content: "No response received over HTTPS within the configured timeout.",
      contentType: "text",
    });
    findings.push(make({
      title: "HTTPS not available",
      severity: "high",
      confidence: "tested",
      category: "Transport security",
      cwe: "CWE-319",
      owasp: "A02:2021 Cryptographic Failures",
      cvss: 7.4,
      asset,
      evidenceIds: [evId],
      description: "The host did not serve a usable HTTPS response on port 443.",
      impact: "All traffic to this host is exposed to interception and modification in transit.",
      remediation: "Provision a valid TLS certificate and serve the application over HTTPS only.",
      module: MODULE,
    }));
  }

  if (plainHttp && !plainHttp.redirectsToHttps && plainHttp.status < 400) {
    const evId = store.add({
      module: MODULE,
      source: `http://${asset}/`,
      content: `HTTP ${plainHttp.status}${plainHttp.location ? `\nLocation: ${plainHttp.location}` : "\nNo Location header returned"}`,
      contentType: "http-headers",
    });
    findings.push(make({
      title: "Plaintext HTTP served without redirect to HTTPS",
      severity: "high",
      confidence: "validated",
      category: "Transport security",
      cwe: "CWE-319",
      owasp: "A02:2021 Cryptographic Failures",
      cvss: 7.4,
      asset,
      endpoint: `http://${asset}/`,
      evidenceIds: [evId],
      description: `A plain HTTP request returned ${plainHttp.status} without redirecting to HTTPS.`,
      impact:
        "Credentials, session cookies and application data can be read or altered by anyone on the network path.",
      remediation: "Return a 301 redirect to the HTTPS equivalent for every HTTP path, then enable HSTS.",
      module: MODULE,
    }));
  }

  return findings;
}

// ---------------------------------------------------------------------------
// CORS
// ---------------------------------------------------------------------------

export type CorsProbeResult = {
  testedOrigin: string;
  allowOrigin: string | null;
  allowCredentials: boolean;
  allowMethods: string | null;
  reflects: boolean;
};

export function analyzeCors(
  asset: string,
  url: string,
  cors: CorsProbeResult,
  store: EvidenceStore,
): Finding[] {
  if (!cors.reflects && cors.allowOrigin !== "*") return [];
  const MODULE = "vuln.cors";

  const evId = store.add({
    module: MODULE,
    source: `GET ${url} with Origin: ${cors.testedOrigin}`,
    content: [
      `Origin: ${cors.testedOrigin}`,
      `Access-Control-Allow-Origin: ${cors.allowOrigin ?? "(absent)"}`,
      `Access-Control-Allow-Credentials: ${cors.allowCredentials}`,
      cors.allowMethods ? `Access-Control-Allow-Methods: ${cors.allowMethods}` : "",
    ].filter(Boolean).join("\n"),
    contentType: "http-headers",
  });

  const critical = cors.reflects && cors.allowCredentials;

  return [make({
    title: critical
      ? "CORS reflects arbitrary origins with credentials permitted"
      : "Permissive CORS policy",
    severity: critical ? "critical" : "medium",
    confidence: "validated",
    category: "Application security",
    cwe: "CWE-942",
    owasp: "A05:2021 Security Misconfiguration",
    cvss: critical ? 9.1 : 5.3,
    asset,
    endpoint: url,
    evidenceIds: [evId],
    description: critical
      ? `The server echoed the attacker-supplied origin \`${cors.testedOrigin}\` in Access-Control-Allow-Origin and set Access-Control-Allow-Credentials: true.`
      : `Access-Control-Allow-Origin is \`${cors.allowOrigin}\`.`,
    impact: critical
      ? "Any website a victim visits can issue authenticated cross-origin requests to this endpoint and read the responses, giving full read access to the victim's data."
      : "Any origin can read responses from this endpoint. This is only acceptable for data that is genuinely public.",
    remediation:
      "Validate the Origin header against an explicit allowlist and echo only matching values. Never combine a reflected or wildcard origin with Access-Control-Allow-Credentials: true.",
    references: ["https://portswigger.net/web-security/cors"],
    module: MODULE,
  })];
}

// ---------------------------------------------------------------------------
// Exposed paths and information disclosure
// ---------------------------------------------------------------------------

const HIGH_RISK_PATHS: { match: RegExp; title: string; severity: Severity; cwe: string; why: string }[] = [
  { match: /^\/\.env$/, title: "Environment file exposed", severity: "critical", cwe: "CWE-538", why: "Environment files routinely contain database credentials, API keys and signing secrets." },
  { match: /^\/\.git\//, title: "Git repository exposed", severity: "critical", cwe: "CWE-538", why: "A reachable .git directory allows the full source history — including removed secrets — to be reconstructed." },
  { match: /^\/\.svn\//, title: "Subversion metadata exposed", severity: "high", cwe: "CWE-538", why: "Version control metadata can disclose source code and internal paths." },
  { match: /backup|\.sql$|\.zip$|\.tar\.gz$/, title: "Backup archive reachable", severity: "critical", cwe: "CWE-530", why: "Backups commonly contain the full application source and a database dump." },
  { match: /^\/phpinfo\.php$/, title: "phpinfo() output exposed", severity: "high", cwe: "CWE-200", why: "Discloses the full PHP configuration, loaded modules, absolute paths and environment variables." },
  { match: /^\/server-status|^\/server-info/, title: "Web server status page exposed", severity: "medium", cwe: "CWE-200", why: "Discloses live request URLs, client addresses and server internals." },
  { match: /^\/actuator/, title: "Spring Boot Actuator endpoint exposed", severity: "high", cwe: "CWE-200", why: "Actuator endpoints can expose configuration, environment variables, heap dumps and shutdown controls." },
  { match: /^\/\.DS_Store$/, title: "macOS directory index file exposed", severity: "low", cwe: "CWE-538", why: "Reveals filenames present in the deployed directory." },
  { match: /^\/config/, title: "Configuration file reachable", severity: "high", cwe: "CWE-538", why: "Application configuration frequently embeds credentials and internal endpoints." },
];

export function analyzeExposedPaths(
  asset: string,
  endpoints: DiscoveredEndpoint[],
  store: EvidenceStore,
  bodies: Map<string, string>,
): Finding[] {
  const findings: Finding[] = [];
  const MODULE = "vuln.exposure";

  for (const e of endpoints) {
    if (e.status !== 200) continue;
    const rule = HIGH_RISK_PATHS.find((r) => r.match.test(e.path));
    if (!rule) continue;

    const body = bodies.get(e.url) ?? "";
    // Only report if the response actually looks like the artefact, not a SPA fallback.
    if (/text\/html/i.test(e.contentType) && !/^\/(server-status|server-info|actuator|config)/.test(e.path)) {
      continue;
    }

    const evId = store.add({
      module: MODULE,
      source: `GET ${e.url}`,
      content: `HTTP ${e.status} ${e.contentType} (${e.bytes} bytes)\n\n${body.slice(0, 1500)}`,
      contentType: "http-body",
    });

    findings.push(make({
      title: `${rule.title}: ${e.path}`,
      severity: rule.severity,
      confidence: "evidence-collected",
      category: "Information disclosure",
      cwe: rule.cwe,
      owasp: "A05:2021 Security Misconfiguration",
      cvss: rule.severity === "critical" ? 9.1 : rule.severity === "high" ? 7.5 : 5.3,
      asset,
      endpoint: e.url,
      evidenceIds: [evId],
      description: `\`${e.path}\` returned HTTP 200 with ${e.bytes} bytes of ${e.contentType || "unknown"} content.`,
      impact: rule.why,
      remediation:
        "Deny access to this path at the web server or CDN, and remove the artefact from the deployed document root. Treat any credential it contained as compromised and rotate it.",
      module: MODULE,
    }));
  }

  // Directory listing.
  for (const e of endpoints) {
    const body = bodies.get(e.url) ?? "";
    if (e.status !== 200 || !body) continue;
    if (!/<title>index of \/|<h1>index of \//i.test(body)) continue;
    const evId = store.add({
      module: MODULE,
      source: `GET ${e.url}`,
      content: body.slice(0, 1200),
      contentType: "http-body",
    });
    findings.push(make({
      title: `Directory listing enabled at ${e.path}`,
      severity: "medium",
      confidence: "evidence-collected",
      category: "Information disclosure",
      cwe: "CWE-548",
      owasp: "A05:2021 Security Misconfiguration",
      cvss: 5.3,
      asset,
      endpoint: e.url,
      evidenceIds: [evId],
      description: "The server returned an automatically generated directory index.",
      impact: "Discloses file names that are not linked from the application, often revealing backups, notes and unreferenced scripts.",
      remediation: "Disable automatic indexing (nginx `autoindex off`, Apache `Options -Indexes`).",
      module: MODULE,
    }));
  }

  return findings;
}

// ---------------------------------------------------------------------------
// Email / DNS posture
// ---------------------------------------------------------------------------

export function analyzeDnsPosture(
  asset: string,
  dns: DnsRecords,
  email: { spf: string | null; dmarc: string | null; dkimObserved: boolean },
  store: EvidenceStore,
): Finding[] {
  const findings: Finding[] = [];
  const MODULE = "vuln.dns";

  if (dns.mx.length > 0) {
    if (!email.spf) {
      const evId = store.addDnsRecord(MODULE, asset, "TXT", dns.txt.length ? dns.txt : ["(no TXT records)"]);
      findings.push(make({
        title: "No SPF record published",
        severity: "medium",
        confidence: "validated",
        category: "Email security",
        cwe: "CWE-290",
        owasp: "A07:2021 Identification and Authentication Failures",
        cvss: 5.3,
        asset,
        evidenceIds: [evId],
        description: "The domain publishes MX records but no `v=spf1` TXT record.",
        impact: "Receiving mail servers have no authorised-sender list, so mail can be spoofed from this domain for phishing.",
        remediation: "Publish an SPF record enumerating legitimate senders and ending in `-all`.",
        module: MODULE,
      }));
    }

    if (!email.dmarc) {
      const evId = store.addDnsRecord(MODULE, `_dmarc.${asset}`, "TXT", ["(no record returned)"]);
      findings.push(make({
        title: "No DMARC policy published",
        severity: "medium",
        confidence: "validated",
        category: "Email security",
        cwe: "CWE-290",
        owasp: "A07:2021 Identification and Authentication Failures",
        cvss: 5.3,
        asset,
        evidenceIds: [evId],
        description: "No TXT record was returned for `_dmarc`.",
        impact: "Without DMARC, SPF and DKIM failures are not acted on and spoofed mail is still delivered.",
        remediation: "Publish `v=DMARC1; p=quarantine; rua=mailto:...`, monitor the reports, then move to `p=reject`.",
        module: MODULE,
      }));
    } else if (/p\s*=\s*none/i.test(email.dmarc)) {
      const evId = store.addDnsRecord(MODULE, `_dmarc.${asset}`, "TXT", [email.dmarc]);
      findings.push(make({
        title: "DMARC policy is monitoring-only (p=none)",
        severity: "low",
        confidence: "validated",
        category: "Email security",
        cwe: "CWE-290",
        cvss: 3.7,
        asset,
        evidenceIds: [evId],
        description: email.dmarc,
        impact: "Failing mail is reported but still delivered, so the policy provides no active protection against spoofing.",
        remediation: "Move to `p=quarantine`, then `p=reject`, after confirming legitimate senders pass alignment.",
        module: MODULE,
      }));
    }
  }

  if (dns.caa.length === 0 && (dns.a.length > 0 || dns.aaaa.length > 0)) {
    const evId = store.addDnsRecord(MODULE, asset, "CAA", ["(no CAA records)"]);
    findings.push(make({
      title: "No CAA record restricting certificate issuance",
      severity: "low",
      confidence: "validated",
      category: "PKI",
      cwe: "CWE-295",
      cvss: 3.1,
      asset,
      evidenceIds: [evId],
      description: "No CAA records are published for this domain.",
      impact: "Any public certificate authority may issue a certificate for this name, widening the mis-issuance surface.",
      remediation: "Publish CAA records naming only the CAs you use, with an `iodef` contact for violation reports.",
      module: MODULE,
    }));
  }

  return findings;
}

// ---------------------------------------------------------------------------
// Technology / version disclosure feeding CVE correlation
// ---------------------------------------------------------------------------

export function analyzeOutdatedDisclosure(
  asset: string,
  tech: TechDetection[],
  store: EvidenceStore,
): Finding[] {
  const versioned = tech.filter((t) => t.version);
  if (versioned.length === 0) return [];

  const evId = store.add({
    module: "vuln.tech",
    source: `Technology fingerprint for ${asset}`,
    content: versioned.map((t) => `${t.name} ${t.version} (${t.evidenceSource}: ${t.evidenceValue})`).join("\n"),
    contentType: "text",
  });

  return [make({
    title: `Exact software versions are publicly disclosed (${versioned.length})`,
    severity: "low",
    confidence: "evidence-collected",
    category: "Information disclosure",
    cwe: "CWE-200",
    owasp: "A06:2021 Vulnerable and Outdated Components",
    cvss: 3.1,
    asset,
    evidenceIds: [evId],
    description: versioned.map((t) => `${t.name} ${t.version}`).join(", "),
    impact:
      "Precise version strings let an attacker select known exploits without sending probing traffic that might otherwise be detected.",
    remediation:
      "Suppress version banners, and keep these components patched — the disclosed versions are the input to the CVE correlation below.",
    module: "vuln.tech",
  })];
}
