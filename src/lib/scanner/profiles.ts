/**
 * Scan profiles.
 *
 * Each profile is a real, honest description of what the scanner will actually
 * do. Modules that would need the self-hosted worker (Nmap, Amass, active
 * brute-force enumeration) are only enabled when a worker is configured; the
 * profile record still reports them as declared so the UI can show honestly
 * whether they were skipped.
 */

import type { ScanProfile } from "./types";

export const PROFILES: Record<string, ScanProfile> = {
  passive: {
    key: "passive",
    label: "Passive reconnaissance",
    description:
      "Read-only intelligence: DNS, Certificate Transparency, DoH lookups, and a single HTTPS probe of the target. Sends no traffic to subdomains or paths.",
    modules: ["dns", "ct", "wildcard", "http.probe", "tech", "vuln.headers", "vuln.transport", "vuln.dns"],
    crawlMaxDepth: 0,
    crawlMaxPages: 0,
    crawlConcurrency: 1,
    subdomainProbeLimit: 0,
    activeDnsEnumeration: false,
    activeVulnChecks: false,
    portScan: false,
  },
  quick: {
    key: "quick",
    label: "Quick assessment",
    description:
      "Passive reconnaissance plus a shallow crawl of the target origin and a small path probe list. Suitable for a first look.",
    modules: [
      "dns", "ct", "wildcard", "http.probe", "tech", "crawl", "endpoints", "js",
      "vuln.headers", "vuln.transport", "vuln.cookies", "vuln.dns", "vuln.exposure", "vuln.cors", "vuln.tech", "cve",
    ],
    crawlMaxDepth: 1,
    crawlMaxPages: 40,
    crawlConcurrency: 4,
    subdomainProbeLimit: 25,
    activeDnsEnumeration: false,
    activeVulnChecks: false,
    portScan: false,
  },
  standard: {
    key: "standard",
    label: "Standard assessment",
    description:
      "Quick assessment plus deeper crawl, larger endpoint wordlist, API discovery, subdomain enumeration and CVE correlation.",
    modules: [
      "dns", "ct", "wildcard", "http.probe", "tech", "crawl", "endpoints", "js", "api",
      "vuln.headers", "vuln.transport", "vuln.cookies", "vuln.dns", "vuln.exposure", "vuln.cors", "vuln.tech", "cve",
    ],
    crawlMaxDepth: 2,
    crawlMaxPages: 120,
    crawlConcurrency: 6,
    subdomainProbeLimit: 80,
    activeDnsEnumeration: true,
    activeVulnChecks: false,
    portScan: true,
  },
  deep: {
    key: "deep",
    label: "Deep assessment",
    description:
      "Full crawl, extensive endpoint probing, active DNS enumeration, port scan via the worker, and safe non-destructive vulnerability validation.",
    modules: [
      "dns", "ct", "wildcard", "http.probe", "tech", "crawl", "endpoints", "js", "api", "ports",
      "vuln.headers", "vuln.transport", "vuln.cookies", "vuln.dns", "vuln.exposure", "vuln.cors", "vuln.tech", "cve",
    ],
    crawlMaxDepth: 3,
    crawlMaxPages: 300,
    crawlConcurrency: 8,
    subdomainProbeLimit: 200,
    activeDnsEnumeration: true,
    activeVulnChecks: true,
    portScan: true,
  },
};

export const DEFAULT_PROFILE = PROFILES['quick']!;

export function getProfile(key: string): ScanProfile {
  return PROFILES[key] ?? DEFAULT_PROFILE;
}

export const MODULE_LABELS: Record<string, string> = {
  dns: "DNS records",
  ct: "Certificate Transparency",
  wildcard: "Wildcard DNS detection",
  "http.probe": "HTTP probe",
  tech: "Technology fingerprinting",
  crawl: "Web crawl",
  endpoints: "Endpoint discovery",
  js: "JavaScript analysis",
  api: "API discovery",
  ports: "Port and service discovery",
  "vuln.headers": "Security headers",
  "vuln.transport": "Transport security",
  "vuln.cookies": "Cookie attributes",
  "vuln.dns": "DNS & email posture",
  "vuln.exposure": "Exposed paths & information disclosure",
  "vuln.cors": "CORS policy",
  "vuln.tech": "Version disclosure",
  cve: "CVE correlation",
};
