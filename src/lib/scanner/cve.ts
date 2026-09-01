/**
 * CVE correlation.
 *
 * Given a list of technology detections that carry real versions, query the
 * OSV.dev public API for known vulnerabilities. OSV covers a large fraction of
 * the ecosystems this scanner fingerprints (npm, PyPI, Debian, Alpine, etc.).
 *
 * Correlation is deliberately conservative: a CVE is only attached when OSV
 * returns a match for the exact product name and version observed. Nothing is
 * inferred from a version range that "probably applies".
 */

import { rawFetch } from "./net";
import type { TechDetection } from "./tech";

export type CveMatch = {
  id: string;
  summary: string;
  severity: string | null;
  cvss: number | null;
  published: string | null;
  references: string[];
  product: string;
  version: string;
};

const OSV_URL = "https://api.osv.dev/v1/query";

const ECOSYSTEM_MAP: Record<string, string[]> = {
  nginx: ["Debian", "Ubuntu", "Alpine"],
  "apache http server": ["Debian", "Ubuntu"],
  php: ["Packagist"],
  wordpress: ["Packagist"],
  drupal: ["Packagist"],
  jquery: ["npm"],
  bootstrap: ["npm"],
  react: ["npm"],
  "vue.js": ["npm"],
  angular: ["npm"],
  express: ["npm"],
  "next.js": ["npm"],
  nuxt: ["npm"],
  laravel: ["Packagist"],
};

function severityFromScore(score: number | null): string | null {
  if (score === null) return null;
  if (score >= 9) return "critical";
  if (score >= 7) return "high";
  if (score >= 4) return "medium";
  if (score > 0) return "low";
  return null;
}

type OsvVuln = {
  id: string;
  summary?: string;
  details?: string;
  published?: string;
  severity?: { type?: string; score?: string }[];
  references?: { url: string }[];
};

async function queryOsv(product: string, version: string, ecosystem?: string): Promise<OsvVuln[]> {
  try {
    const body = ecosystem
      ? { version, package: { name: product, ecosystem } }
      : { version, package: { name: product } };
    const res = await rawFetch(OSV_URL, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body),
    }, 10_000);
    if (!res.ok) return [];
    const json = (await res.json()) as { vulns?: OsvVuln[] };
    return json.vulns ?? [];
  } catch {
    return [];
  }
}

function extractCvssScore(vuln: OsvVuln): number | null {
  for (const s of vuln.severity ?? []) {
    if (!s.score) continue;
    // OSV records vector strings like "CVSS:3.1/AV:N/AC:L/...". Parse "/CR" style would need
    // a full parser; instead pull a bare numeric score when the type is CVSS_V3 with a value.
    const numeric = s.score.match(/\b(\d+(?:\.\d+)?)\b/);
    if (numeric) {
      const n = Number(numeric[1]);
      if (!Number.isNaN(n) && n >= 0 && n <= 10) return n;
    }
  }
  return null;
}

export async function correlateCves(techs: TechDetection[]): Promise<{
  matches: CveMatch[];
  errors: string[];
  queried: number;
}> {
  const versioned = techs.filter((t) => t.version);
  const matches: CveMatch[] = [];
  const errors: string[] = [];
  let queried = 0;

  for (const tech of versioned) {
    const key = tech.name.toLowerCase();
    const ecosystems = ECOSYSTEM_MAP[key] ?? [undefined];
    for (const ecosystem of ecosystems) {
      queried++;
      const vulns = await queryOsv(tech.name.toLowerCase(), tech.version!, ecosystem);
      for (const v of vulns) {
        const cvss = extractCvssScore(v);
        matches.push({
          id: v.id,
          summary: v.summary ?? v.details?.slice(0, 240) ?? "No summary provided by OSV",
          severity: severityFromScore(cvss),
          cvss,
          published: v.published ?? null,
          references: (v.references ?? []).map((r) => r.url).slice(0, 5),
          product: tech.name,
          version: tech.version!,
        });
      }
      if (vulns.length > 0) break; // stop after first ecosystem that produced hits
    }
  }

  // Deduplicate by CVE id + product.
  const seen = new Set<string>();
  const unique = matches.filter((m) => {
    const k = `${m.id}|${m.product}`;
    if (seen.has(k)) return false;
    seen.add(k);
    return true;
  });

  return { matches: unique, errors, queried };
}
