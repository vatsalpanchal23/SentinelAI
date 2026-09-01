/**
 * Certificate Transparency discovery.
 *
 * Two independent log aggregators are queried. Results from both are merged,
 * and the module reports which sources actually answered so the report can
 * state honestly whether CT coverage was complete or partial.
 */

import { rawFetch } from "./net";

export type CtResult = {
  names: string[];
  wildcards: string[];
  sourcesQueried: string[];
  sourcesSucceeded: string[];
  errors: string[];
};

function collect(raw: string, apex: string, names: Set<string>, wildcards: Set<string>) {
  for (const piece of raw.split(/[\n,]/)) {
    const n = piece.trim().toLowerCase().replace(/\.$/, "");
    if (!n) continue;
    if (n.startsWith("*.")) {
      const base = n.slice(2);
      if (base === apex || base.endsWith(`.${apex}`)) wildcards.add(n);
      continue;
    }
    if (n === apex || n.endsWith(`.${apex}`)) names.add(n);
  }
}

export async function certTransparency(apex: string): Promise<CtResult> {
  const names = new Set<string>();
  const wildcards = new Set<string>();
  const errors: string[] = [];
  const sourcesQueried: string[] = [];
  const sourcesSucceeded: string[] = [];

  // Source 1 — Cert Spotter.
  sourcesQueried.push("certspotter");
  try {
    const res = await rawFetch(
      `https://api.certspotter.com/v1/issuances?domain=${encodeURIComponent(apex)}&include_subdomains=true&expand=dns_names`,
      { headers: { accept: "application/json" } },
      20000,
    );
    if (res.ok) {
      const rows = (await res.json()) as { dns_names?: string[] }[];
      for (const row of rows) for (const n of row.dns_names ?? []) collect(n, apex, names, wildcards);
      sourcesSucceeded.push("certspotter");
    } else if (res.status === 429) {
      errors.push("Cert Spotter rate limit reached — partial CT coverage");
    } else {
      errors.push(`Cert Spotter returned HTTP ${res.status}`);
    }
  } catch (err) {
    errors.push(`Cert Spotter unavailable — ${err instanceof Error ? err.message : String(err)}`);
  }

  // Source 2 — crt.sh.
  sourcesQueried.push("crt.sh");
  try {
    const res = await rawFetch(
      `https://crt.sh/?q=%25.${encodeURIComponent(apex)}&output=json`,
      { headers: { accept: "application/json" } },
      25000,
    );
    if (res.ok) {
      const text = await res.text();
      const rows = JSON.parse(text) as { name_value?: string; common_name?: string }[];
      for (const row of rows) {
        if (row.name_value) collect(row.name_value, apex, names, wildcards);
        if (row.common_name) collect(row.common_name, apex, names, wildcards);
      }
      sourcesSucceeded.push("crt.sh");
    } else {
      errors.push(`crt.sh returned HTTP ${res.status}`);
    }
  } catch (err) {
    errors.push(`crt.sh unavailable — ${err instanceof Error ? err.message : String(err)}`);
  }

  if (sourcesSucceeded.length === 0) {
    errors.push("Tool unavailable — no Certificate Transparency source responded");
  }

  return {
    names: [...names].sort(),
    wildcards: [...wildcards].sort(),
    sourcesQueried,
    sourcesSucceeded,
    errors,
  };
}
