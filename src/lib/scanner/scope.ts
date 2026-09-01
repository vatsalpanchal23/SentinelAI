/**
 * Scope enforcement.
 *
 * Nothing is scanned unless it passes these checks. Hosts discovered during
 * reconnaissance (certificate transparency, crawling, JavaScript analysis)
 * are funnelled through `isInScope` before any request is made to them.
 */

import type { ScopeRules } from "./types";
import { isIpLiteral, parseIp, METADATA_HOSTNAMES } from "./ip";

export function normalizeHostname(input: string): string {
  let t = input.trim().toLowerCase();
  t = t.replace(/^[a-z]+:\/\//, "");
  t = t.replace(/^[^@/]*@/, ""); // strip userinfo (SSRF bypass vector)
  t = t.split("/")[0] ?? t;
  t = t.split("?")[0] ?? t;
  t = t.split("#")[0] ?? t;
  // Strip port, but keep IPv6 brackets intact.
  if (!t.startsWith("[")) t = t.replace(/:\d+$/, "");
  t = t.replace(/\.$/, ""); // trailing root dot
  return t;
}

export function isValidHostname(host: string): boolean {
  if (host.length === 0 || host.length > 253) return false;
  if (isIpLiteral(host)) return true;
  return /^(?!-)[a-z0-9_-]{1,63}(\.(?!-)[a-z0-9_-]{1,63})+$/.test(host);
}


/** Registrable-ish parent used for default scope: last two labels. */
export function apexOf(host: string): string {
  const parts = host.split(".");
  return parts.length <= 2 ? host : parts.slice(-2).join(".");
}

function matchesPattern(host: string, pattern: string): boolean {
  const p = pattern.trim().toLowerCase().replace(/\.$/, "");
  if (!p) return false;
  if (p.startsWith("*.")) {
    const suffix = p.slice(1); // ".example.com"
    return host.endsWith(suffix) && host.length > suffix.length;
  }
  return host === p;
}

export type ScopeVerdict = {
  allowed: boolean;
  reason: string;
};

/**
 * Decide whether a hostname may be contacted.
 *
 * Order matters: exclusions beat allowances, and metadata hostnames are
 * refused regardless of configuration unless private targets are explicitly
 * enabled for a controlled lab.
 */
export function isInScope(host: string, scope: ScopeRules): ScopeVerdict {
  const h = normalizeHostname(host);

  if (!h) return { allowed: false, reason: "Empty hostname" };

  if (METADATA_HOSTNAMES.includes(h) && !scope.allowPrivateTargets) {
    return { allowed: false, reason: "Cloud metadata hostname is refused" };
  }

  if (scope.excludedHosts.some((p) => matchesPattern(h, p))) {
    return { allowed: false, reason: "Host is explicitly excluded from scope" };
  }

  if (isIpLiteral(h)) {
    const permitted = scope.allowedIps.some((entry) => entry.trim() === h);
    if (!permitted) {
      return { allowed: false, reason: "IP literal is not in the allowed IP list" };
    }
    const ip = parseIp(h);
    if (ip && !scope.allowPrivateTargets) {
      return { allowed: true, reason: "Explicitly allowed IP" };
    }
    return { allowed: true, reason: "Explicitly allowed IP (lab mode)" };
  }

  if (!isValidHostname(h)) {
    return { allowed: false, reason: "Not a syntactically valid hostname" };
  }

  if (scope.allowedDomains.some((p) => matchesPattern(h, p))) {
    return { allowed: true, reason: "Matches an allowed domain rule" };
  }

  return {
    allowed: false,
    reason: "Outside the declared assessment scope",
  };
}

/**
 * Build the default scope for a freshly entered target: the target itself
 * plus its subdomains. Nothing else is ever implied.
 */
export function defaultScopeFor(target: string): ScopeRules {
  const t = normalizeHostname(target);
  return {
    target: t,
    allowedDomains: [t, `*.${t}`],
    allowedIps: [],
    excludedHosts: [],
    allowPrivateTargets: false,
  };
}

/** Partition a discovered host list into in-scope and rejected, with reasons. */
export function partitionByScope(hosts: string[], scope: ScopeRules) {
  const inScope: string[] = [];
  const rejected: { host: string; reason: string }[] = [];
  for (const raw of hosts) {
    const h = normalizeHostname(raw);
    const verdict = isInScope(h, scope);
    if (verdict.allowed) {
      if (!inScope.includes(h)) inScope.push(h);
    } else {
      rejected.push({ host: h, reason: verdict.reason });
    }
  }
  return { inScope, rejected };
}
