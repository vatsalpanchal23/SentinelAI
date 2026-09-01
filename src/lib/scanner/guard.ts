/**
 * SSRF guard.
 *
 * The check is deliberately not "does the hostname look public". A hostname is
 * resolved, every resolved address is classified, and the decision is made on
 * the addresses. Redirect targets are re-validated from scratch on every hop.
 *
 * Known residual risk, stated plainly: the Workers runtime does not expose an
 * API to pin a connection to an already-resolved IP, so there is a small
 * window between our resolution and the runtime's own resolution in which a
 * hostile authoritative nameserver could return a different answer (classic
 * DNS rebinding). Two things reduce it to an acceptable level here:
 *
 *   1. The Workers sandbox has no route to RFC1918 / loopback space at all,
 *      so a rebind to a private address fails to connect rather than
 *      succeeding against an internal service.
 *   2. Every redirect hop is re-resolved and re-validated, and responses from
 *      hosts that fail validation are discarded rather than parsed.
 *
 * When SentinelAI is deployed to the self-hosted scanner worker (which does
 * sit on a real network), the worker performs the same validation *and* pins
 * the socket to the validated address.
 */

import { parseIp, isPrivateIp, isIpLiteral, METADATA_HOSTS, METADATA_HOSTNAMES } from "./ip";
import { resolveAddresses } from "./doh";
import { isInScope, normalizeHostname } from "./scope";
import type { ScopeRules } from "./types";

export type GuardVerdict = {
  allowed: boolean;
  reason: string;
  hostname: string;
  resolvedIps: string[];
};

export type GuardOptions = {
  scope: ScopeRules;
  /** Skip the scope check — used for target-independent trusted endpoints. */
  skipScope?: boolean;
};

const ALLOWED_PROTOCOLS = new Set(["http:", "https:"]);

/**
 * Validate a URL end to end: protocol, hostname shape, scope, DNS resolution,
 * and the classification of every resolved address.
 */
export async function validateUrl(url: string, opts: GuardOptions): Promise<GuardVerdict> {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    return { allowed: false, reason: "Malformed URL", hostname: "", resolvedIps: [] };
  }

  if (!ALLOWED_PROTOCOLS.has(parsed.protocol)) {
    return {
      allowed: false,
      reason: `Protocol ${parsed.protocol} is not permitted (only http and https)`,
      hostname: parsed.hostname,
      resolvedIps: [],
    };
  }

  if (parsed.username || parsed.password) {
    return {
      allowed: false,
      reason: "URLs carrying credentials are refused",
      hostname: parsed.hostname,
      resolvedIps: [],
    };
  }

  const hostname = normalizeHostname(parsed.hostname);

  if (METADATA_HOSTNAMES.includes(hostname)) {
    return {
      allowed: false,
      reason: "Cloud metadata hostname",
      hostname,
      resolvedIps: [],
    };
  }

  if (!opts.skipScope) {
    const verdict = isInScope(hostname, opts.scope);
    if (!verdict.allowed) {
      return { allowed: false, reason: verdict.reason, hostname, resolvedIps: [] };
    }
  }

  // Direct IP literal — classify without DNS.
  if (isIpLiteral(hostname)) {
    if (METADATA_HOSTS.includes(hostname)) {
      return { allowed: false, reason: "Cloud metadata address", hostname, resolvedIps: [hostname] };
    }
    const ip = parseIp(hostname);
    if (!ip) {
      return { allowed: false, reason: "Unparseable IP literal", hostname, resolvedIps: [] };
    }
    if (isPrivateIp(ip) && !opts.scope.allowPrivateTargets) {
      return {
        allowed: false,
        reason: "Address is in a private, loopback, link-local or reserved range",
        hostname,
        resolvedIps: [hostname],
      };
    }
    return { allowed: true, reason: "Validated IP literal", hostname, resolvedIps: [hostname] };
  }

  // Hostname — resolve, then classify every answer.
  const addresses = await resolveAddresses(hostname);
  if (addresses.length === 0) {
    return {
      allowed: false,
      reason: "Hostname does not resolve to any address",
      hostname,
      resolvedIps: [],
    };
  }

  for (const addr of addresses) {
    if (METADATA_HOSTS.includes(addr)) {
      return {
        allowed: false,
        reason: `Resolves to cloud metadata address ${addr}`,
        hostname,
        resolvedIps: addresses,
      };
    }
    const ip = parseIp(addr);
    if (!ip) {
      return {
        allowed: false,
        reason: `Resolved address ${addr} could not be parsed`,
        hostname,
        resolvedIps: addresses,
      };
    }
    if (isPrivateIp(ip) && !opts.scope.allowPrivateTargets) {
      return {
        allowed: false,
        reason: `Resolves to non-public address ${addr}`,
        hostname,
        resolvedIps: addresses,
      };
    }
  }

  return {
    allowed: true,
    reason: "All resolved addresses are public and in scope",
    hostname,
    resolvedIps: addresses,
  };
}

export class BlockedRequestError extends Error {
  readonly verdict: GuardVerdict;
  constructor(verdict: GuardVerdict) {
    super(`Blocked request to ${verdict.hostname || "unknown host"}: ${verdict.reason}`);
    this.name = "BlockedRequestError";
    this.verdict = verdict;
  }
}
