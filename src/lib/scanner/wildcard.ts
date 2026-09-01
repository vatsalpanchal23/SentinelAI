/**
 * Wildcard DNS detection.
 *
 * Without this, a domain with a wildcard A record makes every brute-forced
 * label "resolve", producing a subdomain list that is entirely false positives.
 * Random labels are resolved first to establish a baseline; any candidate whose
 * answer set matches the baseline is discarded.
 */

import { resolveAddresses } from "./doh";

export type WildcardBaseline = {
  detected: boolean;
  /** Address sets observed for guaranteed-nonexistent labels. */
  addressSets: string[][];
  probesUsed: string[];
};

function randomLabel(): string {
  // 20 hex chars — collision with a real record is not a practical concern.
  const bytes = new Uint8Array(10);
  crypto.getRandomValues(bytes);
  return `sentinel-${Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("")}`;
}

export async function detectWildcard(apex: string, probes = 3): Promise<WildcardBaseline> {
  const probeHosts = Array.from({ length: probes }, () => `${randomLabel()}.${apex}`);
  const addressSets: string[][] = [];

  for (const host of probeHosts) {
    const addrs = await resolveAddresses(host);
    if (addrs.length > 0) addressSets.push([...addrs].sort());
  }

  return {
    detected: addressSets.length > 0,
    addressSets,
    probesUsed: probeHosts,
  };
}

/** True when this answer set is indistinguishable from the wildcard baseline. */
export function isWildcardAnswer(addresses: string[], baseline: WildcardBaseline): boolean {
  if (!baseline.detected || addresses.length === 0) return false;
  const key = [...addresses].sort().join(",");
  return baseline.addressSets.some((set) => set.join(",") === key);
}
