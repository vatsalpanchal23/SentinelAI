/**
 * DNS resolution over HTTPS.
 *
 * Cloudflare Workers has no UDP socket API, so DNS-over-HTTPS is the only
 * available resolver. Two independent providers are used so a single provider
 * outage does not silently produce an empty (and therefore misleading) result.
 */

import { rawFetch, LIMITS } from "./net";
import type { DnsRecords } from "./types";

const PROVIDERS = [
  { name: "cloudflare", url: "https://cloudflare-dns.com/dns-query" },
  { name: "google", url: "https://dns.google/resolve" },
] as const;

export type DohAnswer = { name: string; type: number; data: string; ttl: number };

export type DohResult = {
  answers: DohAnswer[];
  /** DNS RCODE. 0 = NOERROR, 3 = NXDOMAIN. null when no provider responded. */
  status: number | null;
  provider: string | null;
  error: string | null;
};

const TYPE_NUMBERS: Record<string, number> = {
  A: 1,
  NS: 2,
  CNAME: 5,
  SOA: 6,
  MX: 15,
  TXT: 16,
  AAAA: 28,
  CAA: 257,
};

/** Query one record type. Tries providers in order until one answers. */
export async function dohQuery(name: string, type: string): Promise<DohResult> {
  let lastError = "no provider attempted";

  for (const provider of PROVIDERS) {
    try {
      const res = await rawFetch(
        `${provider.url}?name=${encodeURIComponent(name)}&type=${encodeURIComponent(type)}`,
        { headers: { accept: "application/dns-json" } },
        6000,
      );
      if (!res.ok) {
        lastError = `${provider.name} returned HTTP ${res.status}`;
        continue;
      }
      const json = (await res.json()) as {
        Status?: number;
        Answer?: { name: string; type: number; data: string; TTL?: number }[];
      };
      const answers = (json.Answer ?? [])
        .filter((a) => a.type === TYPE_NUMBERS[type])
        .map((a) => ({
          name: a.name,
          type: a.type,
          data: a.data.replace(/^"|"$/g, "").replace(/"\s+"/g, ""),
          ttl: a.TTL ?? 0,
        }));
      return {
        answers,
        status: json.Status ?? 0,
        provider: provider.name,
        error: null,
      };
    } catch (err) {
      lastError = `${provider.name}: ${err instanceof Error ? err.message : String(err)}`;
    }
  }

  return { answers: [], status: null, provider: null, error: lastError };
}

async function dataOf(name: string, type: string): Promise<string[]> {
  const r = await dohQuery(name, type);
  return r.answers.map((a) => a.data);
}

export async function resolveAll(host: string): Promise<{
  records: DnsRecords;
  errors: string[];
}> {
  const errors: string[] = [];
  const types = ["A", "AAAA", "CNAME", "MX", "NS", "TXT", "CAA", "SOA"] as const;

  const results = await Promise.all(
    types.map(async (t) => {
      const r = await dohQuery(host, t);
      if (r.error) errors.push(`${t} lookup failed — ${r.error}`);
      return [t, r.answers.map((a) => a.data)] as const;
    }),
  );

  const map = Object.fromEntries(results) as Record<(typeof types)[number], string[]>;

  return {
    records: {
      a: map.A ?? [],
      aaaa: map.AAAA ?? [],
      cname: map.CNAME ?? [],
      mx: map.MX ?? [],
      ns: map.NS ?? [],
      txt: map.TXT ?? [],
      caa: map.CAA ?? [],
      soa: map.SOA ?? [],
    },
    errors,
  };
}

/** All A and AAAA addresses for a host, following CNAMEs the resolver returns. */
export async function resolveAddresses(host: string): Promise<string[]> {
  const [a, aaaa] = await Promise.all([dataOf(host, "A"), dataOf(host, "AAAA")]);
  return [...a, ...aaaa].filter((x) => /^[0-9a-f.:]+$/i.test(x));
}

/** True when the host resolves to anything at all. */
export async function hostResolves(host: string): Promise<boolean> {
  const addrs = await resolveAddresses(host);
  return addrs.length > 0;
}

export { LIMITS };
