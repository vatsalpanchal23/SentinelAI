/**
 * IP parsing and private-range classification.
 *
 * Deliberately strict: an address that cannot be parsed with confidence is
 * treated as unsafe rather than allowed through.
 */

export type ParsedIp =
  | { version: 4; bytes: [number, number, number, number] }
  | { version: 6; words: number[] };

/**
 * Parse an IPv4 literal including the legacy forms `curl` and libc accept:
 * dotted-quad, dotted-octal (0177.0.0.1), dotted-hex (0x7f.0.0.1),
 * 32-bit decimal (2130706433), and hex (0x7f000001).
 * These are common SSRF filter bypasses.
 */
export function parseIpv4(input: string): ParsedIp | null {
  const s = input.trim();
  if (!/^[0-9a-fx.]+$/i.test(s)) return null;

  const parts = s.split(".");
  if (parts.length > 4 || parts.length === 0) return null;

  const nums: number[] = [];
  for (const p of parts) {
    if (p === "") return null;
    let n: number;
    if (/^0x[0-9a-f]+$/i.test(p)) n = parseInt(p.slice(2), 16);
    else if (/^0[0-7]+$/.test(p)) n = parseInt(p.slice(1), 8);
    else if (/^[0-9]+$/.test(p)) n = parseInt(p, 10);
    else return null;
    if (!Number.isFinite(n) || n < 0) return null;
    nums.push(n);
  }

  // Fewer than 4 parts: the final part fills the remaining bytes.
  const count = nums.length;
  const last = nums[count - 1]!;
  const maxLast = Math.pow(256, 4 - count + 1);
  if (last >= maxLast) return null;
  for (let i = 0; i < count - 1; i++) if (nums[i]! > 255) return null;

  let value = 0;
  for (let i = 0; i < count - 1; i++) value += nums[i]! * Math.pow(256, 3 - i);
  value += last;
  if (value > 0xffffffff) return null;

  return {
    version: 4,
    bytes: [
      (value >>> 24) & 0xff,
      (value >>> 16) & 0xff,
      (value >>> 8) & 0xff,
      value & 0xff,
    ],
  };
}

export function parseIpv6(input: string): ParsedIp | null {
  let s = input.trim().replace(/^\[|\]$/g, "");
  if (!s.includes(":")) return null;
  // Strip zone index.
  s = s.split("%")[0] ?? s;

  // Embedded IPv4 tail (::ffff:127.0.0.1).
  let tail: number[] = [];
  const v4match = s.match(/(\d+\.\d+\.\d+\.\d+)$/);
  if (v4match) {
    const v4 = parseIpv4(v4match[1]!);
    if (!v4 || v4.version !== 4) return null;
    tail = [
      (v4.bytes[0] << 8) | v4.bytes[1],
      (v4.bytes[2] << 8) | v4.bytes[3],
    ];
    s = s.slice(0, s.length - v4match[1]!.length).replace(/:$/, "") + ":";
    if (s.endsWith("::")) s = s.slice(0, -1);
  }

  const halves = s.split("::");
  if (halves.length > 2) return null;

  const toWords = (chunk: string): number[] | null => {
    if (!chunk) return [];
    const out: number[] = [];
    for (const g of chunk.split(":")) {
      if (g === "") continue;
      if (!/^[0-9a-f]{1,4}$/i.test(g)) return null;
      out.push(parseInt(g, 16));
    }
    return out;
  };

  const head = toWords(halves[0] ?? "");
  const rest = halves.length === 2 ? toWords(halves[1] ?? "") : null;
  if (head === null || (halves.length === 2 && rest === null)) return null;

  let words: number[];
  if (halves.length === 2) {
    const right = [...(rest ?? []), ...tail];
    const fill = 8 - head.length - right.length;
    if (fill < 0) return null;
    words = [...head, ...Array(fill).fill(0), ...right];
  } else {
    words = [...head, ...tail];
  }
  if (words.length !== 8) return null;
  return { version: 6, words };
}

export function parseIp(input: string): ParsedIp | null {
  return parseIpv6(input) ?? parseIpv4(input);
}

function inV4Cidr(bytes: number[], cidr: string): boolean {
  const [net, bitsRaw] = cidr.split("/");
  const parsed = parseIpv4(net!);
  if (!parsed || parsed.version !== 4) return false;
  const bits = parseInt(bitsRaw ?? "32", 10);
  const toInt = (b: number[]) =>
    ((b[0]! << 24) >>> 0) + (b[1]! << 16) + (b[2]! << 8) + b[3]!;
  const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
  return ((toInt(bytes) & mask) >>> 0) === ((toInt(parsed.bytes) & mask) >>> 0);
}

/** RFC1918 + loopback + link-local + CGNAT + reserved + multicast + broadcast. */
const BLOCKED_V4 = [
  "0.0.0.0/8",
  "10.0.0.0/8",
  "100.64.0.0/10",
  "127.0.0.0/8",
  "169.254.0.0/16",
  "172.16.0.0/12",
  "192.0.0.0/24",
  "192.0.2.0/24",
  "192.88.99.0/24",
  "192.168.0.0/16",
  "198.18.0.0/15",
  "198.51.100.0/24",
  "203.0.113.0/24",
  "224.0.0.0/4",
  "240.0.0.0/4",
  "255.255.255.255/32",
];

/**
 * Cloud instance metadata services. 169.254.169.254 is already covered by
 * link-local, these are the additional documented endpoints.
 */
export const METADATA_HOSTS = [
  "169.254.169.254", // AWS / Azure / GCP / DigitalOcean / OpenStack
  "169.254.170.2", // AWS ECS task metadata
  "100.100.100.200", // Alibaba Cloud
  "192.0.0.192", // Oracle Cloud
  "fd00:ec2::254", // AWS IMDSv6
];

export const METADATA_HOSTNAMES = [
  "metadata.google.internal",
  "metadata.goog",
  "instance-data",
  "metadata",
];

export function isPrivateIp(ip: ParsedIp): boolean {
  if (ip.version === 4) {
    return BLOCKED_V4.some((c) => inV4Cidr(ip.bytes, c));
  }
  const w = ip.words;
  // ::  and ::1
  if (w.every((x) => x === 0)) return true;
  if (w.slice(0, 7).every((x) => x === 0) && w[7] === 1) return true;
  // IPv4-mapped ::ffff:0:0/96 — classify by the embedded v4 address.
  if (w.slice(0, 5).every((x) => x === 0) && w[5] === 0xffff) {
    const bytes = [w[6]! >> 8, w[6]! & 0xff, w[7]! >> 8, w[7]! & 0xff];
    return BLOCKED_V4.some((c) => inV4Cidr(bytes, c));
  }
  // IPv4-compatible ::a.b.c.d
  if (w.slice(0, 6).every((x) => x === 0)) return true;
  const first = w[0]!;
  if ((first & 0xfe00) === 0xfc00) return true; // fc00::/7 unique-local
  if ((first & 0xffc0) === 0xfe80) return true; // fe80::/10 link-local
  if ((first & 0xff00) === 0xff00) return true; // ff00::/8 multicast
  if (first === 0x2001 && (w[1]! & 0xff00) === 0x0000) return true; // 2001::/32 Teredo
  if (first === 0x2002) return true; // 6to4
  return false;
}

export function formatIp(ip: ParsedIp): string {
  if (ip.version === 4) return ip.bytes.join(".");
  return ip.words.map((w) => w.toString(16)).join(":");
}

/** True when the string is any kind of IP literal (used to reject IP targets). */
export function isIpLiteral(host: string): boolean {
  return parseIp(host) !== null;
}
