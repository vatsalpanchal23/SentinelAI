/**
 * Technology fingerprinting.
 *
 * Every detection records which evidence source produced it. A version is only
 * reported when it was literally present in a banner or asset path — inferred
 * versions are never emitted, because CVE correlation downstream depends on
 * versions being trustworthy.
 */

import type { HttpProbe } from "./types";

export type TechDetection = {
  name: string;
  category:
    | "server"
    | "language"
    | "framework"
    | "cms"
    | "frontend"
    | "cdn"
    | "waf"
    | "analytics"
    | "library";
  /** Only set when observed verbatim. */
  version: string | null;
  /** e.g. "header:server", "body:meta-generator", "cookie:PHPSESSID". */
  evidenceSource: string;
  evidenceValue: string;
};

type HeaderRule = {
  name: string;
  category: TechDetection["category"];
  header: string;
  match: RegExp;
  /** Capture group 1 is treated as the version. */
  versionFrom?: RegExp;
};

const HEADER_RULES: HeaderRule[] = [
  { name: "nginx", category: "server", header: "server", match: /nginx/i, versionFrom: /nginx\/([\d.]+)/i },
  { name: "Apache HTTP Server", category: "server", header: "server", match: /apache/i, versionFrom: /apache\/([\d.]+)/i },
  { name: "Microsoft IIS", category: "server", header: "server", match: /iis/i, versionFrom: /iis\/([\d.]+)/i },
  { name: "LiteSpeed", category: "server", header: "server", match: /litespeed/i },
  { name: "Caddy", category: "server", header: "server", match: /caddy/i },
  { name: "Cloudflare", category: "cdn", header: "server", match: /cloudflare/i },
  { name: "Vercel", category: "cdn", header: "server", match: /vercel/i },
  { name: "Netlify", category: "cdn", header: "server", match: /netlify/i },
  { name: "Amazon S3", category: "cdn", header: "server", match: /amazons3/i },
  { name: "AWS Elastic Load Balancer", category: "cdn", header: "server", match: /awselb/i },
  { name: "Google Frontend", category: "cdn", header: "server", match: /gws|google frontend/i },
  { name: "PHP", category: "language", header: "x-powered-by", match: /php/i, versionFrom: /php\/([\d.]+)/i },
  { name: "ASP.NET", category: "framework", header: "x-powered-by", match: /asp\.net/i },
  { name: "Express", category: "framework", header: "x-powered-by", match: /express/i },
  { name: "Next.js", category: "framework", header: "x-powered-by", match: /next\.js/i },
  { name: "Phusion Passenger", category: "server", header: "x-powered-by", match: /phusion passenger/i },
  { name: "WordPress", category: "cms", header: "link", match: /wp-json/i },
  { name: "Drupal", category: "cms", header: "x-generator", match: /drupal/i, versionFrom: /drupal\s*([\d.]+)/i },
  { name: "Shopify", category: "cms", header: "x-shopify-stage", match: /.+/ },
  { name: "Varnish", category: "cdn", header: "via", match: /varnish/i },
  { name: "Fastly", category: "cdn", header: "x-served-by", match: /cache-/i },
  { name: "Akamai", category: "cdn", header: "x-akamai-transformed", match: /.+/ },
  { name: "Sucuri WAF", category: "waf", header: "x-sucuri-id", match: /.+/ },
  { name: "Imperva/Incapsula WAF", category: "waf", header: "x-iinfo", match: /.+/ },
  { name: "AWS WAF", category: "waf", header: "x-amzn-waf-action", match: /.+/ },
];

type BodyRule = {
  name: string;
  category: TechDetection["category"];
  match: RegExp;
  versionFrom?: RegExp;
  label: string;
};

const BODY_RULES: BodyRule[] = [
  { name: "WordPress", category: "cms", match: /\/wp-content\/|\/wp-includes\//i, label: "body:wp-paths" },
  { name: "Drupal", category: "cms", match: /\/sites\/(all|default)\/(files|modules|themes)\//i, label: "body:drupal-paths" },
  { name: "Joomla", category: "cms", match: /\/media\/jui\/|joomla/i, label: "body:joomla" },
  { name: "React", category: "frontend", match: /data-reactroot|__REACT_DEVTOOLS|react(-dom)?[.@-][\d.]+/i, label: "body:react" },
  { name: "Vue.js", category: "frontend", match: /data-v-[0-9a-f]{8}|__VUE__|vue(\.runtime)?[.@-][\d.]+/i, label: "body:vue" },
  { name: "Angular", category: "frontend", match: /ng-version="([\d.]+)"|_nghost-/i, versionFrom: /ng-version="([\d.]+)"/i, label: "body:angular" },
  { name: "Svelte", category: "frontend", match: /svelte-[a-z0-9]{6}/i, label: "body:svelte" },
  { name: "jQuery", category: "library", match: /jquery[.-]([\d.]+)(\.min)?\.js/i, versionFrom: /jquery[.-]([\d.]+)/i, label: "body:jquery" },
  { name: "Bootstrap", category: "library", match: /bootstrap[.-]([\d.]+)?(\.min)?\.(js|css)/i, versionFrom: /bootstrap[.-]([\d.]+)/i, label: "body:bootstrap" },
  { name: "Google Analytics", category: "analytics", match: /googletagmanager\.com\/gtag|google-analytics\.com\/analytics\.js/i, label: "body:ga" },
  { name: "Next.js", category: "framework", match: /\/_next\/static\//i, label: "body:next-static" },
  { name: "Nuxt", category: "framework", match: /\/_nuxt\//i, label: "body:nuxt" },
  { name: "Laravel", category: "framework", match: /laravel_session|csrf-token/i, label: "body:laravel" },
];

const COOKIE_RULES: { name: string; category: TechDetection["category"]; match: RegExp }[] = [
  { name: "PHP", category: "language", match: /^PHPSESSID=/i },
  { name: "Java", category: "language", match: /^JSESSIONID=/i },
  { name: "ASP.NET", category: "framework", match: /^ASP\.NET_SessionId=/i },
  { name: "Laravel", category: "framework", match: /^laravel_session=/i },
  { name: "Django", category: "framework", match: /^(csrftoken|sessionid)=/i },
  { name: "Ruby on Rails", category: "framework", match: /^_[a-z0-9_]+_session=/i },
  { name: "Express", category: "framework", match: /^connect\.sid=/i },
];

export function fingerprint(probe: HttpProbe | null): TechDetection[] {
  if (!probe) return [];
  const out = new Map<string, TechDetection>();

  const push = (d: TechDetection) => {
    const existing = out.get(d.name);
    // Prefer a detection that carries a real version.
    if (!existing || (!existing.version && d.version)) out.set(d.name, d);
  };

  for (const rule of HEADER_RULES) {
    const value = probe.headers[rule.header];
    if (!value || !rule.match.test(value)) continue;
    const version = rule.versionFrom ? (value.match(rule.versionFrom)?.[1] ?? null) : null;
    push({
      name: rule.name,
      category: rule.category,
      version,
      evidenceSource: `header:${rule.header}`,
      evidenceValue: `${rule.header}: ${value}`,
    });
  }

  if (probe.headers["cf-ray"]) {
    push({
      name: "Cloudflare",
      category: "cdn",
      version: null,
      evidenceSource: "header:cf-ray",
      evidenceValue: `cf-ray: ${probe.headers["cf-ray"]}`,
    });
  }

  const body = probe.body ?? "";
  if (body) {
    for (const rule of BODY_RULES) {
      const m = body.match(rule.match);
      if (!m) continue;
      const version = rule.versionFrom ? (body.match(rule.versionFrom)?.[1] ?? null) : null;
      push({
        name: rule.name,
        category: rule.category,
        version,
        evidenceSource: rule.label,
        evidenceValue: m[0].slice(0, 200),
      });
    }

    const generator = body.match(/<meta[^>]+name=["']generator["'][^>]+content=["']([^"']+)["']/i);
    if (generator?.[1]) {
      const content = generator[1];
      const versionMatch = content.match(/([\d]+\.[\d.]+)/);
      push({
        name: content.replace(/\s*[\d.]+\s*$/, "").trim() || content,
        category: "cms",
        version: versionMatch?.[1] ?? null,
        evidenceSource: "body:meta-generator",
        evidenceValue: `<meta name="generator" content="${content}">`,
      });
    }
  }

  for (const cookie of probe.setCookies) {
    for (const rule of COOKIE_RULES) {
      if (rule.match.test(cookie)) {
        push({
          name: rule.name,
          category: rule.category,
          version: null,
          evidenceSource: "cookie",
          evidenceValue: cookie.split(";")[0] ?? cookie,
        });
      }
    }
  }

  return [...out.values()].sort((a, b) => a.name.localeCompare(b.name));
}
