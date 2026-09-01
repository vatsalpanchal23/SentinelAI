/**
 * Scan engine — orchestration.
 *
 * Runs the modules a profile declares against a target, honouring the scope
 * rules end to end. Every module records its own timing, item counts and
 * errors, so the UI and the report can show honestly what actually ran, what
 * was skipped, and why.
 */

import type {
  Finding, HostAsset, ModuleRun, ScanLogEntry, ScanProfile, ScopeRules, DnsRecords, HttpProbe,
} from "./types";
import { EvidenceStore } from "./evidence";
import { resolveAll } from "./doh";
import { certTransparency } from "./ct";
import { detectWildcard, isWildcardAnswer } from "./wildcard";
import { probeHost, guardedFetch, extractTitle, toHttpProbe } from "./http";
import { BlockedRequestError } from "./guard";
import { fingerprint, type TechDetection } from "./tech";
import { crawl, type CrawlResult } from "./crawler";
import { analyzeScripts, type JsAnalysisResult } from "./jsanalysis";
import {
  baselineNotFound, probePaths, extractParameters, discoverApis, COMMON_PATHS,
  type DiscoveredEndpoint, type DiscoveredParameter, type ApiInventoryEntry,
} from "./endpoints";
import {
  analyzeSecurityHeaders, analyzeCookies, analyzeTransport, analyzeCors,
  analyzeExposedPaths, analyzeDnsPosture, analyzeOutdatedDisclosure, resetFindingIds,
  type CorsProbeResult,
} from "./vuln";
import { correlateCves, type CveMatch } from "./cve";
import { workerPortScan, workerEnumSubdomains } from "./worker";
import { partitionByScope, defaultScopeFor, normalizeHostname, apexOf } from "./scope";
import { resolveAddresses } from "./doh";
import { buildAttackPaths, type AttackPath } from "./attackpaths";
import { buildFindingGuidance } from "./guidance";

export type EngineOptions = {
  target: string;
  profile: ScanProfile;
  scope: ScopeRules;
  /** Signed authorization confirmation. */
  authorization: { confirmed: true; principal: string; at: string };
  onLog?: (entry: ScanLogEntry) => void;
  onModule?: (m: ModuleRun) => void;
  signal?: AbortSignal;
};

export type EngineResult = {
  target: string;
  profile: string;
  startedAt: string;
  finishedAt: string;
  durationMs: number;
  scope: ScopeRules;
  authorization: EngineOptions["authorization"];
  modules: ModuleRun[];
  dns: DnsRecords | null;
  hosts: HostAsset[];
  wildcardDetected: boolean;
  crawl: CrawlResult | null;
  scripts: JsAnalysisResult | null;
  endpoints: DiscoveredEndpoint[];
  parameters: DiscoveredParameter[];
  apis: ApiInventoryEntry[];
  technologies: TechDetection[];
  cveMatches: CveMatch[];
  findings: Finding[];
  attackPaths: AttackPath[];
  evidence: ReturnType<EvidenceStore["all"]>;
  logs: ScanLogEntry[];
  ports: {
    available: boolean;
    reason?: string;
    open: { host: string; port: number; protocol: string; service: string | null; banner: string | null }[];
  };
  subdomainSources: string[];
};

class Recorder {
  private modules = new Map<string, ModuleRun>();
  logs: ScanLogEntry[] = [];
  private onLog: ((entry: ScanLogEntry) => void) | undefined;
  private onModule: ((m: ModuleRun) => void) | undefined;
  constructor(hooks: { onLog?: ((e: ScanLogEntry) => void) | undefined; onModule?: ((m: ModuleRun) => void) | undefined }) {
    this.onLog = hooks.onLog;
    this.onModule = hooks.onModule;
  }
  register(key: string, label: string): ModuleRun {
    const run: ModuleRun = {
      key, label, status: "pending",
      startedAt: null, finishedAt: null, durationMs: null,
      itemsProcessed: 0, itemsDiscovered: 0, progress: 0, errors: [], note: null,
    };
    this.modules.set(key, run);
    this.onModule?.(run);
    return run;
  }
  start(key: string) {
    const m = this.modules.get(key);
    if (!m) return;
    m.status = "running";
    m.startedAt = new Date().toISOString();
    m.progress = 1;
    this.onModule?.(m);
    this.log("info", key, "started");
  }
  finish(key: string, patch: Partial<Pick<ModuleRun, "itemsProcessed" | "itemsDiscovered" | "note">> = {}) {
    const m = this.modules.get(key);
    if (!m) return;
    if (m.startedAt) m.durationMs = Date.now() - Date.parse(m.startedAt);
    m.finishedAt = new Date().toISOString();
    m.status = m.errors.length > 0 && (patch.itemsProcessed ?? 0) === 0 ? "failed" : "completed";
    if (patch.itemsProcessed !== undefined) m.itemsProcessed = patch.itemsProcessed;
    if (patch.itemsDiscovered !== undefined) m.itemsDiscovered = patch.itemsDiscovered;
    if (patch.note !== undefined) m.note = patch.note;
    m.progress = 100;
    this.onModule?.(m);
    this.log("info", key, `finished (${m.durationMs}ms)`);
  }
  unavailable(key: string, reason: string) {
    const m = this.modules.get(key);
    if (!m) return;
    m.status = "unavailable";
    m.note = reason;
    m.finishedAt = new Date().toISOString();
    m.progress = 100;
    this.onModule?.(m);
    this.log("warn", key, reason);
  }
  fail(key: string, error: string) {
    const m = this.modules.get(key);
    if (!m) return;
    m.errors.push(error);
    m.status = "failed";
    m.finishedAt = new Date().toISOString();
    if (m.startedAt) m.durationMs = Date.now() - Date.parse(m.startedAt);
    m.progress = 100;
    this.onModule?.(m);
    this.log("error", key, error);
  }
  error(key: string, error: string) {
    const m = this.modules.get(key);
    if (m) m.errors.push(error);
    this.log("error", key, error);
  }
  log(level: ScanLogEntry["level"], module: string, message: string) {
    const entry: ScanLogEntry = { at: new Date().toISOString(), level, module, message };
    this.logs.push(entry);
    this.onLog?.(entry);
  }
  get list(): ModuleRun[] {
    return [...this.modules.values()];
  }
}

async function corsProbe(url: string, scope: ScopeRules): Promise<CorsProbeResult | null> {
  const origin = "https://attacker.example";
  try {
    const res = await guardedFetch(url, {
      scope,
      headers: { origin, "access-control-request-method": "GET" },
      timeoutMs: 8000,
      discardBody: true,
    });
    const allowOrigin = res.headers["access-control-allow-origin"] ?? null;
    return {
      testedOrigin: origin,
      allowOrigin,
      allowCredentials: (res.headers["access-control-allow-credentials"] ?? "").toLowerCase() === "true",
      allowMethods: res.headers["access-control-allow-methods"] ?? null,
      reflects: allowOrigin === origin,
    };
  } catch {
    return null;
  }
}

export async function runScan(opts: EngineOptions): Promise<EngineResult> {
  resetFindingIds();
  const evidence = new EvidenceStore();
  const findings: Finding[] = [];
  const rec = new Recorder({ onLog: opts.onLog, onModule: opts.onModule });
  const startedAt = new Date().toISOString();
  const t0 = Date.now();

  const { profile, scope } = opts;
  const target = normalizeHostname(opts.target);
  const apex = apexOf(target);

  const modules = profile.modules;
  for (const key of modules) {
    rec.register(key, key);
  }

  // ---- DNS ------------------------------------------------------------
  let dns: DnsRecords | null = null;
  if (modules.includes("dns")) {
    rec.start("dns");
    try {
      const r = await resolveAll(target);
      dns = r.records;
      for (const err of r.errors) rec.error("dns", err);
      const total = Object.values(dns).reduce((n, arr) => n + arr.length, 0);
      for (const [type, values] of Object.entries(dns)) {
        if (values.length) evidence.addDnsRecord("dns", target, type.toUpperCase(), values);
      }
      rec.finish("dns", { itemsProcessed: 8, itemsDiscovered: total });
    } catch (err) {
      rec.fail("dns", err instanceof Error ? err.message : String(err));
    }
  }

  // ---- Wildcard -------------------------------------------------------
  let wildcard = { detected: false, addressSets: [] as string[][], probesUsed: [] as string[] };
  if (modules.includes("wildcard")) {
    rec.start("wildcard");
    try {
      wildcard = await detectWildcard(apex);
      rec.finish("wildcard", {
        itemsProcessed: wildcard.probesUsed.length,
        itemsDiscovered: wildcard.detected ? 1 : 0,
        note: wildcard.detected ? "Wildcard DNS detected — subdomain results filtered accordingly" : null,
      });
    } catch (err) {
      rec.fail("wildcard", err instanceof Error ? err.message : String(err));
    }
  }

  // ---- Certificate Transparency + subdomain enumeration ---------------
  const discoveredHosts = new Set<string>([target]);
  const subdomainSources: string[] = [];
  if (modules.includes("ct")) {
    rec.start("ct");
    try {
      const ct = await certTransparency(apex);
      subdomainSources.push(...ct.sourcesSucceeded.map((s) => `ct:${s}`));
      for (const err of ct.errors) rec.error("ct", err);
      const { inScope } = partitionByScope(ct.names, scope);
      for (const h of inScope) discoveredHosts.add(h);
      rec.finish("ct", {
        itemsProcessed: ct.sourcesQueried.length,
        itemsDiscovered: inScope.length,
        note: ct.sourcesSucceeded.length === 0 ? "No CT source responded — coverage is empty" : null,
      });
    } catch (err) {
      rec.fail("ct", err instanceof Error ? err.message : String(err));
    }
  }

  if (profile.activeDnsEnumeration && modules.includes("ct")) {
    // Try the worker's subfinder/amass path in addition to CT.
    const sub = await workerEnumSubdomains(apex);
    if (sub.available) {
      const { inScope } = partitionByScope(sub.names, scope);
      for (const h of inScope) discoveredHosts.add(h);
      subdomainSources.push(...sub.sources.map((s) => `worker:${s}`));
      rec.log("info", "ct", `Worker enumeration added ${inScope.length} additional in-scope names via ${sub.tool}`);
    } else {
      rec.log("warn", "ct", sub.reason);
    }
  }

  // ---- HTTP probe of every discovered host ----------------------------
  const hosts: HostAsset[] = [];
  const primaryProbes: { host: string; probe: HttpProbe }[] = [];
  if (modules.includes("http.probe")) {
    rec.start("http.probe");
    const list = [...discoveredHosts].slice(0, Math.max(1, profile.subdomainProbeLimit || 1));
    let probed = 0;
    for (const host of list) {
      try {
        const addrs = await resolveAddresses(host);
        if (isWildcardAnswer(addrs, wildcard)) {
          rec.log("info", "http.probe", `Skipping ${host} — matches wildcard baseline`);
          continue;
        }
        const { probe, scheme } = await probeHost(host, { scope });
        const asset: HostAsset = {
          hostname: host,
          ipv4: addrs.filter((a) => a.includes(".")),
          ipv6: addrs.filter((a) => a.includes(":")),
          cname: [],
          httpStatus: scheme === "http" ? probe?.status ?? null : null,
          httpsStatus: scheme === "https" ? probe?.status ?? null : null,
          title: probe ? extractTitle(probe.body) : null,
          server: probe?.headers["server"] ?? null,
          technologies: [],
          responseTimeMs: probe?.responseTimeMs ?? null,
          discoveredVia: host === target ? "seed" : "certificate-transparency",
        };
        hosts.push(asset);
        if (probe) primaryProbes.push({ host, probe });
        probed++;
      } catch (err) {
        if (err instanceof BlockedRequestError) rec.error("http.probe", err.message);
        else rec.error("http.probe", `${host} — ${err instanceof Error ? err.message : String(err)}`);
      }
    }
    rec.finish("http.probe", { itemsProcessed: list.length, itemsDiscovered: probed });
  }

  // Pick the primary probe (the target).
  const primary = primaryProbes.find((p) => p.host === target) ?? primaryProbes[0] ?? null;

  // ---- Technology fingerprinting --------------------------------------
  let technologies: TechDetection[] = [];
  if (modules.includes("tech") && primary) {
    rec.start("tech");
    technologies = fingerprint(primary.probe);
    // annotate hosts too
    for (const p of primaryProbes) {
      const asset = hosts.find((h) => h.hostname === p.host);
      if (asset) asset.technologies = fingerprint(p.probe).map((t) => t.name);
    }
    rec.finish("tech", { itemsProcessed: 1, itemsDiscovered: technologies.length });
  }

  // ---- Crawl ----------------------------------------------------------
  let crawlResult: CrawlResult | null = null;
  if (modules.includes("crawl") && primary && profile.crawlMaxPages > 0) {
    rec.start("crawl");
    try {
      const startUrl = primary.probe.finalUrl;
      crawlResult = await crawl(startUrl, {
        scope,
        maxDepth: profile.crawlMaxDepth,
        maxPages: profile.crawlMaxPages,
        concurrency: profile.crawlConcurrency,
        onPage: (page) => rec.log("info", "crawl", `${page.status} ${page.url}`),
      });
      for (const err of crawlResult.errors) rec.error("crawl", err);
      rec.finish("crawl", {
        itemsProcessed: crawlResult.pages.length,
        itemsDiscovered: crawlResult.pages.length,
        note: crawlResult.queuedNotFetched.length > 0 ? `Page budget reached — ${crawlResult.queuedNotFetched.length} URLs left unfetched` : null,
      });
    } catch (err) {
      rec.fail("crawl", err instanceof Error ? err.message : String(err));
    }
  }

  // ---- JavaScript analysis -------------------------------------------
  let scripts: JsAnalysisResult | null = null;
  if (modules.includes("js") && crawlResult && crawlResult.scriptUrls.length > 0) {
    rec.start("js");
    scripts = await analyzeScripts(crawlResult.scriptUrls, {
      scope,
      concurrency: Math.min(4, profile.crawlConcurrency),
      maxScripts: Math.max(20, profile.crawlMaxPages),
    });
    for (const err of scripts.errors) rec.error("js", err);
    rec.finish("js", {
      itemsProcessed: scripts.scriptsFetched + scripts.scriptsFailed,
      itemsDiscovered: scripts.endpoints.length + scripts.urls.length,
    });
  }

  // ---- Endpoint / path probing ---------------------------------------
  let endpoints: DiscoveredEndpoint[] = [];
  const endpointBodies = new Map<string, string>();
  if (modules.includes("endpoints") && primary) {
    rec.start("endpoints");
    try {
      const origin = new URL(primary.probe.finalUrl).origin;
      const baseline = await baselineNotFound(origin, scope);
      const paths = new Set<string>(COMMON_PATHS);
      // Enrich with paths discovered in crawl and JS.
      if (crawlResult) {
        for (const page of crawlResult.pages) {
          try {
            const p = new URL(page.url).pathname;
            if (p && p !== "/") paths.add(p);
          } catch { /* skip */ }
        }
      }
      if (scripts) for (const p of scripts.endpoints) paths.add(p);

      const { endpoints: found, softNotFoundFiltered, errors } = await probePaths(
        origin, [...paths], { scope, concurrency: profile.crawlConcurrency, baseline, source: "wordlist" },
      );
      endpoints = found;
      for (const e of errors) rec.error("endpoints", e);
      // Retain body snippets for high-risk paths so the exposure module can cite them.
      for (const e of found) {
        if (/(\.env|\.git|backup|phpinfo|server-status|actuator|config)/i.test(e.path)) {
          try {
            const res = await guardedFetch(e.url, { scope, timeoutMs: 8000, maxBodyBytes: 500_000 });
            endpointBodies.set(e.url, res.body);
          } catch { /* skip */ }
        }
      }
      rec.finish("endpoints", {
        itemsProcessed: paths.size,
        itemsDiscovered: endpoints.length,
        note: softNotFoundFiltered ? `Soft-404 filter removed ${softNotFoundFiltered} responses` : null,
      });
    } catch (err) {
      rec.fail("endpoints", err instanceof Error ? err.message : String(err));
    }
  }

  // ---- API discovery --------------------------------------------------
  let apis: ApiInventoryEntry[] = [];
  let parameters: DiscoveredParameter[] = [];
  if (modules.includes("api") && primary) {
    rec.start("api");
    const origin = new URL(primary.probe.finalUrl).origin;
    const disco = await discoverApis(origin, endpoints, { scope });
    apis = disco.apis;
    parameters = extractParameters(
      [
        ...(crawlResult?.pages.map((p) => p.url) ?? []),
        ...(scripts?.urls ?? []),
      ],
      crawlResult?.forms ?? [],
    );
    parameters.push(...disco.parameters);
    for (const err of disco.errors) rec.error("api", err);
    rec.finish("api", { itemsProcessed: endpoints.length, itemsDiscovered: apis.length + parameters.length });
  }

  // ---- Port / service discovery (worker) ------------------------------
  let ports: EngineResult["ports"] = { available: false, reason: "not requested", open: [] };
  if (modules.includes("ports") && profile.portScan) {
    rec.start("ports");
    const r = await workerPortScan(target);
    if (r.available) {
      ports = {
        available: true,
        open: r.open.map((o) => ({ host: target, port: o.port, protocol: o.protocol, service: o.service, banner: o.banner ?? null })),
      };
      rec.finish("ports", { itemsProcessed: r.scannedPorts, itemsDiscovered: r.open.length, note: `via ${r.tool}` });
    } else {
      ports = { available: false, reason: r.reason, open: [] };
      rec.unavailable("ports", r.reason);
    }
  }

  // ---- Vulnerability rules --------------------------------------------
  if (primary) {
    if (modules.includes("vuln.headers")) {
      rec.start("vuln.headers");
      const f = analyzeSecurityHeaders(primary.host, primary.probe, evidence);
      findings.push(...f);
      rec.finish("vuln.headers", { itemsProcessed: 1, itemsDiscovered: f.length });
    }
    if (modules.includes("vuln.cookies")) {
      rec.start("vuln.cookies");
      const f = analyzeCookies(primary.host, primary.probe, evidence);
      findings.push(...f);
      rec.finish("vuln.cookies", { itemsProcessed: primary.probe.setCookies.length, itemsDiscovered: f.length });
    }
    if (modules.includes("vuln.transport")) {
      rec.start("vuln.transport");
      let plainHttp: { status: number; redirectsToHttps: boolean; location: string | null } | null = null;
      try {
        const res = await guardedFetch(`http://${primary.host}/`, {
          scope, timeoutMs: 8000, followRedirects: false, discardBody: true,
        });
        const loc = res.headers["location"] ?? null;
        plainHttp = {
          status: res.status,
          redirectsToHttps: !!(loc && /^https:/i.test(loc)),
          location: loc,
        };
      } catch { /* http may be closed entirely — that is fine */ }
      const httpsProbe = primary.probe.finalUrl.startsWith("https://") ? primary.probe : null;
      const f = analyzeTransport(primary.host, httpsProbe, plainHttp, evidence);
      findings.push(...f);
      rec.finish("vuln.transport", { itemsProcessed: 2, itemsDiscovered: f.length });
    }
    if (modules.includes("vuln.cors")) {
      rec.start("vuln.cors");
      const cors = await corsProbe(primary.probe.finalUrl, scope);
      if (cors) {
        const f = analyzeCors(primary.host, primary.probe.finalUrl, cors, evidence);
        findings.push(...f);
        rec.finish("vuln.cors", { itemsProcessed: 1, itemsDiscovered: f.length });
      } else {
        rec.finish("vuln.cors", { itemsProcessed: 1, itemsDiscovered: 0, note: "CORS probe did not complete" });
      }
    }
    if (modules.includes("vuln.exposure")) {
      rec.start("vuln.exposure");
      const f = analyzeExposedPaths(primary.host, endpoints, evidence, endpointBodies);
      findings.push(...f);
      rec.finish("vuln.exposure", { itemsProcessed: endpoints.length, itemsDiscovered: f.length });
    }
    if (modules.includes("vuln.dns") && dns) {
      rec.start("vuln.dns");
      const spf = dns.txt.find((t) => /^v=spf1/i.test(t)) ?? null;
      let dmarc: string | null = null;
      try {
        const r = await resolveAll(`_dmarc.${apex}`);
        dmarc = r.records.txt.find((t) => /^v=DMARC1/i.test(t)) ?? null;
      } catch { /* dmarc lookup failure is itself the finding */ }
      const f = analyzeDnsPosture(primary.host, dns, { spf, dmarc, dkimObserved: false }, evidence);
      findings.push(...f);
      rec.finish("vuln.dns", { itemsProcessed: 3, itemsDiscovered: f.length });
    }
    if (modules.includes("vuln.tech")) {
      rec.start("vuln.tech");
      const f = analyzeOutdatedDisclosure(primary.host, technologies, evidence);
      findings.push(...f);
      rec.finish("vuln.tech", { itemsProcessed: technologies.length, itemsDiscovered: f.length });
    }
  }

  // ---- CVE correlation ------------------------------------------------
  let cveMatches: CveMatch[] = [];
  if (modules.includes("cve") && technologies.some((t) => t.version)) {
    rec.start("cve");
    const r = await correlateCves(technologies);
    cveMatches = r.matches;
    for (const err of r.errors) rec.error("cve", err);
    // Emit a finding per CVE with an evidence record citing the tech observation.
    for (const cve of cveMatches) {
      const evId = evidence.add({
        module: "cve",
        source: `OSV.dev ${cve.id}`,
        content: `${cve.id} — ${cve.product} ${cve.version}\n\n${cve.summary}\n\nReferences:\n${cve.references.join("\n")}`,
        contentType: "text",
      });
      const severity = (cve.severity as Finding["severity"]) ?? "medium";
      const guidance = buildFindingGuidance({
        title: `${cve.id} affects ${cve.product} ${cve.version}`,
        asset: primary?.host ?? target,
        category: "Known vulnerability",
        remediation: `Upgrade ${cve.product} to a fixed release, or apply the vendor-supplied mitigation referenced in the advisory.`,
      });
      findings.push({
        id: `cve-${cve.id}`,
        title: `${cve.id} affects ${cve.product} ${cve.version}`,
        severity,
        confidence: "evidence-collected",
        category: "Known vulnerability",
        cvss: cve.cvss,
        cwe: null,
        owasp: "A06:2021 Vulnerable and Outdated Components",
        asset: primary?.host ?? target,
        endpoint: null,
        parameter: null,
        evidenceIds: [evId],
        description: cve.summary,
        impact: "The advertised version is publicly recorded as vulnerable. Exploit code or detailed technical write-ups are typically available for CVEs of this severity.",
        remediation: `Upgrade ${cve.product} to a fixed release, or apply the vendor-supplied mitigation referenced in the advisory.`,
        exposureSteps: guidance.exposureSteps,
        remediationSteps: guidance.remediationSteps,
        references: cve.references,
        module: "cve",
        detectedAt: new Date().toISOString(),
      });
    }
    rec.finish("cve", { itemsProcessed: r.queried, itemsDiscovered: cveMatches.length });
  }

  const attackPaths = buildAttackPaths(findings);
  const finishedAt = new Date().toISOString();

  return {
    target,
    profile: profile.key,
    startedAt,
    finishedAt,
    durationMs: Date.now() - t0,
    scope,
    authorization: opts.authorization,
    modules: rec.list,
    dns,
    hosts,
    wildcardDetected: wildcard.detected,
    crawl: crawlResult,
    scripts,
    endpoints,
    parameters,
    apis,
    technologies,
    cveMatches,
    findings,
    attackPaths,
    evidence: evidence.all(),
    logs: rec.logs,
    ports,
    subdomainSources,
  };
}

/** Convenience wrapper for the default target-only scope. */
export function makeDefaultScope(target: string): ScopeRules {
  return defaultScopeFor(target);
}
