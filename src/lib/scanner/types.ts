/**
 * SentinelAI — shared scanner types.
 *
 * Every value produced by the scanner is traceable to an evidence record.
 * Nothing in this file describes simulated or example data.
 */

export type Severity = "critical" | "high" | "medium" | "low" | "info";

/** How much the scanner actually proved. Never skip straight to "validated". */
export type Confidence = "detected" | "tested" | "evidence-collected" | "validated";

/** Where a piece of data came from. Used to keep AI output out of scanner findings. */
export type ProvenanceKind = "scanner-evidence" | "ai-inference";

export type ModuleStatus =
  | "pending"
  | "running"
  | "completed"
  | "failed"
  | "skipped"
  | "unavailable"
  | "cancelled";

/** A raw, verbatim artefact captured from the target. Findings must cite these. */
export type Evidence = {
  id: string;
  /** Module that captured it, e.g. "http.probe". */
  module: string;
  /** What produced it, e.g. "GET https://example.com/". */
  source: string;
  /** Verbatim captured content, truncated to MAX_EVIDENCE_BYTES. */
  content: string;
  contentType: "http-headers" | "http-body" | "dns-record" | "tls" | "text" | "json";
  capturedAt: string;
  truncated: boolean;
};

export type Finding = {
  id: string;
  title: string;
  severity: Severity;
  confidence: Confidence;
  category: string;
  /** null when no reliable CVSS can be derived from evidence. */
  cvss: number | null;
  cwe: string | null;
  owasp: string | null;
  /** Hostname or IP the finding applies to. */
  asset: string;
  endpoint: string | null;
  parameter: string | null;
  /** IDs into the evidence store. A finding with no evidence is not reported. */
  evidenceIds: string[];
  description: string;
  impact: string;
  remediation: string;
  /** Ordered, explanatory steps describing how the observed condition can be abused. */
  exposureSteps: string[];
  /** Ordered implementation and verification steps for reducing the risk. */
  remediationSteps: string[];
  references: string[];
  /** Detection module identifier. */
  module: string;
  detectedAt: string;
};

export type DnsRecords = {
  a: string[];
  aaaa: string[];
  cname: string[];
  mx: string[];
  ns: string[];
  txt: string[];
  caa: string[];
  soa: string[];
};

export type HostAsset = {
  hostname: string;
  ipv4: string[];
  ipv6: string[];
  cname: string[];
  httpStatus: number | null;
  httpsStatus: number | null;
  title: string | null;
  server: string | null;
  technologies: string[];
  responseTimeMs: number | null;
  /** How this host was found: "seed" | "certificate-transparency" | "dns" | "crawl" | ... */
  discoveredVia: string;
};

export type HttpProbe = {
  url: string;
  finalUrl: string;
  status: number;
  redirected: boolean;
  redirectChain: string[];
  headers: Record<string, string>;
  setCookies: string[];
  title: string | null;
  bodyBytes: number;
  responseTimeMs: number;
  /** Body text, capped. Empty when the body was not retained. */
  body: string;
};

export type ModuleRun = {
  key: string;
  label: string;
  status: ModuleStatus;
  /** Real wall-clock timestamps. Never fabricated, never padded. */
  startedAt: string | null;
  finishedAt: string | null;
  durationMs: number | null;
  itemsProcessed: number;
  itemsDiscovered: number;
  /** 0-100, derived from real work completed. */
  progress: number;
  errors: string[];
  /** Set when a tool the module needs is not reachable. */
  note: string | null;
};

export type ScanLogEntry = {
  at: string;
  level: "info" | "warn" | "error";
  module: string;
  message: string;
};

export type ScanProfileKey = "passive" | "quick" | "standard" | "deep" | "custom";

export type ScanProfile = {
  key: ScanProfileKey;
  label: string;
  description: string;
  modules: string[];
  crawlMaxDepth: number;
  crawlMaxPages: number;
  crawlConcurrency: number;
  subdomainProbeLimit: number;
  activeDnsEnumeration: boolean;
  activeVulnChecks: boolean;
  portScan: boolean;
};

export type ScopeRules = {
  /** Primary target hostname. */
  target: string;
  /** Hostnames or *.suffix patterns permitted for scanning. */
  allowedDomains: string[];
  /** Literal IPs or CIDRs permitted. Empty means "resolve from allowed domains". */
  allowedIps: string[];
  /** Hostnames or patterns that must never be scanned, overrides allow. */
  excludedHosts: string[];
  /** Only true for explicitly-configured controlled lab environments. */
  allowPrivateTargets: boolean;
};

export type AssessmentStatus =
  | "draft"
  | "queued"
  | "running"
  | "completed"
  | "completed-with-warnings"
  | "failed"
  | "cancelled";
