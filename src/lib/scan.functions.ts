import { aiAnalyze, type AiAnalysis } from "./scanner/ai";
import { runScan, makeDefaultScope, type EngineResult } from "./scanner/engine";
import { getProfile, MODULE_LABELS, PROFILES } from "./scanner/profiles";
import { isValidHostname, normalizeHostname } from "./scanner/scope";

export type StartScanInput = {
  target: string;
  profile: string;
  authorizationConfirmed: boolean;
  principal: string;
  allowedDomains?: string[];
  allowedIps?: string[];
  excludedHosts?: string[];
};

export async function startScan(raw: StartScanInput): Promise<EngineResult> {
  const target = normalizeHostname(String(raw.target ?? ""));
  if (!isValidHostname(target)) throw new Error(`Target must be a valid domain name or IP (got: "${raw.target}")`);
  if (raw.authorizationConfirmed !== true) throw new Error("Authorization must be explicitly confirmed");
  if (!raw.principal || String(raw.principal).trim().length < 2) throw new Error("Authorizing principal is required");
  const scope = makeDefaultScope(target);
  if (raw.allowedDomains?.length) scope.allowedDomains = raw.allowedDomains;
  if (raw.allowedIps?.length) scope.allowedIps = raw.allowedIps;
  if (raw.excludedHosts?.length) scope.excludedHosts = raw.excludedHosts;
  return runScan({
    target,
    profile: getProfile(raw.profile),
    scope,
    authorization: { confirmed: true, principal: String(raw.principal).trim(), at: new Date().toISOString() },
  });
}

export async function analyzeScan(result: EngineResult): Promise<AiAnalysis> {
  return aiAnalyze(result);
}

export function listProfiles() {
  return { profiles: Object.values(PROFILES), moduleLabels: MODULE_LABELS };
}