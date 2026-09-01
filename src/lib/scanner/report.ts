import type { EngineResult } from "./engine";
import type { AiAnalysis } from "./ai";

const SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"] as const;
const SEVERITY_COLOR: Record<string, string> = {
  critical: "#b42318",
  high: "#c2410c",
  medium: "#a16207",
  low: "#0e7490",
  info: "#64748b",
};

function esc(value: unknown): string {
  return String(value ?? "")
    .replace(/&/g, "&amp;").replace(/</g, "&lt;")
    .replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}

export function severityCounts(result: EngineResult): Record<string, number> {
  const counts: Record<string, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const finding of result.findings) counts[finding.severity] = (counts[finding.severity] ?? 0) + 1;
  return counts;
}

export function reportSubject(result: EngineResult): string {
  const counts = severityCounts(result);
  return `SentinelAI security assessment — ${result.target} (${counts.critical} critical, ${counts.high} high)`;
}

const mark = `<svg width="34" height="40" viewBox="0 0 34 40" aria-label="SentinelAI shield mark" role="img"><path d="M17 1 31 6v11c0 10.3-5.8 17.9-14 22C8.8 34.9 3 27.3 3 17V6L17 1Z" fill="#153b3b"/><path d="m10 19 4.2 4.2L24.5 13" fill="none" stroke="#70d5bf" stroke-width="2.8" stroke-linecap="round" stroke-linejoin="round"/></svg>`;

function rows(result: EngineResult, generatedAt: string, note?: string, ai?: AiAnalysis): string {
  const counts = severityCounts(result);
  const findings = [...result.findings].sort((a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity));
  const summary = SEVERITY_ORDER.map((severity) =>
    `<td style="border:1px solid #dbe3e2;padding:14px;text-align:center;width:20%"><strong style="display:block;font-size:25px;color:${SEVERITY_COLOR[severity]}">${counts[severity] ?? 0}</strong><span style="font-size:10px;letter-spacing:.1em;text-transform:uppercase;color:#657575">${severity}</span></td>`).join("");
  const findingRows = findings.length ? findings.map((f) => `<tr>
    <td style="border-top:1px solid #e4ebea;padding:16px;vertical-align:top">
      <div style="font-size:14px;font-weight:700;color:#153b3b">${esc(f.title)}</div>
      <div style="margin-top:4px;font-size:11px;color:#657575">${esc(f.asset)}${f.endpoint ? ` · ${esc(f.endpoint)}` : ""} · ${esc(f.module)} · ${esc(f.id)}</div>
      <p style="margin:12px 0 0;font-size:12px;line-height:1.55;color:#334847">${esc(f.description)}</p>
      <p style="margin:8px 0 0;font-size:12px;line-height:1.5;color:#334847"><b>Impact:</b> ${esc(f.impact)}</p>
       <div style="margin-top:12px;padding:10px 12px;border-left:3px solid #279b89;background:#f0faf7">
         <b style="font-size:11px;color:#153b3b">How this can be exposed</b>
         <ol style="margin:6px 0 0;padding-left:18px;font-size:11px;line-height:1.55;color:#334847">${f.exposureSteps.map((step) => `<li>${esc(step)}</li>`).join("")}</ol>
       </div>
       <div style="margin-top:10px;padding:10px 12px;border-left:3px solid #6b7d7b;background:#f5f8f7">
         <b style="font-size:11px;color:#153b3b">Remediation plan</b>
         <p style="margin:5px 0 0;font-size:11px;line-height:1.5;color:#334847">${esc(f.remediation)}</p>
         <ol style="margin:6px 0 0;padding-left:18px;font-size:11px;line-height:1.55;color:#334847">${f.remediationSteps.map((step) => `<li>${esc(step)}</li>`).join("")}</ol>
       </div>
      <div style="margin-top:9px;font-size:10px;color:#657575">Confidence ${esc(f.confidence)}${f.cvss !== null ? ` · CVSS ${f.cvss}` : ""}${f.cwe ? ` · ${esc(f.cwe)}` : ""} · Evidence references: ${f.evidenceIds.map(esc).join(", ") || "none"}</div>
    </td><td style="border-top:1px solid #e4ebea;padding:16px;vertical-align:top;white-space:nowrap"><span style="padding:4px 8px;border-radius:3px;background:${SEVERITY_COLOR[f.severity]};color:#fff;font-size:10px;font-weight:700;letter-spacing:.08em">${esc(f.severity.toUpperCase())}</span></td>
  </tr>`).join("") : `<tr><td colspan="2" style="padding:16px;color:#657575;font-size:12px">No findings were reported for this assessment.</td></tr>`;
  const moduleRows = result.modules.map((m) => `<tr><td style="border-top:1px solid #e4ebea;padding:8px 10px;font-size:11px;color:#153b3b">${esc(m.label)}</td><td style="border-top:1px solid #e4ebea;padding:8px 10px;font-size:11px;color:#334847">${esc(m.status)}${m.note ? ` — ${esc(m.note)}` : ""}</td><td style="border-top:1px solid #e4ebea;padding:8px 10px;font-size:11px;color:#657575">${m.durationMs === null ? "—" : `${Math.round(m.durationMs)} ms`}</td></tr>`).join("");
  const evidenceRows = result.evidence.map((e) => `<tr><td style="border-top:1px solid #e4ebea;padding:8px 10px;font:10px monospace;color:#153b3b">${esc(e.id)}</td><td style="border-top:1px solid #e4ebea;padding:8px 10px;font-size:11px;color:#334847">${esc(e.module)}<br/><span style="color:#657575">${esc(e.source)}</span></td><td style="border-top:1px solid #e4ebea;padding:8px 10px;font-size:11px;color:#657575;white-space:pre-wrap">${esc(e.content.slice(0, 420))}${e.content.length > 420 ? "…" : ""}</td></tr>`).join("");
  const hostRows = result.hosts.map((h) => `<tr><td style="border-top:1px solid #e4ebea;padding:8px 10px;font-size:11px;color:#153b3b">${esc(h.hostname)}</td><td style="border-top:1px solid #e4ebea;padding:8px 10px;font-size:11px;color:#334847">${esc(h.title ?? "—")}<br/>HTTP ${h.httpStatus ?? "—"} / HTTPS ${h.httpsStatus ?? "—"}</td><td style="border-top:1px solid #e4ebea;padding:8px 10px;font-size:11px;color:#657575">${esc(h.technologies.join(", ") || "—")}</td></tr>`).join("");
  const attackRows = result.attackPaths.map((p) => `<li style="margin:0 0 12px;color:#334847;font-size:12px"><b>${esc(p.title)}</b> · ${esc(p.severity)} severity · ${esc(p.likelihood)} likelihood<br/><span style="color:#657575">${esc(p.impact)} Steps: ${p.steps.map((s) => `${s.order}. ${esc(s.action)}`).join(" → ")}</span></li>`).join("");
  const inventory = `<h2>Asset inventory</h2><p class="sub">${result.hosts.length} host assets · ${result.endpoints.length} endpoints · ${result.apis.length} APIs · ${result.technologies.length} technology observations · ${result.ports.open.length} open services</p><table><tr><th>Host</th><th>Observed response</th><th>Technologies</th></tr>${hostRows || `<tr><td colspan="3" class="empty">No host assets were returned.</td></tr>`}</table><div class="two"><div><h3>Endpoints</h3><p class="mono">${result.endpoints.map((e) => `${esc(e.method)} ${esc(e.path)} · ${esc(e.status)}`).join("<br/>") || "No endpoints were returned."}</p></div><div><h3>Services</h3><p class="mono">${result.ports.available ? result.ports.open.map((p) => `${esc(p.host)}:${p.port}/${esc(p.protocol)} · ${esc(p.service ?? "unknown")}`).join("<br/>") || "No open services were returned." : esc(result.ports.reason ?? "Port discovery was not requested.")}</p></div></div>`;
  const noteBlock = note ? `<div class="note"><b>Assessment note</b><br/>${esc(note)}</div>` : "";
  const aiBlock = `<h2>AI analysis</h2><div class="legal">${ai?.available ? `<p><b>Executive summary:</b> ${esc(ai.executiveSummary)}</p><p><b>Risk narrative:</b> ${esc(ai.riskNarrative)}</p>${ai.prioritizedActions.length ? `<p><b>Prioritized actions:</b> ${ai.prioritizedActions.map((a) => `${esc(a.title)} — ${esc(a.rationale)} [${a.findingIds.map(esc).join(", ")}]`).join(" · ")}</p>` : ""}${ai.detectedThemes.length ? `<p><b>Detected themes:</b> ${ai.detectedThemes.map(esc).join(", ")}</p>` : ""}<p class="sub">AI output is inference only and is not scanner evidence.</p>` : `<p>AI analysis was not run for this report.${ai?.reason ? ` ${esc(ai.reason)}` : ""}</p>`}</div>`;
  return `<main class="paper"><div class="watermark">SENTINELAI</div><header><div class="brand">${mark}<div><div class="wordmark">SENTINEL<span>AI</span></div><div class="kicker">EVIDENCE-DRIVEN SECURITY ASSESSMENT</div></div></div><div class="classified">AUTHORIZED USE<br/><span>CONFIDENTIAL</span></div></header><div class="rule"></div><section class="cover"><div class="eyebrow">ASSESSMENT REPORT</div><h1>${esc(result.target)}</h1><p class="lede">A traceable assessment record for the target named above. This report contains only observations returned by the SentinelAI scanner and clearly labels unavailable coverage.</p><div class="meta-grid"><div><span>Generated</span><b>${esc(generatedAt)}</b></div><div><span>Scan started</span><b>${esc(result.startedAt)}</b></div><div><span>Scan completed</span><b>${esc(result.finishedAt)}</b></div><div><span>Profile / duration</span><b>${esc(result.profile)} · ${Math.round(result.durationMs / 100) / 10}s</b></div><div><span>Authorizing principal</span><b>${esc(result.authorization.principal)}</b></div><div><span>Evidence records</span><b>${result.evidence.length}</b></div></div>${noteBlock}</section><h2>Severity summary</h2><table class="summary"><tr>${summary}</tr></table><h2>Findings</h2><table><tr><th>Finding detail</th><th>Severity</th></tr>${findingRows}</table>${attackRows ? `<h2>Correlated attack paths</h2><ol>${attackRows}</ol>` : ""}<h2>Module status</h2><table><tr><th>Module</th><th>Status / note</th><th>Runtime</th></tr>${moduleRows}</table>${inventory}<h2>Evidence references</h2><p class="sub">Raw records are retained as captured. Findings cite these IDs; AI analysis is not used as scanner evidence.</p><table><tr><th>Record</th><th>Source</th><th>Captured content excerpt</th></tr>${evidenceRows || `<tr><td colspan="3" class="empty">No evidence records were returned.</td></tr>`}</table>${aiBlock}<h2>Authorization and limitations</h2><div class="legal"><p><b>Authorization:</b> This assessment was run after an explicit authorization confirmation by ${esc(result.authorization.principal)} at ${esc(result.authorization.at)}.</p><p><b>Scope:</b> Target ${esc(result.scope.target)}. Allowed domains: ${esc(result.scope.allowedDomains.join(", ") || "none listed")}. Allowed IPs: ${esc(result.scope.allowedIps.join(", ") || "resolved from allowed domains")}. Excluded hosts: ${esc(result.scope.excludedHosts.join(", ") || "none listed")}.</p><p><b>Limitations:</b> Results describe only the modules and target paths that completed. Unavailable, failed, skipped, or budget-limited modules did not produce findings. A finding is not proof of exploitability, and absence of a finding is not proof of security. Review scope and evidence before taking action.</p></div><footer><div>${mark}<span>SentinelAI · Evidence before inference</span></div><span>Generated ${esc(generatedAt)} · ${esc(result.target)}</span></footer></main>`;
}

export function renderReportHtml(result: EngineResult, note?: string, generatedAt = new Date().toISOString(), ai?: AiAnalysis): string {
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/><title>${esc(reportSubject(result))}</title><style>
  @page{size:A4;margin:16mm}*{box-sizing:border-box}body{margin:0;background:#eaf0ef;color:#253c3b;font-family:Manrope,sans-serif;font-size:12px}.paper{position:relative;max-width:860px;margin:30px auto;padding:54px 58px;background:#fbfdfc;box-shadow:0 14px 50px #153b3b14;overflow:hidden}.watermark{position:absolute;top:46%;left:12%;z-index:0;transform:rotate(-28deg);font-size:74px;letter-spacing:12px;font-weight:800;color:#70d5bf14;pointer-events:none}.paper>*:not(.watermark){position:relative;z-index:1}header,footer,.brand{display:flex;align-items:center;justify-content:space-between}.brand{justify-content:flex-start;gap:11px}.wordmark{font-size:16px;letter-spacing:.12em;font-weight:800;color:#153b3b}.wordmark span{color:#279b89}.kicker,.eyebrow{font-size:9px;letter-spacing:.16em;color:#6b7d7b;font-weight:700}.classified{text-align:right;color:#b42318;font-size:9px;letter-spacing:.12em;font-weight:700}.classified span{color:#6b7d7b}.rule{height:1px;background:#dbe3e2;margin:22px 0 42px}.cover{padding-bottom:26px}.eyebrow{color:#279b89}.cover h1{font-size:38px;letter-spacing:-.04em;margin:10px 0;color:#153b3b}.lede{max-width:620px;color:#657575;font-size:13px;line-height:1.65}.meta-grid{display:grid;grid-template-columns:repeat(3,1fr);gap:0;border-top:1px solid #dbe3e2;border-bottom:1px solid #dbe3e2;margin-top:28px}.meta-grid div{padding:13px 14px 13px 0}.meta-grid span{display:block;font-size:9px;text-transform:uppercase;letter-spacing:.1em;color:#72817f;margin-bottom:4px}.meta-grid b{font:11px 'DM Mono',monospace;color:#253c3b;overflow-wrap:anywhere}.note{margin-top:20px;padding:11px 13px;border-left:3px solid #f0a348;background:#fff8ed;color:#536563;line-height:1.5}h2{margin:30px 0 9px;color:#153b3b;font-size:15px;letter-spacing:-.01em}h3{font-size:12px;color:#153b3b;margin:0 0 8px}.sub{margin:-3px 0 10px;color:#72817f;font-size:11px}table{width:100%;border-collapse:collapse;border:1px solid #dbe3e2;page-break-inside:auto}th{background:#f1f6f5;text-align:left;padding:8px 10px;color:#657575;font-size:9px;letter-spacing:.1em;text-transform:uppercase}td{page-break-inside:avoid}.summary{border:0}.summary td{background:#fbfcfc}.empty{padding:14px;color:#72817f}.two{display:grid;grid-template-columns:1fr 1fr;gap:20px;margin-top:18px}.two>div{border-top:1px solid #dbe3e2;padding-top:11px}.mono{font:10px/1.7 'DM Mono',monospace;color:#657575;overflow-wrap:anywhere}.legal{background:#f5f8f7;border-left:3px solid #279b89;padding:12px 14px;color:#536563;line-height:1.6}.legal p{margin:0 0 7px}.legal p:last-child{margin-bottom:0}footer{border-top:1px solid #dbe3e2;margin-top:42px;padding-top:16px;color:#72817f;font-size:9px;letter-spacing:.03em}footer>div{display:flex;align-items:center;gap:6px}footer svg{width:20px;height:24px}@media(max-width:700px){.paper{margin:0;padding:28px 20px}.meta-grid{grid-template-columns:1fr 1fr}.cover h1{font-size:29px}.two{grid-template-columns:1fr}.watermark{font-size:46px;left:0}}@media print{body{background:#fff}.paper{margin:0;box-shadow:none;max-width:none;padding:0}.watermark{color:#70d5bf1c}}
  </style></head><body>${rows(result, generatedAt, note, ai)}</body></html>`;
}

export function renderReportText(result: EngineResult, note?: string, generatedAt = new Date().toISOString(), ai?: AiAnalysis): string {
  const counts = severityCounts(result);
  const lines = [`SENTINELAI SECURITY ASSESSMENT`, `Target: ${result.target}`, `Generated: ${generatedAt}`, `Scan started: ${result.startedAt}`, `Scan completed: ${result.finishedAt}`, `Profile: ${result.profile}`, `Authorized by: ${result.authorization.principal}`, "", note ? `Note: ${note}` : "", `Severity: ${SEVERITY_ORDER.map((s) => `${s} ${counts[s]}`).join(" | ")}`, "", "FINDINGS"];
  for (const f of result.findings) lines.push(
    `[${f.severity.toUpperCase()}] ${f.id} — ${f.title}`,
    `Asset: ${f.asset}${f.endpoint ? ` ${f.endpoint}` : ""}`,
    f.description,
    `Impact: ${f.impact}`,
    "How this can be exposed:",
    ...f.exposureSteps.map((step, index) => `  ${index + 1}. ${step}`),
    `Remediation: ${f.remediation}`,
    "Remediation plan:",
    ...f.remediationSteps.map((step, index) => `  ${index + 1}. ${step}`),
    `Evidence: ${f.evidenceIds.join(", ") || "none"}`,
    "",
  );
  lines.push(
    "MODULE STATUS",
    ...result.modules.map((m) => `- ${m.label}: ${m.status}${m.note ? ` — ${m.note}` : ""}`),
    "",
    "ATTACK PATHS",
    ...(result.attackPaths.length ? result.attackPaths.map((p) => `- ${p.title} (${p.severity}; ${p.likelihood} likelihood): ${p.steps.map((s) => s.action).join(" -> ")}`) : ["No attack paths were returned."]),
    "",
    "INVENTORY",
    `Hosts: ${result.hosts.length} | Endpoints: ${result.endpoints.length} | APIs: ${result.apis.length} | Technologies: ${result.technologies.length} | Open services: ${result.ports.open.length}`,
    "",
    "EVIDENCE REFERENCES",
    ...result.evidence.map((e) => `- ${e.id} | ${e.module} | ${e.source}`),
    "",
    "AI ANALYSIS",
    ai?.available ? `Executive summary: ${ai.executiveSummary}\nRisk narrative: ${ai.riskNarrative}\nPrioritized actions: ${ai.prioritizedActions.map((a) => `${a.title} — ${a.rationale} [${a.findingIds.join(", ")}]`).join(" | ") || "none"}\nDetected themes: ${ai.detectedThemes.join(", ") || "none"}` : `AI analysis was not run for this report.${ai?.reason ? ` ${ai.reason}` : ""}`,
    "",
    "AUTHORIZATION / LIMITATIONS",
    `Authorization confirmed by ${result.authorization.principal} at ${result.authorization.at}.`,
    `Scope: ${result.scope.target}; allowed domains: ${result.scope.allowedDomains.join(", ") || "none listed"}.`,
    "Only completed modules and returned observations are represented. Unavailable or failed modules did not produce findings. Absence of a finding is not proof of security.",
    "",
    "SentinelAI | Evidence before inference",
  );
  return lines.filter((line) => line !== undefined).join("\n");
}