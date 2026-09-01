/**
 * Assessment result surface.
 *
 * Renders exactly what the engine returned. Nothing is fabricated here; if a
 * module was skipped or a tool was unavailable, the module strip and result
 * sections say so plainly.
 */

import type { UseMutationResult } from "@tanstack/react-query";
import type { EngineResult } from "@/lib/scanner/engine";
import type { StartScanInput } from "@/lib/scan.functions";
import type { AiAnalysis } from "@/lib/scanner/ai";
import { ModuleStrip } from "./ModuleStrip";
import { FindingsList } from "./FindingsList";
import { AttackPathsList } from "./AttackPathsList";
import { EvidencePanel } from "./EvidencePanel";
import { InventoryPanel } from "./InventoryPanel";
import { AiPanel } from "./AiPanel";
import { DownloadReportPanel } from "./DownloadReportPanel";
import { AlertCircle, Info, Sparkles } from "lucide-react";

type Props = {
  config: StartScanInput | null;
  scan: UseMutationResult<EngineResult, Error, StartScanInput>;
  ai: UseMutationResult<AiAnalysis, Error, void>;
  onRequestAi: () => void;
};

export function ScanResults({ config, scan, ai, onRequestAi }: Props) {
  if (!config && !scan.data && !scan.isPending) {
    return (
      <section data-testid="state-no-assessment" className="rounded-2xl border border-dashed border-border/70 bg-card/70 p-10 text-center">
        <Info className="mx-auto h-8 w-8 text-muted-foreground" />
        <h2 className="mt-3 text-base font-semibold">No assessment running</h2>
        <p className="mx-auto mt-1 max-w-md text-sm text-muted-foreground">
          Configure a target on the left. The scanner performs live reconnaissance and analysis — no simulated data is ever produced.
        </p>
      </section>
    );
  }

  if (scan.isPending) {
    return (
      <section data-testid="state-scan-loading" className="scan-card flex flex-col gap-5 rounded-2xl border border-border/70 bg-card p-6">
        <div>
          <h2 className="text-base font-semibold">Assessing {config?.target}</h2>
          <p className="text-xs text-muted-foreground">
            Live scan in progress. Runtime is real — no artificial delays.
          </p>
        </div>
        <div className="space-y-3">
          <div className="h-2 w-3/4 animate-pulse rounded-full bg-muted" />
          <div className="h-2 w-1/2 animate-pulse rounded-full bg-muted" />
          <div className="h-12 animate-pulse rounded-xl bg-muted/70" />
          <p className="flex items-center gap-3 text-sm text-muted-foreground"><span className="h-2 w-2 animate-pulse rounded-full bg-primary" /> Running modules — full results will appear when the scan completes.</p>
        </div>
      </section>
    );
  }

  if (scan.error) {
    return (
      <section data-testid="state-scan-error" className="flex items-start gap-3 rounded-2xl border border-destructive/60 bg-destructive/10 p-4 text-sm text-destructive">
        <AlertCircle className="mt-0.5 h-5 w-5" />
        <div>
          <div className="font-medium">Scan could not start</div>
          <p>{scan.error.message}</p>
        </div>
      </section>
    );
  }

  const result = scan.data;
  if (!result) return null;

  const severityCounts = {
    critical: result.findings.filter((f) => f.severity === "critical").length,
    high: result.findings.filter((f) => f.severity === "high").length,
    medium: result.findings.filter((f) => f.severity === "medium").length,
    low: result.findings.filter((f) => f.severity === "low").length,
    info: result.findings.filter((f) => f.severity === "info").length,
  };

  return (
    <section data-testid="section-scan-results" className="flex flex-col gap-5">
      <div className="scan-card rounded-2xl border border-border/70 bg-card p-5 sm:p-6">
        <div className="flex flex-wrap items-baseline justify-between gap-3">
          <div>
            <div className="mb-2 flex items-center gap-2 text-[10px] font-bold uppercase tracking-[0.16em] text-primary"><span className="h-1.5 w-1.5 rounded-full bg-primary" /> Live assessment result</div>
            <h2 data-testid="text-assessment-target" className="text-xl font-extrabold tracking-tight">Assessment of {result.target}</h2>
            <p className="text-xs text-muted-foreground">
              Profile <span className="font-medium">{result.profile}</span> · Authorized by {result.authorization.principal} · Completed {result.finishedAt} · Duration {Math.round(result.durationMs / 100) / 10}s
            </p>
          </div>
          <button
            onClick={onRequestAi}
            disabled={ai.isPending}
            className="inline-flex items-center gap-2 rounded-md border border-primary/40 bg-primary/10 px-3 py-1.5 text-xs font-medium text-primary transition hover:bg-primary/20 disabled:opacity-60"
          >
            <Sparkles className="h-3.5 w-3.5" />
            {ai.isPending ? "Analysing…" : ai.data ? "Re-run AI analysis" : "Run AI analysis"}
          </button>
        </div>
        <div data-testid="grid-severity-summary" className="mt-5 grid grid-cols-2 gap-2 sm:grid-cols-5">
          <SeverityCell label="Critical" value={severityCounts.critical} tone="critical" />
          <SeverityCell label="High" value={severityCounts.high} tone="high" />
          <SeverityCell label="Medium" value={severityCounts.medium} tone="medium" />
          <SeverityCell label="Low" value={severityCounts.low} tone="low" />
          <SeverityCell label="Evidence records" value={result.evidence.length} tone="info" />
        </div>
      </div>

      <ModuleStrip modules={result.modules} />
      <FindingsList findings={result.findings} evidence={result.evidence} />
      <AttackPathsList paths={result.attackPaths} />
      <InventoryPanel result={result} />
      <AiPanel state={ai} />
      <DownloadReportPanel result={result} ai={ai.data} />
      <EvidencePanel evidence={result.evidence} />
    </section>
  );
}

function SeverityCell({ label, value, tone }: { label: string; value: number; tone: "critical" | "high" | "medium" | "low" | "info" }) {
  const tones: Record<string, string> = {
    critical: "border-red-500/50 bg-red-500/10 text-red-500",
    high: "border-orange-500/50 bg-orange-500/10 text-orange-500",
    medium: "border-yellow-500/50 bg-yellow-500/10 text-yellow-600",
    low: "border-sky-500/50 bg-sky-500/10 text-sky-500",
    info: "border-border/60 bg-muted/40 text-muted-foreground",
  };
  return (
    <div className={`rounded-md border p-3 ${tones[tone]}`}>
      <div className="text-2xl font-semibold leading-none">{value}</div>
      <div className="mt-1 text-[11px] uppercase tracking-wide">{label}</div>
    </div>
  );
}
