import { useState } from "react";
import type { Evidence, Finding, Severity } from "@/lib/scanner/types";
import { ChevronDown, ChevronRight, ShieldAlert } from "lucide-react";

const SEV_ORDER: Record<Severity, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
const SEV_STYLE: Record<Severity, string> = {
  critical: "severity-critical",
  high: "severity-high",
  medium: "severity-medium",
  low: "severity-low",
  info: "severity-info",
};

export function FindingsList({ findings, evidence }: { findings: Finding[]; evidence: Evidence[] }) {
  const [open, setOpen] = useState<string | null>(null);
  const sorted = [...findings].sort((a, b) => SEV_ORDER[a.severity] - SEV_ORDER[b.severity] || a.title.localeCompare(b.title));

  if (sorted.length === 0) {
    return (
      <section className="rounded-lg border border-border/60 bg-card p-5 text-sm text-muted-foreground">
        <div className="flex items-center gap-2 font-medium text-foreground">
          <ShieldAlert className="h-4 w-4" />
          Findings
        </div>
        <p className="mt-2">
          No findings were produced. This means the modules that ran did not observe any of the conditions in their rule set — not that the target is free of vulnerabilities.
        </p>
      </section>
    );
  }

  return (
    <section className="rounded-lg border border-border/60 bg-card">
      <header className="flex items-center justify-between border-b border-border/60 p-5">
        <h3 className="text-sm font-semibold">Findings ({sorted.length})</h3>
        <span className="text-xs text-muted-foreground">Every finding cites at least one evidence record.</span>
      </header>
      <ul className="divide-y divide-border/60">
        {sorted.map((f) => (
          <li key={f.id}>
            <button
              type="button"
              aria-expanded={open === f.id}
              aria-controls={`finding-detail-${f.id}`}
              onClick={() => setOpen(open === f.id ? null : f.id)}
              className="flex w-full items-start gap-3 px-5 py-3 text-left hover:bg-muted/20"
            >
              {open === f.id ? <ChevronDown className="mt-1 h-4 w-4 shrink-0 text-muted-foreground" /> : <ChevronRight className="mt-1 h-4 w-4 shrink-0 text-muted-foreground" />}
              <span className={`inline-flex shrink-0 items-center rounded-full border px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wide ${SEV_STYLE[f.severity]}`}>
                {f.severity}
              </span>
              <div className="min-w-0 flex-1">
                <div className="text-sm font-medium">{f.title}</div>
                <div className="mt-0.5 text-xs text-muted-foreground">
                  {f.asset} · {f.category} · confidence: <span className="font-medium text-foreground/80">{f.confidence}</span>
                  {f.cvss !== null && <> · CVSS <span className="font-medium text-foreground/80">{f.cvss}</span></>}
                  {f.cwe && <> · {f.cwe}</>}
                </div>
              </div>
            </button>
            {open === f.id && (
              <div id={`finding-detail-${f.id}`} className="grid gap-4 border-t border-border/40 bg-muted/10 px-5 py-4 text-sm md:grid-cols-2">
                <div>
                  <h4 className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">Description</h4>
                  <p className="mt-1">{f.description}</p>
                  <h4 className="mt-3 text-xs font-semibold uppercase tracking-wide text-muted-foreground">Impact</h4>
                  <p className="mt-1">{f.impact}</p>
                   <div className="mt-4 rounded-md border border-primary/20 bg-primary/5 p-3">
                     <h4 className="text-xs font-semibold uppercase tracking-wide text-primary">How this can be exposed</h4>
                     <ol className="mt-2 list-decimal space-y-1.5 pl-4 text-xs leading-5">
                       {f.exposureSteps.map((step) => <li key={step}>{step}</li>)}
                     </ol>
                   </div>
                  {f.references.length > 0 && (
                    <>
                      <h4 className="mt-3 text-xs font-semibold uppercase tracking-wide text-muted-foreground">References</h4>
                      <ul className="mt-1 space-y-0.5 text-xs">
                        {f.references.map((r) => (
                          <li key={r}>
                            <a href={r} target="_blank" rel="noreferrer" className="text-primary underline underline-offset-2">
                              {r}
                            </a>
                          </li>
                        ))}
                      </ul>
                    </>
                  )}
                </div>
                <div>
                   <div className="rounded-md border border-border/60 bg-background p-3">
                     <h4 className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">Remediation plan</h4>
                     <p className="mt-1 text-xs leading-5 text-muted-foreground">{f.remediation}</p>
                     <ol className="mt-2 list-decimal space-y-1.5 pl-4 text-xs leading-5">
                       {f.remediationSteps.map((step) => <li key={step}>{step}</li>)}
                     </ol>
                   </div>
                  <h4 className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">Evidence</h4>
                  <div className="mt-1 space-y-2">
                    {f.evidenceIds.map((id) => {
                      const ev = evidence.find((e) => e.id === id);
                      if (!ev) return null;
                      return (
                        <div key={id} className="rounded-md border border-border/60 bg-background p-2">
                          <div className="flex items-baseline justify-between text-[11px] text-muted-foreground">
                            <span className="font-mono">{ev.id}</span>
                            <span>{ev.contentType}</span>
                          </div>
                          <div className="text-[11px] text-muted-foreground">{ev.source}</div>
                          <pre className="mt-1 max-h-48 overflow-auto whitespace-pre-wrap break-words rounded bg-muted/40 p-2 text-[11px] font-mono">
                            {ev.content}
                          </pre>
                          {ev.truncated && <div className="mt-1 text-[10px] text-yellow-600">Evidence truncated for storage.</div>}
                        </div>
                      );
                    })}
                  </div>
                  <div className="mt-3 text-[11px] text-muted-foreground">
                    Detected by <span className="font-mono">{f.module}</span> at {new Date(f.detectedAt).toLocaleTimeString()}
                  </div>
                </div>
              </div>
            )}
          </li>
        ))}
      </ul>
    </section>
  );
}
