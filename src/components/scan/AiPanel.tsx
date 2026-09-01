import type { UseMutationResult } from "@tanstack/react-query";
import type { AiAnalysis } from "@/lib/scanner/ai";
import { Sparkles } from "lucide-react";

export function AiPanel({ state }: { state: UseMutationResult<AiAnalysis, Error, void> }) {
  if (!state.data && !state.isPending && !state.error) return null;
  return (
    <section className="rounded-lg border border-primary/30 bg-primary/5 p-5">
      <div className="mb-3 flex items-center gap-2 text-sm font-semibold">
        <Sparkles className="h-4 w-4 text-primary" />
        AI security copilot
        <span className="rounded-full border border-primary/30 bg-background px-2 py-0.5 text-[10px] uppercase text-primary">
          Inference — not evidence
        </span>
      </div>

      {state.isPending && <p className="text-sm text-muted-foreground">Analysing evidence…</p>}
      {state.error && (
        <p className="text-sm text-destructive">Analysis failed: {state.error.message}</p>
      )}
      {state.data && !state.data.available && (
        <p className="text-sm text-muted-foreground">
          {state.data.reason ?? "AI analysis is not available."}
        </p>
      )}
      {state.data?.available && (
        <div className="space-y-4 text-sm">
          <div>
            <h4 className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">Executive summary</h4>
            <p className="mt-1">{state.data.executiveSummary}</p>
          </div>
          <div>
            <h4 className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">Risk narrative</h4>
            <p className="mt-1 whitespace-pre-wrap">{state.data.riskNarrative}</p>
          </div>
          {state.data.prioritizedActions.length > 0 && (
            <div>
              <h4 className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">Prioritised actions</h4>
              <ol className="mt-1 space-y-2">
                {state.data.prioritizedActions.map((a, i) => (
                  <li key={i} className="rounded-md border border-border/60 bg-background p-3">
                    <div className="text-sm font-medium">{i + 1}. {a.title}</div>
                    <p className="mt-1 text-xs text-muted-foreground">{a.rationale}</p>
                    {a.findingIds.length > 0 && (
                      <div className="mt-1 text-[10px] text-muted-foreground">
                        Findings: {a.findingIds.map((id) => <code key={id} className="mx-0.5 rounded bg-muted px-1">{id}</code>)}
                      </div>
                    )}
                  </li>
                ))}
              </ol>
            </div>
          )}
          {state.data.detectedThemes.length > 0 && (
            <div>
              <h4 className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">Themes</h4>
              <div className="mt-1 flex flex-wrap gap-1 text-xs">
                {state.data.detectedThemes.map((t) => (
                  <span key={t} className="rounded-full border border-border/60 bg-background px-2 py-0.5">{t}</span>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </section>
  );
}
