import type { AttackPath } from "@/lib/scanner/attackpaths";
import { GitBranch } from "lucide-react";

export function AttackPathsList({ paths }: { paths: AttackPath[] }) {
  if (paths.length === 0) return null;
  return (
    <section className="rounded-lg border border-border/60 bg-card p-5">
      <div className="mb-3 flex items-center gap-2">
        <GitBranch className="h-4 w-4 text-primary" />
        <h3 className="text-sm font-semibold">Attack paths ({paths.length})</h3>
      </div>
      <p className="mb-4 text-xs text-muted-foreground">
        Each path is composed of real observed findings. Every step cites the finding IDs that support it.
      </p>
      <ol className="space-y-4">
        {paths.map((p) => (
          <li key={p.id} className="rounded-md border border-border/60 bg-muted/10 p-4">
            <div className="flex flex-wrap items-baseline justify-between gap-2">
              <h4 className="text-sm font-semibold">{p.title}</h4>
              <div className="flex gap-2 text-[10px] uppercase tracking-wide">
                <span className="rounded-full border border-border/60 bg-background px-2 py-0.5">Severity {p.severity}</span>
                <span className="rounded-full border border-border/60 bg-background px-2 py-0.5">Likelihood {p.likelihood}</span>
              </div>
            </div>
            <p className="mt-1 text-xs text-muted-foreground">{p.impact}</p>
            <ol className="mt-3 space-y-1.5 text-xs">
              {p.steps.map((s) => (
                <li key={s.order} className="flex gap-2">
                  <span className="inline-flex h-5 w-5 shrink-0 items-center justify-center rounded-full bg-primary/20 text-[10px] font-semibold text-primary">
                    {s.order}
                  </span>
                  <div>
                    <div>{s.action}</div>
                    <div className="text-[10px] text-muted-foreground">
                      Supported by: {s.findingIds.map((id) => <code key={id} className="mx-0.5 rounded bg-muted px-1">{id}</code>)}
                    </div>
                  </div>
                </li>
              ))}
            </ol>
          </li>
        ))}
      </ol>
    </section>
  );
}
