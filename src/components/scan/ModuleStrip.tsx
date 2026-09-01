import type { ModuleRun } from "@/lib/scanner/types";
import { MODULE_LABELS } from "@/lib/scanner/profiles";
import { CheckCircle2, Circle, AlertTriangle, XCircle, MinusCircle } from "lucide-react";

const ICON: Record<ModuleRun["status"], React.ReactNode> = {
  completed: <CheckCircle2 className="h-3.5 w-3.5 text-emerald-500" />,
  running: <Circle className="h-3.5 w-3.5 animate-pulse text-primary" />,
  pending: <Circle className="h-3.5 w-3.5 text-muted-foreground" />,
  failed: <XCircle className="h-3.5 w-3.5 text-destructive" />,
  unavailable: <MinusCircle className="h-3.5 w-3.5 text-yellow-500" />,
  skipped: <MinusCircle className="h-3.5 w-3.5 text-muted-foreground" />,
  cancelled: <MinusCircle className="h-3.5 w-3.5 text-muted-foreground" />,
};

export function ModuleStrip({ modules }: { modules: ModuleRun[] }) {
  return (
    <section className="rounded-lg border border-border/60 bg-card p-5">
      <div className="mb-3 flex items-center justify-between">
        <h3 className="text-sm font-semibold">Modules</h3>
        <span className="text-xs text-muted-foreground">
          {modules.filter((m) => m.status === "completed").length} completed ·{" "}
          {modules.filter((m) => m.status === "unavailable").length} tool unavailable ·{" "}
          {modules.filter((m) => m.status === "failed").length} failed
        </span>
      </div>
      <ul className="grid gap-2 sm:grid-cols-2 lg:grid-cols-3">
        {modules.map((m) => (
          <li
            key={m.key}
            className="flex items-start gap-2 rounded-md border border-border/40 bg-muted/20 px-3 py-2 text-xs"
          >
            <div className="mt-0.5">{ICON[m.status]}</div>
            <div className="min-w-0 flex-1">
              <div className="flex items-baseline justify-between gap-2">
                <span className="truncate font-medium text-foreground">{MODULE_LABELS[m.key] ?? m.key}</span>
                <span className="shrink-0 text-[10px] text-muted-foreground">
                  {m.durationMs !== null ? `${m.durationMs}ms` : ""}
                </span>
              </div>
              <div className="text-[11px] text-muted-foreground">
                {m.status === "completed" && `${m.itemsDiscovered} found · ${m.itemsProcessed} processed`}
                {m.status === "unavailable" && m.note}
                {m.status === "failed" && (m.errors[0] ?? "Failed")}
                {m.status === "running" && "Running…"}
                {m.status === "pending" && "Queued"}
              </div>
              {m.status === "completed" && m.note && (
                <div className="mt-1 flex items-start gap-1 text-[11px] text-yellow-500">
                  <AlertTriangle className="mt-0.5 h-3 w-3 shrink-0" />
                  <span>{m.note}</span>
                </div>
              )}
            </div>
          </li>
        ))}
      </ul>
    </section>
  );
}
