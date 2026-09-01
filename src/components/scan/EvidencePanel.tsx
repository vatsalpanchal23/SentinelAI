import { useState } from "react";
import type { Evidence } from "@/lib/scanner/types";
import { FileText } from "lucide-react";

export function EvidencePanel({ evidence }: { evidence: Evidence[] }) {
  const [open, setOpen] = useState(false);
  if (evidence.length === 0) return null;
  return (
    <section className="rounded-lg border border-border/60 bg-card">
      <button type="button" aria-expanded={open} onClick={() => setOpen((v) => !v)} className="flex w-full items-center gap-2 p-5 text-left">
        <FileText className="h-4 w-4" />
        <span className="text-sm font-semibold">Full evidence log ({evidence.length})</span>
        <span className="ml-auto text-xs text-muted-foreground">{open ? "Hide" : "Show"}</span>
      </button>
      {open && (
        <ul className="max-h-96 divide-y divide-border/40 overflow-auto border-t border-border/40">
          {evidence.map((e) => (
            <li key={e.id} className="p-4 text-xs">
              <div className="flex items-baseline justify-between text-[11px] text-muted-foreground">
                <span className="font-mono">{e.id} · {e.module}</span>
                <span>{e.contentType} · {new Date(e.capturedAt).toLocaleTimeString()}</span>
              </div>
              <div className="text-muted-foreground">{e.source}</div>
              <pre className="mt-1 max-h-40 overflow-auto whitespace-pre-wrap break-words rounded bg-muted/40 p-2 font-mono">
                {e.content}
              </pre>
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}
