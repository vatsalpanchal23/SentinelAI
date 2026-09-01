import { useState } from "react";
import type { AiAnalysis } from "@/lib/scanner/ai";
import type { EngineResult } from "@/lib/scanner/engine";
import { Download, FileText, Printer } from "lucide-react";
import { renderReportHtml, renderReportText } from "@/lib/scanner/report";

type Props = { result: EngineResult; ai?: AiAnalysis };

export function DownloadReportPanel({ result, ai }: Props) {
  const [lastGenerated, setLastGenerated] = useState<string | null>(null);
  const fileSlug = result.target.replace(/[^a-z0-9.-]+/gi, "-") || "target";

  const makeReport = () => {
    const generatedAt = new Date().toISOString();
    const html = renderReportHtml(result, undefined, generatedAt, ai);
    const blob = new Blob([html], { type: "text/html;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = `sentinelai-${fileSlug}-assessment.html`;
    document.body.appendChild(anchor);
    anchor.click();
    anchor.remove();
    URL.revokeObjectURL(url);
    setLastGenerated(generatedAt);
  };
  const printReport = () => {
    const generatedAt = new Date().toISOString();
    const html = renderReportHtml(result, undefined, generatedAt, ai);
    const win = window.open("", "_blank");
    if (!win) return;
    win.document.write(html);
    win.document.close();
    win.focus();
    window.setTimeout(() => win.print(), 250);
    setLastGenerated(generatedAt);
  };
  const downloadText = () => {
    const generatedAt = new Date().toISOString();
    const blob = new Blob([renderReportText(result, undefined, generatedAt, ai)], { type: "text/plain;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = `sentinelai-${fileSlug}-assessment.txt`;
    document.body.appendChild(anchor);
    anchor.click();
    anchor.remove();
    URL.revokeObjectURL(url);
    setLastGenerated(generatedAt);
  };

  return (
    <section data-testid="panel-report-actions" className="report-panel scan-card overflow-hidden rounded-2xl border">
      <div className="flex flex-col gap-5 p-5 sm:flex-row sm:items-center sm:justify-between sm:p-6">
        <div className="flex gap-4">
          <div className="report-mark grid h-11 w-11 shrink-0 place-items-center rounded-xl">
            <FileText className="h-5 w-5" />
          </div>
          <div>
            <p className="text-[10px] font-bold uppercase tracking-[0.18em] text-primary">Assessment record</p>
            <h3 className="mt-1 text-base font-bold text-foreground">Package the evidence for review</h3>
            <p className="report-copy mt-1 max-w-xl text-xs leading-5">Download a self-contained HTML report with the SentinelAI mark, watermark, exact timestamps, findings, evidence references, inventory, attack paths, and coverage limitations.</p>
          </div>
        </div>
        <div className="flex shrink-0 flex-wrap gap-2">
          <button data-testid="button-download-report" type="button" onClick={makeReport} className="inline-flex items-center justify-center gap-2 rounded-lg bg-primary px-4 py-2.5 text-xs font-bold text-primary-foreground shadow-sm transition hover:bg-primary/90">
            <Download className="h-4 w-4" /> Download report
          </button>
          <button data-testid="button-print-report" type="button" onClick={printReport} className="report-secondary-button inline-flex items-center justify-center gap-2 rounded-lg border px-3 py-2.5 text-xs font-semibold transition">
            <Printer className="h-4 w-4" /> Print / Save as PDF
          </button>
          <button data-testid="button-download-text-report" type="button" onClick={downloadText} className="report-text-button rounded-lg border border-transparent px-2 py-2 text-xs font-semibold underline underline-offset-4 transition">Plain text</button>
        </div>
      </div>
      {lastGenerated && <div data-testid="status-report-generated" className="report-status border-t px-5 py-2.5 text-[10px] font-mono sm:px-6">Last generated: {lastGenerated}</div>}
    </section>
  );
}