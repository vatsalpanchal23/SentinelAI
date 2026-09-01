import type { EngineResult } from "@/lib/scanner/engine";
import { Boxes, Globe, Layers, Network, Server } from "lucide-react";

export function InventoryPanel({ result }: { result: EngineResult }) {
  return (
    <section className="grid gap-4 md:grid-cols-2">
      <Card icon={<Globe className="h-4 w-4" />} title={`Hosts in scope (${result.hosts.length})`}>
        {result.hosts.length === 0 ? (
          <Empty>No hosts probed.</Empty>
        ) : (
          <ul className="divide-y divide-border/40 text-xs">
            {result.hosts.map((h) => (
              <li key={h.hostname} className="py-2">
                <div className="flex items-baseline justify-between">
                  <span className="font-mono">{h.hostname}</span>
                  <span className="text-muted-foreground">
                    {h.httpsStatus !== null ? `https ${h.httpsStatus}` : h.httpStatus !== null ? `http ${h.httpStatus}` : "no response"}
                  </span>
                </div>
                <div className="text-muted-foreground">
                  {[...h.ipv4, ...h.ipv6].join(", ") || "no address"} · via {h.discoveredVia}
                </div>
                {h.title && <div className="text-muted-foreground">Title: {h.title}</div>}
                {h.technologies.length > 0 && (
                  <div className="mt-1 flex flex-wrap gap-1">
                    {h.technologies.map((t) => (
                      <span key={t} className="rounded-full border border-border/60 bg-background px-2 py-0.5 text-[10px]">{t}</span>
                    ))}
                  </div>
                )}
              </li>
            ))}
          </ul>
        )}
      </Card>

      <Card icon={<Server className="h-4 w-4" />} title="Ports & services">
        {!result.ports.available ? (
          <Empty>
            {result.ports.reason ?? "Port scan not requested."}{" "}
            <span className="text-yellow-500">
              {result.ports.reason?.startsWith("Tool unavailable") ? "Deploy the scanner-worker to enable this module." : ""}
            </span>
          </Empty>
        ) : result.ports.open.length === 0 ? (
          <Empty>No open TCP ports observed.</Empty>
        ) : (
          <ul className="grid grid-cols-2 gap-1 text-xs sm:grid-cols-3">
            {result.ports.open.map((o) => (
              <li key={`${o.host}:${o.port}`} className="rounded border border-border/60 bg-muted/20 px-2 py-1 font-mono">
                {o.port}/{o.protocol} {o.service && <span className="text-muted-foreground">· {o.service}</span>}
              </li>
            ))}
          </ul>
        )}
      </Card>

      <Card icon={<Layers className="h-4 w-4" />} title={`Endpoints (${result.endpoints.length})`}>
        {result.endpoints.length === 0 ? <Empty>No endpoints observed.</Empty> : (
          <div className="max-h-60 overflow-auto">
            <table className="w-full text-xs">
              <thead className="text-[10px] uppercase tracking-wide text-muted-foreground">
                <tr><th className="py-1 text-left">Path</th><th className="py-1 text-left">Status</th><th className="py-1 text-left">Bytes</th></tr>
              </thead>
              <tbody>
                {result.endpoints.map((e) => (
                  <tr key={e.url} className="border-t border-border/40 font-mono">
                    <td className="py-1 pr-2 truncate">{e.path}</td>
                    <td className="py-1 pr-2">{e.status}</td>
                    <td className="py-1 pr-2 text-muted-foreground">{e.bytes}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>

      <Card icon={<Network className="h-4 w-4" />} title={`APIs (${result.apis.length})`}>
        {result.apis.length === 0 ? <Empty>No API surfaces enumerated.</Empty> : (
          <ul className="space-y-1 text-xs">
            {result.apis.map((a) => (
              <li key={a.url} className="rounded border border-border/60 bg-muted/20 px-2 py-1">
                <div className="font-mono truncate">{a.url}</div>
                <div className="text-muted-foreground">{a.kind} · {a.detail}</div>
              </li>
            ))}
          </ul>
        )}
      </Card>

      <Card icon={<Boxes className="h-4 w-4" />} title={`Technologies (${result.technologies.length})`}>
        {result.technologies.length === 0 ? <Empty>No technology fingerprints matched.</Empty> : (
          <ul className="flex flex-wrap gap-1 text-xs">
            {result.technologies.map((t) => (
              <li key={t.name} className="rounded-full border border-border/60 bg-muted/20 px-2 py-0.5" title={`${t.evidenceSource}: ${t.evidenceValue}`}>
                {t.name}{t.version && <span className="text-muted-foreground"> {t.version}</span>}
              </li>
            ))}
          </ul>
        )}
      </Card>

      <Card icon={<Layers className="h-4 w-4" />} title={`CVE correlations (${result.cveMatches.length})`}>
        {result.cveMatches.length === 0 ? <Empty>No CVEs matched the disclosed versions via OSV.dev.</Empty> : (
          <ul className="max-h-56 space-y-1 overflow-auto text-xs">
            {result.cveMatches.map((c) => (
              <li key={c.id} className="rounded border border-border/60 bg-muted/20 px-2 py-1">
                <div className="flex items-baseline justify-between gap-2">
                  <span className="font-mono">{c.id}</span>
                  <span className="text-[10px] uppercase text-muted-foreground">{c.severity ?? "unscored"}{c.cvss !== null && ` · ${c.cvss}`}</span>
                </div>
                <div className="text-muted-foreground">{c.product} {c.version}</div>
                <div className="line-clamp-2">{c.summary}</div>
              </li>
            ))}
          </ul>
        )}
      </Card>
    </section>
  );
}

function Card({ icon, title, children }: { icon: React.ReactNode; title: string; children: React.ReactNode }) {
  return (
    <div className="rounded-lg border border-border/60 bg-card p-4">
      <div className="mb-2 flex items-center gap-2 text-sm font-semibold">{icon}{title}</div>
      {children}
    </div>
  );
}

function Empty({ children }: { children: React.ReactNode }) {
  return <p className="text-xs text-muted-foreground">{children}</p>;
}
