import { createFileRoute } from "@tanstack/react-router";
import { useMutation } from "@tanstack/react-query";
import { useServerFn } from "@tanstack/react-start";
import { useState } from "react";
import { runScan, analyzeScan } from "@/lib/scan.functions";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Separator } from "@/components/ui/separator";

type ScanResult = Awaited<ReturnType<typeof runScan>>;
type Finding = ScanResult["findings"][number];

const TITLE = "SentinelAI — Passive Attack Surface Assessment";
const DESCRIPTION =
  "Run non-intrusive reconnaissance on a domain you own: DNS, certificate transparency subdomains, security headers, CORS, cookies, email spoofing posture and AI risk analysis.";

export const Route = createFileRoute("/")({
  head: () => ({
    meta: [
      { title: TITLE },
      { name: "description", content: DESCRIPTION },
      { property: "og:title", content: TITLE },
      { property: "og:description", content: DESCRIPTION },
      { property: "og:type", content: "website" },
      { name: "twitter:card", content: "summary_large_image" },
    ],
  }),
  component: Index,
});

const SEVERITY_STYLES: Record<Finding["severity"], string> = {
  critical: "bg-destructive/15 text-destructive border-destructive/40",
  high: "bg-warning/15 text-warning border-warning/40",
  medium: "bg-caution/15 text-caution border-caution/40",
  low: "bg-muted text-muted-foreground border-border",
  info: "bg-primary/10 text-primary border-primary/30",
};

const SEVERITY_ORDER: Finding["severity"][] = ["critical", "high", "medium", "low", "info"];

function Stat({ label, value }: { label: string; value: string | number }) {
  return (
    <div className="rounded-lg border border-border bg-card px-4 py-3">
      <div className="font-mono text-2xl text-foreground">{value}</div>
      <div className="text-xs uppercase tracking-widest text-muted-foreground">{label}</div>
    </div>
  );
}

function RecordList({ label, values }: { label: string; values: string[] }) {
  if (!values.length) return null;
  return (
    <div className="space-y-1">
      <div className="text-xs uppercase tracking-widest text-muted-foreground">{label}</div>
      <ul className="space-y-1">
        {values.map((v) => (
          <li key={v} className="break-all font-mono text-sm text-foreground">
            {v}
          </li>
        ))}
      </ul>
    </div>
  );
}

function Index() {
  const [target, setTarget] = useState("");
  const [authorized, setAuthorized] = useState(false);
  const scanFn = useServerFn(runScan);
  const analyzeFn = useServerFn(analyzeScan);

  const scan = useMutation({
    mutationFn: (t: string) => scanFn({ data: { target: t } }),
  });
  const analysis = useMutation({
    mutationFn: (result: ScanResult) => analyzeFn({ data: { result } }),
  });

  const result = scan.data;

  const counts = SEVERITY_ORDER.map((s) => ({
    severity: s,
    count: result?.findings.filter((f) => f.severity === s).length ?? 0,
  }));

  function downloadReport() {
    if (!result) return;
    const blob = new Blob([JSON.stringify({ ...result, aiAnalysis: analysis.data?.content }, null, 2)], {
      type: "application/json",
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `sentinelai-${result.target}-${result.scannedAt.slice(0, 10)}.json`;
    a.click();
    URL.revokeObjectURL(url);
  }

  return (
    <main className="min-h-screen bg-background">
      <div className="mx-auto max-w-5xl px-5 py-12">
        <header className="mb-10">
          <div className="flex items-center gap-2 font-mono text-xs uppercase tracking-[0.3em] text-primary">
            <span className="h-2 w-2 rounded-full bg-primary" /> SentinelAI
          </div>
          <h1 className="mt-4 text-4xl font-semibold tracking-tight text-foreground sm:text-5xl">
            Passive attack surface assessment
          </h1>
          <p className="mt-3 max-w-2xl text-muted-foreground">
            Non-intrusive reconnaissance against a domain you are authorized to test: DNS and
            email posture, certificate-transparency subdomains, live host fingerprinting, exposed
            paths, transport and header hardening — correlated by AI into a remediation roadmap.
          </p>
        </header>

        <Card className="border-border bg-card">
          <CardContent className="pt-6">
            <form
              className="flex flex-col gap-3 sm:flex-row"
              onSubmit={(e) => {
                e.preventDefault();
                analysis.reset();
                scan.mutate(target);
              }}
            >
              <Input
                value={target}
                onChange={(e) => setTarget(e.target.value)}
                placeholder="example.com"
                autoComplete="off"
                spellCheck={false}
                className="font-mono"
                aria-label="Target domain"
              />
              <Button type="submit" disabled={!authorized || !target.trim() || scan.isPending}>
                {scan.isPending ? "Scanning…" : "Run assessment"}
              </Button>
            </form>
            <label className="mt-4 flex items-start gap-2 text-sm text-muted-foreground">
              <input
                type="checkbox"
                checked={authorized}
                onChange={(e) => setAuthorized(e.target.checked)}
                className="mt-1 accent-[var(--primary)]"
              />
              I own this domain or have written authorization to assess it. All checks are passive
              HTTP/DNS requests — no exploitation, brute force or port scanning is performed.
            </label>
            {scan.error ? (
              <p className="mt-4 text-sm text-destructive">{(scan.error as Error).message}</p>
            ) : null}
          </CardContent>
        </Card>

        {scan.isPending ? (
          <p className="mt-8 animate-pulse font-mono text-sm text-muted-foreground">
            Resolving DNS · querying certificate transparency · probing live hosts…
          </p>
        ) : null}

        {result ? (
          <div className="mt-10 space-y-8">
            <section className="grid grid-cols-2 gap-3 sm:grid-cols-5">
              <Stat label="Grade" value={result.grade} />
              <Stat label="Score" value={`${result.score}/100`} />
              <Stat label="Findings" value={result.findings.length} />
              <Stat label="Subdomains" value={result.subdomains.length} />
              <Stat label="Duration" value={`${(result.durationMs / 1000).toFixed(1)}s`} />
            </section>

            <div className="flex flex-wrap items-center gap-2">
              {counts.map((c) => (
                <Badge key={c.severity} variant="outline" className={SEVERITY_STYLES[c.severity]}>
                  {c.count} {c.severity}
                </Badge>
              ))}
              <div className="ml-auto flex gap-2">
                <Button
                  variant="secondary"
                  size="sm"
                  disabled={analysis.isPending}
                  onClick={() => analysis.mutate(result)}
                >
                  {analysis.isPending ? "Analyzing…" : "AI analysis"}
                </Button>
                <Button variant="outline" size="sm" onClick={downloadReport}>
                  Export report
                </Button>
              </div>
            </div>

            <Tabs defaultValue="findings">
              <TabsList>
                <TabsTrigger value="findings">Findings</TabsTrigger>
                <TabsTrigger value="surface">Attack surface</TabsTrigger>
                <TabsTrigger value="infra">Infrastructure</TabsTrigger>
                <TabsTrigger value="ai">AI report</TabsTrigger>
              </TabsList>

              <TabsContent value="findings" className="space-y-3 pt-4">
                {result.findings.length === 0 ? (
                  <p className="text-sm text-muted-foreground">No issues detected.</p>
                ) : null}
                {SEVERITY_ORDER.flatMap((s) => result.findings.filter((f) => f.severity === s)).map(
                  (f) => (
                    <Card key={f.id} className="border-border bg-card">
                      <CardHeader className="pb-2">
                        <div className="flex flex-wrap items-center gap-2">
                          <Badge variant="outline" className={SEVERITY_STYLES[f.severity]}>
                            {f.severity}
                          </Badge>
                          <CardTitle className="text-base">{f.title}</CardTitle>
                          <span className="ml-auto text-xs uppercase tracking-widest text-muted-foreground">
                            {f.category}
                          </span>
                        </div>
                      </CardHeader>
                      <CardContent className="space-y-2 text-sm">
                        <p className="break-all font-mono text-xs text-muted-foreground">
                          {f.evidence}
                        </p>
                        <p className="text-foreground">{f.recommendation}</p>
                      </CardContent>
                    </Card>
                  ),
                )}
              </TabsContent>

              <TabsContent value="surface" className="space-y-6 pt-4">
                <Card className="border-border bg-card">
                  <CardHeader className="pb-2">
                    <CardTitle className="text-base">
                      Subdomains from certificate transparency
                    </CardTitle>
                  </CardHeader>
                  <CardContent className="space-y-2">
                    {result.subdomains.length === 0 ? (
                      <p className="text-sm text-muted-foreground">None discovered.</p>
                    ) : (
                      result.subdomains.map((s) => (
                        <div
                          key={s.host}
                          className="flex flex-wrap items-center gap-3 border-b border-border py-2 last:border-0"
                        >
                          <span className="font-mono text-sm text-foreground">{s.host}</span>
                          <Badge
                            variant="outline"
                            className={
                              s.status && s.status < 400
                                ? "border-primary/40 bg-primary/10 text-primary"
                                : "border-border text-muted-foreground"
                            }
                          >
                            {s.status ?? "no response"}
                          </Badge>
                          {s.title ? (
                            <span className="truncate text-xs text-muted-foreground">
                              {s.title}
                            </span>
                          ) : null}
                        </div>
                      ))
                    )}
                  </CardContent>
                </Card>

                <Card className="border-border bg-card">
                  <CardHeader className="pb-2">
                    <CardTitle className="text-base">Path exposure checks</CardTitle>
                  </CardHeader>
                  <CardContent className="space-y-1">
                    {result.exposedPaths.map((p) => (
                      <div key={p.path} className="flex items-center gap-3 py-1 font-mono text-sm">
                        <span
                          className={
                            p.status === 200 ? "text-destructive" : "text-muted-foreground"
                          }
                        >
                          {p.status}
                        </span>
                        <span className="text-foreground">{p.path}</span>
                        <span className="ml-auto text-xs text-muted-foreground">{p.note}</span>
                      </div>
                    ))}
                  </CardContent>
                </Card>
              </TabsContent>

              <TabsContent value="infra" className="space-y-6 pt-4">
                <Card className="border-border bg-card">
                  <CardHeader className="pb-2">
                    <CardTitle className="text-base">DNS &amp; email posture</CardTitle>
                  </CardHeader>
                  <CardContent className="grid gap-4 sm:grid-cols-2">
                    <RecordList label="A" values={result.dns.a} />
                    <RecordList label="AAAA" values={result.dns.aaaa} />
                    <RecordList label="CNAME" values={result.dns.cname} />
                    <RecordList label="MX" values={result.dns.mx} />
                    <RecordList label="NS" values={result.dns.ns} />
                    <RecordList label="CAA" values={result.dns.caa} />
                    <RecordList label="SPF" values={result.email.spf ? [result.email.spf] : []} />
                    <RecordList
                      label="DMARC"
                      values={result.email.dmarc ? [result.email.dmarc] : []}
                    />
                  </CardContent>
                </Card>

                <Card className="border-border bg-card">
                  <CardHeader className="pb-2">
                    <CardTitle className="text-base">HTTP fingerprint</CardTitle>
                  </CardHeader>
                  <CardContent className="space-y-3 text-sm">
                    {result.http ? (
                      <>
                        <div className="font-mono text-xs text-muted-foreground">
                          {result.http.status} · {result.http.finalUrl}
                        </div>
                        {result.technologies.length ? (
                          <div className="flex flex-wrap gap-2">
                            {result.technologies.map((t) => (
                              <Badge key={t} variant="secondary">
                                {t}
                              </Badge>
                            ))}
                          </div>
                        ) : null}
                        <Separator />
                        <div className="max-h-72 space-y-1 overflow-auto">
                          {Object.entries(result.http.headers).map(([k, v]) => (
                            <div key={k} className="break-all font-mono text-xs">
                              <span className="text-primary">{k}</span>
                              <span className="text-muted-foreground">: {v}</span>
                            </div>
                          ))}
                        </div>
                      </>
                    ) : (
                      <p className="text-muted-foreground">No HTTPS response captured.</p>
                    )}
                  </CardContent>
                </Card>
              </TabsContent>

              <TabsContent value="ai" className="pt-4">
                <Card className="border-border bg-card">
                  <CardContent className="pt-6">
                    {analysis.error ? (
                      <p className="text-sm text-destructive">
                        {(analysis.error as Error).message}
                      </p>
                    ) : null}
                    {analysis.data ? (
                      <pre className="whitespace-pre-wrap font-sans text-sm leading-relaxed text-foreground">
                        {analysis.data.content}
                      </pre>
                    ) : (
                      <p className="text-sm text-muted-foreground">
                        Run “AI analysis” to correlate these findings into an executive summary and
                        a 30/60/90 day remediation roadmap.
                      </p>
                    )}
                  </CardContent>
                </Card>
              </TabsContent>
            </Tabs>
          </div>
        ) : null}
      </div>
    </main>
  );
}
