import { useEffect, useState, type ReactNode } from "react";
import { QueryClient, QueryClientProvider, useMutation } from "@tanstack/react-query";
import { Activity, ChevronRight, CircleDot, FileCheck2, Moon, ShieldCheck, Sun, Target, Waves } from "lucide-react";
import { ErrorBoundary } from "@/components/error-boundary";
import { Toaster } from "@/components/ui/toaster";
import { TooltipProvider } from "@/components/ui/tooltip";
import { ScanConfigForm } from "@/components/scan/ScanConfigForm";
import { ScanResults } from "@/components/scan/ScanResults";
import { analyzeScan, startScan, type StartScanInput } from "@/lib/scan.functions";
import { Router as WouterRouter, Route, Switch, useLocation } from "wouter";
import NotFound from "@/pages/not-found";

const queryClient = new QueryClient();

function Brand() {
  return (
    <div className="flex items-center gap-3">
      <div className="brand-mark grid h-10 w-10 place-items-center rounded-xl">
        <ShieldCheck className="h-6 w-6" strokeWidth={2.3} />
      </div>
      <div>
        <div className="brand-wordmark text-[15px] font-extrabold tracking-[0.13em]">SENTINEL<span className="brand-ai">AI</span></div>
        <div className="brand-subtitle mt-0.5 text-[9px] font-bold uppercase tracking-[0.16em]">Security console</div>
      </div>
    </div>
  );
}

function ThemeToggle({ dark, onToggle }: { dark: boolean; onToggle: () => void }) {
  return (
    <button
      type="button"
      aria-label={dark ? "Switch to light theme" : "Switch to dark theme"}
      aria-pressed={dark}
      title={dark ? "Switch to light theme" : "Switch to dark theme"}
      onClick={onToggle}
      className="theme-toggle inline-flex h-9 w-9 items-center justify-center rounded-full border transition hover:brightness-105 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary focus-visible:ring-offset-2 focus-visible:ring-offset-background"
    >
      {dark ? <Sun className="h-4 w-4" /> : <Moon className="h-4 w-4" />}
    </button>
  );
}

function Home() {
  const [config, setConfig] = useState<StartScanInput | null>(null);
  const [dark, setDark] = useState(() => {
    if (typeof window === "undefined") return true;
    const stored = window.localStorage.getItem("sentinelai-theme");
    return stored ? stored === "dark" : true;
  });
  const scan = useMutation({ mutationFn: (input: StartScanInput) => startScan(input) });
  const ai = useMutation({ mutationFn: () => scan.data ? analyzeScan(scan.data) : Promise.reject(new Error("No scan result to analyse")) });

  useEffect(() => {
    document.documentElement.classList.toggle("dark", dark);
    document.documentElement.style.colorScheme = dark ? "dark" : "light";
    window.localStorage.setItem("sentinelai-theme", dark ? "dark" : "light");
  }, [dark]);

  const submit = (input: StartScanInput) => {
    setConfig(input);
    ai.reset();
    scan.mutate(input);
  };

  return (
    <div className="min-h-[100dvh] bg-background text-foreground">
      <header className="app-header sticky top-0 z-20 border-b backdrop-blur">
        <div className="mx-auto flex max-w-[1520px] items-center justify-between px-4 py-3 sm:px-8">
          <Brand />
          <div className="flex items-center gap-3">
            <ThemeToggle dark={dark} onToggle={() => setDark((value) => !value)} />
            <div className="status-pill status-pill-scanner hidden items-center gap-2 rounded-full px-3 py-1.5 text-[10px] font-bold uppercase tracking-[0.12em] sm:flex"><CircleDot className="h-3 w-3" /> Browser scanner</div>
            <div className="status-pill status-pill-authorized rounded-full px-3 py-1.5 text-[10px] font-bold uppercase tracking-[0.12em]">Authorized targets only</div>
          </div>
        </div>
      </header>
      <div className="mx-auto grid max-w-[1520px] lg:grid-cols-[260px_1fr]">
        <aside className="app-sidebar hidden min-h-[calc(100dvh-65px)] border-r px-5 py-7 lg:block">
          <div className="sidebar-label text-[10px] font-extrabold uppercase tracking-[0.18em]">Workspace</div>
          <nav className="mt-4 space-y-1">
            <div className="sidebar-active flex items-center gap-3 rounded-xl px-3 py-2.5 text-xs font-bold"><Target className="h-4 w-4" /> New assessment <ChevronRight className="ml-auto h-3.5 w-3.5" /></div>
            <div className="sidebar-muted flex items-center gap-3 rounded-xl px-3 py-2.5 text-xs font-medium"><Activity className="h-4 w-4" /> Live telemetry</div>
            <div className="sidebar-muted flex items-center gap-3 rounded-xl px-3 py-2.5 text-xs font-medium"><FileCheck2 className="h-4 w-4" /> Assessment reports</div>
          </nav>
          <div className="sidebar-divider mt-14 border-t pt-5">
            <div className="sidebar-label flex items-center gap-2 text-[10px] font-extrabold uppercase tracking-[0.16em]"><Waves className="h-3.5 w-3.5 text-primary" /> Operating principles</div>
            <p className="sidebar-copy mt-3 text-[11px] leading-5">Every finding is traceable to captured evidence. Unavailable tools are reported, never implied.</p>
          </div>
          <div className="sidebar-foot mt-auto pt-16 font-mono text-[9px] uppercase tracking-[0.1em]">SNTL / 01<br />Evidence first</div>
        </aside>
        <main className="console-grid min-w-0 px-4 py-6 sm:px-8 sm:py-8 xl:px-12">
          <div className="mx-auto max-w-[1120px]">
            <div className="mb-7 flex flex-col justify-between gap-3 sm:flex-row sm:items-end">
              <div>
                <div className="mb-2 flex items-center gap-2 text-[10px] font-extrabold uppercase tracking-[0.2em] text-primary"><span className="h-1.5 w-1.5 rounded-full bg-primary" /> Assessment workspace</div>
                <h1 className="text-3xl font-extrabold tracking-[-0.04em] text-foreground sm:text-4xl">See what the surface reveals.</h1>
                <p className="mt-2 max-w-2xl text-sm leading-6 text-muted-foreground">Run a scoped, evidence-driven vulnerability assessment against an authorized target. Results stay grounded in what the scanner actually observed.</p>
              </div>
              <div className="font-mono text-[10px] uppercase tracking-[0.12em] text-muted-foreground">Run ID <span className="font-medium text-foreground/80">{scan.data ? scan.data.startedAt.slice(0, 16).replace("T", " / ") : "Awaiting target"}</span></div>
            </div>
            <div className="grid gap-5 xl:grid-cols-[340px_1fr]">
              <ScanConfigForm onSubmit={submit} disabled={scan.isPending} />
              <ScanResults config={config} scan={scan} ai={ai} onRequestAi={() => ai.mutate()} />
            </div>
          </div>
        </main>
      </div>
    </div>
  );
}

function Router() {
  return <RoutedErrorBoundary><Switch><Route path="/" component={Home} /><Route component={NotFound} /></Switch></RoutedErrorBoundary>;
}

function RoutedErrorBoundary({ children }: { children: ReactNode }) {
  const [location] = useLocation();
  return <ErrorBoundary resetKey={location}>{children}</ErrorBoundary>;
}

function App() {
  return <QueryClientProvider client={queryClient}><TooltipProvider><WouterRouter base={import.meta.env.BASE_URL.replace(/\/$/, "")}><Router /></WouterRouter><Toaster /></TooltipProvider></QueryClientProvider>;
}

export default App;