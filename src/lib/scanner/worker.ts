/**
 * Scanner-worker client.
 *
 * The heavy tools (Nmap, Subfinder, Amass, masscan, nuclei) do not run in
 * the Workers runtime. When the user configures a self-hosted worker via
 * SCANNER_WORKER_URL/SCANNER_WORKER_TOKEN, requests are proxied to it. When
 * the worker is not configured, every module that needs it returns a clean
 * "unavailable" status instead of pretending to have run.
 *
 * The worker exposes:
 *   POST /portscan   {host, ports?} -> {open: [{port, service, banner?}], scannedPorts, tool}
 *   POST /subdomains {domain}       -> {names: string[], sources: string[], tool}
 *   GET  /health                    -> {ok: true, tools: string[]}
 */

export type WorkerConfig = {
  url: string;
  token: string;
};

export function readWorkerConfig(): WorkerConfig | null {
  const url = import.meta.env.VITE_SCANNER_WORKER_URL as string | undefined;
  const token = import.meta.env.VITE_SCANNER_WORKER_TOKEN as string | undefined;
  if (!url || !token) return null;
  try {
    const parsed = new URL(url);
    if (parsed.protocol !== "https:" && parsed.protocol !== "http:") return null;
    return { url: parsed.origin + parsed.pathname.replace(/\/$/, ""), token };
  } catch {
    return null;
  }
}

export type WorkerUnavailable = { available: false; reason: string };
export type PortScanResult =
  | WorkerUnavailable
  | {
      available: true;
      open: { port: number; protocol: "tcp" | "udp"; service: string | null; banner: string | null }[];
      scannedPorts: number;
      tool: string;
      durationMs: number;
    };

export type SubdomainResult =
  | WorkerUnavailable
  | { available: true; names: string[]; sources: string[]; tool: string };

async function callWorker<T>(path: string, body: unknown, timeoutMs: number): Promise<T | WorkerUnavailable> {
  const cfg = readWorkerConfig();
  if (!cfg) {
    return {
      available: false,
      reason:
        "Tool unavailable — no scanner-worker is configured. Deploy the SentinelAI scanner-worker container and set SCANNER_WORKER_URL / SCANNER_WORKER_TOKEN to enable heavy tooling.",
    };
  }
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const res = await fetch(`${cfg.url}${path}`, {
      method: "POST",
      signal: ctrl.signal,
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${cfg.token}`,
      },
      body: JSON.stringify(body),
    });
    if (!res.ok) {
      return { available: false, reason: `Scanner-worker returned HTTP ${res.status}` };
    }
    return (await res.json()) as T;
  } catch (err) {
    return {
      available: false,
      reason: `Scanner-worker unreachable — ${err instanceof Error ? err.message : String(err)}`,
    };
  } finally {
    clearTimeout(timer);
  }
}

export async function workerPortScan(host: string, ports?: number[]): Promise<PortScanResult> {
  const body = ports ? { host, ports } : { host };
  return callWorker<PortScanResult>("/portscan", body, 120_000);
}

export async function workerEnumSubdomains(domain: string): Promise<SubdomainResult> {
  return callWorker<SubdomainResult>("/subdomains", { domain }, 90_000);
}
