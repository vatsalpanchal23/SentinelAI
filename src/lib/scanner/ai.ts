/**
 * AI security analysis.
 *
 * Sends a compact, redacted digest of the scan evidence to the Lovable AI
 * Gateway and returns a strictly-typed analysis. The gateway response is
 * clearly labelled as inference — the caller displays it separately from
 * scanner findings so evidence-derived data is never mixed with model output.
 */

import type { EngineResult } from "./engine";

export type AiAnalysis = {
  available: boolean;
  reason?: string;
  executiveSummary: string;
  riskNarrative: string;
  prioritizedActions: { title: string; rationale: string; findingIds: string[] }[];
  detectedThemes: string[];
  raw?: string;
};

function digest(result: EngineResult): string {
  const findings = result.findings.slice(0, 40).map((f) => ({
    id: f.id, title: f.title, severity: f.severity, confidence: f.confidence,
    category: f.category, asset: f.asset, endpoint: f.endpoint,
    cwe: f.cwe, owasp: f.owasp, cvss: f.cvss,
  }));
  return JSON.stringify({
    target: result.target,
    profile: result.profile,
    modules: result.modules.map((m) => ({ key: m.key, status: m.status, discovered: m.itemsDiscovered, note: m.note })),
    technologies: result.technologies.map((t) => ({ name: t.name, version: t.version })),
    endpoints: result.endpoints.slice(0, 30).map((e) => ({ path: e.path, status: e.status })),
    apis: result.apis.map((a) => ({ kind: a.kind, detail: a.detail })),
    attackPaths: result.attackPaths.map((p) => ({ title: p.title, severity: p.severity, likelihood: p.likelihood })),
    findings,
    ports: result.ports.available ? result.ports.open.slice(0, 20) : { unavailable: result.ports.reason },
  });
}

const SYSTEM_PROMPT = `You are a senior offensive security consultant reviewing a machine-generated \
vulnerability assessment. You do NOT invent findings that were not observed. Your job is to \
synthesise the evidence into an executive-quality narrative, identify systemic themes, and \
propose a prioritised remediation order. Output MUST be a single JSON object matching the \
schema described in the user message. Reference finding IDs verbatim; do not fabricate IDs.`;

const RESPONSE_SCHEMA = {
  type: "object",
  additionalProperties: false,
  required: ["executiveSummary", "riskNarrative", "prioritizedActions", "detectedThemes"],
  properties: {
    executiveSummary: { type: "string" },
    riskNarrative: { type: "string" },
    prioritizedActions: {
      type: "array",
      items: {
        type: "object",
        additionalProperties: false,
        required: ["title", "rationale", "findingIds"],
        properties: {
          title: { type: "string" },
          rationale: { type: "string" },
          findingIds: { type: "array", items: { type: "string" } },
        },
      },
    },
    detectedThemes: { type: "array", items: { type: "string" } },
  },
} as const;

export async function aiAnalyze(result: EngineResult): Promise<AiAnalysis> {
  const apiKey = import.meta.env.VITE_LOVABLE_API_KEY as string | undefined;
  if (!apiKey) {
    return {
      available: false,
      reason: "AI Gateway is not configured on this deployment.",
      executiveSummary: "",
      riskNarrative: "",
      prioritizedActions: [],
      detectedThemes: [],
    };
  }
  try {
    const res = await fetch("https://ai.gateway.lovable.dev/v1/chat/completions", {
      method: "POST",
      headers: {
        authorization: `Bearer ${apiKey}`,
        "content-type": "application/json",
      },
      body: JSON.stringify({
        model: "google/gemini-2.5-flash",
        messages: [
          { role: "system", content: SYSTEM_PROMPT },
          {
            role: "user",
            content: `Scan evidence digest follows. Return ONLY JSON matching the schema.\n\n${digest(result)}`,
          },
        ],
        response_format: {
          type: "json_schema",
          json_schema: { name: "analysis", strict: true, schema: RESPONSE_SCHEMA },
        },
      }),
    });
    if (!res.ok) {
      return {
        available: false,
        reason: `AI Gateway returned HTTP ${res.status}`,
        executiveSummary: "",
        riskNarrative: "",
        prioritizedActions: [],
        detectedThemes: [],
      };
    }
    const body = (await res.json()) as {
      choices?: { message?: { content?: string } }[];
    };
    const raw = body.choices?.[0]?.message?.content ?? "";
    try {
      const parsed = JSON.parse(raw) as Omit<AiAnalysis, "available" | "raw">;
      return { available: true, raw, ...parsed };
    } catch {
      return {
        available: false,
        reason: "AI Gateway returned non-JSON content",
        executiveSummary: "",
        riskNarrative: "",
        prioritizedActions: [],
        detectedThemes: [],
        raw,
      };
    }
  } catch (err) {
    return {
      available: false,
      reason: `AI Gateway unreachable — ${err instanceof Error ? err.message : String(err)}`,
      executiveSummary: "",
      riskNarrative: "",
      prioritizedActions: [],
      detectedThemes: [],
    };
  }
}
