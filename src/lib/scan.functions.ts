import { createServerFn } from "@tanstack/react-start";

export const runScan = createServerFn({ method: "POST" })
  .inputValidator((data: { target: string }) => {
    if (!data || typeof data.target !== "string" || !data.target.trim()) {
      throw new Error("A target domain is required.");
    }
    return { target: data.target.trim().slice(0, 253) };
  })
  .handler(async ({ data }) => {
    const recon = await import("./recon.server");
    const host = recon.normalizeTarget(data.target);
    if (!recon.isValidHostname(host)) {
      throw new Error(`"${data.target}" is not a valid domain name.`);
    }
    if (recon.isDisallowedTarget(host)) {
      throw new Error("Internal, loopback and raw-IP targets are not permitted.");
    }
    return recon.runFullScan(host);
  });

export const analyzeScan = createServerFn({ method: "POST" })
  .inputValidator((data: { result: unknown }) => {
    if (!data?.result) throw new Error("Scan result required.");
    return data;
  })
  .handler(async ({ data }) => {
    const apiKey = process.env["LOVABLE_API_KEY"] ?? process.env["AI_API_KEY"];
    if (!apiKey)
      throw new Error(
        "AI is not configured. Set AI_API_KEY (and optionally AI_BASE_URL / AI_MODEL) in your .env file.",
      );

    const recon = await import("./recon.server");
    const content = await recon.aiAnalysis(
      data.result as Awaited<ReturnType<typeof recon.runFullScan>>,
      apiKey,
    );
    return { content };
  });
