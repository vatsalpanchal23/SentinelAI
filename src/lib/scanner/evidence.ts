/**
 * Evidence store.
 *
 * Every finding must cite at least one record here. The store holds verbatim
 * captured artefacts — never paraphrase, never synthesise. If the scanner did
 * not observe it, it does not go in.
 */

import { LIMITS } from "./net";
import type { Evidence, HttpProbe } from "./types";

export class EvidenceStore {
  private items: Evidence[] = [];
  private counter = 0;

  add(input: {
    module: string;
    source: string;
    content: string;
    contentType: Evidence["contentType"];
  }): string {
    const id = `ev-${(++this.counter).toString().padStart(4, "0")}`;
    const truncated = input.content.length > LIMITS.MAX_EVIDENCE_BYTES;
    this.items.push({
      id,
      module: input.module,
      source: input.source,
      content: truncated ? input.content.slice(0, LIMITS.MAX_EVIDENCE_BYTES) : input.content,
      contentType: input.contentType,
      capturedAt: new Date().toISOString(),
      truncated,
    });
    return id;
  }

  /** Capture the response headers of a probe verbatim. */
  addHeaders(module: string, probe: HttpProbe): string {
    const lines = Object.entries(probe.headers)
      .map(([k, v]) => `${k}: ${v}`)
      .sort()
      .join("\n");
    return this.add({
      module,
      source: `${probe.status} ${probe.finalUrl}`,
      content: `HTTP ${probe.status}\n${lines}`,
      contentType: "http-headers",
    });
  }

  addDnsRecord(module: string, host: string, type: string, values: string[]): string {
    return this.add({
      module,
      source: `DNS ${type} ${host}`,
      content: values.join("\n"),
      contentType: "dns-record",
    });
  }

  get(id: string): Evidence | undefined {
    return this.items.find((e) => e.id === id);
  }

  all(): Evidence[] {
    return [...this.items];
  }

  get size(): number {
    return this.items.length;
  }
}
