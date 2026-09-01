/**
 * Attack-path correlation.
 *
 * Combines multiple findings into concrete, plausible chains that describe how
 * observed weaknesses could be composed to achieve an impact. Every step in a
 * chain references a real finding — a chain with no supporting findings is
 * never produced.
 */

import type { Finding } from "./types";

export type AttackPathStep = {
  order: number;
  action: string;
  findingIds: string[];
};

export type AttackPath = {
  id: string;
  title: string;
  impact: string;
  severity: "critical" | "high" | "medium" | "low";
  likelihood: "high" | "medium" | "low";
  steps: AttackPathStep[];
};

function has(findings: Finding[], predicate: (f: Finding) => boolean): Finding[] {
  return findings.filter(predicate);
}

export function buildAttackPaths(findings: Finding[]): AttackPath[] {
  const paths: AttackPath[] = [];
  let n = 0;
  const id = () => `path-${++n}`;

  const exposedSecrets = has(findings, (f) => /env file|git repository|backup archive|actuator/i.test(f.title));
  const noHsts = has(findings, (f) => f.title.includes("Strict Transport Security"));
  const plainHttp = has(findings, (f) => f.title.includes("Plaintext HTTP served"));
  const weakCookies = has(findings, (f) => /Cookie ".*" missing/.test(f.title));
  const missingCsrfHint = has(findings, (f) => /SameSite attribute missing|SameSite=None/.test(f.description));
  const openCors = has(findings, (f) => f.title.startsWith("CORS reflects") || f.title === "Permissive CORS policy");
  const noCsp = has(findings, (f) => f.title === "No Content-Security-Policy" || f.title.includes("CSP weakened"));
  const cveHigh = has(findings, (f) => f.category === "Known vulnerability" && (f.severity === "critical" || f.severity === "high"));
  const swaggerOpen = has(findings, (f) => /Swagger UI|API documentation UI/i.test(f.title));
  const graphqlOpen = has(findings, (f) => /GraphQL endpoint/i.test(f.title));

  if (exposedSecrets.length > 0) {
    paths.push({
      id: id(),
      title: "Credential leak via exposed source or configuration",
      impact:
        "An unauthenticated attacker downloads the exposed artefact, extracts credentials or signing keys, and pivots into any system that trusts them.",
      severity: "critical",
      likelihood: "high",
      steps: [
        { order: 1, action: "Retrieve the exposed artefact directly over HTTPS.", findingIds: exposedSecrets.map((f) => f.id) },
        { order: 2, action: "Parse the retrieved content for credentials, API keys, JWT signing secrets, or database URIs.", findingIds: exposedSecrets.map((f) => f.id) },
        { order: 3, action: "Authenticate against the disclosed services using the extracted material.", findingIds: exposedSecrets.map((f) => f.id) },
      ],
    });
  }

  if (plainHttp.length > 0 || (noHsts.length > 0 && weakCookies.length > 0)) {
    paths.push({
      id: id(),
      title: "Session hijack via network-adjacent traffic interception",
      impact:
        "An attacker on the same network path downgrades a connection to plaintext, reads the session cookie, and replays it to impersonate the user.",
      severity: plainHttp.length > 0 ? "high" : "medium",
      likelihood: plainHttp.length > 0 ? "medium" : "low",
      steps: [
        { order: 1, action: "Coerce the client onto plaintext HTTP for at least one request.", findingIds: [...plainHttp, ...noHsts].map((f) => f.id) },
        { order: 2, action: "Read the session cookie in transit.", findingIds: weakCookies.map((f) => f.id) },
        { order: 3, action: "Replay the captured cookie to the origin to inherit the session.", findingIds: weakCookies.map((f) => f.id) },
      ],
    });
  }

  if (openCors.length > 0) {
    paths.push({
      id: id(),
      title: "Cross-origin data theft via reflected CORS with credentials",
      impact:
        "Any website an authenticated user visits can read that user's data from the affected endpoint through their browser.",
      severity: openCors.some((f) => f.severity === "critical") ? "critical" : "medium",
      likelihood: "medium",
      steps: [
        { order: 1, action: "Lure the target user to a page under the attacker's control.", findingIds: openCors.map((f) => f.id) },
        { order: 2, action: "Issue a credentialed cross-origin fetch to the affected endpoint from the attacker page.", findingIds: openCors.map((f) => f.id) },
        { order: 3, action: "Exfiltrate the response body to attacker-controlled storage.", findingIds: openCors.map((f) => f.id) },
      ],
    });
  }

  if (missingCsrfHint.length > 0 && noCsp.length > 0) {
    paths.push({
      id: id(),
      title: "Cross-site request forgery amplified by missing CSP",
      impact:
        "State-changing requests can be forged from any origin using the victim's session, with no meaningful browser-side defence to inspect the request.",
      severity: "medium",
      likelihood: "medium",
      steps: [
        { order: 1, action: "Craft a cross-site request that triggers a sensitive state change.", findingIds: missingCsrfHint.map((f) => f.id) },
        { order: 2, action: "Trigger it from an attacker page while the victim is authenticated.", findingIds: missingCsrfHint.map((f) => f.id) },
        { order: 3, action: "Rely on missing CSP to load and execute supporting script without restriction.", findingIds: noCsp.map((f) => f.id) },
      ],
    });
  }

  if (cveHigh.length > 0) {
    paths.push({
      id: id(),
      title: "Exploitation of a known vulnerability in disclosed software",
      impact:
        "Exact software versions are advertised in responses, and one or more of those versions carry high-severity CVEs with public exploit references.",
      severity: cveHigh.some((f) => f.severity === "critical") ? "critical" : "high",
      likelihood: "medium",
      steps: [
        { order: 1, action: "Read the advertised version from the response.", findingIds: has(findings, (f) => f.title === `Server software version disclosed` || f.title.includes("versions are publicly disclosed")).map((f) => f.id) },
        { order: 2, action: "Match the version against the observed CVE.", findingIds: cveHigh.map((f) => f.id) },
        { order: 3, action: "Attempt the corresponding public exploit.", findingIds: cveHigh.map((f) => f.id) },
      ],
    });
  }

  if (swaggerOpen.length > 0 || graphqlOpen.length > 0) {
    paths.push({
      id: id(),
      title: "API surface mapping through publicly reachable documentation",
      impact:
        "Interactive API documentation or GraphQL introspection lets an attacker enumerate every operation, parameter, and authentication scheme without any brute forcing.",
      severity: "medium",
      likelihood: "high",
      steps: [
        { order: 1, action: "Enumerate operations and parameters from the reachable documentation.", findingIds: [...swaggerOpen, ...graphqlOpen].map((f) => f.id) },
        { order: 2, action: "Identify operations without authentication or without object-level authorization checks.", findingIds: [...swaggerOpen, ...graphqlOpen].map((f) => f.id) },
        { order: 3, action: "Target those operations directly for data exfiltration or privilege abuse.", findingIds: [...swaggerOpen, ...graphqlOpen].map((f) => f.id) },
      ],
    });
  }

  return paths;
}
