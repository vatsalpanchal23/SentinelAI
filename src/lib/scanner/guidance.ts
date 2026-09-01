export type GuidanceInput = {
  title: string;
  asset: string;
  endpoint?: string | null;
  parameter?: string | null;
  category: string;
  remediation: string;
};

export type FindingGuidance = {
  exposureSteps: string[];
  remediationSteps: string[];
};

const locationFor = (input: GuidanceInput) => input.endpoint ?? `${input.asset}/`;

/**
 * Convert a scanner observation into an analyst-friendly attack path and
 * ordered remediation plan. These are explanatory steps, not proof that an
 * exploit was completed.
 */
export function buildFindingGuidance(input: GuidanceInput): FindingGuidance {
  const title = input.title.toLowerCase();
  const location = locationFor(input);

  if (title.includes("strict transport")) {
    return {
      exposureSteps: [
        "A user first requests the origin over plaintext HTTP or follows an insecure link.",
        "A network attacker intercepts the initial request before the browser has an HSTS policy.",
        "The attacker downgrades, observes, or modifies the session and redirects the user.",
      ],
      remediationSteps: [
        "Return Strict-Transport-Security on every HTTPS response.",
        "Use a long max-age and includeSubDomains only after every subdomain is HTTPS-ready.",
        "Verify first-visit HTTP behavior and consider preload after validating the full domain inventory.",
      ],
    };
  }

  if (title.includes("content-security-policy")) {
    return {
      exposureSteps: [
        `An attacker reaches an input or response path on ${location} that can inject markup or script.`,
        "The browser receives no restrictive CSP, so injected script is not constrained by a policy.",
        "The script can read accessible page data, act as the user, or send data to an attacker-controlled origin.",
      ],
      remediationSteps: [
        "Deploy a report-only policy and review real violation reports.",
        "Enforce a least-privilege policy with explicit script, style, image, and connection sources.",
        "Replace inline script allowances with nonces or hashes and regression-test the application flows.",
      ],
    };
  }

  if (title.includes("mime type")) {
    return {
      exposureSteps: [
        "An attacker places or reflects content at an endpoint that is served with an ambiguous MIME type.",
        "A browser sniffs the response instead of honoring the declared content type.",
        "The content can be interpreted as executable script in the victim's origin.",
      ],
      remediationSteps: [
        "Send X-Content-Type-Options: nosniff on all application and static responses.",
        "Set an accurate Content-Type for every upload and download route.",
        "Store user uploads outside executable document roots and test the upload/download path.",
      ],
    };
  }

  if (title.includes("clickjacking")) {
    return {
      exposureSteps: [
        "An attacker embeds the target page in an iframe on a page they control.",
        "A transparent or disguised overlay positions the target's controls beneath attacker UI.",
        "An authenticated victim clicks the overlay and unintentionally performs a state-changing action.",
      ],
      remediationSteps: [
        "Set CSP frame-ancestors to none or to an explicit trusted-origin allowlist.",
        "Add X-Frame-Options: DENY or SAMEORIGIN for legacy browser coverage.",
        "Test login, payment, and other state-changing pages inside an iframe after deployment.",
      ],
    };
  }

  if (title.includes("referrer-policy")) {
    return {
      exposureSteps: [
        "A user visits a URL containing an identifier, reset token, or other sensitive path/query value.",
        "The user follows a link to an external origin.",
        "The browser sends the original URL in Referer, exposing the value to the external site or its analytics.",
      ],
      remediationSteps: [
        "Set Referrer-Policy to strict-origin-when-cross-origin or stricter.",
        "Remove secrets from URLs and use short-lived, one-time server-side tokens instead.",
        "Check third-party links, analytics, redirects, and error pages for URL leakage.",
      ],
    };
  }

  if (title.includes("server software version") || title.includes("x-powered-by") || title.includes("software versions")) {
    return {
      exposureSteps: [
        `An unauthenticated client requests ${location}.`,
        "The response exposes a framework, server, runtime, or exact version in headers or fingerprints.",
        "An attacker matches that version against public advisories and selects targeted follow-up probes.",
      ],
      remediationSteps: [
        "Suppress version banners at the application server and reverse proxy.",
        "Maintain an internal software inventory so removing the banner does not replace patch management.",
        "Retest response headers and run dependency/CVE checks as part of release pipelines.",
      ],
    };
  }

  if (title.includes("cookie")) {
    return {
      exposureSteps: [
        "The application sets the observed cookie during a normal response.",
        "A missing Secure, HttpOnly, or SameSite attribute exposes it to plaintext transport, script access, or cross-site requests.",
        "A separate XSS, network interception, or CSRF condition can then turn the weak cookie into account impact.",
      ],
      remediationSteps: [
        "Set Secure, HttpOnly, and SameSite=Lax or Strict on session cookies.",
        "Use SameSite=None only for a documented cross-site flow and always pair it with Secure.",
        "Invalidate and rotate affected sessions after deployment, then test login, logout, and cross-site flows.",
      ],
    };
  }

  if (title.includes("https not available")) {
    return {
      exposureSteps: [
        `A client connects to ${location} and cannot establish a usable TLS session.`,
        "The client falls back to plaintext or cannot verify the service identity.",
        "A network attacker can observe, modify, or impersonate application traffic.",
      ],
      remediationSteps: [
        "Install a valid certificate covering the hostname and configure the complete certificate chain.",
        "Serve the application over HTTPS on every public entry point.",
        "Redirect HTTP to HTTPS and validate certificate renewal, redirects, and mixed-content behavior.",
      ],
    };
  }

  if (title.includes("plaintext http")) {
    return {
      exposureSteps: [
        `A client requests ${location} over HTTP.`,
        "The server returns a successful response without redirecting to the HTTPS equivalent.",
        "Credentials, cookies, and application data remain readable or modifiable on the network path.",
      ],
      remediationSteps: [
        "Redirect every HTTP route to the equivalent HTTPS URL with a permanent redirect.",
        "Mark sensitive cookies Secure and remove mixed-content dependencies.",
        "Enable HSTS after HTTPS coverage and redirect behavior are verified.",
      ],
    };
  }

  if (title.includes("cors")) {
    return {
      exposureSteps: [
        `A malicious site sends a cross-origin request to ${location}.`,
        "The server accepts or reflects the untrusted Origin and, in the critical case, permits credentials.",
        "The browser allows the malicious site to read the authenticated response.",
      ],
      remediationSteps: [
        "Create an explicit allowlist of trusted origins for this endpoint.",
        "Never combine wildcard/reflected origins with Access-Control-Allow-Credentials: true.",
        "Retest preflight and credentialed requests from both trusted and untrusted origins.",
      ],
    };
  }

  if (title.includes("exposed") || title.includes("reachable") || title.includes("directory listing")) {
    return {
      exposureSteps: [
        `An unauthenticated client requests ${location}.`,
        "The server returns HTTP 200 and the sensitive artefact or directory index is accessible.",
        "An attacker downloads the content, enumerates related files, and uses any disclosed secrets or paths for follow-up access.",
      ],
      remediationSteps: [
        "Remove the artefact from the deployed document root and deny the path at the server/CDN layer.",
        "Disable directory indexing and add automated checks for sensitive files before deployment.",
        "Treat any exposed credential as compromised: revoke, rotate, and review access logs.",
      ],
    };
  }

  if (title.includes("spf")) {
    return {
      exposureSteps: [
        "An attacker sends a message claiming to use the assessed domain in the From address.",
        "Receiving systems have no published SPF sender policy to compare against.",
        "The spoofed message can support phishing, brand impersonation, or credential theft.",
      ],
      remediationSteps: [
        "Inventory every legitimate mail sender used by the domain.",
        "Publish one SPF record containing those senders and finish with -all.",
        "Monitor delivery and SPF results, then retest DNS propagation and alignment.",
      ],
    };
  }

  if (title.includes("dmarc")) {
    return {
      exposureSteps: [
        "An attacker sends mail that fails SPF or DKIM alignment while using the domain in the visible From address.",
        "The domain has no enforcement policy, or is configured only to monitor failures.",
        "Receiving systems can still deliver the spoofed message to the victim.",
      ],
      remediationSteps: [
        "Publish a DMARC record with reporting addresses and start with p=none for visibility.",
        "Review aggregate reports, fix legitimate sender alignment, and move to p=quarantine.",
        "After monitoring confirms coverage, enforce p=reject and continue reviewing reports.",
      ],
    };
  }

  if (title.includes("caa")) {
    return {
      exposureSteps: [
        "An attacker requests a certificate for the assessed hostname from a public certificate authority.",
        "No CAA record restricts which authorities may issue for the domain.",
        "A mis-issued certificate could support impersonation until detection or revocation.",
      ],
      remediationSteps: [
        "Identify the certificate authorities that legitimately issue for the domain.",
        "Publish CAA records allowing only those authorities and add an iodef contact.",
        "Monitor certificate transparency logs and retest issuance restrictions.",
      ],
    };
  }

  if (input.category.toLowerCase().includes("known vulnerability")) {
    return {
      exposureSteps: [
        `An attacker fingerprints the deployed component and version associated with ${location}.`,
        "The version is matched to the cited public vulnerability advisory.",
        "The attacker sends the advisory's applicable exploit or trigger against an exposed component path.",
      ],
      remediationSteps: [
        "Upgrade to a vendor-fixed version or apply the vendor mitigation.",
        "Run regression and compatibility tests, then redeploy the fixed dependency.",
        "Retest the affected component and confirm the vulnerable version is absent from production.",
      ],
    };
  }

  return {
    exposureSteps: [
      `An unauthenticated client reaches ${location}.`,
      "The response or behavior matches the observed condition described in this finding.",
      "An attacker can use the condition to gather information, bypass a control, or increase the impact of another weakness.",
    ],
    remediationSteps: [
      "Apply the recommended control at the application, server, or edge layer.",
      "Retest the affected endpoint with the same evidence-producing request.",
      "Review related assets and rotate exposed secrets if the condition revealed sensitive data.",
    ],
  };
}