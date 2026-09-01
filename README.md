# SentinelAI

SentinelAI is an evidence-driven web vulnerability assessment console for authorized web security assessments.

## Current branch

The sentinelai-react-console branch contains the current React/Vite SentinelAI console while the original Flask/Python application remains preserved on main. The console includes the updated dark theme, responsive assessment workflow, local report generation, and expanded vulnerability guidance.

## Included updates

- Dark theme enabled by default for new sessions, with a persistent light/dark toggle.
- Downloadable professional reports instead of email-based reporting. Reports support self-contained branded HTML, print or Save as PDF, and plain text export.
- SentinelAI branding, logo watermarking, exact report-generation timestamps, scan timestamps, authorization details, findings, evidence, inventory, attack paths, AI status, and coverage limitations.
- Expandable finding guidance explaining step by step how a vulnerability can be exposed, followed by ordered remediation and verification steps.
- Guidance for HTTPS, HSTS, CSP, cookies, CORS, exposed files, directory listings, DNS and email security, CAA, version disclosure, and known CVEs.
- Mobile-safe responsive behavior for the assessment form and results panels.

## Setup

```bash
pnpm install
pnpm run dev
```

The development server defaults to port 5173. The Vite HTML entrypoint is generated automatically before development and production builds, so a downloaded branch is ready after dependency installation.

## Commands

```bash
pnpm run typecheck
pnpm run build
pnpm run serve
```

## Security posture

- Only scan targets for which you have written authorization.
- Scope rules are applied by the scanner before requests are made.
- Findings are evidence-bound; unavailable or failed modules are reported instead of inferred.
- AI analysis is clearly labeled as inference and is not treated as scanner evidence.
- Reports are generated locally in the browser; no email or external reporting service is required.
