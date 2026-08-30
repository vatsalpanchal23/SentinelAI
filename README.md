# SentinelAI

SentinelAI is an evidence-driven web vulnerability assessment console. It runs authorized browser-based scans and produces branded, timestamped reports with findings, evidence, exposure paths, remediation plans, and coverage limitations.

## Setup

```bash
pnpm install
pnpm run dev
```

Open the local URL printed by Vite. The development server defaults to port 5173 and the production build defaults to `/` as its base path.

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

## Reporting

Completed assessments can be downloaded as self-contained HTML, printed or saved as PDF, or exported as plain text. Each finding includes an explanation of how the condition can be exposed and an ordered remediation plan.
