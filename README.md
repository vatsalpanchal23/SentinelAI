# SentinelAI

AI-powered Web Application Security Assessment Framework.

## Setup

```bash
python -m venv venv
source venv/bin/activate   # Windows: venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env
python app.py
```

Visit http://localhost:5000

## Security posture

- Binds to `127.0.0.1` and runs with the debugger off by default (`HOST` / `FLASK_DEBUG`).
  Serving on another interface requires `AUTH_PASSWORD_HASH` (or `AUTH_PASSWORD`) —
  the app refuses to start otherwise, and never starts off-loopback with the debugger on.
- With credentials configured, every route is behind HTTP Basic auth.
- Submitted targets that resolve to loopback/private addresses are rejected unless
  `ALLOW_PRIVATE_TARGETS=true`; link-local/metadata and reserved ranges are always rejected.
- `SECRET_KEY` unset means a random per-process key, never a shipped default.

## Structure

- `dashboard/` — Flask blueprint: assessment list, target input, detail views
- `planner/` — decides which modules run for an assessment
- `modules/` — recon, fingerprint, endpoints, javascript, headers, vulnerabilities, reporting
- `ai/` — LLM client + correlation engine
- `database/` — SQLAlchemy models (Assessment, ModuleRun, Finding, Evidence)
- `evidence/` / `reports/` — generated artifacts
- `config/` — app settings

## SentinelAI React Console updates

This branch documents the updated SentinelAI security-assessment console work. The interface is designed for authorized, evidence-driven web assessments and includes:

- A dark theme enabled by default for new sessions, with a persistent light/dark toggle.
- Downloadable professional reports instead of email-based reporting. Reports can be exported as self-contained branded HTML, printed or saved as PDF, or downloaded as plain text.
- SentinelAI branding, logo watermarking, exact report-generation timestamps, scan timestamps, authorization details, findings, evidence, inventory, attack paths, AI status, and coverage limitations.
- Expandable finding guidance that explains step by step how a vulnerability can be exposed, followed by ordered remediation and verification steps.
- Guidance for HTTPS, HSTS, CSP, cookies, CORS, exposed files, directory listings, DNS and email security, CAA, version disclosure, and known CVEs.
- Responsive assessment and results layouts, including mobile-safe form behavior.

Reports are generated locally in the browser. No email or external reporting service is required. Only scan systems for which you have explicit authorization.
