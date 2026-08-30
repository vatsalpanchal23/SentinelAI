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
