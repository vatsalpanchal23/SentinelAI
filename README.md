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

## Structure

- `dashboard/` — Flask blueprint: assessment list, target input, detail views
- `planner/` — decides which modules run for an assessment
- `modules/` — recon, fingerprint, endpoints, javascript, headers, vulnerabilities, reporting
- `ai/` — LLM client + correlation engine
- `database/` — SQLAlchemy models (Assessment, ModuleRun, Finding, Evidence)
- `evidence/` / `reports/` — generated artifacts
- `config/` — app settings
