"""
Report Generator module.

Takes a completed assessment's findings + module results and renders a
single self-contained HTML file (no external assets, so it still looks
right when opened offline or emailed as an attachment). Kept as plain
Python string templating rather than Jinja, since this needs to run
outside of a request context from inside the worker thread.
"""

import html
import os
from datetime import datetime

from config.settings import Config
from scoring import compute_risk, SEVERITIES
from ai.correlation import analyze as ai_analyze

PLUGIN_METADATA = {
    "name": "reporting",
    "description": "HTML report generation",
    "version": "0.1.0",
    "author": "SentinelAI",
    "priority": 90,
    "enabled": True,
    "scan_type": "reporting",
}


_SEVERITY_COLORS = {
    "critical": "#dc2626", "high": "#ea580c", "medium": "#d97706",
    "low": "#65a30d", "info": "#64748b",
}


def generate(assessment_id: int) -> str:
    """Renders the report for `assessment_id` to REPORTS_DIR and returns the
    file path. Must be called inside an app context (worker.py handles that)."""
    from database.models import Assessment  # local import: avoid circular import at module load time

    assessment = Assessment.query.get(assessment_id)
    if assessment is None:
        raise ValueError(f"No assessment with id {assessment_id}")

    counts, risk_score = compute_risk(assessment.findings)
    findings_by_severity = {sev: [] for sev in SEVERITIES}
    for f in assessment.findings:
        findings_by_severity.setdefault(f.severity, []).append(f)

    ai_summary = ai_analyze(assessment)  # None if disabled/unavailable -- report still renders fine

    os.makedirs(Config.REPORTS_DIR, exist_ok=True)
    filename = f"assessment_{assessment_id}_{datetime.utcnow().strftime('%Y%m%d%H%M%S')}.html"
    path = os.path.join(Config.REPORTS_DIR, filename)

    with open(path, "w", encoding="utf-8") as fh:
        fh.write(_render(assessment, counts, risk_score, findings_by_severity, ai_summary))

    return path


def _esc(value) -> str:
    return html.escape(str(value)) if value is not None else ""


def _render(assessment, counts, risk_score, findings_by_severity, ai_summary=None) -> str:
    severity_cards = "".join(
        f"""<div class="stat"><div class="stat-num" style="color:{_SEVERITY_COLORS[sev]}">{counts[sev]}</div>
            <div class="stat-label">{sev}</div></div>"""
        for sev in SEVERITIES
    )

    findings_html = ""
    for sev in SEVERITIES:
        items = findings_by_severity.get(sev, [])
        if not items:
            continue
        findings_html += f'<h3 style="color:{_SEVERITY_COLORS[sev]}">{sev.upper()} ({len(items)})</h3>'
        for f in items:
            findings_html += f"""
            <div class="finding">
                <div class="finding-title">{_esc(f.title)}</div>
                <div class="finding-meta">source: {_esc(f.source_modules)}</div>
                {f'<div class="finding-desc">{_esc(f.description)}</div>' if f.description else ''}
                {f'<div class="finding-fix">Fix: {_esc(f.recommendation)}</div>' if f.recommendation else ''}
            </div>"""

    modules_html = "".join(
        f"""<tr><td>{_esc(m.name)}</td><td>{_esc(m.status)}</td>
            <td>{_esc(m.started_at.strftime('%H:%M:%S') if m.started_at else '-')}</td>
            <td>{_esc(round((m.finished_at - m.started_at).total_seconds(), 1) if m.started_at and m.finished_at else '-')}s</td></tr>"""
        for m in assessment.modules
    )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>SentinelAI Report -- {_esc(assessment.target_url)}</title>
<style>
  body {{ font-family: -apple-system, Segoe UI, Roboto, sans-serif; background:#0f172a; color:#e2e8f0; margin:0; padding:2rem; }}
  .container {{ max-width: 900px; margin: 0 auto; }}
  h1 {{ font-size: 1.5rem; margin-bottom:0.25rem; }}
  .subtitle {{ color:#94a3b8; font-size:0.85rem; margin-bottom:2rem; }}
  .stats {{ display:flex; gap:1rem; margin-bottom:2rem; flex-wrap:wrap; }}
  .stat {{ background:#1e293b; border-radius:8px; padding:1rem 1.5rem; text-align:center; min-width:90px; }}
  .stat-num {{ font-size:1.75rem; font-weight:600; }}
  .stat-label {{ font-size:0.75rem; text-transform:uppercase; color:#94a3b8; margin-top:0.25rem; }}
  .risk {{ font-size:2.5rem; font-weight:700; }}
  table {{ width:100%; border-collapse:collapse; margin-bottom:2rem; font-size:0.85rem; }}
  th, td {{ text-align:left; padding:0.5rem 0.75rem; border-bottom:1px solid #1e293b; }}
  th {{ color:#94a3b8; font-weight:500; }}
  .finding {{ background:#1e293b; border-radius:8px; padding:1rem; margin-bottom:0.75rem; }}
  .finding-title {{ font-weight:600; margin-bottom:0.25rem; }}
  .finding-meta {{ font-size:0.75rem; color:#94a3b8; margin-bottom:0.5rem; }}
  .finding-desc {{ font-size:0.85rem; color:#cbd5e1; white-space:pre-line; margin-bottom:0.5rem; }}
  .finding-fix {{ font-size:0.85rem; color:#34d399; }}
</style>
</head>
<body>
<div class="container">
  <h1>SentinelAI Security Assessment Report</h1>
  <div class="subtitle">
    Target: {_esc(assessment.target_url)} &middot;
    Assessment #{assessment.id} &middot;
    Generated {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}
  </div>

  <div class="stats">
    <div class="stat"><div class="risk" style="color:{'#dc2626' if risk_score < 50 else '#d97706' if risk_score < 80 else '#22c55e'}">{risk_score}</div>
      <div class="stat-label">Risk Score / 100</div></div>
    {severity_cards}
  </div>

  {f'''<h2>AI Analysis</h2>
  <div class="finding" style="white-space:pre-line;">{_esc(ai_summary)}</div>''' if ai_summary else ''}

  <h2>Module Execution</h2>
  <table>
    <tr><th>Module</th><th>Status</th><th>Started</th><th>Duration</th></tr>
    {modules_html}
  </table>

  <h2>Findings</h2>
  {findings_html or '<p style="color:#94a3b8">No findings were recorded.</p>'}

  <p style="color:#475569; font-size:0.75rem; margin-top:2rem;">
    Generated by SentinelAI. Automated findings -- verify manually before treating any item as confirmed.
  </p>
</div>
</body>
</html>"""
