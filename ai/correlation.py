"""
AI Analysis layer.

Takes an assessment's already-collected findings (from recon, headers,
endpoints, javascript, vulnerabilities, cve, active_scan -- all of which
did the actual detection work) and asks the configured LLM to reason
*over* them: write a plain-language executive summary, rank the top risks
with an explanation of how they could plausibly be chained together, and
prioritize remediation. The model never runs a test or generates a
payload itself -- everything it's reasoning about was already confirmed
by a module above. That split matters: the model is doing the "think
like a pentester" prioritization/explanation work, not the
testing/exploitation work.

Degrades gracefully (returns None) if AI_ANALYSIS_ENABLED is off, or if
the configured provider is unreachable -- this must never block a report
from being generated.
"""

from flask import current_app

from ai.client import ask

_SYSTEM_PROMPT = (
    "You are a senior penetration tester writing the analysis section of a "
    "client-facing report. You are given a list of findings that automated "
    "tooling already confirmed -- do not invent new findings, do not suggest "
    "further exploitation steps to perform, and do not include any working "
    "exploit code or payloads. Your job is purely to explain, prioritize, and "
    "advise: write a short executive summary (2-4 sentences), then a "
    "prioritized list of the top risks explaining *why* each matters and how "
    "it could realistically be chained with other findings (e.g. an exposed "
    ".env plus a missing CSRF token is worse together than either alone), "
    "then concise remediation guidance ordered by priority. Plain language, "
    "no markdown headers, no code blocks."
)


def analyze(assessment) -> str | None:
    if not current_app.config.get("AI_ANALYSIS_ENABLED", True):
        return None
    if not assessment.findings:
        return None

    prompt = _build_prompt(assessment)
    try:
        return ask(prompt, system=_SYSTEM_PROMPT)
    except Exception:  # noqa: BLE001 - AI analysis is a bonus section, never fatal to the report
        return None


def _build_prompt(assessment) -> str:
    lines = [f"Target: {assessment.target_url}", "", "Findings:"]
    for f in sorted(assessment.findings, key=lambda x: x.id):
        lines.append(f"- [{f.severity.upper()}] {f.title} (source: {f.source_modules})")
        if f.description:
            lines.append(f"  {f.description[:300]}")
    return "\n".join(lines)
