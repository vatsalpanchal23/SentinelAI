"""
Shared risk-scoring logic, used by both the live dashboard API (routes.py)
and the generated report (reporting.py) so the two never disagree.

v1: simple weighted-deduction model. Documented limitation: this treats
severities as independent and additive, which isn't how real risk works
(e.g. many low-severity findings don't really compound the way one
critical does) -- a CVSS/OWASP-Risk-Rating-based model would be more
defensible. Tracked as a future improvement, not done here.
"""

import logging

logger = logging.getLogger("sentinelai.scoring")

SEVERITY_WEIGHTS = {"critical": 10, "high": 5, "medium": 2, "low": 1, "info": 0}
SEVERITIES = ["critical", "high", "medium", "low", "info"]


def compute_risk(findings) -> tuple[dict, int]:
    """findings: iterable of objects/dicts with a `.severity` attribute or key.
    Returns (severity_counts, risk_score)."""
    counts = {sev: 0 for sev in SEVERITIES}
    for f in findings:
        severity = f.severity if hasattr(f, "severity") else f["severity"]
        if severity not in counts:
            # An unrecognized severity contributes nothing to the score below,
            # so a typo'd severity would quietly make a finding weightless.
            logger.warning("finding has unrecognized severity %r; it will not affect the risk score", severity)
        counts[severity] = counts.get(severity, 0) + 1
    raw_score = sum(counts[sev] * weight for sev, weight in SEVERITY_WEIGHTS.items())
    risk_score = max(0, 100 - raw_score)
    return counts, risk_score
