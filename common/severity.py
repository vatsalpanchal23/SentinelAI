"""Normalization onto SentinelAI's severity scale.

Third-party sources label severity in their own vocabularies (Nuclei's
`info`/`unknown`, OSV's `database_specific.severity`, raw CVSS scores); modules
funnel them through here so the scale stays consistent with scoring.py.
"""

from scoring import SEVERITIES


def normalize_severity(label, default: str = "info") -> str:
    """Map a free-form severity label onto our scale, or `default` if unknown."""
    normalized = (label or "").strip().lower()
    return normalized if normalized in SEVERITIES else default


def severity_from_cvss(score: float) -> str:
    """CVSS base score -> our scale, using the standard CVSS v3 bands."""
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    return "low"
