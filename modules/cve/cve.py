"""
CVE Matching module.

Cross-references version strings other modules already discovered against
OSV.dev's public API (https://api.osv.dev) -- a pure data lookup, not an
active test against the target itself. Deliberately narrow in v1: OSV's
package/ecosystem model matches cleanly onto real package-manager
ecosystems (PyPI, npm, ...), so this only queries triples we can name with
confidence:

  - Werkzeug version, parsed from recon's Server header -> PyPI
  - JS libraries javascript.py already flagged as outdated (currently
    jQuery) -> npm

Generic web-server products (nginx, Apache) are deliberately NOT queried
here: OSV doesn't cleanly index them the way it does language packages, and
a wrong ecosystem guess would produce confident-looking false results --
worse than no result. Extend PACKAGE_SOURCES below once a reliable mapping
for a given product is confirmed.

Needs outbound network access to api.osv.dev; any failure (offline, DNS,
timeout, no matches) degrades to an empty result rather than raising, same
pattern as every other module.
"""

import re

import requests

OSV_ENDPOINT = "https://api.osv.dev/v1/query"
PLUGIN_METADATA = {
    "name": "cve",
    "description": "Known vulnerability intelligence matching",
    "version": "0.1.0",
    "author": "SentinelAI",
    "priority": 50,
    "enabled": True,
    "scan_type": "intelligence",
}


TIMEOUT = 10

_WERKZEUG_RE = re.compile(r"Werkzeug/(\d+\.\d+(?:\.\d+)?)", re.IGNORECASE)


def run(target_url: str, context: dict | None = None) -> dict:
    result = {"module": "cve", "target": target_url, "matches": [], "errors": []}
    context = context or {}

    packages = _identify_packages(context)
    for name, ecosystem, version, source in packages:
        try:
            vulns = _query_osv(name, ecosystem, version)
        except requests.RequestException as exc:
            result["errors"].append(f"OSV lookup failed for {name}@{version}: {exc}")
            continue
        for v in vulns:
            result["matches"].append(
                {
                    "package": name,
                    "version": version,
                    "ecosystem": ecosystem,
                    "id": v.get("id"),
                    "summary": (v.get("summary") or v.get("details") or "")[:400],
                    "severity": _extract_severity(v),
                    "source_field": source,
                }
            )

    return result


def _identify_packages(context: dict) -> list:
    """Returns (name, ecosystem, version, source_description) tuples."""
    found = []

    recon = context.get("recon") or {}
    server = recon.get("server") or ""
    m = _WERKZEUG_RE.search(server)
    if m:
        found.append(("werkzeug", "PyPI", m.group(1), f"recon Server header: {server}"))

    js = context.get("javascript") or {}
    for lib in js.get("outdated_libraries", []):
        if lib.get("name", "").lower() == "jquery" and lib.get("version"):
            found.append(("jquery", "npm", lib["version"], f"javascript module: {lib['source']}"))

    return found


def _query_osv(name: str, ecosystem: str, version: str) -> list:
    payload = {"package": {"name": name, "ecosystem": ecosystem}, "version": version}
    resp = requests.post(OSV_ENDPOINT, json=payload, timeout=TIMEOUT)
    resp.raise_for_status()
    return resp.json().get("vulns", [])


def _extract_severity(vuln: dict) -> str:
    """OSV severity reporting is inconsistent across sources (CVSS vector
    strings, database_specific labels, or nothing at all) -- best-effort
    normalize to our critical/high/medium/low/info scale, defaulting to
    medium rather than guessing wrong in either direction."""
    db_specific = vuln.get("database_specific") or {}
    label = (db_specific.get("severity") or "").upper()
    if label in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        return label.lower()

    for entry in vuln.get("severity") or []:
        score_str = entry.get("score", "")
        cvss_match = re.search(r"(\d+(?:\.\d+)?)", score_str)
        if cvss_match:
            score = float(cvss_match.group(1))
            if score >= 9.0:
                return "critical"
            if score >= 7.0:
                return "high"
            if score >= 4.0:
                return "medium"
            return "low"

    return "medium"
