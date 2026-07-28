"""
Active Scan module -- orchestrates established, community-vetted scanners
instead of SentinelAI reimplementing exploit logic itself.

Only ever invoked when the user explicitly opted into active_scan_enabled
at submission (see planner.py / routes.py) -- this is meaningfully more
intrusive than every other module (many more requests, longer-running,
runs third-party tools this codebase doesn't control).

Hard boundaries, non-negotiable regardless of future edits to this file:
  - Nuclei: DoS and "intrusive"-tagged templates are excluded by default
    (-etags dos,intrusive). Only detection/exposure templates run.
  - sqlmap: capped at --level=1 --risk=1 (the safe/default tier), --batch
    (non-interactive), and NEVER passed --dump, --os-shell, --sql-shell,
    --file-read, --file-write, or any other data-extraction/RCE flag.
    This module detects and reports; it does not exfiltrate data or gain
    execution. Do not add those flags here.
  - Both tools run with a hard wall-clock timeout so a slow/unresponsive
    target can't hang the assessment indefinitely.

If a tool isn't installed, that section is skipped with a clear message
rather than failing the whole module -- most environments will have at
most one of these installed, if either.
"""

import json
import re
import shutil
import subprocess

PLUGIN_METADATA = {
    "name": "active_scan",
    "description": "Optional active scanner integration",
    "version": "0.1.0",
    "author": "SentinelAI",
    "priority": 80,
    "enabled": True,
    "scan_type": "active",
}


NUCLEI_TIMEOUT_SECONDS = 300
SQLMAP_TIMEOUT_SECONDS = 300

_NUCLEI_SEVERITY_MAP = {
    "critical": "critical", "high": "high", "medium": "medium",
    "low": "low", "info": "info", "unknown": "info",
}


def run(target_url: str, context: dict | None = None) -> dict:
    result = {
        "module": "active_scan",
        "target": target_url,
        "tools_available": {"nuclei": bool(shutil.which("nuclei")), "sqlmap": bool(shutil.which("sqlmap"))},
        "nuclei_findings": [],
        "sqlmap_findings": [],
        "errors": [],
    }

    if shutil.which("nuclei"):
        try:
            result["nuclei_findings"] = _run_nuclei(target_url)
        except subprocess.TimeoutExpired:
            result["errors"].append(f"nuclei timed out after {NUCLEI_TIMEOUT_SECONDS}s")
        except Exception as exc:  # noqa: BLE001 - keep the other tool running even if this one breaks
            result["errors"].append(f"nuclei run failed: {exc}")
    else:
        result["errors"].append("nuclei not found on PATH -- install it to enable template-based scanning")

    if shutil.which("sqlmap"):
        try:
            result["sqlmap_findings"] = _run_sqlmap(target_url)
        except subprocess.TimeoutExpired:
            result["errors"].append(f"sqlmap timed out after {SQLMAP_TIMEOUT_SECONDS}s")
        except Exception as exc:  # noqa: BLE001
            result["errors"].append(f"sqlmap run failed: {exc}")
    else:
        result["errors"].append("sqlmap not found on PATH -- install it to enable SQLi detection")

    return result


def _run_nuclei(target_url: str) -> list:
    cmd = [
        "nuclei", "-u", target_url,
        "-jsonl",
        "-etags", "dos,intrusive",  # exclude anything that could disrupt the target
        "-silent",
        "-timeout", "10",
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=NUCLEI_TIMEOUT_SECONDS)

    findings = []
    for line in (proc.stdout or "").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            continue
        info = entry.get("info", {})
        findings.append(
            {
                "template_id": entry.get("template-id") or entry.get("template_id"),
                "name": info.get("name"),
                "severity": _NUCLEI_SEVERITY_MAP.get((info.get("severity") or "info").lower(), "info"),
                "matched_at": entry.get("matched-at") or entry.get("matched_at") or target_url,
                "description": info.get("description"),
            }
        )
    return findings


_SQLMAP_PARAM_RE = re.compile(r"Parameter:\s*(\S+)\s*\(([^)]+)\)")
_SQLMAP_TYPE_RE = re.compile(r"Type:\s*(.+)")


def _run_sqlmap(target_url: str) -> list:
    """sqlmap's machine-readable output requires a session/output-dir setup;
    v1 parses the human-readable stdout it prints in --batch mode instead.
    This is inherently more brittle than JSON parsing -- if sqlmap changes
    its output format this will need updating. Flags are capped at the
    detection-only tier; see module docstring."""
    cmd = [
        "sqlmap", "-u", target_url,
        "--batch",       # non-interactive, accept sqlmap's defaults on prompts
        "--level=1", "--risk=1",  # safest/default tier -- do not raise without reconsidering the risk
        "--forms",       # also test same-page GET forms, not just the URL's own query string
        "--crawl=0",     # we already discovered links via endpoints.py; don't have sqlmap crawl separately
        "--batch-timeout=" + str(SQLMAP_TIMEOUT_SECONDS),
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=SQLMAP_TIMEOUT_SECONDS)
    output = proc.stdout or ""

    findings = []
    if "is vulnerable" in output.lower() or "parameter" in output.lower() and "injectable" in output.lower():
        for match in _SQLMAP_PARAM_RE.finditer(output):
            param, location = match.group(1), match.group(2)
            type_match = _SQLMAP_TYPE_RE.search(output[match.end():match.end() + 500])
            findings.append(
                {
                    "param": param,
                    "location": location,
                    "injection_type": type_match.group(1).strip() if type_match else "unknown",
                }
            )
    return findings
