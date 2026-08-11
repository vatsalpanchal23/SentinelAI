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

from common.results import module_result
from common.severity import normalize_severity

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


def run(target_url: str, context: dict | None = None) -> dict:
    tools = [
        ("nuclei", "nuclei_findings", _run_nuclei, NUCLEI_TIMEOUT_SECONDS,
         "install it to enable template-based scanning"),
        ("sqlmap", "sqlmap_findings", _run_sqlmap, SQLMAP_TIMEOUT_SECONDS,
         "install it to enable SQLi detection"),
    ]

    result = module_result(
        "active_scan", target_url,
        tools_available={tool: bool(shutil.which(tool)) for tool, *_ in tools},
        nuclei_findings=[],
        sqlmap_findings=[],
    )

    for tool, result_key, runner, timeout_seconds, install_hint in tools:
        if not shutil.which(tool):
            result["errors"].append(f"{tool} not found on PATH -- {install_hint}")
            continue
        try:
            result[result_key] = runner(target_url)
        except subprocess.TimeoutExpired:
            result["errors"].append(f"{tool} timed out after {timeout_seconds}s")
        except Exception as exc:  # noqa: BLE001 - keep the other tool running even if this one breaks
            result["errors"].append(f"{tool} run failed: {exc}")

    return result


def _run_tool(cmd: list, timeout_seconds: int) -> str:
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout_seconds)
    return proc.stdout or ""


def _run_nuclei(target_url: str) -> list:
    cmd = [
        "nuclei", "-u", target_url,
        "-jsonl",
        "-etags", "dos,intrusive",  # exclude anything that could disrupt the target
        "-silent",
        "-timeout", "10",
    ]
    findings = []
    for line in _run_tool(cmd, NUCLEI_TIMEOUT_SECONDS).splitlines():
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
                "severity": normalize_severity(info.get("severity")),
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
    output = _run_tool(cmd, SQLMAP_TIMEOUT_SECONDS)

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
