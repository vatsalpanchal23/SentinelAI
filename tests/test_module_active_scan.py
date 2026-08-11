"""Coverage for modules.active_scan: tool availability handling, output
parsing, and the safety flags the module must never exceed."""

import json
import subprocess

import pytest

from modules.active_scan import active_scan as active_module

TARGET = "http://example.test/"


@pytest.fixture
def tools(monkeypatch):
    """Controls which of nuclei/sqlmap appear installed, and their output."""

    state = {"available": set(), "runs": [], "results": {}, "raises": {}}

    def which(name):
        return f"/usr/bin/{name}" if name in state["available"] else None

    def run(cmd, capture_output=None, text=None, timeout=None):
        state["runs"].append(cmd)
        tool = cmd[0]
        if tool in state["raises"]:
            raise state["raises"][tool]
        return subprocess.CompletedProcess(cmd, 0, stdout=state["results"].get(tool, ""), stderr="")

    monkeypatch.setattr(active_module.shutil, "which", which)
    monkeypatch.setattr(active_module.subprocess, "run", run)
    return state


def test_no_tools_installed_reports_install_hints(tools):
    result = active_module.run(TARGET)
    assert result["tools_available"] == {"nuclei": False, "sqlmap": False}
    assert result["nuclei_findings"] == [] and result["sqlmap_findings"] == []
    assert any("nuclei not found on PATH" in e for e in result["errors"])
    assert any("sqlmap not found on PATH" in e for e in result["errors"])
    assert tools["runs"] == []


def test_nuclei_jsonl_output_is_parsed(tools):
    tools["available"] = {"nuclei"}
    tools["results"]["nuclei"] = "\n".join(
        [
            json.dumps({"template-id": "exposed-env", "matched-at": "http://example.test/.env",
                        "info": {"name": "Exposed .env", "severity": "HIGH",
                                 "description": "env file readable"}}),
            "",
            "not json at all",
            json.dumps({"template_id": "legacy-key", "matched_at": "http://example.test/x",
                        "info": {"severity": "unknown"}}),
            json.dumps({"template-id": "no-matched-at", "info": {}}),
        ]
    )

    result = active_module.run(TARGET)
    assert result["tools_available"]["nuclei"] is True
    assert result["nuclei_findings"] == [
        {"template_id": "exposed-env", "name": "Exposed .env", "severity": "high",
         "matched_at": "http://example.test/.env", "description": "env file readable"},
        {"template_id": "legacy-key", "name": None, "severity": "info",
         "matched_at": "http://example.test/x", "description": None},
        {"template_id": "no-matched-at", "name": None, "severity": "info",
         "matched_at": TARGET, "description": None},
    ]


def test_nuclei_excludes_disruptive_templates(tools):
    tools["available"] = {"nuclei"}
    active_module.run(TARGET)
    cmd = tools["runs"][0]
    assert cmd[:3] == ["nuclei", "-u", TARGET]
    assert "-etags" in cmd and cmd[cmd.index("-etags") + 1] == "dos,intrusive"


def test_nuclei_timeout_and_crash_are_reported_without_failing_the_module(tools):
    tools["available"] = {"nuclei"}
    tools["raises"]["nuclei"] = subprocess.TimeoutExpired("nuclei", active_module.NUCLEI_TIMEOUT_SECONDS)
    result = active_module.run(TARGET)
    assert result["nuclei_findings"] == []
    assert any("nuclei timed out" in e for e in result["errors"])

    tools["raises"]["nuclei"] = OSError("exec format error")
    result = active_module.run(TARGET)
    assert any("nuclei run failed: exec format error" in e for e in result["errors"])


SQLMAP_VULNERABLE_OUTPUT = """
GET parameter 'id' is vulnerable. Do you want to keep testing the others? [y/N] N
sqlmap identified the following injection point(s):
---
Parameter: id (GET)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
Parameter: name (POST)
    Type: time-based blind
---
the back-end DBMS is MySQL
"""


def test_sqlmap_output_is_parsed_into_findings(tools):
    tools["available"] = {"sqlmap"}
    tools["results"]["sqlmap"] = SQLMAP_VULNERABLE_OUTPUT
    result = active_module.run(TARGET)
    assert result["sqlmap_findings"] == [
        {"param": "id", "location": "GET", "injection_type": "boolean-based blind"},
        {"param": "name", "location": "POST", "injection_type": "time-based blind"},
    ]


def test_sqlmap_clean_run_reports_nothing(tools):
    tools["available"] = {"sqlmap"}
    tools["results"]["sqlmap"] = "all tested parameters do not appear to be injectable"
    assert active_module.run(TARGET)["sqlmap_findings"] == []


def test_sqlmap_parameter_block_without_a_vulnerable_marker_is_ignored(tools):
    tools["available"] = {"sqlmap"}
    tools["results"]["sqlmap"] = "Parameter: id (GET)\n    Type: boolean-based blind"
    assert active_module.run(TARGET)["sqlmap_findings"] == []


def test_sqlmap_is_capped_at_the_detection_only_tier(tools):
    tools["available"] = {"sqlmap"}
    active_module.run(TARGET)
    cmd = tools["runs"][0]
    assert {"--batch", "--level=1", "--risk=1"} <= set(cmd)
    forbidden = {"--dump", "--dump-all", "--os-shell", "--sql-shell", "--file-read", "--file-write"}
    assert not forbidden & set(cmd), "active_scan must never request data extraction or execution"


def test_sqlmap_timeout_and_crash_are_reported(tools):
    tools["available"] = {"sqlmap"}
    tools["raises"]["sqlmap"] = subprocess.TimeoutExpired("sqlmap", active_module.SQLMAP_TIMEOUT_SECONDS)
    assert any("sqlmap timed out" in e for e in active_module.run(TARGET)["errors"])

    tools["raises"]["sqlmap"] = OSError("permission denied")
    assert any("sqlmap run failed: permission denied" in e for e in active_module.run(TARGET)["errors"])


def test_one_missing_tool_does_not_stop_the_other(tools):
    tools["available"] = {"sqlmap"}
    tools["results"]["sqlmap"] = SQLMAP_VULNERABLE_OUTPUT
    result = active_module.run(TARGET)
    assert len(result["sqlmap_findings"]) == 2
    assert any("nuclei not found" in e for e in result["errors"])
