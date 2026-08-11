"""Coverage for scoring.compute_risk, ai.client provider dispatch, and
ai.correlation's graceful degradation."""

import pytest
import requests

from ai import client as ai_client
from ai import correlation
from conftest import FakeResponse
from database.models import Finding, db
from scoring import SEVERITY_WEIGHTS, compute_risk


class Stub:
    def __init__(self, severity):
        self.severity = severity


# --- scoring -----------------------------------------------------------------


def test_no_findings_is_a_perfect_score():
    counts, score = compute_risk([])
    assert score == 100
    assert counts == {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}


@pytest.mark.parametrize("severity,weight", SEVERITY_WEIGHTS.items())
def test_each_severity_deducts_its_weight(severity, weight):
    counts, score = compute_risk([Stub(severity)])
    assert counts[severity] == 1
    assert score == 100 - weight


def test_deductions_accumulate_across_findings():
    findings = [Stub("critical"), Stub("high"), Stub("medium"), Stub("low"), Stub("info")]
    counts, score = compute_risk(findings)
    assert score == 100 - (10 + 5 + 2 + 1)
    assert all(count == 1 for count in counts.values())


def test_score_is_clamped_at_zero():
    counts, score = compute_risk([Stub("critical")] * 20)
    assert counts["critical"] == 20
    assert score == 0


def test_dict_findings_are_supported():
    counts, score = compute_risk([{"severity": "high"}, {"severity": "high"}])
    assert counts["high"] == 2 and score == 90


def test_unknown_severity_is_counted_but_does_not_change_the_score():
    counts, score = compute_risk([Stub("catastrophic")])
    assert counts["catastrophic"] == 1
    assert score == 100


# --- ai.client ---------------------------------------------------------------


def test_ollama_request_shape_and_response_extraction(app, monkeypatch):
    calls = []

    class FakeRequests:
        RequestException = requests.RequestException

        def post(self, url, json=None, timeout=None):
            calls.append((url, json, timeout))
            return FakeResponse(json_data={"response": "an executive summary"})

    monkeypatch.setattr(ai_client, "requests", FakeRequests())
    assert ai_client.ask("prompt text", system="be terse") == "an executive summary"
    url, payload, timeout = calls[0]
    assert url == "http://localhost:11434/api/generate"
    assert payload == {"model": "qwen3", "prompt": "prompt text", "stream": False,
                       "system": "be terse"}
    assert timeout == 120


def test_system_prompt_is_omitted_when_not_supplied(app, monkeypatch):
    payloads = []

    class FakeRequests:
        RequestException = requests.RequestException

        def post(self, url, json=None, timeout=None):
            payloads.append(json)
            return FakeResponse(json_data={})

    monkeypatch.setattr(ai_client, "requests", FakeRequests())
    assert ai_client.ask("prompt text") == "", "a response-less reply degrades to an empty string"
    assert "system" not in payloads[0]


def test_provider_http_error_propagates(app, monkeypatch):
    class FakeRequests:
        RequestException = requests.RequestException

        def post(self, url, json=None, timeout=None):
            return FakeResponse(status_code=502)

    monkeypatch.setattr(ai_client, "requests", FakeRequests())
    with pytest.raises(requests.HTTPError):
        ai_client.ask("prompt text")


def test_unwired_providers_raise_not_implemented(app):
    app.config["AI_PROVIDER"] = "gemini"
    with pytest.raises(NotImplementedError, match="gemini"):
        ai_client.ask("prompt text")


# --- ai.correlation ----------------------------------------------------------


@pytest.fixture
def assessment_with_findings(assessment):
    db.session.add_all(
        [
            Finding(assessment_id=assessment.id, title="Exposed .env", severity="high",
                    description="d" * 400, source_modules="endpoints"),
            Finding(assessment_id=assessment.id, title="Missing CSRF", severity="medium",
                    description=None, source_modules="endpoints"),
        ]
    )
    db.session.commit()
    return assessment


def test_analysis_is_skipped_when_disabled(app, assessment_with_findings, monkeypatch):
    monkeypatch.setattr(correlation, "ask", lambda *a, **k: pytest.fail("must not call the model"))
    app.config["AI_ANALYSIS_ENABLED"] = False
    assert correlation.analyze(assessment_with_findings) is None


def test_analysis_is_skipped_without_findings(app, assessment, monkeypatch):
    monkeypatch.setattr(correlation, "ask", lambda *a, **k: pytest.fail("must not call the model"))
    app.config["AI_ANALYSIS_ENABLED"] = True
    assert correlation.analyze(assessment) is None


def test_prompt_lists_findings_with_severity_source_and_truncated_description(
    app, assessment_with_findings, monkeypatch
):
    captured = {}

    def fake_ask(prompt, system=None):
        captured["prompt"] = prompt
        captured["system"] = system
        return "summary text"

    monkeypatch.setattr(correlation, "ask", fake_ask)
    app.config["AI_ANALYSIS_ENABLED"] = True

    assert correlation.analyze(assessment_with_findings) == "summary text"
    prompt = captured["prompt"]
    assert prompt.startswith("Target: http://example.test")
    assert "- [HIGH] Exposed .env (source: endpoints)" in prompt
    assert "- [MEDIUM] Missing CSRF (source: endpoints)" in prompt
    assert "d" * 300 in prompt and "d" * 301 not in prompt
    assert "no markdown headers" in captured["system"]


def test_provider_failure_degrades_to_no_summary(app, assessment_with_findings, monkeypatch):
    monkeypatch.setattr(
        correlation, "ask",
        lambda *a, **k: (_ for _ in ()).throw(requests.ConnectionError("ollama down")),
    )
    app.config["AI_ANALYSIS_ENABLED"] = True
    assert correlation.analyze(assessment_with_findings) is None


def test_analysis_is_enabled_by_default_when_config_is_absent(
    app, assessment_with_findings, monkeypatch
):
    monkeypatch.setattr(correlation, "ask", lambda *a, **k: "summary")
    app.config.pop("AI_ANALYSIS_ENABLED")
    assert correlation.analyze(assessment_with_findings) == "summary"
