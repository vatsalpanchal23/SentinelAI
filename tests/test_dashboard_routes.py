"""Coverage for dashboard.routes: URL/authorization validation, duplicate
confirmation, detail + report views, and the status/SSE APIs."""

import json
from datetime import datetime, timedelta

import pytest

from dashboard.routes import _validate_target_url
from database.models import Assessment, Finding, ModuleRun, db


@pytest.fixture(autouse=True)
def no_background_jobs(monkeypatch):
    """Submissions must not spawn real scans during tests."""
    import worker

    submitted = []
    monkeypatch.setattr(worker, "submit_assessment_job", lambda app, aid: submitted.append(aid))
    return submitted


@pytest.fixture
def submitted(no_background_jobs):
    return no_background_jobs


def post_target(client, **overrides):
    form = {"target_url": "http://target.test", "authorized": "1"}
    form.update(overrides)
    return client.post("/target", data=form)


# --- validation --------------------------------------------------------------


@pytest.mark.parametrize(
    "raw,expected_fragment",
    [
        ("", "required"),
        ("ftp://example.test", "http:// or https://"),
        ("example.test", "http:// or https://"),
        ("http://", "must include a host"),
    ],
)
def test_unusable_urls_are_rejected(raw, expected_fragment):
    assert expected_fragment in _validate_target_url(raw)


@pytest.mark.parametrize("raw", ["http://example.test", "https://example.test:8443/app"])
def test_valid_urls_pass(raw):
    assert _validate_target_url(raw) is None


# --- pages -------------------------------------------------------------------


def test_dashboard_lists_assessments_newest_first(client, app):
    older = Assessment(target_url="http://old.test", created_at=datetime(2024, 1, 1))
    newer = Assessment(target_url="http://new.test", created_at=datetime(2024, 6, 1))
    db.session.add_all([older, newer])
    db.session.commit()

    body = client.get("/").get_data(as_text=True)
    assert body.index("http://new.test") < body.index("http://old.test")


def test_target_form_renders(client):
    assert client.get("/target").status_code == 200


def test_submission_creates_the_assessment_plans_modules_and_queues_the_job(client, submitted):
    response = post_target(client, active_scan_enabled="1")
    assessment = Assessment.query.one()

    assert response.status_code == 302
    assert response.headers["Location"].endswith(f"/assessment/{assessment.id}")
    assert assessment.target_url == "http://target.test"
    assert assessment.status == "pending"
    assert assessment.authorized is True and assessment.active_scan_enabled is True
    assert submitted == [assessment.id]

    planned = [m.name for m in ModuleRun.query.filter_by(assessment_id=assessment.id)]
    assert "active_scan" in planned and planned[-1] == "reporting"


def test_active_scan_stays_opt_in(client, submitted):
    post_target(client)
    assessment = Assessment.query.one()
    assert assessment.active_scan_enabled is False
    planned = [m.name for m in ModuleRun.query.filter_by(assessment_id=assessment.id)]
    assert "active_scan" not in planned


def test_submission_without_the_authorization_checkbox_is_refused(client, submitted):
    response = post_target(client, authorized="0")
    assert response.status_code == 200
    assert "authorized to test this target" in response.get_data(as_text=True)
    assert Assessment.query.count() == 0
    assert submitted == []


def test_invalid_url_is_re_rendered_with_the_error(client, submitted):
    response = post_target(client, target_url="not-a-url")
    assert "http:// or https://" in response.get_data(as_text=True)
    assert Assessment.query.count() == 0
    assert submitted == []


def test_recent_duplicate_requires_confirmation(client, submitted):
    post_target(client)
    assert Assessment.query.count() == 1

    response = post_target(client)
    assert response.status_code == 200
    assert Assessment.query.count() == 1, "the duplicate is not created until confirmed"
    assert len(submitted) == 1

    post_target(client, confirm_duplicate="1")
    assert Assessment.query.count() == 2
    assert len(submitted) == 2


def test_a_stale_previous_run_is_not_treated_as_a_duplicate(client, app, submitted):
    stale = Assessment(
        target_url="http://target.test",
        created_at=datetime.utcnow() - timedelta(minutes=30),
        authorized=True,
    )
    db.session.add(stale)
    db.session.commit()

    post_target(client)
    assert Assessment.query.count() == 2


def test_assessment_detail_shows_findings_ordered_by_severity(client, assessment):
    db.session.add_all(
        [
            Finding(assessment_id=assessment.id, title="Low finding", severity="low"),
            Finding(assessment_id=assessment.id, title="Critical finding", severity="critical"),
        ]
    )
    db.session.commit()

    body = client.get(f"/assessment/{assessment.id}").get_data(as_text=True)
    assert body.index("Critical finding") < body.index("Low finding")


def test_missing_assessment_detail_is_a_404(client):
    assert client.get("/assessment/999").status_code == 404


def test_report_view_is_404_until_the_report_exists(client, assessment, tmp_path):
    assert client.get(f"/assessment/{assessment.id}/report").status_code == 404

    assessment.report_path = str(tmp_path / "gone.html")
    db.session.commit()
    assert client.get(f"/assessment/{assessment.id}/report").status_code == 404, "stale path"

    report = tmp_path / "report.html"
    report.write_text("<html>report</html>")
    assessment.report_path = str(report)
    db.session.commit()

    response = client.get(f"/assessment/{assessment.id}/report")
    assert response.status_code == 200
    assert b"<html>report</html>" in response.data


def test_report_view_for_unknown_assessment_is_a_404(client):
    assert client.get("/assessment/999/report").status_code == 404


# --- status API --------------------------------------------------------------


@pytest.fixture
def running_assessment(assessment):
    started = datetime.utcnow() - timedelta(seconds=5)
    assessment.status = "running"
    assessment.progress = 50
    db.session.add_all(
        [
            ModuleRun(assessment_id=assessment.id, name="recon", status="completed",
                      started_at=started, finished_at=started + timedelta(seconds=2)),
            ModuleRun(assessment_id=assessment.id, name="headers", status="running",
                      started_at=started),
            ModuleRun(assessment_id=assessment.id, name="cve", status="failed",
                      started_at=started, finished_at=started,
                      raw_output="Traceback...\nConnectionError: refused"),
            ModuleRun(assessment_id=assessment.id, name="reporting", status="pending"),
            Finding(assessment_id=assessment.id, title="Missing CSP", severity="medium",
                    description="no CSP header", recommendation="add one",
                    source_modules="headers"),
        ]
    )
    db.session.commit()
    return assessment


def test_status_api_serializes_progress_modules_and_findings(client, running_assessment):
    payload = client.get(f"/api/assessment/{running_assessment.id}/status").get_json()

    assert payload["status"] == "running" and payload["progress"] == 50
    assert payload["report_available"] is False
    assert payload["risk_score"] == 98 and payload["severity_counts"]["medium"] == 1
    assert payload["findings"] == [
        {"id": 1, "title": "Missing CSP", "severity": "medium", "source_modules": "headers",
         "description": "no CSP header", "recommendation": "add one"}
    ]

    modules = {m["name"]: m for m in payload["modules"]}
    assert modules["recon"]["duration_seconds"] == 2.0
    assert modules["headers"]["duration_seconds"] >= 4, "a running module is timed against now"
    assert modules["reporting"]["duration_seconds"] is None
    assert modules["cve"]["failure_reason"] == "ConnectionError: refused"
    assert modules["recon"]["failure_reason"] is None


def test_status_api_reports_an_available_report(client, assessment, tmp_path):
    assessment.report_path = str(tmp_path / "r.html")
    db.session.commit()
    payload = client.get(f"/api/assessment/{assessment.id}/status").get_json()
    assert payload["report_available"] is True


def test_status_api_404s_for_an_unknown_assessment(client):
    assert client.get("/api/assessment/999/status").status_code == 404


# --- SSE stream --------------------------------------------------------------


def test_stream_pushes_one_payload_then_closes_for_a_finished_assessment(client, running_assessment):
    running_assessment.status = "completed"
    running_assessment.progress = 100
    db.session.commit()

    response = client.get(f"/api/assessment/{running_assessment.id}/stream")
    assert response.headers["Content-Type"].startswith("text/event-stream")
    assert response.headers["Cache-Control"] == "no-cache"

    body = response.get_data(as_text=True)
    assert body.startswith("data: ")
    payload = json.loads(body[len("data: "):].strip())
    assert payload["status"] == "completed"
    assert payload["progress"] == 100


def test_stream_reports_an_error_event_for_a_missing_assessment(client):
    body = client.get("/api/assessment/999/stream").get_data(as_text=True)
    assert body == 'event: error\ndata: {"error": "not found"}\n\n'


def test_stream_sends_keep_alives_while_the_payload_is_unchanged(client, assessment, monkeypatch):
    import dashboard.routes as routes

    ticks = []
    monkeypatch.setattr(routes.time, "sleep", lambda seconds: ticks.append(seconds))

    # shadow the builtin in the module so the ~10-minute stream loop ends quickly
    monkeypatch.setattr(routes, "range", lambda _iterations: [0, 1, 2], raising=False)
    assessment.status = "running"
    db.session.commit()

    body = client.get(f"/api/assessment/{assessment.id}/stream").get_data(as_text=True)
    assert body.count("data: ") == 1, "the payload is only pushed when it changes"
    assert body.count(": keep-alive") == 2
    assert ticks == [2, 2, 2]
