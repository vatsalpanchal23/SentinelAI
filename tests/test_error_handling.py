"""Regression tests for error propagation: failures must not disappear."""

import logging
import subprocess

import pytest

from app import create_app
from database.models import Assessment, Finding, ModuleRun, db
from engine.plugin import ScannerMetadata
from engine.registry import PluginLoadError
from engine.scan_engine import ScanEngine
from engine.scheduler import ScanScheduler


class _StubPlugin:
    def __init__(self, name, scan_fn, cleanup_fn=None):
        self._metadata = ScannerMetadata(name=name)
        self._scan_fn = scan_fn
        self._cleanup_fn = cleanup_fn

    def initialize(self):
        return None

    def scan(self, target_url, context=None):
        return self._scan_fn(target_url, context)

    def cleanup(self):
        if self._cleanup_fn:
            self._cleanup_fn()

    def health_check(self):
        return True

    def metadata(self):
        return self._metadata


class _StubRegistry:
    def __init__(self, plugins=None, errors=None):
        self._plugins = plugins or {}
        self.errors = errors or []

    def get(self, name):
        return self._plugins.get(name)


@pytest.fixture()
def app(tmp_path):
    class TestConfig:
        SECRET_KEY = "test"
        TESTING = True
        SQLALCHEMY_DATABASE_URI = f"sqlite:///{tmp_path / 'test.db'}"
        SQLALCHEMY_TRACK_MODIFICATIONS = False
        SQLALCHEMY_ENGINE_OPTIONS = {"connect_args": {"check_same_thread": False}}
        EVIDENCE_DIR = str(tmp_path / "evidence")
        REPORTS_DIR = str(tmp_path / "reports")
        AI_ANALYSIS_ENABLED = False
        AI_PROVIDER = "ollama"
        OLLAMA_HOST = "http://localhost:11434"
        OLLAMA_MODEL = "qwen3"

    return create_app(TestConfig)


def _assessment_with_modules(module_names):
    assessment = Assessment(target_url="http://example.test", authorized=True)
    db.session.add(assessment)
    db.session.commit()
    for name in module_names:
        db.session.add(ModuleRun(assessment_id=assessment.id, name=name, status="pending"))
    db.session.commit()
    return assessment


def test_module_reported_errors_are_persisted_and_logged(app, caplog):
    with app.app_context():
        assessment = _assessment_with_modules(["recon"])
        registry = _StubRegistry({
            "recon": _StubPlugin("recon", lambda url, ctx: {"module": "recon", "errors": ["GET failed: timeout"]}),
        })

        with caplog.at_level(logging.WARNING, logger="sentinelai.engine.scan_engine"):
            ScanEngine(registry=registry).run_assessment(assessment.id)

        run_row = ModuleRun.query.filter_by(assessment_id=assessment.id, name="recon").one()
        assert run_row.status == "completed"
        assert run_row.errors == "GET failed: timeout"
        assert "GET failed: timeout" in caplog.text


def test_failed_module_rolls_back_its_partial_findings(app, monkeypatch):
    def _explode(db_, Finding_, assessment_id, module_name, output):
        db_.session.add(
            Finding_(assessment_id=assessment_id, title="half-written", severity="low")
        )
        raise RuntimeError("extraction blew up")

    monkeypatch.setattr("engine.scan_engine._record_findings", _explode)

    with app.app_context():
        assessment = _assessment_with_modules(["recon", "headers"])
        registry = _StubRegistry({
            "recon": _StubPlugin("recon", lambda url, ctx: {"module": "recon"}),
            "headers": _StubPlugin("headers", lambda url, ctx: {"module": "headers"}),
        })

        ScanEngine(registry=registry).run_assessment(assessment.id)

        assert Finding.query.filter_by(assessment_id=assessment.id).count() == 0
        statuses = {m.name: m.status for m in ModuleRun.query.filter_by(assessment_id=assessment.id)}
        # the second module still ran: the rollback left a usable session
        assert statuses == {"recon": "failed", "headers": "failed"}
        assert "extraction blew up" in ModuleRun.query.filter_by(name="recon").one().raw_output
        assert Assessment.query.get(assessment.id).status == "failed"


def test_plugin_load_error_is_reported_instead_of_not_implemented(app):
    with app.app_context():
        assessment = _assessment_with_modules(["recon"])
        registry = _StubRegistry(errors=[PluginLoadError("recon", "ImportError: no module named x")])

        ScanEngine(registry=registry).run_assessment(assessment.id)

        run_row = ModuleRun.query.filter_by(assessment_id=assessment.id, name="recon").one()
        assert run_row.status == "failed"
        assert "no module named x" in run_row.raw_output
        assert Assessment.query.get(assessment.id).status == "failed"


def test_missing_module_is_still_reported_as_skipped(app):
    with app.app_context():
        assessment = _assessment_with_modules(["not_written_yet"])

        ScanEngine(registry=_StubRegistry()).run_assessment(assessment.id)

        run_row = ModuleRun.query.filter_by(assessment_id=assessment.id).one()
        assert run_row.status == "skipped"
        assert Assessment.query.get(assessment.id).status == "completed"


def test_cleanup_failure_does_not_mask_the_scan_error(app):
    def _fail_scan(url, ctx):
        raise RuntimeError("scan failed for the real reason")

    def _fail_cleanup():
        raise RuntimeError("cleanup noise")

    with app.app_context():
        assessment = _assessment_with_modules(["recon"])
        registry = _StubRegistry({"recon": _StubPlugin("recon", _fail_scan, _fail_cleanup)})

        ScanEngine(registry=registry).run_assessment(assessment.id)

        run_row = ModuleRun.query.filter_by(assessment_id=assessment.id).one()
        assert run_row.status == "failed"
        assert "scan failed for the real reason" in run_row.raw_output


def test_crashed_scan_job_marks_assessment_failed(app, monkeypatch, caplog):
    def _crash(self, assessment_id):
        raise RuntimeError("engine crashed before it could record anything")

    monkeypatch.setattr(ScanEngine, "run_assessment", _crash)

    with app.app_context():
        assessment = _assessment_with_modules([])
        assessment.status = "running"
        db.session.commit()
        assessment_id = assessment.id

    scheduler = ScanScheduler(max_workers=1)
    with caplog.at_level(logging.ERROR, logger="sentinelai.engine.scheduler"):
        with pytest.raises(RuntimeError):
            scheduler._run_with_context(app, assessment_id)

    assert "scan job crashed" in caplog.text
    with app.app_context():
        assert Assessment.query.get(assessment_id).status == "failed"


def test_status_payload_exposes_module_errors(app):
    with app.app_context():
        assessment = _assessment_with_modules(["recon"])
        run_row = ModuleRun.query.filter_by(assessment_id=assessment.id).one()
        run_row.status = "completed"
        run_row.errors = "GET /a failed\nGET /b failed"
        db.session.commit()
        assessment_id = assessment.id

    response = app.test_client().get(f"/api/assessment/{assessment_id}/status")
    assert response.status_code == 200
    assert response.get_json()["modules"][0]["errors"] == ["GET /a failed", "GET /b failed"]


def test_queueing_failure_is_reported_to_the_submitter(app, monkeypatch):
    def _fail(*args, **kwargs):
        raise RuntimeError("registry unavailable")

    monkeypatch.setattr("dashboard.routes.plan_assessment", _fail)
    app.config["WTF_CSRF_ENABLED"] = False

    response = app.test_client().post(
        "/target", data={"target_url": "http://example.test", "authorized": "1"}
    )

    assert response.status_code == 500
    assert b"could not be queued" in response.data
    with app.app_context():
        assert Assessment.query.one().status == "failed"


def test_endpoints_records_probe_failures_and_caps_them():
    from modules.endpoints import endpoints

    errors = endpoints._BoundedErrors()
    for i in range(endpoints.MAX_RECORDED_ERRORS + 5):
        errors.append(f"GET /{i} failed")
    errors.flush_suppressed()

    assert len(errors) == endpoints.MAX_RECORDED_ERRORS + 1
    assert errors[-1] == "... and 5 further probe error(s) not listed"


def test_active_scan_reports_non_zero_tool_exit(monkeypatch):
    from modules.active_scan import active_scan

    proc = subprocess.CompletedProcess(args=["nuclei"], returncode=2, stdout="", stderr="could not load templates")
    monkeypatch.setattr(subprocess, "run", lambda *args, **kwargs: proc)
    errors = []

    assert active_scan._run_tool(["nuclei", "-u", "http://example.test"], 1, errors) == ""
    assert errors == ["nuclei exited with code 2: could not load templates"]


def test_report_write_failure_leaves_no_partial_file(app, monkeypatch, tmp_path):
    from modules.reporting import reporting

    monkeypatch.setattr(reporting, "_render", lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError("render failed")))

    with app.app_context():
        assessment = _assessment_with_modules([])

        with pytest.raises(RuntimeError):
            reporting.generate(assessment.id)

    reports_dir = tmp_path / "reports"
    assert list(reports_dir.glob("*")) == []
