"""Coverage for engine.scan_engine.ScanEngine and engine.scheduler."""

import pytest

from database.models import Assessment, Finding, ModuleRun, db
from engine.plugin import FunctionScannerPlugin, MetadataOnlyPlugin, ScannerMetadata
from engine.scan_engine import ScanEngine
from engine.scheduler import ScanScheduler


class StubRegistry:
    def __init__(self, plugins: dict):
        self._plugins = plugins

    def get(self, name):
        return self._plugins.get(name)


class RecordingPlugin:
    """Scanner plugin that records its lifecycle calls."""

    def __init__(self, name, output=None, exc=None):
        self.name = name
        self.output = output if output is not None else {}
        self.exc = exc
        self.lifecycle = []
        self.seen_context = None

    def initialize(self):
        self.lifecycle.append("initialize")

    def scan(self, target_url, context=None):
        self.lifecycle.append("scan")
        self.seen_context = dict(context or {})
        if self.exc:
            raise self.exc
        return self.output

    def cleanup(self):
        self.lifecycle.append("cleanup")

    def health_check(self):
        return True

    def metadata(self):
        return ScannerMetadata(name=self.name)


def plan(assessment_id, *module_names):
    for name in module_names:
        db.session.add(ModuleRun(assessment_id=assessment_id, name=name, status="pending"))
    db.session.commit()


@pytest.fixture
def stub_reporting(monkeypatch, tmp_path):
    """Replaces the real HTML report generator with a path-returning stub."""
    import modules.reporting.reporting as reporting

    calls = []

    def _generate(assessment_id):
        calls.append(assessment_id)
        path = tmp_path / f"report_{assessment_id}.html"
        path.write_text("stub report")
        return str(path)

    monkeypatch.setattr(reporting, "generate", _generate)
    return calls


def test_missing_assessment_is_a_no_op(app, caplog):
    ScanEngine(registry=StubRegistry({})).run_assessment(4242)
    assert "not found" in caplog.text


def test_successful_run_completes_records_findings_and_reaches_full_progress(
    assessment, stub_reporting
):
    plan(assessment.id, "headers", "reporting")
    plugin = RecordingPlugin("headers", {"missing": ["X-Frame-Options"]})

    ScanEngine(registry=StubRegistry({"headers": plugin})).run_assessment(assessment.id)

    assert plugin.lifecycle == ["initialize", "scan", "cleanup"]
    assert assessment.status == "completed"
    assert assessment.progress == 100
    assert assessment.completed_at is not None
    assert assessment.report_path.endswith(f"report_{assessment.id}.html")
    assert stub_reporting == [assessment.id]

    runs = {r.name: r for r in ModuleRun.query.filter_by(assessment_id=assessment.id)}
    assert runs["headers"].status == "completed"
    assert runs["headers"].started_at is not None and runs["headers"].finished_at is not None
    assert "X-Frame-Options" in runs["headers"].raw_output
    assert runs["reporting"].raw_output.startswith("report written to ")

    findings = Finding.query.filter_by(assessment_id=assessment.id).all()
    assert [f.title for f in findings] == ["Missing Security Header: X-Frame-Options"]


def test_each_module_sees_previous_module_output_as_context(assessment, stub_reporting):
    plan(assessment.id, "recon", "cve")
    recon = RecordingPlugin("recon", {"server": "Werkzeug/2.0.1 Python/3.10"})
    cve = RecordingPlugin("cve", {"matches": []})

    ScanEngine(registry=StubRegistry({"recon": recon, "cve": cve})).run_assessment(assessment.id)

    assert cve.seen_context == {"recon": {"server": "Werkzeug/2.0.1 Python/3.10"}}
    assert recon.seen_context == {}, "the first module starts with an empty context"


def test_unknown_module_is_skipped_without_failing_the_assessment(assessment):
    plan(assessment.id, "not_implemented")

    ScanEngine(registry=StubRegistry({})).run_assessment(assessment.id)

    run = ModuleRun.query.filter_by(assessment_id=assessment.id).one()
    assert run.status == "skipped"
    assert run.raw_output == "not implemented yet"
    assert assessment.status == "completed"


def test_module_exception_fails_only_that_module_but_marks_assessment_failed(assessment):
    plan(assessment.id, "recon", "headers")
    broken = RecordingPlugin("recon", exc=RuntimeError("connection reset"))
    healthy = RecordingPlugin("headers", {"missing": []})

    ScanEngine(registry=StubRegistry({"recon": broken, "headers": healthy})).run_assessment(
        assessment.id
    )

    runs = {r.name: r for r in ModuleRun.query.filter_by(assessment_id=assessment.id)}
    assert runs["recon"].status == "failed"
    assert "RuntimeError: connection reset" in runs["recon"].raw_output
    assert runs["headers"].status == "completed"
    assert broken.lifecycle == ["initialize", "scan", "cleanup"], "cleanup runs even when scan raises"
    assert assessment.status == "failed"
    assert assessment.progress == 100


def test_failing_report_generation_marks_the_reporting_module_failed(assessment, monkeypatch):
    import modules.reporting.reporting as reporting

    monkeypatch.setattr(reporting, "generate", lambda _id: (_ for _ in ()).throw(ValueError("boom")))
    plan(assessment.id, "reporting")

    ScanEngine(registry=StubRegistry({})).run_assessment(assessment.id)

    run = ModuleRun.query.filter_by(assessment_id=assessment.id).one()
    assert run.status == "failed"
    assert "ValueError: boom" in run.raw_output
    assert assessment.report_path is None
    assert assessment.status == "failed"


def test_assessment_with_no_planned_modules_still_completes(assessment):
    ScanEngine(registry=StubRegistry({})).run_assessment(assessment.id)
    assert assessment.status == "completed"
    assert assessment.progress == 100


def test_progress_advances_proportionally_across_modules(assessment):
    plan(assessment.id, "a", "b", "c", "d")
    progress_snapshots = []

    class ProgressWatcher(RecordingPlugin):
        def scan(self, target_url, context=None):
            progress_snapshots.append(assessment.progress)
            return super().scan(target_url, context=context)

    plugins = {name: ProgressWatcher(name) for name in ("a", "b", "c", "d")}
    ScanEngine(registry=StubRegistry(plugins)).run_assessment(assessment.id)

    assert progress_snapshots == [0, 25, 50, 75]
    assert assessment.progress == 100


def test_engine_defaults_to_real_plugin_discovery(app):
    engine = ScanEngine()
    assert engine.registry.get("recon") is not None
    assert engine.registry.get("definitely_not_a_module") is None


def test_scheduler_runs_the_assessment_in_an_app_context(app, monkeypatch):
    from concurrent.futures import ThreadPoolExecutor

    row = Assessment(target_url="http://example.test", authorized=True)
    db.session.add(row)
    db.session.commit()
    assessment_id = row.id

    seen = []
    monkeypatch.setattr(
        ScanEngine, "run_assessment", lambda self, aid: seen.append((aid, bool(self.registry)))
    )

    scheduler = ScanScheduler(max_workers=1)
    scheduler.submit_assessment_job(app, assessment_id)
    scheduler._executor.shutdown(wait=True)

    assert seen == [(assessment_id, True)]
    assert isinstance(scheduler._executor, ThreadPoolExecutor)


# --- plugin adapters ---------------------------------------------------------


def test_function_scanner_plugin_wraps_a_module_level_run_function():
    calls = []

    def run(target_url, context=None):
        calls.append((target_url, context))
        return {"module": "demo"}

    plugin = FunctionScannerPlugin(ScannerMetadata(name="demo"), run)
    assert plugin.initialize() is None
    assert plugin.scan("http://example.test", context={"recon": {}}) == {"module": "demo"}
    assert plugin.cleanup() is None
    assert plugin.health_check() is True
    assert plugin.metadata().name == "demo"
    assert calls == [("http://example.test", {"recon": {}})]


def test_metadata_only_plugin_reports_itself_as_skipped():
    plugin = MetadataOnlyPlugin(ScannerMetadata(name="reporting", scan_type="reporting"))
    assert plugin.scan("http://example.test") == {"module": "reporting", "skipped": True}
    assert plugin.initialize() is None
    assert plugin.cleanup() is None
    assert plugin.health_check() is True
    assert plugin.metadata().scan_type == "reporting"
