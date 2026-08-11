"""Database-backed scan orchestration."""

from __future__ import annotations

import logging
import traceback
from datetime import datetime
from typing import Any

from engine.findings import _record_findings
from engine.registry import PluginRegistry, discover_plugins

logger = logging.getLogger("sentinelai.engine.scan_engine")


class ScanEngine:
    """Runs persisted ModuleRun rows for an assessment."""

    def __init__(self, registry: PluginRegistry | None = None) -> None:
        self.registry = registry or discover_plugins()

    def run_assessment(self, assessment_id: int) -> None:
        from database.models import Assessment, Finding, ModuleRun, db

        assessment = Assessment.query.get(assessment_id)
        if assessment is None:
            logger.warning("assessment %s not found", assessment_id)
            return

        assessment.status = "running"
        db.session.commit()
        logger.info("assessment %s: starting pipeline for %s", assessment_id, assessment.target_url)

        module_runs = ModuleRun.query.filter_by(assessment_id=assessment_id).order_by(ModuleRun.id).all()
        total = len(module_runs) or 1
        any_failed = False
        context: dict[str, Any] = {}

        for i, run_row in enumerate(module_runs, start=1):
            run_row.status = "running"
            run_row.started_at = datetime.utcnow()
            db.session.commit()
            logger.info("assessment %s: module '%s' started", assessment_id, run_row.name)

            try:
                if run_row.name == "reporting":
                    self._run_reporting(assessment, assessment_id, run_row)
                else:
                    plugin = self.registry.get(run_row.name)
                    if plugin is None:
                        # A module can be absent because it isn't written yet or
                        # because the registry failed to load it -- those are very
                        # different, so don't report both as "not implemented".
                        load_error = self._load_error_for(run_row.name)
                        if load_error is None:
                            run_row.status = "skipped"
                            run_row.raw_output = "not implemented yet"
                            logger.info("assessment %s: module '%s' skipped (not implemented)", assessment_id, run_row.name)
                        else:
                            run_row.status = "failed"
                            run_row.raw_output = f"plugin failed to load: {load_error}"
                            run_row.errors = run_row.raw_output
                            any_failed = True
                            logger.error("assessment %s: module '%s' failed to load: %s", assessment_id, run_row.name, load_error)
                    else:
                        output = self._run_scanner(plugin, assessment.target_url, context)
                        context[run_row.name] = output
                        run_row.raw_output = str(output)
                        run_row.status = "completed"
                        module_errors = self._module_errors(output)
                        run_row.errors = "\n".join(module_errors) or None
                        findings_added = _record_findings(db, Finding, assessment_id, run_row.name, output)
                        db.session.commit()
                        logger.info("assessment %s: module '%s' completed, %d finding(s) recorded", assessment_id, run_row.name, findings_added)
                        for message in module_errors:
                            logger.warning("assessment %s: module '%s' reported an error: %s", assessment_id, run_row.name, message)
            except Exception as exc:
                # The module may have added Finding rows before it blew up, and
                # a failure raised by commit() itself leaves the session
                # unusable -- roll back so partial writes aren't persisted and
                # the remaining modules still get a working session.
                failure = traceback.format_exc()
                db.session.rollback()
                run_row = self._reload_run_row(ModuleRun, run_row)
                run_row.status = "failed"
                # Full traceback goes to the server log only; raw_output is
                # surfaced in the UI/status API, and a traceback there leaks
                # filesystem paths and internals.
                run_row.raw_output = f"{type(exc).__name__}: {exc}"
                any_failed = True
                logger.error("assessment %s: module '%s' failed\n%s", assessment_id, run_row.name, failure)

            run_row.finished_at = datetime.utcnow()
            assessment.progress = int(i / total * 100)
            db.session.commit()

        assessment.status = "failed" if any_failed else "completed"
        assessment.progress = 100
        assessment.completed_at = datetime.utcnow()
        db.session.commit()
        logger.info("assessment %s: pipeline finished with status=%s", assessment_id, assessment.status)

    def _load_error_for(self, module_name: str) -> str | None:
        for load_error in self.registry.errors:
            if load_error.module_name == module_name:
                return load_error.error
        return None

    @staticmethod
    def _module_errors(output: Any) -> list[str]:
        """Modules report recoverable problems (failed requests, unparsable
        HTML, missing external tools) in output["errors"] rather than raising.
        Return them so they are logged and persisted instead of only ending up
        buried in the stringified raw output."""
        if not isinstance(output, dict):
            return []
        errors = output.get("errors") or []
        if isinstance(errors, str):
            return [errors]
        return [str(e) for e in errors]

    @staticmethod
    def _reload_run_row(ModuleRun, run_row):
        """After a rollback the row's pending changes are gone and the instance
        may be detached, so re-fetch it before recording the failure."""
        return ModuleRun.query.get(run_row.id) or run_row

    def _run_scanner(self, plugin, target_url: str, context: dict[str, Any]) -> dict[str, Any]:
        plugin.initialize()
        try:
            return plugin.scan(target_url, context=context)
        finally:
            # A failing cleanup() must not replace the scan's own exception,
            # which is the one that explains why the module failed.
            try:
                plugin.cleanup()
            except Exception:
                logger.exception("plugin '%s' cleanup failed", plugin.metadata().name)

    def _run_reporting(self, assessment, assessment_id: int, run_row) -> None:
        from modules.reporting.reporting import generate as generate_report

        report_path = generate_report(assessment_id)
        assessment.report_path = report_path
        run_row.status = "completed"
        run_row.raw_output = f"report written to {report_path}"
        logger.info("assessment %s: report generated at %s", assessment_id, report_path)
