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
                        run_row.status = "skipped"
                        run_row.raw_output = "not implemented yet"
                        logger.info("assessment %s: module '%s' skipped (not implemented)", assessment_id, run_row.name)
                    else:
                        output = self._run_scanner(plugin, assessment.target_url, context)
                        context[run_row.name] = output
                        run_row.raw_output = str(output)
                        run_row.status = "completed"
                        findings_added = _record_findings(db, Finding, assessment_id, run_row.name, output)
                        db.session.commit()
                        logger.info("assessment %s: module '%s' completed, %d finding(s) recorded", assessment_id, run_row.name, findings_added)
            except Exception as exc:
                # Full traceback goes to the server log only; raw_output is
                # surfaced in the UI/status API, and a traceback there leaks
                # filesystem paths and internals.
                run_row.status = "failed"
                run_row.raw_output = f"{type(exc).__name__}: {exc}"
                any_failed = True
                logger.error(
                    "assessment %s: module '%s' failed\n%s",
                    assessment_id, run_row.name, traceback.format_exc(),
                )

            run_row.finished_at = datetime.utcnow()
            assessment.progress = int(i / total * 100)
            db.session.commit()

        assessment.status = "failed" if any_failed else "completed"
        assessment.progress = 100
        assessment.completed_at = datetime.utcnow()
        db.session.commit()
        logger.info("assessment %s: pipeline finished with status=%s", assessment_id, assessment.status)

    def _run_scanner(self, plugin, target_url: str, context: dict[str, Any]) -> dict[str, Any]:
        plugin.initialize()
        try:
            return plugin.scan(target_url, context=context)
        finally:
            plugin.cleanup()

    def _run_reporting(self, assessment, assessment_id: int, run_row) -> None:
        from modules.reporting.reporting import generate as generate_report

        report_path = generate_report(assessment_id)
        assessment.report_path = report_path
        run_row.status = "completed"
        run_row.raw_output = f"report written to {report_path}"
        logger.info("assessment %s: report generated at %s", assessment_id, report_path)
