"""Background scan scheduling."""

from __future__ import annotations

import logging
from concurrent.futures import ThreadPoolExecutor

from engine.scan_engine import ScanEngine

logger = logging.getLogger("sentinelai.engine.scheduler")


class ScanScheduler:
    """Thin ThreadPoolExecutor wrapper for scan jobs."""

    def __init__(self, max_workers: int = 4) -> None:
        self._executor = ThreadPoolExecutor(max_workers=max_workers)

    def submit_assessment_job(self, app, assessment_id: int) -> None:
        self._executor.submit(self._run_with_context, app, assessment_id)

    def _run_with_context(self, app, assessment_id: int) -> None:
        # Nothing ever calls Future.result() on the submitted job, so an
        # exception escaping here would be stored on the future and never
        # seen: no traceback in the log, and the assessment left stuck on its
        # last status forever. Log it and mark the assessment failed instead.
        try:
            with app.app_context():
                ScanEngine().run_assessment(assessment_id)
        except BaseException:
            logger.exception("assessment %s: scan job crashed", assessment_id)
            self._mark_assessment_failed(app, assessment_id)
            raise

    @staticmethod
    def _mark_assessment_failed(app, assessment_id: int) -> None:
        from database.models import Assessment, db

        try:
            with app.app_context():
                db.session.rollback()
                assessment = Assessment.query.get(assessment_id)
                if assessment is None:
                    return
                assessment.status = "failed"
                db.session.commit()
        except Exception:
            logger.exception(
                "assessment %s: could not persist failed status after crash", assessment_id
            )
