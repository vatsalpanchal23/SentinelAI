"""Background scan scheduling."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

from engine.scan_engine import ScanEngine


class ScanScheduler:
    """Thin ThreadPoolExecutor wrapper for scan jobs."""

    def __init__(self, max_workers: int = 4) -> None:
        self._executor = ThreadPoolExecutor(max_workers=max_workers)

    def submit_assessment_job(self, app, assessment_id: int) -> None:
        self._executor.submit(self._run_with_context, app, assessment_id)

    def _run_with_context(self, app, assessment_id: int) -> None:
        with app.app_context():
            ScanEngine().run_assessment(assessment_id)
