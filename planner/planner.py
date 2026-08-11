"""
AI Planner

Decides which modules to run for a given assessment, and in what order.
v1: static pipeline (+ one conditional step). Later: LLM-driven, target-aware planning.
"""

import logging

from database.models import db, ModuleRun

logger = logging.getLogger("sentinelai.planner")

DEFAULT_PIPELINE = [
    "recon",
    "fingerprint",
    "endpoints",
    "javascript",
    "cve",
    "headers",
    "vulnerabilities",
    "active_scan",  # only included when active_scan_enabled -- see plan_assessment
    "reporting",
]


def plan_assessment(assessment_id: int, active_scan_enabled: bool = False) -> list[str]:
    """Create ModuleRun rows for the assessment pipeline. Returns the module order."""
    try:
        from engine.pipeline import build_pipeline

        pipeline = build_pipeline(active_scan_enabled=active_scan_enabled)
    except Exception:
        # Preserve legacy behavior if registry discovery fails during startup/tests,
        # but log why -- silently falling back hides a broken registry behind a
        # pipeline that looks normal.
        logger.exception("registry-driven pipeline unavailable; falling back to DEFAULT_PIPELINE")
        pipeline = [m for m in DEFAULT_PIPELINE if m != "active_scan" or active_scan_enabled]
    for module_name in pipeline:
        run = ModuleRun(assessment_id=assessment_id, name=module_name, status="pending")
        db.session.add(run)
    db.session.commit()
    return pipeline
