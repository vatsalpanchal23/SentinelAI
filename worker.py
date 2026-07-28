"""Backward-compatible background job entry point."""

from __future__ import annotations

import logging

from engine.registry import PluginRegistry, discover_plugins
from engine.scheduler import ScanScheduler

logger = logging.getLogger("sentinelai.worker")

_scheduler = ScanScheduler(max_workers=4)
_registry: PluginRegistry | None = None

# Legacy compatibility for code/tests that introspect or call register_module.
_MODULE_RUNNERS = {}


def get_registry() -> PluginRegistry:
    """Return a lazily discovered plugin registry."""
    global _registry
    if _registry is None:
        _registry = discover_plugins()
    return _registry


def register_module(name, run_fn):
    """Compatibility shim for the pre-registry worker API."""
    _MODULE_RUNNERS[name] = run_fn
    logger.debug("legacy module registered: %s", name)


def submit_assessment_job(app, assessment_id: int) -> None:
    """Submit an assessment for background execution."""
    _scheduler.submit_assessment_job(app, assessment_id)
