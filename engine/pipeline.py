"""Pipeline planning helpers."""

from __future__ import annotations

from engine.registry import PluginRegistry, discover_plugins


def build_pipeline(active_scan_enabled: bool = False, registry: PluginRegistry | None = None) -> list[str]:
    """Return module names in execution order, preserving legacy behavior."""
    registry = registry or discover_plugins()
    return [p.metadata().name for p in registry.ordered_plugins(include_active=active_scan_enabled)]
