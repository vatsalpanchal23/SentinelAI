"""Automatic scanner plugin discovery."""

from __future__ import annotations

import importlib
import logging
import pkgutil
from dataclasses import dataclass
from types import ModuleType
from engine.plugin import FunctionScannerPlugin, MetadataOnlyPlugin, ScannerMetadata, ScannerPlugin, metadata_from_module

logger = logging.getLogger("sentinelai.engine.registry")

_DEFAULT_PRIORITIES = {
    "recon": 10,
    "fingerprint": 20,
    "endpoints": 30,
    "javascript": 40,
    "cve": 50,
    "headers": 60,
    "vulnerabilities": 70,
    "active_scan": 80,
    "reporting": 90,
}

@dataclass(frozen=True)
class PluginLoadError:
    module_name: str
    error: str


class PluginRegistry:
    """Discovers and stores scanner plugins from the modules package."""

    def __init__(self, package: str = "modules") -> None:
        self.package = package
        self._plugins: dict[str, ScannerPlugin] = {}
        self.errors: list[PluginLoadError] = []

    def discover(self) -> "PluginRegistry":
        self._plugins.clear()
        self.errors.clear()
        package = importlib.import_module(self.package)
        for info in pkgutil.iter_modules(package.__path__):
            if info.name.startswith("_"):
                continue
            self._load_plugin(info.name)
        return self

    def _load_plugin(self, name: str) -> None:
        try:
            module = self._import_scanner_module(name)
            plugin = self._plugin_from_module(name, module)
        except Exception as exc:  # keep app startup resilient to one bad plugin
            self.errors.append(PluginLoadError(name, f"{type(exc).__name__}: {exc}"))
            logger.exception("failed to load plugin %s", name)
            return
        meta = plugin.metadata()
        if meta.enabled:
            self._plugins[meta.name] = plugin

    def _import_scanner_module(self, name: str) -> ModuleType:
        # Current convention is modules.<name>.<name>. Keep package fallback for future plugins.
        try:
            return importlib.import_module(f"{self.package}.{name}.{name}")
        except ModuleNotFoundError:
            return importlib.import_module(f"{self.package}.{name}")

    def _plugin_from_module(self, name: str, module: ModuleType) -> ScannerPlugin:
        if hasattr(module, "get_plugin"):
            plugin = module.get_plugin()
            if not plugin.metadata().name:
                raise ValueError("plugin metadata must include a name")
            return plugin
        metadata = metadata_from_module(module, name, _DEFAULT_PRIORITIES.get(name, 100))
        if not hasattr(module, "run"):
            if metadata.scan_type == "reporting":
                return MetadataOnlyPlugin(metadata)
            raise ValueError("plugin module must expose run() or get_plugin()")
        return FunctionScannerPlugin(metadata, module.run)

    def get(self, name: str) -> ScannerPlugin | None:
        return self._plugins.get(name)

    def names(self) -> list[str]:
        return [p.metadata().name for p in self.ordered_plugins(include_active=True, include_reporting=True)]

    def ordered_plugins(self, include_active: bool = False, include_reporting: bool = True) -> list[ScannerPlugin]:
        plugins = list(self._plugins.values())
        if not include_active:
            plugins = [p for p in plugins if p.metadata().name != "active_scan"]
        if not include_reporting:
            plugins = [p for p in plugins if p.metadata().name != "reporting"]
        return sorted(plugins, key=lambda p: (p.metadata().priority, p.metadata().name))


def discover_plugins(package: str = "modules") -> PluginRegistry:
    return PluginRegistry(package=package).discover()
