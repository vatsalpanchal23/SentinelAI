"""Scanner plugin interface and compatibility adapters."""

from __future__ import annotations

from dataclasses import dataclass
from types import ModuleType
from typing import Any, Callable, Protocol


@dataclass(frozen=True)
class ScannerMetadata:
    """Describes a scanner or pipeline stage discovered by the registry."""

    name: str
    description: str = ""
    version: str = "0.1.0"
    author: str = "SentinelAI"
    priority: int = 100
    enabled: bool = True
    scan_type: str = "scanner"


class ScannerPlugin(Protocol):
    """Lifecycle expected from scanner plugins."""

    def initialize(self) -> None: ...
    def scan(self, target_url: str, context: dict[str, Any] | None = None) -> dict[str, Any]: ...
    def cleanup(self) -> None: ...
    def health_check(self) -> bool: ...
    def metadata(self) -> ScannerMetadata: ...


class FunctionScannerPlugin:
    """Adapter for legacy modules exposing run(target_url, context=None)."""

    def __init__(self, metadata: ScannerMetadata, run_fn: Callable[..., dict[str, Any]]):
        self._metadata = metadata
        self._run_fn = run_fn

    def initialize(self) -> None:
        return None

    def scan(self, target_url: str, context: dict[str, Any] | None = None) -> dict[str, Any]:
        return self._run_fn(target_url, context=context)

    def cleanup(self) -> None:
        return None

    def health_check(self) -> bool:
        return callable(self._run_fn)

    def metadata(self) -> ScannerMetadata:
        return self._metadata


def metadata_from_module(module: ModuleType, fallback_name: str, priority: int) -> ScannerMetadata:
    """Build metadata from a module-level PLUGIN_METADATA dict or defaults."""
    raw = getattr(module, "PLUGIN_METADATA", {}) or {}
    return ScannerMetadata(
        name=raw.get("name", fallback_name),
        description=raw.get("description", f"SentinelAI {fallback_name} stage"),
        version=raw.get("version", "0.1.0"),
        author=raw.get("author", "SentinelAI"),
        priority=int(raw.get("priority", priority)),
        enabled=bool(raw.get("enabled", True)),
        scan_type=raw.get("scan_type", "scanner"),
    )


class MetadataOnlyPlugin:
    """Pipeline stage placeholder for non-scanner stages such as reporting."""

    def __init__(self, metadata: ScannerMetadata) -> None:
        self._metadata = metadata

    def initialize(self) -> None:
        return None

    def scan(self, target_url: str, context: dict[str, Any] | None = None) -> dict[str, Any]:
        return {"module": self._metadata.name, "skipped": True}

    def cleanup(self) -> None:
        return None

    def health_check(self) -> bool:
        return True

    def metadata(self) -> ScannerMetadata:
        return self._metadata
