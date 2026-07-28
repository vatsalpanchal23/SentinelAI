from engine.pipeline import build_pipeline
from engine.registry import discover_plugins


def test_registry_discovers_expected_plugins():
    registry = discover_plugins()
    assert registry.errors == []
    assert registry.names() == [
        "recon", "fingerprint", "endpoints", "javascript", "cve",
        "headers", "vulnerabilities", "active_scan", "reporting",
    ]


def test_pipeline_preserves_legacy_order_without_active_scan():
    assert build_pipeline(active_scan_enabled=False) == [
        "recon", "fingerprint", "endpoints", "javascript", "cve",
        "headers", "vulnerabilities", "reporting",
    ]


def test_pipeline_preserves_legacy_order_with_active_scan():
    assert build_pipeline(active_scan_enabled=True) == [
        "recon", "fingerprint", "endpoints", "javascript", "cve",
        "headers", "vulnerabilities", "active_scan", "reporting",
    ]
