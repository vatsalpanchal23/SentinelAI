"""Coverage for engine.registry's discovery rules, engine.pipeline ordering,
planner fallback behaviour, and the legacy worker shims.

Discovery is exercised against a synthetic plugin package written to a temp
directory, so each rule can be tested in isolation from the real modules/.
"""

import sys
import textwrap

import pytest

from engine.pipeline import build_pipeline
from engine.registry import PluginRegistry, discover_plugins


@pytest.fixture
def plugin_package(tmp_path, monkeypatch):
    """Builds an importable package of synthetic plugin modules."""
    package_name = "synthetic_plugins"
    package_dir = tmp_path / package_name
    package_dir.mkdir()
    (package_dir / "__init__.py").write_text("")
    monkeypatch.syspath_prepend(str(tmp_path))

    def add(name: str, source: str, nested: bool = True):
        """nested=True writes <name>/<name>.py, the repo's own convention."""
        if nested:
            module_dir = package_dir / name
            module_dir.mkdir()
            (module_dir / "__init__.py").write_text("")
            (module_dir / f"{name}.py").write_text(textwrap.dedent(source))
        else:
            (package_dir / f"{name}.py").write_text(textwrap.dedent(source))

    yield add, package_name

    for module in [m for m in sys.modules if m.startswith(package_name)]:
        del sys.modules[module]


def discover(package_name):
    return discover_plugins(package=package_name)


def test_run_function_modules_become_function_plugins(plugin_package):
    add, package_name = plugin_package
    add("alpha", """
        PLUGIN_METADATA = {"name": "alpha", "priority": 5, "description": "d", "version": "9.9",
                           "author": "someone", "scan_type": "recon"}

        def run(target_url, context=None):
            return {"module": "alpha", "target": target_url, "context": context}
    """)

    registry = discover(package_name)
    assert registry.errors == []
    plugin = registry.get("alpha")
    assert plugin.scan("http://x.test", context={"a": 1}) == {
        "module": "alpha", "target": "http://x.test", "context": {"a": 1}
    }
    meta = plugin.metadata()
    assert (meta.priority, meta.version, meta.author, meta.scan_type) == (5, "9.9", "someone", "recon")


def test_metadata_defaults_are_applied_when_the_module_declares_none(plugin_package):
    add, package_name = plugin_package
    add("recon", "def run(target_url, context=None):\n    return {}\n")

    meta = discover(package_name).get("recon").metadata()
    assert meta.name == "recon"
    assert meta.priority == 10, "known stage names keep their default priority"
    assert meta.description == "SentinelAI recon stage"
    assert meta.version == "0.1.0" and meta.author == "SentinelAI"
    assert meta.enabled is True and meta.scan_type == "scanner"


def test_unknown_stage_names_get_the_fallback_priority(plugin_package):
    add, package_name = plugin_package
    add("brand_new", "def run(target_url, context=None):\n    return {}\n")
    assert discover(package_name).get("brand_new").metadata().priority == 100


def test_single_file_modules_are_imported_via_the_package_fallback(plugin_package):
    add, package_name = plugin_package
    add("flat", "def run(target_url, context=None):\n    return {'module': 'flat'}\n", nested=False)

    registry = discover(package_name)
    assert registry.errors == []
    assert registry.get("flat").scan("http://x.test") == {"module": "flat"}


def test_get_plugin_factories_are_used_directly(plugin_package):
    add, package_name = plugin_package
    add("custom", """
        from engine.plugin import ScannerMetadata

        class Custom:
            def initialize(self): pass
            def cleanup(self): pass
            def health_check(self): return True
            def scan(self, target_url, context=None): return {"module": "custom"}
            def metadata(self): return ScannerMetadata(name="custom", priority=1)

        def get_plugin():
            return Custom()
    """)

    plugin = discover(package_name).get("custom")
    assert plugin.scan("http://x.test") == {"module": "custom"}
    assert plugin.metadata().priority == 1


def test_a_plugin_factory_without_a_name_is_a_load_error(plugin_package):
    add, package_name = plugin_package
    add("nameless", """
        from engine.plugin import ScannerMetadata

        class Nameless:
            def metadata(self): return ScannerMetadata(name="")

        def get_plugin():
            return Nameless()
    """)

    registry = discover(package_name)
    assert registry.get("nameless") is None
    assert registry.errors[0].module_name == "nameless"
    assert "plugin metadata must include a name" in registry.errors[0].error


def test_a_module_without_run_is_a_load_error(plugin_package):
    add, package_name = plugin_package
    add("empty", "SOMETHING = 1\n")

    registry = discover(package_name)
    assert registry.get("empty") is None
    assert len(registry.errors) == 1
    assert "must expose run() or get_plugin()" in registry.errors[0].error


def test_a_reporting_stage_needs_no_run_function(plugin_package):
    add, package_name = plugin_package
    add("reporting", 'PLUGIN_METADATA = {"name": "reporting", "scan_type": "reporting"}\n')

    registry = discover(package_name)
    assert registry.errors == []
    assert registry.get("reporting").scan("http://x.test") == {"module": "reporting", "skipped": True}


def test_an_importable_but_broken_module_does_not_break_discovery(plugin_package):
    add, package_name = plugin_package
    add("broken", "raise RuntimeError('boom at import time')\n")
    add("healthy", "def run(target_url, context=None):\n    return {}\n")

    registry = discover(package_name)
    assert registry.get("healthy") is not None
    assert registry.errors[0].module_name == "broken"
    assert registry.errors[0].error == "RuntimeError: boom at import time"


def test_disabled_plugins_are_not_registered(plugin_package):
    add, package_name = plugin_package
    add("off", """
        PLUGIN_METADATA = {"name": "off", "enabled": False}

        def run(target_url, context=None):
            return {}
    """)

    registry = discover(package_name)
    assert registry.get("off") is None
    assert registry.errors == []


def test_private_modules_are_skipped(plugin_package):
    add, package_name = plugin_package
    add("_internal", "raise RuntimeError('never imported')\n", nested=False)

    registry = discover(package_name)
    assert registry.names() == []
    assert registry.errors == []


def test_rediscovery_clears_previous_state(plugin_package):
    add, package_name = plugin_package
    add("alpha", "def run(target_url, context=None):\n    return {}\n")

    registry = PluginRegistry(package=package_name).discover()
    assert registry.names() == ["alpha"]
    registry.discover()
    assert registry.names() == ["alpha"], "plugins are not duplicated across discoveries"


def test_ordering_is_by_priority_then_name(plugin_package):
    add, package_name = plugin_package
    for name, priority in (("zulu", 10), ("alpha", 10), ("mid", 5)):
        add(name, f'PLUGIN_METADATA = {{"name": "{name}", "priority": {priority}}}\n'
                  "def run(target_url, context=None):\n    return {}\n")

    registry = discover(package_name)
    assert registry.names() == ["mid", "alpha", "zulu"]


def test_active_and_reporting_stages_can_be_filtered_out(plugin_package):
    add, package_name = plugin_package
    add("active_scan", 'PLUGIN_METADATA = {"name": "active_scan"}\n'
                       "def run(target_url, context=None):\n    return {}\n")
    add("reporting", 'PLUGIN_METADATA = {"name": "reporting", "scan_type": "reporting"}\n')
    add("recon", "def run(target_url, context=None):\n    return {}\n")

    registry = discover(package_name)
    assert [p.metadata().name for p in registry.ordered_plugins()] == ["recon", "reporting"]
    assert [p.metadata().name for p in registry.ordered_plugins(include_reporting=False)] == ["recon"]
    assert [p.metadata().name for p in
            registry.ordered_plugins(include_active=True, include_reporting=False)] == [
        "recon", "active_scan"
    ]


def test_build_pipeline_uses_an_injected_registry(plugin_package):
    add, package_name = plugin_package
    add("recon", "def run(target_url, context=None):\n    return {}\n")
    add("active_scan", 'PLUGIN_METADATA = {"name": "active_scan"}\n'
                       "def run(target_url, context=None):\n    return {}\n")

    registry = discover(package_name)
    assert build_pipeline(registry=registry) == ["recon"]
    assert build_pipeline(active_scan_enabled=True, registry=registry) == ["recon", "active_scan"]


# --- planner + worker shims --------------------------------------------------


def test_planner_falls_back_to_the_static_pipeline_when_discovery_fails(app, monkeypatch):
    import planner.planner as planner_module
    from database.models import Assessment, ModuleRun, db

    monkeypatch.setattr(
        "engine.pipeline.build_pipeline",
        lambda active_scan_enabled=False: (_ for _ in ()).throw(RuntimeError("registry broken")),
    )

    row = Assessment(target_url="http://example.test", authorized=True)
    db.session.add(row)
    db.session.commit()

    pipeline = planner_module.plan_assessment(row.id, active_scan_enabled=True)
    assert pipeline == planner_module.DEFAULT_PIPELINE
    assert [m.name for m in ModuleRun.query.filter_by(assessment_id=row.id)] == pipeline


def test_worker_registry_is_cached_and_legacy_registration_still_works(app):
    import worker

    assert worker.get_registry() is worker.get_registry()

    worker.register_module("legacy", lambda target_url, context=None: {})
    assert "legacy" in worker._MODULE_RUNNERS
