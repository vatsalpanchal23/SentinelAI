"""Coverage for the app factory's baseline response headers, the default
SECRET_KEY warning, and worker's job-submission shim."""

import logging

from app import create_app
from config.settings import Config, _env


def test_baseline_security_headers_are_set_on_responses(client):
    response = client.get("/target")
    assert response.headers["X-Frame-Options"] == "DENY"
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["Referrer-Policy"] == "no-referrer-when-downgrade"
    assert "default-src 'self'" in response.headers["Content-Security-Policy"]


def test_default_secret_key_triggers_a_warning(config_class, caplog):
    config_class.SECRET_KEY = "dev-secret-change-me"
    with caplog.at_level(logging.WARNING, logger="sentinelai.app"):
        create_app(config_class)
    assert "default SECRET_KEY" in caplog.text


def test_a_configured_secret_key_does_not_warn(config_class, caplog):
    with caplog.at_level(logging.WARNING, logger="sentinelai.app"):
        create_app(config_class)
    assert "default SECRET_KEY" not in caplog.text


def test_worker_submits_jobs_through_the_scheduler(app, monkeypatch):
    import worker

    submitted = []
    monkeypatch.setattr(
        worker._scheduler, "submit_assessment_job",
        lambda app_obj, assessment_id: submitted.append((app_obj, assessment_id)),
    )
    worker.submit_assessment_job(app, 7)
    assert submitted == [(app, 7)]


def test_blank_environment_values_fall_back_to_the_default(monkeypatch):
    monkeypatch.setenv("SENTINELAI_TEST_VALUE", "   ")
    assert _env("SENTINELAI_TEST_VALUE", "fallback") == "fallback"

    monkeypatch.setenv("SENTINELAI_TEST_VALUE", "configured")
    assert _env("SENTINELAI_TEST_VALUE", "fallback") == "configured"

    monkeypatch.delenv("SENTINELAI_TEST_VALUE")
    assert _env("SENTINELAI_TEST_VALUE", "fallback") == "fallback"


def test_default_config_points_at_repo_local_directories():
    assert Config.SQLALCHEMY_DATABASE_URI.startswith("sqlite:///")
    assert Config.REPORTS_DIR.endswith("reports")
    assert Config.EVIDENCE_DIR.endswith("evidence")
    assert Config.SQLALCHEMY_ENGINE_OPTIONS == {"connect_args": {"check_same_thread": False}}
