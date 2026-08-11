import pytest
from werkzeug.security import generate_password_hash

from app import create_app
from targets import target_address_error


class _BaseConfig:
    SECRET_KEY = "test"
    TESTING = True
    WTF_CSRF_ENABLED = False
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ENGINE_OPTIONS = {"connect_args": {"check_same_thread": False}}
    AI_ANALYSIS_ENABLED = False
    AI_PROVIDER = "ollama"
    OLLAMA_HOST = "http://localhost:11434"
    OLLAMA_MODEL = "qwen3"
    ALLOW_PRIVATE_TARGETS = False
    AUTH_USERNAME = "sentinel"
    AUTH_PASSWORD_HASH = ""
    AUTH_PASSWORD = ""


def _make_app(tmp_path, **overrides):
    config = type(
        "Config",
        (_BaseConfig,),
        {
            "SQLALCHEMY_DATABASE_URI": f"sqlite:///{tmp_path / 'test.db'}",
            "EVIDENCE_DIR": str(tmp_path / "evidence"),
            "REPORTS_DIR": str(tmp_path / "reports"),
            **overrides,
        },
    )
    return create_app(config)


@pytest.mark.parametrize(
    "url",
    [
        "http://169.254.169.254/latest/meta-data/",  # cloud metadata
        "http://127.0.0.1:8000/",
        "http://10.0.0.5/",
        "http://[::1]/",
    ],
)
def test_internal_targets_rejected(url):
    assert target_address_error(url, allow_private=False) is not None


def test_metadata_target_rejected_even_when_private_allowed():
    assert target_address_error("http://169.254.169.254/", allow_private=True) is not None


def test_private_target_allowed_when_opted_in():
    assert target_address_error("http://127.0.0.1:8000/", allow_private=True) is None


def test_target_submission_rejects_internal_host(tmp_path):
    app = _make_app(tmp_path)
    client = app.test_client()
    response = client.post(
        "/target", data={"target_url": "http://127.0.0.1:8000/", "authorized": "1"}
    )
    assert response.status_code == 200  # form re-rendered with an error
    assert b"private or loopback" in response.data


def test_routes_require_credentials_when_configured(tmp_path):
    app = _make_app(tmp_path, AUTH_PASSWORD_HASH=generate_password_hash("s3cret"))
    client = app.test_client()

    assert client.get("/").status_code == 401
    assert client.get("/api/assessment/1/status").status_code == 401
    assert client.post("/target", data={}).status_code == 401
    assert client.get("/", auth=("sentinel", "wrong")).status_code == 401
    assert client.get("/", auth=("sentinel", "s3cret")).status_code == 200


def test_routes_open_when_no_credentials_configured(tmp_path):
    app = _make_app(tmp_path)
    assert app.test_client().get("/").status_code == 200
