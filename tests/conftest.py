"""Shared fixtures and HTTP doubles for the test suite.

Scanner modules all talk to the network through a module-level `requests`
import, so tests swap that attribute for a `FakeRequests` router: no real
sockets are opened and each test declares exactly which URLs exist.
"""

import pytest
import requests
from requests.structures import CaseInsensitiveDict

from app import create_app
from database.models import Assessment, Finding, ModuleRun, db


@pytest.fixture
def config_class(tmp_path):
    class TestConfig:
        SECRET_KEY = "test"
        TESTING = True
        WTF_CSRF_ENABLED = False
        SQLALCHEMY_DATABASE_URI = f"sqlite:///{tmp_path / 'test.db'}"
        SQLALCHEMY_TRACK_MODIFICATIONS = False
        SQLALCHEMY_ENGINE_OPTIONS = {"connect_args": {"check_same_thread": False}}
        EVIDENCE_DIR = str(tmp_path / "evidence")
        REPORTS_DIR = str(tmp_path / "reports")
        AI_ANALYSIS_ENABLED = False
        AI_PROVIDER = "ollama"
        OLLAMA_HOST = "http://localhost:11434"
        OLLAMA_MODEL = "qwen3"
        RATELIMIT_ENABLED = False

    return TestConfig


@pytest.fixture
def app(config_class):
    application = create_app(config_class)
    with application.app_context():
        yield application
        db.session.remove()


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def assessment(app):
    row = Assessment(target_url="http://example.test", authorized=True)
    db.session.add(row)
    db.session.commit()
    return row


@pytest.fixture
def record_findings(app):
    """Runs engine.findings._record_findings and returns the created rows."""
    from engine.findings import _record_findings

    def _record(assessment_id: int, module_name: str, output: dict):
        added = _record_findings(db, Finding, assessment_id, module_name, output)
        db.session.commit()
        rows = Finding.query.filter_by(assessment_id=assessment_id).order_by(Finding.id).all()
        assert added == len(rows), "reported count must match persisted rows"
        return rows

    return _record


class FakeRaw:
    """Stands in for urllib3's response object (multi-value headers + read())."""

    def __init__(self, content: bytes, set_cookies: list[str] | None = None):
        self._content = content
        self.headers = _MultiHeaders(set_cookies or [])

    def read(self, amount=None, decode_content=True):
        return self._content[:amount] if amount else self._content


class _MultiHeaders:
    def __init__(self, set_cookies: list[str]):
        self._set_cookies = set_cookies

    def getlist(self, name: str) -> list[str]:
        return list(self._set_cookies) if name.lower() == "set-cookie" else []


class FakeResponse:
    def __init__(
        self,
        url: str = "http://example.test/",
        status_code: int = 200,
        headers: dict | None = None,
        text: str = "",
        content: bytes | None = None,
        set_cookies: list[str] | None = None,
        json_data=None,
        raw: object = ...,
    ):
        self.url = url
        self.status_code = status_code
        self.headers = CaseInsensitiveDict(headers or {})
        self.text = text
        self.content = content if content is not None else text.encode()
        self._json_data = json_data
        if set_cookies:
            self.headers.setdefault("Set-Cookie", set_cookies[0])
        self.raw = FakeRaw(self.content, set_cookies) if raw is ... else raw

    def json(self):
        return self._json_data

    def raise_for_status(self):
        if self.status_code >= 400:
            raise requests.HTTPError(f"{self.status_code} for {self.url}")


class FakeRequests:
    """Routes HTTP calls to canned responses keyed by URL.

    A route value may be a FakeResponse, an Exception instance (raised), or a
    callable taking the URL. Unrouted URLs get `default`, which defaults to a
    404 so "not found" is the implicit behaviour of every scanner probe.
    """

    RequestException = requests.RequestException

    def __init__(self, routes: dict | None = None, default=None):
        self.routes = dict(routes or {})
        self.default = default if default is not None else FakeResponse(status_code=404)
        self.calls: list[tuple[str, str]] = []

    def _resolve(self, method: str, url: str):
        self.calls.append((method, url))
        value = self.routes.get(url, self.default)
        if callable(value) and not isinstance(value, FakeResponse):
            value = value(url)
        if isinstance(value, Exception):
            raise value
        return value

    def get(self, url, **kwargs):
        return self._resolve("GET", url)

    def post(self, url, **kwargs):
        return self._resolve("POST", url)

    def head(self, url, **kwargs):
        return self._resolve("HEAD", url)

    def options(self, url, **kwargs):
        return self._resolve("OPTIONS", url)


@pytest.fixture
def fake_http(monkeypatch):
    """Installs a FakeRequests router onto the given scanner module."""

    def _install(module, routes=None, default=None) -> FakeRequests:
        fake = FakeRequests(routes=routes, default=default)
        monkeypatch.setattr(module, "requests", fake)
        return fake

    return _install


@pytest.fixture
def urls_of():
    def _urls(fake: FakeRequests, method: str | None = None) -> list[str]:
        return [u for m, u in fake.calls if method is None or m == method]

    return _urls


__all__ = ["FakeRequests", "FakeResponse", "FakeRaw", "Assessment", "Finding", "ModuleRun"]
