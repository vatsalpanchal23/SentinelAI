import requests

from common.html import LinkParser, feed_html, same_origin
from common.http import HttpClient, cookie_dict, set_cookie_headers, user_agent
from common.results import module_result
from common.severity import normalize_severity, severity_from_cvss


class _FakeResponse:
    def __init__(self, headers=None, raw_cookies=None):
        self.headers = headers or {}
        self.raw = _FakeRaw(raw_cookies) if raw_cookies is not None else None


class _FakeRaw:
    def __init__(self, cookies):
        self.headers = _FakeRawHeaders(cookies)


class _FakeRawHeaders:
    def __init__(self, cookies):
        self._cookies = cookies

    def getlist(self, name):
        return list(self._cookies)


def test_user_agent_identifies_module():
    assert user_agent("Recon") == "SentinelAI-Recon/0.1 (authorized-assessment)"


def test_client_records_transport_error_and_returns_none(monkeypatch):
    def _boom(url, **kwargs):
        raise requests.ConnectionError("refused")

    monkeypatch.setattr(requests, "get", _boom)
    errors = []
    client = HttpClient("Recon", errors)

    assert client.get("http://example.test/") is None
    assert errors == ["GET http://example.test/ failed: refused"]

    assert client.get("http://example.test/", error_label="Reflection probe") is None
    assert errors[-1] == "Reflection probe failed: refused"

    assert client.get("http://example.test/", record_error=False) is None
    assert len(errors) == 2


def test_client_passes_agent_and_timeout(monkeypatch):
    captured = {}

    def _get(url, **kwargs):
        captured.update(kwargs)
        return "response"

    monkeypatch.setattr(requests, "get", _get)

    assert HttpClient("Headers", timeout=3).get("http://example.test/") == "response"
    assert captured["headers"] == {"User-Agent": user_agent("Headers")}
    assert captured["timeout"] == 3


def test_set_cookie_headers_splits_folded_header():
    resp = _FakeResponse(headers={"Set-Cookie": "a=1; Expires=Mon, 01 Jan 2035 00:00:00 GMT, b=2; HttpOnly"})
    assert set_cookie_headers(resp) == ["a=1; Expires=Mon, 01 Jan 2035 00:00:00 GMT", "b=2; HttpOnly"]


def test_cookie_dict_strips_attributes():
    resp = _FakeResponse(raw_cookies=["session=abc.def.ghi; Path=/", "csrftoken=xyz", "novalue"])
    assert cookie_dict(resp) == {"session": "abc.def.ghi", "csrftoken": "xyz"}


def test_link_parser_resolves_relative_hrefs_and_filters_origin():
    parser = LinkParser("http://example.test/dir/page")
    errors = []

    assert feed_html(parser, '<a href="sub">a</a><a href="https://other.test/x">b</a>', errors)
    assert errors == []
    assert parser.links == {"http://example.test/dir/sub", "https://other.test/x"}
    assert same_origin(sorted(parser.links), "example.test") == ["http://example.test/dir/sub"]


def test_feed_html_records_parse_failure():
    class _Exploding(LinkParser):
        def feed(self, text):
            raise ValueError("bad markup")

    errors = []
    assert feed_html(_Exploding("http://example.test/"), "<a>", errors, "HTML parse error on homepage") is False
    assert errors == ["HTML parse error on homepage: bad markup"]


def test_module_result_shape():
    assert module_result("recon", "http://example.test/", server=None) == {
        "module": "recon",
        "target": "http://example.test/",
        "server": None,
        "errors": [],
    }


def test_severity_normalization():
    assert normalize_severity("HIGH") == "high"
    assert normalize_severity("unknown") == "info"
    assert normalize_severity(None, default="medium") == "medium"
    assert [severity_from_cvss(s) for s in (9.8, 7.0, 4.1, 2.0)] == ["critical", "high", "medium", "low"]
