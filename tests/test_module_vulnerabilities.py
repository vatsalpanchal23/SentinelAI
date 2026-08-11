"""Coverage for modules.vulnerabilities: OPTIONS method probing, candidate
link selection, and the reflection / SQLi / open-redirect probes."""

import pytest
import requests

from conftest import FakeResponse
from modules.vulnerabilities import vulnerabilities as vuln_module

TARGET = "http://example.test/"
CANARY = vuln_module.XSS_CANARY


def run_with(fake_http, routes, context=None, default=None):
    fake = fake_http(vuln_module, routes, default=default)
    return vuln_module.run(TARGET, context=context), fake


# --- HTTP methods ------------------------------------------------------------


def test_dangerous_methods_are_extracted_from_the_allow_header(fake_http):
    routes = {TARGET: FakeResponse(url=TARGET, headers={"Allow": "GET, POST, put, TRACE, DELETE"})}
    result, _ = run_with(fake_http, routes)
    assert result["dangerous_methods"] == ["DELETE", "PUT", "TRACE"]


def test_safe_methods_only_yields_nothing(fake_http):
    routes = {TARGET: FakeResponse(url=TARGET, headers={"Allow": "GET, HEAD, POST, OPTIONS"})}
    assert run_with(fake_http, routes)[0]["dangerous_methods"] == []


def test_missing_allow_header_yields_nothing(fake_http):
    assert run_with(fake_http, {TARGET: FakeResponse(url=TARGET)})[0]["dangerous_methods"] == []


def test_options_failure_is_recorded(fake_http):
    result, _ = run_with(fake_http, {TARGET: requests.ConnectionError("refused")})
    assert result["dangerous_methods"] == []
    assert any("OPTIONS http://example.test/ failed" in e for e in result["errors"])


# --- candidate link selection -----------------------------------------------


def test_endpoints_context_is_preferred_over_crawling(fake_http):
    context = {
        "endpoints": {
            "links": ["http://example.test/search?q=1", "http://example.test/about"],
            "forms": [
                {"action": "http://example.test/find", "method": "GET", "field_names": ["term", "page"]},
                {"action": "http://example.test/login", "method": "POST", "field_names": ["user"]},
                {"action": "http://example.test/empty", "method": "GET", "field_names": []},
            ],
        }
    }
    links = vuln_module._candidate_links(TARGET, context, {"errors": []})
    assert links == ["http://example.test/search?q=1", "http://example.test/find?term=1&page=1"]


def test_crawl_fallback_keeps_same_origin_links_only(fake_http):
    body = '<a href="/a?x=1">a</a><a href="https://other.test/b?y=2">b</a>'
    fake_http(vuln_module, {TARGET: FakeResponse(url=TARGET, text=body)})
    links = vuln_module._candidate_links(TARGET, None, {"errors": []})
    assert links == ["http://example.test/a?x=1"]


def test_crawl_fallback_records_request_failures(fake_http):
    fake_http(vuln_module, {TARGET: requests.ConnectionError("reset")})
    result = {"errors": []}
    assert vuln_module._candidate_links(TARGET, None, result) == []
    assert any("GET http://example.test/ failed" in e for e in result["errors"])


def test_context_without_links_falls_back_to_crawling(fake_http):
    fake_http(vuln_module, {TARGET: FakeResponse(url=TARGET, text='<a href="/z?q=1">z</a>')})
    links = vuln_module._candidate_links(TARGET, {"endpoints": {"links": []}}, {"errors": []})
    assert links == ["http://example.test/z?q=1"]


def test_probe_count_is_capped(fake_http):
    context = {
        "endpoints": {
            "links": [f"http://example.test/p{i}?a=1&b=2&c=3" for i in range(20)],
            "forms": [],
        }
    }
    fake = fake_http(vuln_module, {TARGET: FakeResponse(url=TARGET)})
    vuln_module.run(TARGET, context=context)
    probes = [url for method, url in fake.calls if method == "GET"]
    assert len(probes) == 2 * vuln_module.MAX_PARAM_PROBES


def test_parameterless_links_are_not_probed(fake_http):
    context = {"endpoints": {"links": ["http://example.test/about"], "forms": []}}
    fake = fake_http(vuln_module, {TARGET: FakeResponse(url=TARGET)})
    vuln_module.run(TARGET, context=context)
    assert [url for method, url in fake.calls if method == "GET"] == []


# --- probes ------------------------------------------------------------------


def context_for(link):
    return {"endpoints": {"links": [link], "forms": []}}


def test_reflected_canary_is_reported(fake_http):
    link = "http://example.test/search?q=hello"
    routes = {TARGET: FakeResponse(url=TARGET)}
    fake_http(vuln_module, routes,
              default=FakeResponse(text=f"<p>results for {CANARY}</p>"))
    result = vuln_module.run(TARGET, context=context_for(link))
    assert result["reflected_params"] == [{"url": link, "param": "q"}]


def test_escaped_reflection_is_not_reported(fake_http):
    link = "http://example.test/search?q=hello"
    escaped = CANARY.replace('"', "&quot;").replace("<", "&lt;").replace(">", "&gt;")
    fake_http(vuln_module, {TARGET: FakeResponse(url=TARGET)},
              default=FakeResponse(text=f"<p>{escaped}</p>"))
    assert vuln_module.run(TARGET, context=context_for(link))["reflected_params"] == []


def test_reflection_probe_failure_is_recorded(fake_http):
    result = {"errors": [], "reflected_params": []}
    fake_http(vuln_module, {}, default=requests.Timeout("timed out"))
    vuln_module._probe_reflection("http://example.test/?q=1", "q", result)
    assert result["reflected_params"] == []
    assert any("Reflection probe on" in e for e in result["errors"])


@pytest.mark.parametrize(
    "body",
    [
        "You have an error in your SQL syntax; check the manual",
        "Warning: mysql_query() expects",
        "Unclosed quotation mark after the character string",
        "SQLSTATE[42000]",
        "pg_query() failed",
        "ORA-01756: quoted string not properly terminated",
        "sqlite3.OperationalError: near",
        "System.Data.SqlClient.SqlException",
        "psycopg2.ProgrammingError",
    ],
)
def test_database_error_signatures_are_detected(fake_http, body):
    result = {"errors": [], "sqli_indicators": []}
    fake_http(vuln_module, {}, default=FakeResponse(text=body))
    vuln_module._probe_sqli("http://example.test/?id=1", "id", result)
    assert result["sqli_indicators"][0]["param"] == "id"


def test_ordinary_error_page_is_not_a_sqli_indicator(fake_http):
    result = {"errors": [], "sqli_indicators": []}
    fake_http(vuln_module, {}, default=FakeResponse(text="<h1>500 Internal Server Error</h1>"))
    vuln_module._probe_sqli("http://example.test/?id=1", "id", result)
    assert result["sqli_indicators"] == []


def test_sqli_probe_failure_is_recorded(fake_http):
    result = {"errors": [], "sqli_indicators": []}
    fake_http(vuln_module, {}, default=requests.ConnectionError("reset"))
    vuln_module._probe_sqli("http://example.test/?id=1", "id", result)
    assert any("SQLi probe on" in e for e in result["errors"])


def test_open_redirect_is_probed_only_for_redirect_looking_params(fake_http):
    location = f"https://{vuln_module.REDIRECT_TEST_HOST}/"
    fake_http(vuln_module, {TARGET: FakeResponse(url=TARGET)},
              default=FakeResponse(status_code=302, headers={"Location": location}))

    redirect_link = "http://example.test/go?return_to=/home"
    result = vuln_module.run(TARGET, context=context_for(redirect_link))
    assert result["open_redirects"] == [
        {"url": redirect_link, "param": "return_to", "location": location}
    ]

    other_link = "http://example.test/go?page=2"
    assert vuln_module.run(TARGET, context=context_for(other_link))["open_redirects"] == []


def test_redirect_to_a_different_host_is_not_reported(fake_http):
    fake_http(vuln_module, {TARGET: FakeResponse(url=TARGET)},
              default=FakeResponse(status_code=302, headers={"Location": "/login"}))
    link = "http://example.test/go?next=/home"
    assert vuln_module.run(TARGET, context=context_for(link))["open_redirects"] == []


def test_open_redirect_probe_failure_is_recorded(fake_http):
    result = {"errors": [], "open_redirects": []}
    fake_http(vuln_module, {}, default=requests.ConnectionError("reset"))
    vuln_module._probe_open_redirect("http://example.test/?next=/", "next", result)
    assert any("Open-redirect probe on" in e for e in result["errors"])


def test_replace_param_preserves_other_query_values():
    replaced = vuln_module._replace_param("http://example.test/s?a=1&b=2", "a", "probe")
    assert replaced in (
        "http://example.test/s?a=probe&b=2",
        "http://example.test/s?b=2&a=probe",
    )
    assert "b=2" in replaced


def test_crawl_fallback_records_html_parse_errors(fake_http, monkeypatch):
    monkeypatch.setattr(
        vuln_module._LinkParser, "feed",
        lambda self, data: (_ for _ in ()).throw(AssertionError("parser blew up")),
    )
    fake_http(vuln_module, {TARGET: FakeResponse(url=TARGET, text='<a href="/a?x=1">a</a>')})
    result = {"errors": []}
    assert vuln_module._candidate_links(TARGET, None, result) == []
    assert result["errors"] == ["HTML parse error: parser blew up"]


def test_link_parser_resolves_relative_hrefs():
    parser = vuln_module._LinkParser(TARGET)
    parser.feed('<a href="/x">x</a><a href="y">y</a><a>no href</a>')
    assert parser.links == {"http://example.test/x", "http://example.test/y"}
