"""Coverage for modules.javascript: script discovery, secret/internal-URL
regexes, source-map exposure, risky sinks, and outdated-library detection."""

import pytest
import requests

from conftest import FakeResponse
from modules.javascript import javascript as js_module

TARGET = "http://example.test/"


def page(html):
    return FakeResponse(url=TARGET, text=html)


def js(body):
    return FakeResponse(url=TARGET, text=body, content=body.encode())


def test_request_failure_returns_the_empty_result(fake_http):
    fake_http(js_module, {TARGET: requests.Timeout("timed out")})
    result = js_module.run(TARGET)
    assert result["js_files"] == []
    assert "GET http://example.test/ failed: timed out" in result["errors"]


def test_only_same_origin_scripts_are_fetched(fake_http):
    html = """
      <script src="/app.js"></script>
      <script src="http://example.test/other.js"></script>
      <script src="https://cdn.other.test/vendor.js"></script>
    """
    fake = fake_http(js_module, {TARGET: page(html), "http://example.test/app.js": js("var a=1;")})
    result = js_module.run(TARGET)
    assert result["js_files"] == ["http://example.test/app.js", "http://example.test/other.js"]
    assert "https://cdn.other.test/vendor.js" not in [url for _, url in fake.calls]


def test_script_discovery_is_capped(fake_http):
    html = "".join(f'<script src="/{i}.js"></script>' for i in range(js_module.MAX_JS_FILES + 5))
    fake_http(js_module, {TARGET: page(html)}, default=js("var a=1;"))
    assert len(js_module.run(TARGET)["js_files"]) == js_module.MAX_JS_FILES


def test_failed_js_fetch_is_recorded_and_other_files_still_scanned(fake_http):
    html = '<script src="/broken.js"></script><script src="/ok.js"></script>'
    fake_http(
        js_module,
        {
            TARGET: page(html),
            "http://example.test/broken.js": requests.ConnectionError("reset"),
            "http://example.test/ok.js": js('var k = "AKIAABCDEFGHIJKLMNOP";'),
        },
    )
    result = js_module.run(TARGET)
    assert "GET http://example.test/broken.js failed: reset" in result["errors"]
    assert [s["type"] for s in result["secrets_found"]] == ["AWS Access Key ID"]


@pytest.mark.parametrize(
    "snippet,expected_type,expected_severity",
    [
        ('var k = "AKIAABCDEFGHIJKLMNOP";', "AWS Access Key ID", "critical"),
        ('k="AIza' + "a" * 35 + '";', "Google API Key", "high"),
        ('k="sk_live_' + "a" * 24 + '";', "Stripe Live Secret Key", "critical"),
        ('k="xoxb-1234567890abcdef";', "Slack Token", "high"),
        ("var pem = `-----BEGIN RSA PRIVATE KEY-----`;", "Private Key Block", "critical"),
        ('const api_key = "abcdefghijklmnopqrst";', "Generic hardcoded secret/token", "medium"),
        ('client_secret: "abcdefghijklmnopqrst"', "Generic hardcoded secret/token", "medium"),
    ],
)
def test_secret_patterns_are_detected_with_their_severity(
    fake_http, snippet, expected_type, expected_severity
):
    fake_http(js_module, {TARGET: page(f"<script>{snippet}</script>")})
    secrets = js_module.run(TARGET)["secrets_found"]
    assert [(s["type"], s["severity"], s["source"]) for s in secrets] == [
        (expected_type, expected_severity, "(inline)")
    ]


def test_secret_values_are_masked_never_reported_verbatim(fake_http):
    fake_http(js_module, {TARGET: page('<script>var k = "AKIAABCDEFGHIJKLMNOP";</script>')})
    secret = js_module.run(TARGET)["secrets_found"][0]
    assert secret["masked_value"] == "AKIAAB...MNOP"
    assert "AKIAABCDEFGHIJKLMNOP" != secret["masked_value"]


def test_short_generic_token_values_are_not_flagged(fake_http):
    fake_http(js_module, {TARGET: page('<script>var api_key = "short";</script>')})
    assert js_module.run(TARGET)["secrets_found"] == []


def test_secret_findings_are_capped(fake_http):
    body = "\n".join(f'var k{i} = "AKIAABCDEFGHIJKLMNO{chr(65 + i % 26)}";' for i in range(30))
    fake_http(js_module, {TARGET: page(f"<script>{body}</script>")})
    assert len(js_module.run(TARGET)["secrets_found"]) == 20


@pytest.mark.parametrize(
    "url",
    [
        "http://localhost:3000/api",
        "http://127.0.0.1/health",
        "http://10.1.2.3/internal",
        "http://192.168.1.5/admin",
        "http://172.16.0.9/x",
        "https://api.staging/v1",
        "https://billing.internal/pay",
    ],
)
def test_internal_urls_are_detected(fake_http, url):
    fake_http(js_module, {TARGET: page(f'<script>fetch("{url}");</script>')})
    assert js_module.run(TARGET)["internal_urls_found"] == [url]


def test_public_urls_are_not_treated_as_internal(fake_http):
    fake_http(js_module, {TARGET: page('<script>fetch("https://api.example.com/v1");</script>')})
    assert js_module.run(TARGET)["internal_urls_found"] == []


def test_internal_urls_are_deduplicated(fake_http):
    body = '<script>fetch("http://localhost:3000/a");fetch("http://localhost:3000/a");</script>'
    fake_http(js_module, {TARGET: page(body)})
    assert js_module.run(TARGET)["internal_urls_found"] == ["http://localhost:3000/a"]


def test_exposed_source_map_is_reported_only_when_the_map_returns_200(fake_http):
    html = '<script src="/app.js"></script><script src="/nomap.js"></script>'
    fake_http(
        js_module,
        {
            TARGET: page(html),
            "http://example.test/app.js": js("var a=1;"),
            "http://example.test/app.js.map": FakeResponse(status_code=200),
            "http://example.test/nomap.js": js("var b=1;"),
            "http://example.test/nomap.js.map": FakeResponse(status_code=404),
        },
    )
    assert js_module.run(TARGET)["exposed_source_maps"] == ["http://example.test/app.js.map"]


def test_source_map_probe_failure_is_swallowed(fake_http):
    fake_http(
        js_module,
        {
            TARGET: page('<script src="/app.js"></script>'),
            "http://example.test/app.js": js("var a=1;"),
            "http://example.test/app.js.map": requests.ConnectionError("reset"),
        },
    )
    result = js_module.run(TARGET)
    assert result["exposed_source_maps"] == []
    assert result["errors"] == []


def test_non_js_urls_are_not_probed_for_source_maps(fake_http):
    fake = fake_http(
        js_module,
        {TARGET: page('<script src="/bundle.php"></script>'),
         "http://example.test/bundle.php": js("var a=1;")},
    )
    assert js_module.run(TARGET)["exposed_source_maps"] == []
    assert not [url for _, url in fake.calls if url.endswith(".map")]


@pytest.mark.parametrize(
    "snippet,expected_sink",
    [
        ("eval(userInput);", "eval()"),
        ("eval (userInput);", "eval()"),
        ("document.write(x);", "document.write()"),
    ],
)
def test_risky_sinks_are_reported(fake_http, snippet, expected_sink):
    fake_http(js_module, {TARGET: page(f"<script>{snippet}</script>")})
    assert js_module.run(TARGET)["risky_sinks"] == [{"source": "(inline)", "sink": expected_sink}]


def test_jquery_before_v3_is_reported_as_outdated(fake_http):
    fake_http(js_module, {TARGET: page("<script>/*! jQuery v1.12.4 */</script>")})
    libs = js_module.run(TARGET)["outdated_libraries"]
    assert libs[0]["name"] == "jQuery" and libs[0]["version"] == "1.12.4"
    assert libs[0]["source"] == "(inline)"


def test_current_jquery_is_not_reported(fake_http):
    fake_http(js_module, {TARGET: page("<script>/*! jQuery v3.7.1 */</script>")})
    assert js_module.run(TARGET)["outdated_libraries"] == []


def test_page_without_scripts_yields_a_clean_result(fake_http):
    fake_http(js_module, {TARGET: page("<html><body>no scripts here</body></html>")})
    result = js_module.run(TARGET)
    assert result["js_files"] == [] and result["secrets_found"] == []
    assert result["errors"] == []


def test_html_parse_error_is_recorded(fake_http, monkeypatch):
    monkeypatch.setattr(
        js_module._ScriptTagParser, "feed",
        lambda self, data: (_ for _ in ()).throw(AssertionError("parser blew up")),
    )
    fake_http(js_module, {TARGET: page('<script src="/app.js"></script>')})
    result = js_module.run(TARGET)
    assert result["errors"] == ["HTML parse error: parser blew up"]
    assert result["js_files"] == []


def test_script_tag_parser_separates_inline_bodies_from_sources():
    parser = js_module._ScriptTagParser(TARGET)
    parser.feed('<script src="/a.js"></script><script>var x=1;</script><script>var y=2;</script>')
    assert parser.script_srcs == ["http://example.test/a.js"]
    assert parser.inline_scripts == ["var x=1;", "var y=2;"]
