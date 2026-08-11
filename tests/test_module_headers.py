"""Coverage for modules.headers: header presence, CSP/HSTS depth checks,
cookie flags, and the CORS wildcard-plus-credentials combination."""

import pytest
import requests

from conftest import FakeResponse
from modules.headers import headers as headers_module

TARGET = "https://example.test/"

ALL_SECURITY_HEADERS = {
    "Content-Security-Policy": "default-src 'self'",
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "geolocation=()",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
}


def run_against(fake_http, response, target=TARGET):
    fake_http(headers_module, {target: response})
    return headers_module.run(target)


def test_request_failure_is_recorded_and_returns_an_empty_shell(fake_http):
    result = run_against(fake_http, requests.ConnectionError("refused"))
    assert result["module"] == "headers"
    assert result["missing"] == [] and result["present"] == {}
    assert "GET https://example.test/ failed: refused" in result["errors"]
    assert "cookie_issues" not in result, "the early return skips the cookie/CORS section"


def test_all_headers_missing_when_the_response_has_none(fake_http):
    result = run_against(fake_http, FakeResponse(url=TARGET))
    assert result["missing"] == headers_module.CHECKED_HEADERS
    assert result["csp_issues"] == [] and result["hsts_issues"] == []
    assert result["cookie_issues"] == [] and result["cors_issue"] is None


def test_fully_hardened_response_produces_no_issues(fake_http):
    result = run_against(fake_http, FakeResponse(url=TARGET, headers=ALL_SECURITY_HEADERS))
    assert result["missing"] == []
    assert result["present"]["X-Frame-Options"] == "DENY"
    assert result["csp_issues"] == [] and result["hsts_issues"] == []


def test_hsts_is_not_examined_for_plain_http_targets(fake_http):
    target = "http://example.test/"
    result = run_against(
        fake_http,
        FakeResponse(url=target, headers={"Strict-Transport-Security": "max-age=1"}),
        target=target,
    )
    assert result["hsts_issues"] == []


@pytest.mark.parametrize(
    "csp,expected_fragment",
    [
        ("default-src 'self' 'unsafe-inline'", "unsafe-inline"),
        ("default-src 'self'; script-src 'unsafe-eval'", "unsafe-eval"),
        ("script-src *", "script-src allows '*'"),
        ("img-src 'self'", "No default-src or script-src directive"),
    ],
)
def test_csp_weaknesses_are_named(csp, expected_fragment):
    issues = headers_module._check_csp(csp)
    assert any(expected_fragment in issue for issue in issues), issues


def test_csp_wildcard_is_only_flagged_as_a_standalone_source():
    assert headers_module._check_csp("script-src https://*.example.test") == []
    assert len(headers_module._check_csp("script-src 'self' *")) == 1


def test_csp_script_src_overrides_default_src_for_the_wildcard_check():
    assert headers_module._check_csp("default-src *; script-src 'self'") == []


@pytest.mark.parametrize(
    "hsts,expected_issue_count,expected_fragment",
    [
        ("max-age=31536000; includeSubDomains", 0, None),
        ("max-age=31536000", 1, "Missing includeSubDomains"),
        ("max-age=600; includeSubDomains", 1, "max-age=600 is short (~0d)"),
        ("includeSubDomains", 1, "max-age=0"),
        ("MAX-AGE = 100; INCLUDESUBDOMAINS", 1, "max-age=100"),
    ],
)
def test_hsts_policy_strength(hsts, expected_issue_count, expected_fragment):
    issues = headers_module._check_hsts(hsts)
    assert len(issues) == expected_issue_count, issues
    if expected_fragment:
        assert expected_fragment in issues[0]


def test_hsts_max_age_exactly_at_the_minimum_is_accepted():
    assert headers_module._check_hsts(
        f"max-age={headers_module._HSTS_MIN_MAX_AGE}; includeSubDomains"
    ) == []


def test_cookie_flags_are_checked_across_every_set_cookie_header(fake_http):
    response = FakeResponse(
        url=TARGET,
        headers=ALL_SECURITY_HEADERS,
        set_cookies=[
            "sid=abc; Path=/",
            "hardened=1; HttpOnly; Secure; SameSite=Lax",
            "csrf=xyz; Secure",
        ],
    )
    issues = run_against(fake_http, response)["cookie_issues"]
    assert issues == [
        {"name": "sid", "missing": ["HttpOnly", "Secure", "SameSite"]},
        {"name": "csrf", "missing": ["HttpOnly", "SameSite"]},
    ]


def test_cookie_check_falls_back_to_the_single_set_cookie_header(fake_http):
    response = FakeResponse(url=TARGET, headers={"Set-Cookie": "sid=abc; HttpOnly"}, raw=None)
    assert run_against(fake_http, response)["cookie_issues"] == [
        {"name": "sid", "missing": ["Secure", "SameSite"]}
    ]


def test_cookie_check_fallback_with_no_cookies_at_all(fake_http):
    assert run_against(fake_http, FakeResponse(url=TARGET, raw=None))["cookie_issues"] == []


@pytest.mark.parametrize(
    "cors_headers,expected",
    [
        ({}, None),
        ({"Access-Control-Allow-Origin": "*"}, None),
        ({"Access-Control-Allow-Credentials": "true"}, None),
        ({"Access-Control-Allow-Origin": "https://app.test",
          "Access-Control-Allow-Credentials": "true"}, None),
        ({"Access-Control-Allow-Origin": "*", "Access-Control-Allow-Credentials": "TRUE"},
         "Access-Control-Allow-Origin: * combined with Access-Control-Allow-Credentials: true"),
    ],
)
def test_cors_only_flags_wildcard_origin_with_credentials(fake_http, cors_headers, expected):
    result = run_against(fake_http, FakeResponse(url=TARGET, headers=cors_headers))
    assert result["cors_issue"] == expected
