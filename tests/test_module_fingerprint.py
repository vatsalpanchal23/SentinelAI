"""Coverage for modules.fingerprint: signature matching plus the
strong/weak confidence rules that keep generic markers from over-reporting."""

import pytest
import requests

from conftest import FakeResponse
from modules.fingerprint import fingerprint as fp_module

TARGET = "http://example.test/"


def detect(fake_http, headers=None, body="", cookies=None):
    if cookies:
        headers = dict(headers or {})
        headers["Set-Cookie"] = ", ".join(cookies)
    fake_http(fp_module, {TARGET: FakeResponse(url=TARGET, headers=headers, text=body)})
    return fp_module.run(TARGET)["technologies"]


def names(technologies):
    return [t["name"] for t in technologies]


def test_request_failure_returns_no_technologies(fake_http):
    fake_http(fp_module, {TARGET: requests.ConnectionError("refused")})
    result = fp_module.run(TARGET)
    assert result["technologies"] == []
    assert "GET http://example.test/ failed: refused" in result["errors"]


def test_blank_response_detects_nothing(fake_http):
    assert detect(fake_http) == []


@pytest.mark.parametrize(
    "header,value,expected",
    [
        ("Server", "nginx/1.18.0", "Nginx"),
        ("Server", "Apache/2.4.29 (Ubuntu)", "Apache"),
        ("Server", "Microsoft-IIS/10.0", "Microsoft IIS"),
        ("Server", "Werkzeug/2.0.1 Python/3.10.6", "Werkzeug/Flask dev server"),
        ("Server", "cloudflare", "Cloudflare"),
        ("X-Powered-By", "Express", "Express"),
        ("X-Powered-By", "PHP/8.1.2", "PHP"),
        ("X-Powered-By", "ASP.NET", "ASP.NET"),
        ("X-Generator", "Drupal 9 (https://www.drupal.org)", "Drupal"),
        ("X-Vercel-Id", "abc123", "Vercel"),
        ("X-Amz-Cf-Id", "abc123", "AWS (CloudFront/ALB)"),
        ("CF-RAY", "abc-DFW", "Cloudflare"),
    ],
)
def test_header_signatures_are_confirmed_detections(fake_http, header, value, expected):
    detected = detect(fake_http, headers={header: value})
    assert expected in names(detected)
    match = next(t for t in detected if t["name"] == expected)
    assert match["confidence"] == "confirmed"
    assert match["evidence"] == [f"header {header}: {value}"]


@pytest.mark.parametrize(
    "body,expected",
    [
        ('<img src="/wp-content/x.png">', "WordPress"),
        ("<script>Drupal.settings = {};</script>", "Drupal"),
        ('<link href="/media/jui/css/x.css">', "Joomla"),
        ('<script src="https://cdn.shopify.com/s/x.js"></script>', "Shopify"),
        ('<input name="csrfmiddlewaretoken" value="x">', "Django"),
        ('<div data-reactroot=""></div>', "React"),
        ('<app ng-version="15.0.0"></app>', "Angular"),
        ("<script>window.__vue__ = {};</script>", "Vue.js"),
        ('<script id="__NEXT_DATA__">{}</script>', "Next.js"),
        ('<link href="/css/bootstrap.min.css">', "Bootstrap"),
        ('<script src="https://cdn.tailwindcss.com"></script>', "Tailwind CSS"),
    ],
)
def test_body_signatures_are_confirmed_detections(fake_http, body, expected):
    detected = detect(fake_http, body=body)
    assert expected in names(detected)
    assert next(t for t in detected if t["name"] == expected)["confidence"] == "confirmed"


@pytest.mark.parametrize(
    "cookie,expected",
    [
        ("csrftoken=abc; Path=/", "Django"),
        ("laravel_session=abc; Path=/", "Laravel"),
        ("connect.sid=abc; Path=/", "Express"),
        ("PHPSESSID=abc; Path=/", "PHP"),
        ("ASP.NET_SessionId=abc; Path=/", "ASP.NET"),
    ],
)
def test_cookie_name_signatures(fake_http, cookie, expected):
    assert expected in names(detect(fake_http, cookies=[cookie]))


def test_multiple_set_cookie_values_in_one_header_are_split(fake_http):
    detected = detect(fake_http, cookies=["PHPSESSID=abc; Path=/", "laravel_session=xyz; Path=/"])
    assert {"PHP", "Laravel"} <= set(names(detected))


def test_a_single_weak_marker_is_not_enough_to_report(fake_http):
    assert "jQuery" not in names(detect(fake_http, body='<script src="/jquery.min.js"></script>'))
    assert "React" not in names(detect(fake_http, body='<script src="/react-dom.js"></script>'))


def test_two_weak_markers_together_are_reported_as_likely(fake_http):
    detected = detect(fake_http, body='<script src="/react-dom.js"></script><div id="__next_f"></div>')
    react = next(t for t in detected if t["name"] == "React")
    assert react["confidence"] == "likely"
    assert len(react["evidence"]) == 2


def test_strong_evidence_is_listed_before_weak_evidence(fake_http):
    detected = detect(fake_http, body='<div data-reactroot=""></div><script src="/react-dom.js"></script>')
    react = next(t for t in detected if t["name"] == "React")
    assert react["evidence"][0].endswith("'data-reactroot'")
    assert react["confidence"] == "confirmed"


def test_flask_requires_the_signed_session_cookie_shape(fake_http):
    signed = detect(fake_http, cookies=["session=eyJhIjoxfQ.ZaBc12.sIgNaTuRe; Path=/"])
    assert "Flask" in names(signed)
    assert next(t for t in signed if t["name"] == "Flask")["confidence"] == "likely"

    assert "Flask" not in names(detect(fake_http, cookies=["session=plainvalue; Path=/"]))
    assert "Flask" not in names(detect(fake_http, cookies=["sessionid=abc.def.ghi; Path=/"]))


def test_signature_matching_is_case_insensitive(fake_http):
    assert "Nginx" in names(detect(fake_http, headers={"Server": "NGINX"}))
    assert "WordPress" in names(detect(fake_http, body="/WP-CONTENT/themes/x.css"))


def test_a_realistic_stack_is_reported_in_full(fake_http):
    detected = detect(
        fake_http,
        headers={"Server": "nginx/1.18.0", "X-Powered-By": "PHP/8.1.2"},
        body='<link href="/wp-content/themes/x.css"><link href="/css/bootstrap.min.css">',
        cookies=["PHPSESSID=abc; Path=/"],
    )
    assert {"Nginx", "PHP", "WordPress", "Bootstrap"} <= set(names(detected))
    php = next(t for t in detected if t["name"] == "PHP")
    assert len(php["evidence"]) == 2, "header and cookie evidence are both listed"
