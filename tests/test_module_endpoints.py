"""Coverage for modules.endpoints: crawling, form classification,
same-origin vs third-party auth split, and soft-404 baseline filtering."""

import hashlib
import re

import pytest
import requests

from conftest import FakeResponse
from modules.endpoints import endpoints as ep_module

TARGET = "http://example.test/"


def html_response(body, url=TARGET):
    return FakeResponse(url=url, text=body, headers={"Content-Type": "text/html; charset=utf-8"})


def run_with(fake_http, routes, default=None):
    fake = fake_http(ep_module, routes, default=default)
    return ep_module.run(TARGET), fake


def test_request_failure_returns_the_empty_result(fake_http):
    result, _ = run_with(fake_http, {TARGET: requests.ConnectionError("refused")})
    assert result["links"] == [] and result["forms"] == []
    assert "GET http://example.test/ failed: refused" in result["errors"]


def test_same_origin_links_are_collected_and_external_ones_dropped(fake_http):
    body = """
      <a href="/about">about</a>
      <a href="contact">contact</a>
      <a href="https://external.test/x">external</a>
    """
    result, _ = run_with(fake_http, {TARGET: html_response(body)})
    assert "http://example.test/about" in result["links"]
    assert "http://example.test/contact" in result["links"]
    assert not any("external.test" in link for link in result["links"])


def test_second_hop_crawl_collects_deeper_links_and_forms(fake_http):
    home = html_response('<a href="/deep">deep</a>')
    deep = html_response('<a href="/deeper">deeper</a><form action="/x"><input name="q"></form>',
                         url="http://example.test/deep")
    result, _ = run_with(fake_http, {TARGET: home, "http://example.test/deep": deep})
    assert "http://example.test/deeper" in result["links"]
    assert [f["action"] for f in result["forms"]] == ["http://example.test/x"]


def test_non_html_and_unreachable_second_hop_pages_are_skipped(fake_http):
    home = html_response('<a href="/data.json">json</a><a href="/broken">broken</a>')
    routes = {
        TARGET: home,
        "http://example.test/data.json": FakeResponse(
            url="http://example.test/data.json", text='{"links": "/hidden"}',
            headers={"Content-Type": "application/json"},
        ),
        "http://example.test/broken": requests.ConnectionError("reset"),
    }
    result, _ = run_with(fake_http, routes)
    assert "http://example.test/hidden" not in result["links"]
    assert result["errors"] == []


def test_second_hop_crawl_is_bounded(fake_http):
    links = "".join(f'<a href="/p{i}">p</a>' for i in range(ep_module.MAX_CRAWL_PAGES + 10))
    fake = fake_http(ep_module, {TARGET: html_response(links)}, default=html_response(""))
    ep_module.run(TARGET)
    crawled = [url for _, url in fake.calls if re.fullmatch(r"http://example\.test/p\d+", url)]
    assert len(crawled) == ep_module.MAX_CRAWL_PAGES


def test_link_list_is_capped(fake_http):
    links = "".join(f'<a href="/link{i}">l</a>' for i in range(ep_module.MAX_LINKS + 20))
    fake_http(ep_module, {TARGET: html_response(links)}, default=html_response(""))
    assert len(ep_module.run(TARGET)["links"]) == ep_module.MAX_LINKS


def test_directory_listing_detected_on_the_homepage(fake_http):
    result, _ = run_with(fake_http, {TARGET: html_response("<h1>Index of /</h1>")})
    assert result["directory_listing"] is True


def test_directory_listing_detected_on_a_crawled_page(fake_http):
    routes = {
        TARGET: html_response('<a href="/files">files</a>'),
        "http://example.test/files": html_response("<h1>Index of /files</h1>",
                                                   url="http://example.test/files"),
    }
    result, _ = run_with(fake_http, routes)
    assert result["directory_listing"] is True


def test_sensitive_paths_and_api_surfaces_are_reported_when_reachable(fake_http):
    def route(url):
        if url == TARGET:
            return html_response("<html></html>")
        if url.endswith("/.env"):
            return FakeResponse(url=url, status_code=200, text="SECRET_KEY=abc")
        if url.endswith("/swagger.json"):
            return FakeResponse(url=url, status_code=200, text='{"openapi": "3.0"}')
        return FakeResponse(url=url, status_code=404)

    fake_http(ep_module, {}, default=route)
    result = ep_module.run(TARGET)
    assert result["sensitive_paths_found"] == [{"path": ".env", "size": len("SECRET_KEY=abc")}]
    assert result["api_surfaces_found"] == ["swagger.json"]


def test_soft_404_catch_all_suppresses_sensitive_path_and_api_findings(fake_http):
    catch_all = "<html>Not found, but 200</html>"

    def route(url):
        if url == TARGET:
            return html_response("<html></html>")
        return FakeResponse(url=url, status_code=200, text=catch_all)

    fake_http(ep_module, {}, default=route)
    result = ep_module.run(TARGET)
    assert result["sensitive_paths_found"] == []
    assert result["api_surfaces_found"] == []
    assert result["links"] == [], "guessed common paths matching the baseline are also dropped"


def test_probe_failures_during_path_guessing_are_ignored(fake_http):
    def route(url):
        if url == TARGET:
            return html_response("<html></html>")
        raise requests.ConnectionError("reset")

    fake_http(ep_module, {}, default=route)
    result = ep_module.run(TARGET)
    assert result["sensitive_paths_found"] == [] and result["links"] == []
    assert result["errors"] == []


def test_common_paths_that_respond_are_added_to_the_surface(fake_http):
    def route(url):
        if url == TARGET:
            return html_response("<html></html>")
        if url.endswith("/login"):
            return FakeResponse(url=url, status_code=200, text="<form></form>")
        return FakeResponse(url=url, status_code=404)

    fake_http(ep_module, {}, default=route)
    assert ep_module.run(TARGET)["links"] == ["http://example.test/login"]


def test_already_discovered_paths_are_not_probed_again(fake_http):
    fake = fake_http(ep_module, {TARGET: html_response('<a href="/login">login</a>')},
                     default=FakeResponse(status_code=404))
    ep_module.run(TARGET)
    assert [url for _, url in fake.calls].count("http://example.test/login") == 1


def test_baseline_hash_uses_a_random_nonexistent_path(fake_http):
    fake = fake_http(ep_module, {TARGET: html_response("<html></html>")},
                     default=FakeResponse(status_code=404))
    ep_module.run(TARGET)
    probes = [url for _, url in fake.calls if "__sentinelai_nonexistent_check_" in url]
    assert len(probes) == 1


def test_baseline_hash_helper_returns_none_for_a_404_and_on_failure(fake_http):
    fake_http(ep_module, {}, default=FakeResponse(status_code=404, text="nope"))
    assert ep_module._get_baseline_hash(TARGET) is None

    fake_http(ep_module, {}, default=requests.ConnectionError("reset"))
    assert ep_module._get_baseline_hash(TARGET) is None


def test_baseline_hash_helper_hashes_a_soft_404_body(fake_http):
    fake_http(ep_module, {}, default=FakeResponse(status_code=200, text="catch-all"))
    assert ep_module._get_baseline_hash(TARGET) == hashlib.md5(b"catch-all").hexdigest()


def test_login_form_fields_flags_and_csrf_are_parsed(fake_http):
    body = """
      <form action="/login" method="post">
        <input type="text" name="username">
        <input type="password" name="password">
        <input type="hidden" name="csrf_token" value="x">
        <input type="text" name="otp_code">
        <div class="g-recaptcha"></div>
      </form>
    """
    result, _ = run_with(fake_http, {TARGET: html_response(body)})
    form = result["forms"][0]
    assert form["method"] == "POST"
    assert form["has_password_field"] and form["has_csrf_token"]
    assert form["has_mfa_field"] and form["has_captcha"]
    assert form["field_names"] == ["username", "password", "csrf_token", "otp_code"]
    assert form["same_origin"] is True
    assert form["form_type"] == "login"


def test_captcha_detected_from_an_input_class_or_name(fake_http):
    body = '<form action="/login"><input type="password" name="p"><input class="g-recaptcha" name="x"></form>'
    result, _ = run_with(fake_http, {TARGET: html_response(body)})
    assert result["forms"][0]["has_captcha"] is True

    body = '<form action="/login"><input type="password" name="p"><input name="cf-turnstile-response"></form>'
    result, _ = run_with(fake_http, {TARGET: html_response(body)})
    assert result["forms"][0]["has_captcha"] is True


@pytest.mark.parametrize(
    "form,expected",
    [
        ({"action": "/login", "has_password_field": True, "field_names": ["user", "password"]}, "login"),
        ({"action": "/register", "has_password_field": True, "field_names": ["password"]},
         "register_or_reset"),
        ({"action": "/signup", "has_password_field": True, "field_names": ["password"]},
         "register_or_reset"),
        ({"action": "/sign-up", "has_password_field": True, "field_names": ["password"]},
         "register_or_reset"),
        ({"action": "/x", "has_password_field": True, "field_names": ["password", "confirm_password"]},
         "register_or_reset"),
        ({"action": "/reset-password", "has_password_field": True, "field_names": ["password"]},
         "register_or_reset"),
        ({"action": "/forgot", "has_password_field": True, "field_names": ["password"]},
         "register_or_reset"),
        ({"action": "/forgot-password", "has_password_field": False, "field_names": ["email"]},
         "password_reset_request"),
        ({"action": "/search", "has_password_field": False, "field_names": ["q"]}, "other"),
    ],
)
def test_form_classification(form, expected):
    assert ep_module._classify_form(form) == expected


def test_third_party_auth_forms_are_separated_from_same_origin_forms(fake_http):
    body = """
      <form action="https://accounts.google.com/o/oauth2/auth"><input type="password" name="p"></form>
      <form action="https://sso.corp.test/login"><input type="password" name="p"></form>
      <form action="/login"><input type="password" name="p"></form>
    """
    result, _ = run_with(fake_http, {TARGET: html_response(body)})
    assert [f["action"] for f in result["forms"]] == ["http://example.test/login"]
    assert result["external_auth_providers"] == ["Google", "sso.corp.test"]


def test_homepage_parse_error_is_recorded(fake_http, monkeypatch):
    monkeypatch.setattr(
        ep_module._LinkFormParser, "feed",
        lambda self, data: (_ for _ in ()).throw(AssertionError("parser blew up")),
    )
    result, _ = run_with(fake_http, {TARGET: html_response('<a href="/x">x</a>')})
    assert "HTML parse error on homepage: parser blew up" in result["errors"]
    assert result["links"] == []


def test_parse_error_on_a_crawled_page_skips_only_that_page(fake_http, monkeypatch):
    original_feed = ep_module._LinkFormParser.feed

    def feed(self, data):
        if "deep page" in data:
            raise AssertionError("parser blew up")
        return original_feed(self, data)

    monkeypatch.setattr(ep_module._LinkFormParser, "feed", feed)
    routes = {
        TARGET: html_response('<a href="/deep">deep</a>'),
        "http://example.test/deep": html_response(
            '<p>deep page</p><a href="/deeper">deeper</a>', url="http://example.test/deep"
        ),
    }
    result, _ = run_with(fake_http, routes)
    assert "http://example.test/deep" in result["links"]
    assert "http://example.test/deeper" not in result["links"]
    assert result["errors"] == []


def test_parser_collects_script_sources_lowercased():
    parser = ep_module._LinkFormParser(TARGET)
    parser.feed('<script src="/Static/App.JS"></script><script>inline()</script>')
    assert parser.body_lower_fragments == ["/static/app.js"]


def test_malformed_html_still_yields_a_result(fake_http):
    result, _ = run_with(fake_http, {TARGET: html_response("<form><input type=password><a href=/x>")})
    assert result["errors"] == []
    assert result["forms"] == [], "an unclosed form tag is never emitted"
