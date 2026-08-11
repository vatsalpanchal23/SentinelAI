"""Coverage for modules.recon: passive collection, DNS resolution,
HTTP->HTTPS redirect detection, and TLS certificate inspection."""

import hashlib
import socket
import ssl
from datetime import datetime, timedelta

import pytest
import requests

from conftest import FakeResponse
from modules.recon import recon as recon_module

HTTP_TARGET = "http://example.test/"
HTTPS_TARGET = "https://example.test/"


@pytest.fixture(autouse=True)
def no_real_dns(monkeypatch):
    monkeypatch.setattr(
        recon_module.socket, "getaddrinfo",
        lambda host, port: [(2, 1, 6, "", ("93.184.216.34", 0))],
    )


def collect(fake_http, routes, target=HTTP_TARGET, default=None):
    fake_http(recon_module, routes, default=default)
    return recon_module.run(target)


def test_homepage_headers_and_server_are_captured(fake_http):
    response = FakeResponse(url=HTTP_TARGET, headers={"Server": "nginx/1.18.0", "X-Powered-By": "PHP"})
    result = collect(fake_http, {HTTP_TARGET: response})
    assert result["server"] == "nginx/1.18.0"
    assert result["headers"]["X-Powered-By"] == "PHP"


def test_homepage_failure_is_recorded_but_the_scan_continues(fake_http):
    result = collect(fake_http, {HTTP_TARGET: requests.ConnectionError("refused")})
    assert result["server"] is None
    assert "GET http://example.test/ failed: refused" in result["errors"]
    assert result["dns"]["hostname"] == "example.test"


def test_wellknown_files_are_collected_when_present(fake_http):
    routes = {
        HTTP_TARGET: FakeResponse(url=HTTP_TARGET),
        "http://example.test/robots.txt": FakeResponse(text="User-agent: *"),
        "http://example.test/sitemap.xml": FakeResponse(text="<urlset/>"),
        "http://example.test/.well-known/security.txt": FakeResponse(text="Contact: a@b.test"),
        "http://example.test/favicon.ico": FakeResponse(content=b"\x00icon"),
    }
    result = collect(fake_http, routes)
    assert result["robots_txt"] == "User-agent: *"
    assert result["sitemap"] == "<urlset/>"
    assert result["security_txt"] == "Contact: a@b.test"
    assert result["favicon_hash"] == hashlib.md5(b"\x00icon").hexdigest()


def test_absent_wellknown_files_stay_none_without_recording_errors(fake_http):
    result = collect(fake_http, {HTTP_TARGET: FakeResponse(url=HTTP_TARGET)})
    assert result["robots_txt"] is None and result["sitemap"] is None
    assert result["security_txt"] is None and result["favicon_hash"] is None
    assert result["errors"] == []


def test_probe_failures_for_optional_files_are_not_recorded_as_errors(fake_http):
    result = collect(
        fake_http,
        {HTTP_TARGET: FakeResponse(url=HTTP_TARGET)},
        default=requests.ConnectionError("reset"),
    )
    assert result["errors"] == []


def test_empty_favicon_body_is_not_hashed(fake_http):
    routes = {HTTP_TARGET: FakeResponse(url=HTTP_TARGET),
              "http://example.test/favicon.ico": FakeResponse(content=b"")}
    assert collect(fake_http, routes)["favicon_hash"] is None


def test_dns_addresses_are_deduplicated(fake_http, monkeypatch):
    monkeypatch.setattr(
        recon_module.socket, "getaddrinfo",
        lambda host, port: [(2, 1, 6, "", ("1.2.3.4", 0)), (2, 2, 17, "", ("1.2.3.4", 0))],
    )
    result = collect(fake_http, {HTTP_TARGET: FakeResponse(url=HTTP_TARGET)})
    assert result["dns"] == {"hostname": "example.test", "addresses": ["1.2.3.4"]}


def test_dns_failure_is_recorded_with_an_empty_address_list(fake_http, monkeypatch):
    def _fail(host, port):
        raise socket.gaierror("name or service not known")

    monkeypatch.setattr(recon_module.socket, "getaddrinfo", _fail)
    result = collect(fake_http, {HTTP_TARGET: FakeResponse(url=HTTP_TARGET)})
    assert result["dns"] == {"hostname": "example.test", "addresses": []}
    assert any("DNS resolution failed" in e for e in result["errors"])


def test_dns_helper_returns_empty_without_a_hostname():
    result = {"errors": []}
    assert recon_module._resolve_dns("not-a-url", result) == {}


def test_https_redirect_detected_when_the_final_url_is_https(fake_http):
    response = FakeResponse(url="https://example.test/", headers={"Server": "nginx"})
    result = collect(fake_http, {HTTP_TARGET: response})
    assert result["https_redirect"] == {
        "redirects_to_https": True, "final_url": "https://example.test/"
    }
    assert result["tls"] == {}, "TLS inspection is only attempted for https targets"


def test_plain_http_without_redirect_is_flagged(fake_http):
    result = collect(fake_http, {HTTP_TARGET: FakeResponse(url=HTTP_TARGET)})
    assert result["https_redirect"]["redirects_to_https"] is False


def test_https_redirect_check_failure_reports_unknown(fake_http):
    def route(url):
        if url == HTTP_TARGET:
            raise requests.ConnectionError("reset")
        return FakeResponse(status_code=404)

    fake_http(recon_module, {}, default=route)
    result = recon_module.run(HTTP_TARGET)
    assert result["https_redirect"] == {"redirects_to_https": None}
    assert any("HTTPS-redirect check failed" in e for e in result["errors"])


# --- TLS ---------------------------------------------------------------------


class FakeSSLSocket:
    def __init__(self, cert, protocol):
        self._cert = cert
        self._protocol = protocol

    def __enter__(self):
        return self

    def __exit__(self, *exc_info):
        return False

    def getpeercert(self):
        return self._cert

    def version(self):
        return self._protocol


def install_tls(monkeypatch, cert=None, protocol="TLSv1.3", connect_error=None, wrap_error=None):
    class FakeSocket:
        def __enter__(self):
            return self

        def __exit__(self, *exc_info):
            return False

    def create_connection(address, timeout=None):
        if connect_error:
            raise connect_error
        return FakeSocket()

    class FakeContext:
        def wrap_socket(self, sock, server_hostname=None):
            if wrap_error:
                raise wrap_error
            return FakeSSLSocket(cert or {}, protocol)

    monkeypatch.setattr(recon_module.socket, "create_connection", create_connection)
    monkeypatch.setattr(recon_module.ssl, "create_default_context", lambda: FakeContext())


def cert_expiring_in(days):
    expiry = datetime.utcnow() + timedelta(days=days)
    return {
        "notAfter": expiry.strftime("%b %d %H:%M:%S %Y GMT"),
        "issuer": ((("organizationName", "Test CA"),), (("commonName", "Test CA R3"),)),
    }


def test_tls_certificate_details_are_parsed(fake_http, monkeypatch):
    install_tls(monkeypatch, cert=cert_expiring_in(45), protocol="TLSv1.3")
    result = collect(fake_http, {HTTPS_TARGET: FakeResponse(url=HTTPS_TARGET)}, target=HTTPS_TARGET)
    assert result["tls"]["valid"] is True
    assert result["tls"]["protocol"] == "TLSv1.3"
    assert result["tls"]["days_remaining"] in (44, 45)
    assert result["tls"]["issuer"] == "Test CA"


def test_tls_issuer_falls_back_to_common_name(fake_http, monkeypatch):
    cert = {"notAfter": None, "issuer": ((("commonName", "Only CN"),),)}
    install_tls(monkeypatch, cert=cert)
    result = collect(fake_http, {HTTPS_TARGET: FakeResponse(url=HTTPS_TARGET)}, target=HTTPS_TARGET)
    assert result["tls"]["issuer"] == "Only CN"
    assert result["tls"]["days_remaining"] is None


def test_tls_unparseable_expiry_leaves_days_remaining_unset(fake_http, monkeypatch):
    install_tls(monkeypatch, cert={"notAfter": "not a date", "issuer": ()})
    result = collect(fake_http, {HTTPS_TARGET: FakeResponse(url=HTTPS_TARGET)}, target=HTTPS_TARGET)
    assert result["tls"]["days_remaining"] is None
    assert result["tls"]["not_after"] == "not a date"


def test_tls_verification_failure_reports_an_invalid_certificate(fake_http, monkeypatch):
    install_tls(monkeypatch, wrap_error=ssl.SSLCertVerificationError("self-signed"))
    result = collect(fake_http, {HTTPS_TARGET: FakeResponse(url=HTTPS_TARGET)}, target=HTTPS_TARGET)
    assert result["tls"]["valid"] is False
    assert "self-signed" in result["tls"]["error"]
    assert any("TLS certificate verification failed" in e for e in result["errors"])


def test_tls_connection_failure_leaves_tls_empty(fake_http, monkeypatch):
    install_tls(monkeypatch, connect_error=ConnectionRefusedError("refused"))
    result = collect(fake_http, {HTTPS_TARGET: FakeResponse(url=HTTPS_TARGET)}, target=HTTPS_TARGET)
    assert result["tls"] == {}
    assert any("TLS connection failed" in e for e in result["errors"])


def test_tls_helper_returns_empty_without_a_hostname():
    assert recon_module._check_tls("", 443, {"errors": []}) == {}
