"""
Recon module.

Collects: server header, robots.txt, sitemap.xml, favicon hash, basic DNS
info, security.txt, whether HTTP redirects to HTTPS, and (for https targets)
TLS certificate expiry/protocol info.
"""

import hashlib
import socket
import ssl
from datetime import datetime
from urllib.parse import urljoin, urlparse

import requests

TIMEOUT = 8
USER_AGENT = "SentinelAI-Recon/0.1 (authorized-assessment)"


def run(target_url: str, context: dict | None = None) -> dict:
    result = {
        "module": "recon",
        "target": target_url,
        "server": None,
        "headers": {},
        "robots_txt": None,
        "sitemap": None,
        "security_txt": None,
        "favicon_hash": None,
        "dns": {},
        "https_redirect": None,
        "tls": {},
        "errors": [],
    }

    resp = _get(target_url, result)
    if resp is not None:
        result["headers"] = dict(resp.headers)
        result["server"] = resp.headers.get("Server")

    robots = _get(urljoin(target_url, "/robots.txt"), result, record_error=False)
    if robots is not None and robots.status_code == 200:
        result["robots_txt"] = robots.text[:5000]

    sitemap = _get(urljoin(target_url, "/sitemap.xml"), result, record_error=False)
    if sitemap is not None and sitemap.status_code == 200:
        result["sitemap"] = sitemap.text[:5000]

    # RFC 9116 security.txt -- a documented disclosure contact is good practice,
    # its absence isn't a vuln, just noted informationally.
    sec_txt = _get(urljoin(target_url, "/.well-known/security.txt"), result, record_error=False)
    if sec_txt is not None and sec_txt.status_code == 200:
        result["security_txt"] = sec_txt.text[:2000]

    favicon = _get(urljoin(target_url, "/favicon.ico"), result, record_error=False)
    if favicon is not None and favicon.status_code == 200 and favicon.content:
        result["favicon_hash"] = hashlib.md5(favicon.content).hexdigest()

    result["dns"] = _resolve_dns(target_url, result)

    parsed = urlparse(target_url)
    if parsed.scheme == "http":
        result["https_redirect"] = _check_https_redirect(target_url, result)
    elif parsed.scheme == "https":
        result["tls"] = _check_tls(parsed.hostname, parsed.port or 443, result)

    return result


def _get(url: str, result: dict, record_error: bool = True):
    try:
        return requests.get(url, headers={"User-Agent": USER_AGENT}, timeout=TIMEOUT, allow_redirects=True)
    except requests.RequestException as exc:
        if record_error:
            result["errors"].append(f"GET {url} failed: {exc}")
        return None


def _resolve_dns(target_url: str, result: dict) -> dict:
    hostname = urlparse(target_url).hostname
    if not hostname:
        return {}
    try:
        return {"hostname": hostname, "addresses": list({i[4][0] for i in socket.getaddrinfo(hostname, None)})}
    except socket.gaierror as exc:
        result["errors"].append(f"DNS resolution failed for {hostname}: {exc}")
        return {"hostname": hostname, "addresses": []}


def _check_https_redirect(http_url: str, result: dict) -> dict:
    """Does the plain-HTTP site redirect to HTTPS, or serve content over
    unencrypted HTTP indefinitely?"""
    try:
        resp = requests.get(
            http_url, headers={"User-Agent": USER_AGENT}, timeout=TIMEOUT, allow_redirects=True
        )
    except requests.RequestException as exc:
        result["errors"].append(f"HTTPS-redirect check failed: {exc}")
        return {"redirects_to_https": None}
    final_scheme = urlparse(resp.url).scheme
    return {"redirects_to_https": final_scheme == "https", "final_url": resp.url}


def _check_tls(hostname: str, port: int, result: dict) -> dict:
    if not hostname:
        return {}
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((hostname, port), timeout=TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                protocol = ssock.version()
    except ssl.SSLCertVerificationError as exc:
        result["errors"].append(f"TLS certificate verification failed: {exc}")
        return {"valid": False, "error": str(exc)}
    except (socket.timeout, socket.gaierror, ConnectionRefusedError, OSError) as exc:
        result["errors"].append(f"TLS connection failed: {exc}")
        return {}

    not_after = cert.get("notAfter")
    days_remaining = None
    if not_after:
        try:
            expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
            days_remaining = (expiry - datetime.utcnow()).days
        except ValueError:
            pass

    issuer = dict(x[0] for x in cert.get("issuer", []))
    return {
        "valid": True,
        "protocol": protocol,
        "not_after": not_after,
        "days_remaining": days_remaining,
        "issuer": issuer.get("organizationName") or issuer.get("commonName"),
    }
