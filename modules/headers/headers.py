"""
Security Header Analysis module.

Checks presence of the standard security headers, plus goes one level
deeper on the two that are most often present-but-useless: a CSP with
'unsafe-inline'/'unsafe-eval'/wildcard sources isn't doing much, and an
HSTS header with a tiny max-age or missing includeSubDomains is weak.
"""

import re

from common.http import HttpClient, set_cookie_headers
from common.results import module_result

PLUGIN_METADATA = {
    "name": "headers",
    "description": "Security header and cookie analysis",
    "version": "0.1.0",
    "author": "SentinelAI",
    "priority": 60,
    "enabled": True,
    "scan_type": "headers",
}


AGENT_SUFFIX = "Headers"

CHECKED_HEADERS = [
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
    "Cross-Origin-Opener-Policy",
    "Cross-Origin-Resource-Policy",
]

_HSTS_MIN_MAX_AGE = 15552000  # 180 days -- a commonly cited minimum for a meaningful policy


def run(target_url: str, context: dict | None = None) -> dict:
    result = module_result(
        "headers", target_url,
        missing=[],
        present={},
        csp_issues=[],
        hsts_issues=[],
    )

    resp = HttpClient(AGENT_SUFFIX, result["errors"]).get(target_url)
    if resp is None:
        return result

    response_headers = resp.headers
    for header_name in CHECKED_HEADERS:
        value = response_headers.get(header_name)
        if value is None:
            result["missing"].append(header_name)
        else:
            result["present"][header_name] = value

    csp = response_headers.get("Content-Security-Policy")
    if csp:
        result["csp_issues"] = _check_csp(csp)

    hsts = response_headers.get("Strict-Transport-Security")
    is_https = target_url.lower().startswith("https://")
    if is_https:
        if hsts:
            result["hsts_issues"] = _check_hsts(hsts)
        # if hsts is missing it's already flagged via "missing", no need to duplicate

    result["cookie_issues"] = _check_cookies(resp)
    result["cors_issue"] = _check_cors(response_headers)

    return result


def _check_csp(csp: str) -> list:
    issues = []
    lowered = csp.lower()
    if "unsafe-inline" in lowered:
        issues.append("Allows 'unsafe-inline' -- inline <script>/<style> can execute, defeating most of CSP's XSS protection.")
    if "unsafe-eval" in lowered:
        issues.append("Allows 'unsafe-eval' -- eval()/new Function() can run, a common XSS-to-RCE-in-the-browser gadget.")
    directives = dict(
        re.findall(r"([a-z\-]+)\s+([^;]*)", lowered)
    )
    script_src = directives.get("script-src", directives.get("default-src", ""))
    if "*" in script_src.split():
        issues.append("script-src allows '*' -- any origin can supply scripts.")
    if "default-src" not in directives and "script-src" not in directives:
        issues.append("No default-src or script-src directive -- CSP isn't actually restricting script sources.")
    return issues


def _check_hsts(hsts: str) -> list:
    issues = []
    match = re.search(r"max-age\s*=\s*(\d+)", hsts, re.IGNORECASE)
    max_age = int(match.group(1)) if match else 0
    if max_age < _HSTS_MIN_MAX_AGE:
        issues.append(f"max-age={max_age} is short (~{max_age // 86400}d) -- browsers stop enforcing HTTPS-only once it expires.")
    if "includesubdomains" not in hsts.lower():
        issues.append("Missing includeSubDomains -- subdomains aren't covered by this policy.")
    return issues


def _check_cookies(resp) -> list:
    """Flag any Set-Cookie missing HttpOnly / Secure / SameSite."""
    issues = []
    for cookie_str in set_cookie_headers(resp):
        name = cookie_str.split("=", 1)[0].strip()
        lower = cookie_str.lower()
        missing = [
            flag
            for flag, marker in (("HttpOnly", "httponly"), ("Secure", "secure"), ("SameSite", "samesite"))
            if marker not in lower
        ]
        if missing:
            issues.append({"name": name, "missing": missing})
    return issues


def _check_cors(response_headers) -> str | None:
    """v1: flag the clearly dangerous combination -- wildcard origin + credentials allowed."""
    acao = response_headers.get("Access-Control-Allow-Origin")
    acac = (response_headers.get("Access-Control-Allow-Credentials") or "").lower()
    if acao == "*" and acac == "true":
        return "Access-Control-Allow-Origin: * combined with Access-Control-Allow-Credentials: true"
    return None
