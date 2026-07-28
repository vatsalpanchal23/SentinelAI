"""
Technology Detection module.

Lightweight, dependency-free signature matching against response headers,
cookies, and HTML body content. Not a full Wappalyzer port -- a small,
extensible signature table that's easy to add to.

Each signature check now carries a "strong"/"weak" confidence: a header like
Server: nginx is strong evidence; a generic cookie name like "session" alone
is weak (lots of frameworks use that name), so a tech is only reported if it
has at least one strong match, or several weak ones together.
"""

import re

import requests

PLUGIN_METADATA = {
    "name": "fingerprint",
    "description": "Technology fingerprinting",
    "version": "0.1.0",
    "author": "SentinelAI",
    "priority": 20,
    "enabled": True,
    "scan_type": "fingerprint",
}


TIMEOUT = 8
USER_AGENT = "SentinelAI-Fingerprint/0.1 (authorized-assessment)"

# (technology, category) -> list of (source, pattern, confidence) checks.
# source: "header:<Name>" | "cookie" | "body" | "cookie_value_pattern"
SIGNATURES = [
    ("WordPress", "cms", [
        ("body", "wp-content", "strong"),
        ("body", "wp-includes", "strong"),
        ("header:Link", "wp-json", "strong"),
    ]),
    ("Drupal", "cms", [
        ("body", "Drupal.settings", "strong"),
        ("header:X-Generator", "Drupal", "strong"),
        ("header:X-Drupal-Cache", "", "strong"),
    ]),
    ("Joomla", "cms", [
        ("body", "/media/jui/", "strong"),
        ("body", "Joomla!", "weak"),
    ]),
    ("Shopify", "ecommerce", [
        ("body", "cdn.shopify.com", "strong"),
        ("header:X-Shopify-Stage", "", "strong"),
    ]),
    ("Django", "framework", [
        ("body", "csrfmiddlewaretoken", "strong"),
        ("cookie", "csrftoken", "strong"),
        ("cookie", "django_language", "weak"),
    ]),
    ("Laravel", "framework", [
        ("cookie", "laravel_session", "strong"),
        ("cookie", "XSRF-TOKEN", "weak"),
    ]),
    ("Express", "framework", [
        ("header:X-Powered-By", "Express", "strong"),
        ("cookie", "connect.sid", "strong"),
    ]),
    ("PHP", "language", [
        ("header:X-Powered-By", "PHP", "strong"),
        ("cookie", "PHPSESSID", "strong"),
    ]),
    ("ASP.NET", "framework", [
        ("header:X-Powered-By", "ASP.NET", "strong"),
        ("header:X-AspNet-Version", "", "strong"),
        ("cookie", "ASP.NET_SessionId", "strong"),
    ]),
    ("React", "js-framework", [
        ("body", "data-reactroot", "strong"),
        ("body", "react-dom", "weak"),
        ("body", "__next_f", "weak"),
    ]),
    ("Angular", "js-framework", [("body", "ng-version", "strong")]),
    ("Vue.js", "js-framework", [
        ("body", "data-v-", "weak"),
        ("body", "__vue__", "strong"),
    ]),
    ("Next.js", "js-framework", [("body", "__NEXT_DATA__", "strong")]),
    ("jQuery", "js-library", [("body", "jquery", "weak")]),
    ("Bootstrap", "css-framework", [
        ("body", "bootstrap.min.css", "strong"),
        ("body", "bootstrap.bundle", "weak"),
    ]),
    ("Tailwind CSS", "css-framework", [
        ("body", "tailwindcss", "strong"),
        ("body", "cdn.tailwindcss.com", "strong"),
    ]),
    ("Nginx", "webserver", [("header:Server", "nginx", "strong")]),
    ("Apache", "webserver", [("header:Server", "Apache", "strong")]),
    ("Microsoft IIS", "webserver", [("header:Server", "Microsoft-IIS", "strong")]),
    ("Werkzeug/Flask dev server", "webserver", [("header:Server", "Werkzeug", "strong")]),
    ("Cloudflare", "cdn", [
        ("header:Server", "cloudflare", "strong"),
        ("header:CF-RAY", "", "strong"),
    ]),
    ("Vercel", "hosting", [
        ("header:Server", "Vercel", "strong"),
        ("header:X-Vercel-Id", "", "strong"),
    ]),
    ("AWS (CloudFront/ALB)", "hosting", [
        ("header:X-Amz-Cf-Id", "", "strong"),
        ("header:Server", "AmazonS3", "strong"),
    ]),
    ("Vercel Edge / Next.js hosting", "hosting", [("header:X-Matched-Path", "", "weak")]),
]

# Flask specifically needs a stronger check than "a cookie named session
# exists" -- that name is generic. A Flask-signed session cookie is a
# base64-ish value with two literal '.' separators (payload.timestamp.sig);
# require that shape, not just the cookie's name.
_FLASK_SESSION_VALUE_RE = re.compile(r"^[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+$")


def run(target_url: str, context: dict | None = None) -> dict:
    result = {
        "module": "fingerprint",
        "target": target_url,
        "technologies": [],
        "errors": [],
    }

    try:
        resp = requests.get(
            target_url, headers={"User-Agent": USER_AGENT}, timeout=TIMEOUT, allow_redirects=True
        )
    except requests.RequestException as exc:
        result["errors"].append(f"GET {target_url} failed: {exc}")
        return result

    body = resp.text or ""
    cookies = {}  # name -> value
    for raw in re.split(r",(?=\s*\w+=)", resp.headers.get("Set-Cookie", "")):
        if "=" in raw:
            name, _, rest = raw.strip().partition("=")
            cookies[name] = rest.split(";", 1)[0]

    detected = []
    for name, category, checks in SIGNATURES:
        strong_evidence, weak_evidence = [], []
        for source, pattern, confidence in checks:
            hit = None
            if source == "body":
                if pattern.lower() in body.lower():
                    hit = f"body contains '{pattern}'"
            elif source == "cookie":
                if pattern in cookies:
                    hit = f"cookie '{pattern}' set"
            elif source.startswith("header:"):
                header_name = source.split(":", 1)[1]
                header_value = resp.headers.get(header_name, "")
                if header_value and (pattern == "" or pattern.lower() in header_value.lower()):
                    hit = f"header {header_name}: {header_value}"
            if hit:
                (strong_evidence if confidence == "strong" else weak_evidence).append(hit)

        if strong_evidence or len(weak_evidence) >= 2:
            detected.append({
                "name": name,
                "category": category,
                "evidence": strong_evidence + weak_evidence,
                "confidence": "confirmed" if strong_evidence else "likely",
            })

    # Flask: only report it if the session cookie's *value* has Flask's
    # signed-session shape, not just a cookie that happens to be named "session".
    if "session" in cookies and _FLASK_SESSION_VALUE_RE.match(cookies["session"]):
        detected.append({
            "name": "Flask",
            "category": "framework",
            "evidence": ["cookie 'session' has Flask's itsdangerous-signed shape (payload.timestamp.sig)"],
            "confidence": "likely",
        })

    result["technologies"] = detected
    return result
