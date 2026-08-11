"""
Vulnerability Assessment module.

v1: lightweight, passive/low-risk checks written directly against
`requests` -- not a ZAP/Nuclei/Nikto integration (those need the tool
installed and running as a separate process, which isn't assumed to be
present on whatever machine this runs on). Everything here stays
non-destructive:

- dangerous HTTP methods enabled (OPTIONS probe, read-only)
- reflected-parameter check: re-request a discovered link with its
  existing param value tweaked, look for the tweak reflected unescaped
  (classic passive reflected-XSS indicator -- doesn't execute anything)
- error-based SQL injection indicator: append a single quote to a
  parameter value, look for a known DB error signature in the response
  (a single extra quote on a GET request; the same technique manual
  testers use, no destructive payloads)
- open redirect: point a redirect-looking parameter at an external,
  nonexistent test domain and see if the app honors it via Location

All probes are capped in count so this doesn't hammer the target.
"""

import re
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from common.html import LinkParser, feed_html, same_origin
from common.http import HttpClient
from common.results import module_result

PLUGIN_METADATA = {
    "name": "vulnerabilities",
    "description": "Lightweight vulnerability checks",
    "version": "0.1.0",
    "author": "SentinelAI",
    "priority": 70,
    "enabled": True,
    "scan_type": "vulnerability",
}


AGENT_SUFFIX = "VulnCheck"
MAX_PARAM_PROBES = 20
REDIRECT_TEST_HOST = "sentinelai-redirect-poc.invalid"
XSS_CANARY = "sentinelXSSpoc\"'<>"

_SQLI_ERROR_SIGNATURES = [
    re.compile(r"you have an error in your sql syntax", re.IGNORECASE),
    re.compile(r"warning:\s*mysql", re.IGNORECASE),
    re.compile(r"unclosed quotation mark after the character string", re.IGNORECASE),
    re.compile(r"sqlstate\[", re.IGNORECASE),
    re.compile(r"pg_query\(\)", re.IGNORECASE),
    re.compile(r"ora-\d{5}", re.IGNORECASE),
    re.compile(r"sqlite3\.OperationalError", re.IGNORECASE),
    re.compile(r"system\.data\.sqlclient", re.IGNORECASE),
    re.compile(r"psycopg2\.", re.IGNORECASE),
]

_REDIRECT_PARAM_NAMES = {"redirect", "redirect_uri", "redirecturl", "next", "return", "returnurl",
                          "url", "continue", "dest", "destination", "redir", "return_to"}

_DANGEROUS_METHODS = {"PUT", "DELETE", "TRACE", "CONNECT"}


def run(target_url: str, context: dict | None = None) -> dict:
    result = module_result(
        "vulnerabilities", target_url,
        dangerous_methods=[],
        reflected_params=[],
        sqli_indicators=[],
        open_redirects=[],
    )
    client = HttpClient(AGENT_SUFFIX, result["errors"])

    result["dangerous_methods"] = _check_http_methods(target_url, client)

    candidate_links = _candidate_links(target_url, context, client, result)

    param_candidates = []  # (url, param_name)
    for link in candidate_links:
        query = parse_qs(urlparse(link).query)
        for param_name in query:
            param_candidates.append((link, param_name))
        if len(param_candidates) >= MAX_PARAM_PROBES:
            break
    param_candidates = param_candidates[:MAX_PARAM_PROBES]

    for link, param_name in param_candidates:
        _probe_reflection(link, param_name, client, result)
        _probe_sqli(link, param_name, client, result)
        if param_name.lower().replace("_", "") in {p.replace("_", "") for p in _REDIRECT_PARAM_NAMES}:
            _probe_open_redirect(link, param_name, client, result)

    return result


def _candidate_links(target_url: str, context: dict | None, client: HttpClient, result: dict) -> list:
    """Prefer the endpoints module's depth-2 crawl (much broader surface) when
    available via context; fall back to a homepage-only crawl so this module
    still works standalone (e.g. under test, or if endpoints failed)."""
    endpoints_output = (context or {}).get("endpoints")
    if endpoints_output and endpoints_output.get("links"):
        links_with_query = [l for l in endpoints_output["links"] if urlparse(l).query]
        # also treat GET forms' fields as probeable "links" against their action URL
        form_links = []
        for form in endpoints_output.get("forms", []):
            if form.get("method", "GET").upper() != "GET" or not form.get("field_names"):
                continue
            fake_query = "&".join(f"{name}=1" for name in form["field_names"])
            form_links.append(f"{form['action']}?{fake_query}")
        return links_with_query + form_links

    resp = client.get(target_url)
    if resp is None:
        return []

    parser = LinkParser(resp.url)
    feed_html(parser, resp.text, result["errors"])
    return same_origin(parser.links, urlparse(resp.url).netloc)


def _replace_param(url: str, param_name: str, new_value: str) -> str:
    parsed = urlparse(url)
    query = parse_qs(parsed.query)
    query[param_name] = [new_value]
    new_query = urlencode(query, doseq=True)
    return urlunparse(parsed._replace(query=new_query))


def _check_http_methods(target_url: str, client: HttpClient) -> list:
    resp = client.options(target_url)
    if resp is None:
        return []
    allow = resp.headers.get("Allow", "")
    methods = {m.strip().upper() for m in allow.split(",") if m.strip()}
    return sorted(methods & _DANGEROUS_METHODS)


def _probe_reflection(link: str, param_name: str, client: HttpClient, result: dict) -> None:
    probe_url = _replace_param(link, param_name, XSS_CANARY)
    resp = client.get(probe_url, error_label=f"Reflection probe on {link}")
    if resp is None:
        return
    if XSS_CANARY in (resp.text or ""):
        result["reflected_params"].append({"url": link, "param": param_name})


def _probe_sqli(link: str, param_name: str, client: HttpClient, result: dict) -> None:
    probe_url = _replace_param(link, param_name, "sentinelai'probe")
    resp = client.get(probe_url, error_label=f"SQLi probe on {link}")
    if resp is None:
        return
    body = resp.text or ""
    for pattern in _SQLI_ERROR_SIGNATURES:
        if pattern.search(body):
            result["sqli_indicators"].append({"url": link, "param": param_name, "signature": pattern.pattern})
            return


def _probe_open_redirect(link: str, param_name: str, client: HttpClient, result: dict) -> None:
    test_target = f"https://{REDIRECT_TEST_HOST}/"
    probe_url = _replace_param(link, param_name, test_target)
    resp = client.get(probe_url, allow_redirects=False, error_label=f"Open-redirect probe on {link}")
    if resp is None:
        return
    location = resp.headers.get("Location", "")
    if REDIRECT_TEST_HOST in location:
        result["open_redirects"].append({"url": link, "param": param_name, "location": location})
