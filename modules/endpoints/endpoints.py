"""
Endpoint Discovery module.

v1.2: crawls the homepage plus one hop of same-origin links (depth 2),
guesses a short list of common app/API paths, classifies discovered forms
(login/register/reset/other), flags *same-origin* forms missing CSRF
tokens, and passively detects CAPTCHA/MFA presence on auth-looking forms.

A form whose action points off-site (e.g. a "Sign in with Google" button
posting straight to accounts.google.com) is recorded separately as a
third-party auth provider, not judged for CSRF/MFA -- that's the
provider's responsibility, not the target site's, and flagging it as a
"missing CSRF" bug on the target is a false positive.

Everything here is a GET request or static HTML analysis -- nothing
submits data or attempts to trigger lockouts/rate limits.
"""

import hashlib
import re
from html.parser import HTMLParser
from urllib.parse import urljoin, urlparse
from uuid import uuid4

import requests

PLUGIN_METADATA = {
    "name": "endpoints",
    "description": "Endpoint, form, and surface discovery",
    "version": "0.1.0",
    "author": "SentinelAI",
    "priority": 30,
    "enabled": True,
    "scan_type": "discovery",
}


TIMEOUT = 8
USER_AGENT = "SentinelAI-Endpoints/0.1 (authorized-assessment)"
MAX_LINKS = 50
MAX_CRAWL_PAGES = 10  # cap on how many discovered pages we follow one hop into

SENSITIVE_PATHS = [
    ".git/HEAD",
    ".git/config",
    ".env",
    ".env.bak",
    ".env.local",
    "backup.zip",
    "backup.sql",
    "backup.tar.gz",
    ".DS_Store",
    "config.php.bak",
    "web.config.bak",
    "composer.json",
    "package.json",
    ".npmrc",
    "id_rsa",
    "wp-config.php.bak",
    ".htaccess",
    "phpinfo.php",
    "server-status",
    "actuator/health",
    "actuator/env",
    ".aws/credentials",
    "docker-compose.yml",
    "Dockerfile",
]

# API/docs surfaces worth knowing about even when they 200 -- not
# automatically a finding (some are intentionally public), just recorded.
API_DISCOVERY_PATHS = [
    "swagger.json",
    "swagger-ui.html",
    "openapi.json",
    "api/docs",
    "api-docs",
    "graphql",
    ".well-known/openid-configuration",
]

# common app paths to guess at, beyond what crawling finds
COMMON_PATHS = [
    "login", "register", "signup", "sign-up", "logout",
    "dashboard", "profile", "account", "settings",
    "reset-password", "forgot-password", "password/reset",
    "admin", "api",
]

_CSRF_NAME_RE = re.compile(r"csrf|authenticity_token|_token", re.IGNORECASE)
_CAPTCHA_MARKERS = ["recaptcha", "g-recaptcha", "hcaptcha", "cf-turnstile", "turnstile"]
_MFA_MARKERS = ["otp", "mfa", "totp", "2fa", "verification_code", "auth_code"]


class _LinkFormParser(HTMLParser):
    def __init__(self, base_url: str):
        super().__init__()
        self.base_url = base_url
        self.links = set()
        self.forms = []
        self.body_lower_fragments = []
        self._current_form = None

    def handle_starttag(self, tag, attrs):
        attrs_dict = dict(attrs)
        if tag == "a" and attrs_dict.get("href"):
            self.links.add(urljoin(self.base_url, attrs_dict["href"]))
        elif tag == "script" and attrs_dict.get("src"):
            self.body_lower_fragments.append(attrs_dict["src"].lower())
        elif tag == "form":
            self._current_form = {
                "action": urljoin(self.base_url, attrs_dict.get("action", "")),
                "method": attrs_dict.get("method", "get").upper(),
                "has_password_field": False,
                "field_names": [],
                "has_csrf_token": False,
                "has_captcha": False,
                "has_mfa_field": False,
            }
        elif tag == "input" and self._current_form is not None:
            name = (attrs_dict.get("name") or "").lower()
            input_type = (attrs_dict.get("type") or "text").lower()
            if name:
                self._current_form["field_names"].append(name)
            if input_type == "password":
                self._current_form["has_password_field"] = True
            if input_type == "hidden" and _CSRF_NAME_RE.search(name):
                self._current_form["has_csrf_token"] = True
            if any(marker in name for marker in _MFA_MARKERS):
                self._current_form["has_mfa_field"] = True
            cls = (attrs_dict.get("class") or "").lower()
            if any(marker in cls for marker in _CAPTCHA_MARKERS) or any(
                marker in name for marker in _CAPTCHA_MARKERS
            ):
                self._current_form["has_captcha"] = True
        elif tag == "div" and self._current_form is not None:
            cls = (attrs_dict.get("class") or "").lower()
            if any(marker in cls for marker in _CAPTCHA_MARKERS):
                self._current_form["has_captcha"] = True

    def handle_endtag(self, tag):
        if tag == "form" and self._current_form is not None:
            self.forms.append(self._current_form)
            self._current_form = None


def _classify_form(form: dict) -> str:
    names = " ".join(form["field_names"])
    action = form["action"].lower()
    has_pw = form["has_password_field"]
    pw_count = sum(1 for n in form["field_names"] if "password" in n or "confirm" in n)

    if has_pw and (pw_count >= 2 or "register" in action or "signup" in action or "sign-up" in action):
        return "register_or_reset"
    if has_pw and ("reset" in action or "forgot" in action):
        return "register_or_reset"
    if has_pw:
        return "login"
    if "email" in names and ("reset" in action or "forgot" in action):
        return "password_reset_request"
    return "other"


_KNOWN_OAUTH_HOSTS = {
    "accounts.google.com": "Google",
    "www.facebook.com": "Facebook",
    "github.com": "GitHub",
    "login.microsoftonline.com": "Microsoft",
    "appleid.apple.com": "Apple",
    "www.linkedin.com": "LinkedIn",
}


MAX_RECORDED_ERRORS = 25


def _record_error(result: dict, message: str) -> None:
    """Record a non-fatal probe failure. Bounded, because a target that goes
    down mid-scan would otherwise produce one error per probed path."""
    if len(result["errors"]) < MAX_RECORDED_ERRORS:
        result["errors"].append(message)
    else:
        result["errors_suppressed"] = result.get("errors_suppressed", 0) + 1


def _flush_suppressed_errors(result: dict) -> None:
    suppressed = result.pop("errors_suppressed", 0)
    if suppressed:
        result["errors"].append(f"... and {suppressed} further probe error(s) not listed")


def run(target_url: str, context: dict | None = None) -> dict:
    result = {
        "module": "endpoints",
        "target": target_url,
        "links": [],
        "forms": [],
        "external_auth_providers": [],
        "api_surfaces_found": [],
        "sensitive_paths_found": [],
        "directory_listing": False,
        "errors": [],
    }

    try:
        resp = requests.get(
            target_url, headers={"User-Agent": USER_AGENT}, timeout=TIMEOUT, allow_redirects=True
        )
    except requests.RequestException as exc:
        result["errors"].append(f"GET {target_url} failed: {exc}")
        return result

    base_url = resp.url
    base_netloc = urlparse(base_url).netloc

    all_links = set()
    all_forms = []
    directory_listing = "Index of /" in (resp.text or "")

    homepage_parser = _LinkFormParser(base_url)
    try:
        homepage_parser.feed(resp.text or "")
    except Exception as exc:
        result["errors"].append(f"HTML parse error on homepage: {exc}")

    same_origin = {l for l in homepage_parser.links if urlparse(l).netloc in ("", base_netloc)}
    all_links |= same_origin
    all_forms.extend(homepage_parser.forms)

    # one hop deeper: follow a bounded number of discovered same-origin pages
    for link in list(same_origin)[:MAX_CRAWL_PAGES]:
        try:
            r = requests.get(link, headers={"User-Agent": USER_AGENT}, timeout=TIMEOUT, allow_redirects=True)
        except requests.RequestException as exc:
            _record_error(result, f"GET {link} failed during crawl: {exc}")
            continue
        if "text/html" not in r.headers.get("Content-Type", ""):
            continue
        p = _LinkFormParser(r.url)
        try:
            p.feed(r.text or "")
        except Exception as exc:
            _record_error(result, f"HTML parse error on {r.url}: {exc}")
            continue
        all_links |= {l for l in p.links if urlparse(l).netloc in ("", base_netloc)}
        all_forms.extend(p.forms)
        if "Index of /" in (r.text or ""):
            directory_listing = True

    # guess common app paths not already discovered, using the same soft-404 baseline filter
    baseline_hash = _get_baseline_hash(target_url, result)
    for path in COMMON_PATHS:
        url = urljoin(target_url, path)
        if url in all_links:
            continue
        try:
            r = requests.get(url, headers={"User-Agent": USER_AGENT}, timeout=TIMEOUT, allow_redirects=False)
        except requests.RequestException as exc:
            _record_error(result, f"GET {url} failed: {exc}")
            continue
        if r.status_code == 200 and r.content:
            content_hash = hashlib.md5(r.content).hexdigest()
            if baseline_hash is None or content_hash != baseline_hash:
                all_links.add(url)

    # split forms into same-origin (ours to fix) vs third-party auth (not ours to fix)
    external_providers = set()
    same_origin_forms = []
    for form in all_forms:
        form["form_type"] = _classify_form(form)
        action_netloc = urlparse(form["action"]).netloc
        if action_netloc and action_netloc != base_netloc:
            form["same_origin"] = False
            provider = _KNOWN_OAUTH_HOSTS.get(action_netloc, action_netloc)
            external_providers.add(provider)
        else:
            form["same_origin"] = True
            same_origin_forms.append(form)

    result["links"] = sorted(all_links)[:MAX_LINKS]
    result["forms"] = same_origin_forms
    result["external_auth_providers"] = sorted(external_providers)
    result["directory_listing"] = directory_listing

    for path in SENSITIVE_PATHS:
        url = urljoin(target_url, path)
        try:
            r = requests.get(
                url, headers={"User-Agent": USER_AGENT}, timeout=TIMEOUT, allow_redirects=False
            )
        except requests.RequestException as exc:
            _record_error(result, f"GET {url} failed: {exc}")
            continue
        if r.status_code != 200 or not r.content:
            continue
        content_hash = hashlib.md5(r.content).hexdigest()
        if baseline_hash is not None and content_hash == baseline_hash:
            continue
        result["sensitive_paths_found"].append({"path": path, "size": len(r.content)})

    for path in API_DISCOVERY_PATHS:
        url = urljoin(target_url, path)
        try:
            r = requests.get(url, headers={"User-Agent": USER_AGENT}, timeout=TIMEOUT, allow_redirects=False)
        except requests.RequestException as exc:
            _record_error(result, f"GET {url} failed: {exc}")
            continue
        if r.status_code != 200 or not r.content:
            continue
        content_hash = hashlib.md5(r.content).hexdigest()
        if baseline_hash is not None and content_hash == baseline_hash:
            continue
        result["api_surfaces_found"].append(path)

    _flush_suppressed_errors(result)
    return result


def _get_baseline_hash(target_url: str, result: dict):
    """GET a near-certainly-nonexistent path so real finds can be told apart from soft-404 catch-alls."""
    probe_path = f"__sentinelai_nonexistent_check_{uuid4().hex}__"
    url = urljoin(target_url, probe_path)
    try:
        r = requests.get(url, headers={"User-Agent": USER_AGENT}, timeout=TIMEOUT, allow_redirects=False)
    except requests.RequestException as exc:
        # Without a baseline every soft-404 catch-all page looks like a real
        # find, so note that the results are less trustworthy.
        _record_error(result, f"soft-404 baseline probe failed ({exc}); path results may include false positives")
        return None
    if r.status_code == 200 and r.content:
        return hashlib.md5(r.content).hexdigest()
    return None
