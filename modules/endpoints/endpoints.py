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

import re
from urllib.parse import urljoin, urlparse
from uuid import uuid4

from common.html import LinkParser, feed_html, same_origin
from common.http import HttpClient, content_hash
from common.results import module_result

PLUGIN_METADATA = {
    "name": "endpoints",
    "description": "Endpoint, form, and surface discovery",
    "version": "0.1.0",
    "author": "SentinelAI",
    "priority": 30,
    "enabled": True,
    "scan_type": "discovery",
}


AGENT_SUFFIX = "Endpoints"
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


class _LinkFormParser(LinkParser):
    def __init__(self, base_url: str):
        super().__init__(base_url)
        self.forms = []
        self.body_lower_fragments = []
        self._current_form = None

    def handle_starttag(self, tag, attrs):
        super().handle_starttag(tag, attrs)
        attrs_dict = dict(attrs)
        if tag == "script" and attrs_dict.get("src"):
            self.body_lower_fragments.append(attrs_dict["src"].lower())
        elif tag == "form":
            self._current_form = {
                "action": self.resolve(attrs_dict.get("action", "")),
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


def run(target_url: str, context: dict | None = None) -> dict:
    result = module_result(
        "endpoints", target_url,
        links=[],
        forms=[],
        external_auth_providers=[],
        api_surfaces_found=[],
        sensitive_paths_found=[],
        directory_listing=False,
    )
    client = HttpClient(AGENT_SUFFIX, result["errors"])

    resp = client.get(target_url)
    if resp is None:
        return result

    base_url = resp.url
    base_netloc = urlparse(base_url).netloc

    all_links = set()
    all_forms = []
    directory_listing = "Index of /" in (resp.text or "")

    homepage_parser = _LinkFormParser(base_url)
    feed_html(homepage_parser, resp.text, result["errors"], "HTML parse error on homepage")

    homepage_links = set(same_origin(homepage_parser.links, base_netloc))
    all_links |= homepage_links
    all_forms.extend(homepage_parser.forms)

    # one hop deeper: follow a bounded number of discovered same-origin pages
    for link in list(homepage_links)[:MAX_CRAWL_PAGES]:
        r = client.get(link, record_error=False)
        if r is None or "text/html" not in r.headers.get("Content-Type", ""):
            continue
        p = _LinkFormParser(r.url)
        if not feed_html(p, r.text):
            continue
        all_links |= set(same_origin(p.links, base_netloc))
        all_forms.extend(p.forms)
        if "Index of /" in (r.text or ""):
            directory_listing = True

    # guess common app paths not already discovered, using the same soft-404 baseline filter
    baseline_hash = _get_baseline_hash(target_url, client)
    undiscovered = [p for p in COMMON_PATHS if urljoin(target_url, p) not in all_links]
    for path, _resp in _probe_paths(client, target_url, undiscovered, baseline_hash):
        all_links.add(urljoin(target_url, path))

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

    for path, r in _probe_paths(client, target_url, SENSITIVE_PATHS, baseline_hash):
        result["sensitive_paths_found"].append({"path": path, "size": len(r.content)})

    for path, _resp in _probe_paths(client, target_url, API_DISCOVERY_PATHS, baseline_hash):
        result["api_surfaces_found"].append(path)

    return result


def _probe_paths(client: HttpClient, target_url: str, paths: list, baseline_hash: str | None):
    """Yield (path, response) for each path that serves real content: a 200 with
    a body that differs from the soft-404 baseline. Transport errors are skipped
    silently -- an unreachable guessed path is the expected case, not an error
    worth reporting."""
    for path in paths:
        r = client.get(urljoin(target_url, path), allow_redirects=False, record_error=False)
        if r is None or r.status_code != 200 or not r.content:
            continue
        if baseline_hash is not None and content_hash(r.content) == baseline_hash:
            continue
        yield path, r


def _get_baseline_hash(target_url: str, client: HttpClient) -> str | None:
    """GET a near-certainly-nonexistent path so real finds can be told apart from soft-404 catch-alls."""
    probe_path = f"__sentinelai_nonexistent_check_{uuid4().hex}__"
    r = client.get(urljoin(target_url, probe_path), allow_redirects=False, record_error=False)
    if r is not None and r.status_code == 200 and r.content:
        return content_hash(r.content)
    return None
