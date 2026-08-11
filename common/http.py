"""HTTP helpers shared by the scanner modules.

Every module used to repeat the same three things: build a
`{"User-Agent": ...}` header dict with an 8s timeout, wrap the call in
`try/except requests.RequestException` and append a `"<verb> <url> failed: ..."`
string to its own result's `errors` list. `HttpClient` carries the UA/timeout
and does that error recording once.
"""

import hashlib
import re

import requests

DEFAULT_TIMEOUT = 8

_AGENT_TEMPLATE = "SentinelAI-{suffix}/0.1 (authorized-assessment)"

# Set-Cookie values are sometimes folded into one comma-joined header; split
# only on commas that start a new `name=` pair so `Expires=Mon, 01 Jan ...`
# doesn't get torn in half.
_COOKIE_SPLIT_RE = re.compile(r",(?=\s*\w+=)")


def user_agent(suffix: str) -> str:
    """UA string identifying which module is making the request."""
    return _AGENT_TEMPLATE.format(suffix=suffix)


class HttpClient:
    """`requests` wrapper with a fixed User-Agent, timeout, and error sink.

    Returns None instead of raising on a transport error; the failure is
    appended to `errors` (normally the module result's `errors` list) unless
    `record_error=False`.
    """

    def __init__(self, agent_suffix: str, errors: list | None = None, timeout: int = DEFAULT_TIMEOUT):
        self.headers = {"User-Agent": user_agent(agent_suffix)}
        self.errors = errors
        self.timeout = timeout

    def record_error(self, message: str) -> None:
        if self.errors is not None:
            self.errors.append(message)

    def get(self, url: str, **kwargs):
        return self._request(requests.get, "GET", url, **kwargs)

    def head(self, url: str, **kwargs):
        return self._request(requests.head, "HEAD", url, **kwargs)

    def options(self, url: str, **kwargs):
        return self._request(requests.options, "OPTIONS", url, **kwargs)

    def _request(self, fn, verb: str, url: str, record_error: bool = True, error_label: str | None = None, **kwargs):
        try:
            return fn(url, headers=self.headers, timeout=self.timeout, **kwargs)
        except requests.RequestException as exc:
            if record_error:
                self.record_error(f"{error_label or f'{verb} {url}'} failed: {exc}")
            return None


def content_hash(content: bytes) -> str:
    return hashlib.md5(content).hexdigest()


def set_cookie_headers(resp) -> list:
    """Individual Set-Cookie header values from a response."""
    try:
        return list(resp.raw.headers.getlist("Set-Cookie"))
    except AttributeError:
        combined = resp.headers.get("Set-Cookie")
        return [c.strip() for c in _COOKIE_SPLIT_RE.split(combined)] if combined else []


def cookie_dict(resp) -> dict:
    """Cookie name -> value, ignoring attributes (Path, Expires, ...)."""
    cookies = {}
    for raw in set_cookie_headers(resp):
        if "=" in raw:
            name, _, rest = raw.strip().partition("=")
            cookies[name] = rest.split(";", 1)[0]
    return cookies
