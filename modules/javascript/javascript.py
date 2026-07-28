"""
JavaScript Analysis module.

Fetches same-origin JS files linked from the homepage and regex-scans them
for hardcoded secrets/keys, exposed source maps, internal/staging URLs
leaked into client code, risky sinks (eval/document.write), and outdated
jQuery versions with known issues. Static text analysis only -- nothing
here executes the JS or submits anything.
"""

import re
from html.parser import HTMLParser
from urllib.parse import urljoin, urlparse

import requests

PLUGIN_METADATA = {
    "name": "javascript",
    "description": "Client-side JavaScript analysis",
    "version": "0.1.0",
    "author": "SentinelAI",
    "priority": 40,
    "enabled": True,
    "scan_type": "analysis",
}


TIMEOUT = 8
USER_AGENT = "SentinelAI-JSAnalysis/0.1 (authorized-assessment)"
MAX_JS_FILES = 15
MAX_BYTES_PER_FILE = 2_000_000

# (label, regex, severity) -- generic-token patterns are deliberately
# conservative (long enough literal, clear key-ish name) to keep false
# positives down.
SECRET_PATTERNS = [
    ("AWS Access Key ID", re.compile(r"AKIA[0-9A-Z]{16}"), "critical"),
    ("Google API Key", re.compile(r"AIza[0-9A-Za-z\-_]{35}"), "high"),
    ("Stripe Live Secret Key", re.compile(r"sk_live_[0-9a-zA-Z]{20,}"), "critical"),
    ("Slack Token", re.compile(r"xox[baprs]-[0-9A-Za-z\-]{10,}"), "high"),
    ("Private Key Block", re.compile(r"-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----"), "critical"),
    (
        "Generic hardcoded secret/token",
        re.compile(r"""(?i)(?:api[_\-]?key|secret|access[_\-]?token|client[_\-]?secret)\s*[:=]\s*["\']([A-Za-z0-9\-_]{16,})["\']"""),
        "medium",
    ),
]

_INTERNAL_URL_RE = re.compile(
    r"https?://(?:localhost|127\.0\.0\.1|0\.0\.0\.0|10\.\d{1,3}\.\d{1,3}\.\d{1,3}|"
    r"192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3}|"
    r"[a-z0-9\-]+\.(?:internal|local|staging|dev|corp))[\w:/\-\.\?=&%]*",
    re.IGNORECASE,
)

_JQUERY_VERSION_RE = re.compile(r"jQuery\s+v?(\d+)\.(\d+)\.(\d+)", re.IGNORECASE)


class _ScriptTagParser(HTMLParser):
    def __init__(self, base_url: str):
        super().__init__()
        self.base_url = base_url
        self.script_srcs = []
        self.inline_scripts = []
        self._in_script = False
        self._current_inline = []

    def handle_starttag(self, tag, attrs):
        if tag != "script":
            return
        attrs_dict = dict(attrs)
        if attrs_dict.get("src"):
            self.script_srcs.append(urljoin(self.base_url, attrs_dict["src"]))
        else:
            self._in_script = True
            self._current_inline = []

    def handle_data(self, data):
        if self._in_script:
            self._current_inline.append(data)

    def handle_endtag(self, tag):
        if tag == "script" and self._in_script:
            self.inline_scripts.append("".join(self._current_inline))
            self._in_script = False


def run(target_url: str, context: dict | None = None) -> dict:
    result = {
        "module": "javascript",
        "target": target_url,
        "js_files": [],
        "secrets_found": [],
        "internal_urls_found": [],
        "exposed_source_maps": [],
        "risky_sinks": [],
        "outdated_libraries": [],
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

    parser = _ScriptTagParser(base_url)
    try:
        parser.feed(resp.text or "")
    except Exception as exc:
        result["errors"].append(f"HTML parse error: {exc}")

    same_origin_js = [u for u in parser.script_srcs if urlparse(u).netloc in ("", base_netloc)][:MAX_JS_FILES]
    result["js_files"] = same_origin_js

    bodies = {}  # url -> text, for inline scripts key is "" 
    if parser.inline_scripts:
        bodies["(inline)"] = "\n".join(parser.inline_scripts)

    for js_url in same_origin_js:
        try:
            r = requests.get(js_url, headers={"User-Agent": USER_AGENT}, timeout=TIMEOUT, stream=True)
            content = r.raw.read(MAX_BYTES_PER_FILE, decode_content=True)
            text = content.decode("utf-8", errors="replace")
        except requests.RequestException as exc:
            result["errors"].append(f"GET {js_url} failed: {exc}")
            continue
        bodies[js_url] = text

        # source map exposure: <file>.js.map reachable?
        if js_url.endswith(".js"):
            map_url = js_url + ".map"
            try:
                map_resp = requests.head(map_url, headers={"User-Agent": USER_AGENT}, timeout=TIMEOUT)
                if map_resp.status_code == 200:
                    result["exposed_source_maps"].append(map_url)
            except requests.RequestException:
                pass

    for source, text in bodies.items():
        for label, pattern, severity in SECRET_PATTERNS:
            for match in pattern.finditer(text):
                snippet = match.group(0)
                masked = snippet[:6] + "..." + snippet[-4:] if len(snippet) > 12 else "***"
                result["secrets_found"].append({
                    "source": source, "type": label, "severity": severity, "masked_value": masked,
                })

        for match in _INTERNAL_URL_RE.finditer(text):
            url = match.group(0)
            if url not in result["internal_urls_found"]:
                result["internal_urls_found"].append(url)

        if "eval(" in text or "eval (" in text:
            result["risky_sinks"].append({"source": source, "sink": "eval()"})
        if "document.write(" in text:
            result["risky_sinks"].append({"source": source, "sink": "document.write()"})

        jq_match = _JQUERY_VERSION_RE.search(text)
        if jq_match:
            major = int(jq_match.group(1))
            version = ".".join(jq_match.groups())
            if major < 3:
                result["outdated_libraries"].append({
                    "name": "jQuery", "version": version, "source": source,
                    "note": "jQuery < 3.0 has known XSS issues in $(html) parsing / .html() handling.",
                })

    # cap noisy lists so one page doesn't produce hundreds of findings
    result["secrets_found"] = result["secrets_found"][:20]
    result["internal_urls_found"] = result["internal_urls_found"][:20]
    result["risky_sinks"] = result["risky_sinks"][:20]

    return result
