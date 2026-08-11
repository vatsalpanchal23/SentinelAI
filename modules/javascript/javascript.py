"""
JavaScript Analysis module.

Fetches same-origin JS files linked from the homepage and regex-scans them
for hardcoded secrets/keys, exposed source maps, internal/staging URLs
leaked into client code, risky sinks (eval/document.write), and outdated
jQuery versions with known issues. Static text analysis only -- nothing
here executes the JS or submits anything.
"""

import re
from urllib.parse import urlparse

from common.html import BaseTagParser, feed_html, same_origin
from common.http import HttpClient
from common.results import module_result

PLUGIN_METADATA = {
    "name": "javascript",
    "description": "Client-side JavaScript analysis",
    "version": "0.1.0",
    "author": "SentinelAI",
    "priority": 40,
    "enabled": True,
    "scan_type": "analysis",
}


AGENT_SUFFIX = "JSAnalysis"
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


class _ScriptTagParser(BaseTagParser):
    def __init__(self, base_url: str):
        super().__init__(base_url)
        self.script_srcs = []
        self.inline_scripts = []
        self._in_script = False
        self._current_inline = []

    def handle_starttag(self, tag, attrs):
        if tag != "script":
            return
        attrs_dict = dict(attrs)
        if attrs_dict.get("src"):
            self.script_srcs.append(self.resolve(attrs_dict["src"]))
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
    result = module_result(
        "javascript", target_url,
        js_files=[],
        secrets_found=[],
        internal_urls_found=[],
        exposed_source_maps=[],
        risky_sinks=[],
        outdated_libraries=[],
    )
    client = HttpClient(AGENT_SUFFIX, result["errors"])

    resp = client.get(target_url)
    if resp is None:
        return result

    base_url = resp.url
    base_netloc = urlparse(base_url).netloc

    parser = _ScriptTagParser(base_url)
    feed_html(parser, resp.text, result["errors"])

    same_origin_js = same_origin(parser.script_srcs, base_netloc)[:MAX_JS_FILES]
    result["js_files"] = same_origin_js

    bodies = {}  # url -> text, for inline scripts key is "" 
    if parser.inline_scripts:
        bodies["(inline)"] = "\n".join(parser.inline_scripts)

    for js_url in same_origin_js:
        r = client.get(js_url, stream=True)
        if r is None:
            continue
        bodies[js_url] = r.raw.read(MAX_BYTES_PER_FILE, decode_content=True).decode("utf-8", errors="replace")

        # source map exposure: <file>.js.map reachable?
        if js_url.endswith(".js"):
            map_url = js_url + ".map"
            map_resp = client.head(map_url, error_label=f"source-map check for {map_url}")
            if map_resp is not None and map_resp.status_code == 200:
                result["exposed_source_maps"].append(map_url)

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
