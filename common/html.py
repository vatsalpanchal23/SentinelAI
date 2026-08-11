"""HTML parsing helpers shared by the scanner modules."""

from html.parser import HTMLParser
from urllib.parse import urljoin, urlparse


class BaseTagParser(HTMLParser):
    """HTMLParser that resolves relative URLs against the page it came from."""

    def __init__(self, base_url: str):
        super().__init__()
        self.base_url = base_url

    def resolve(self, url: str) -> str:
        return urljoin(self.base_url, url)


class LinkParser(BaseTagParser):
    """Collects absolute hrefs from <a> tags."""

    def __init__(self, base_url: str):
        super().__init__(base_url)
        self.links = set()

    def handle_starttag(self, tag, attrs):
        attrs_dict = dict(attrs)
        if tag == "a" and attrs_dict.get("href"):
            self.links.add(self.resolve(attrs_dict["href"]))


def feed_html(parser: HTMLParser, text: str | None, errors: list | None = None, label: str = "HTML parse error") -> bool:
    """Feed `text` to `parser`, recording (never raising) a parse failure."""
    try:
        parser.feed(text or "")
    except Exception as exc:  # noqa: BLE001 - malformed HTML must not fail a module
        if errors is not None:
            errors.append(f"{label}: {exc}")
        return False
    return True


def same_origin(urls, base_netloc: str) -> list:
    """Subset of `urls` on `base_netloc`, in input order (relative URLs count as
    same-origin)."""
    return [u for u in urls if urlparse(u).netloc in ("", base_netloc)]
