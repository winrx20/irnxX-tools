"""Lightweight, same-origin crawler: links, forms and query parameters.

No JavaScript execution, no unbounded expansion: the crawler respects a page cap,
stays on the registered host, and only keeps parameterised URLs it can safely
replay.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from html.parser import HTMLParser
from urllib.parse import parse_qsl, urlencode, urljoin, urlparse, urlsplit, urlunsplit

SKIP_EXTENSIONS = (
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp", ".woff", ".woff2",
    ".ttf", ".eot", ".mp4", ".mp3", ".avi", ".pdf", ".zip", ".gz", ".tar", ".css",
    ".js", ".map", ".exe", ".dmg", ".apk",
)

STATE_CHANGING_WORDS = (
    "delete", "remove", "destroy", "drop", "logout", "signout", "unsubscribe",
    "cancel", "refund", "transfer", "pay", "purchase", "checkout", "reset",
    "revoke", "disable", "deactivate", "suspend", "terminate", "shutdown",
    "approve", "confirm", "submit", "upload", "send-mail", "broadcast",
)


@dataclass
class Form:
    action: str
    method: str
    inputs: list[dict] = field(default_factory=list)
    source: str = ""

    @property
    def text_inputs(self) -> list[dict]:
        return [i for i in self.inputs if (i.get("type") or "text").lower() in (
            "text", "search", "email", "url", "tel", "number", "textarea", "password", ""
        )]

    @property
    def submit_inputs(self) -> list[dict]:
        return [i for i in self.inputs if (i.get("type") or "").lower() in ("submit", "button", "image")]

    def is_safe(self) -> bool:
        """Only simple GET/POST forms without destructive-looking field names."""
        if self.method.lower() not in ("get", "post"):
            return False
        blob = (self.action + " " + " ".join(i.get("name", "") for i in self.inputs)).lower()
        return not any(word in blob for word in STATE_CHANGING_WORDS)


class _Parser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: list[str] = []
        self.forms: list[Form] = []
        self.scripts: list[str] = []
        self._current: Form | None = None
        self._in_form = False

    def handle_starttag(self, tag: str, attrs) -> None:
        attr = {k.lower(): (v or "") for k, v in attrs}
        if tag in ("a", "link") and attr.get("href"):
            self.links.append(attr["href"].strip())
        elif tag in ("area",) and attr.get("href"):
            self.links.append(attr["href"].strip())
        elif tag == "script" and attr.get("src"):
            self.scripts.append(attr["src"].strip())
        elif tag == "form":
            self._in_form = True
            self._current = Form(action=attr.get("action", "").strip() or "", method=(attr.get("method") or "GET"))
        elif tag in ("input", "select", "textarea", "button") and self._in_form and self._current is not None:
            name = attr.get("name", "").strip()
            if not name:
                return
            self._current.inputs.append(
                {
                    "name": name,
                    "type": tag if tag != "input" else (attr.get("type") or "text").lower(),
                    "value": attr.get("value", ""),
                }
            )

    def handle_startendtag(self, tag: str, attrs) -> None:
        self.handle_starttag(tag, attrs)

    def handle_endtag(self, tag: str) -> None:
        if tag == "form" and self._current is not None:
            self.forms.append(self._current)
            self._current = None
            self._in_form = False

    def close(self) -> None:  # flush an unterminated form
        super().close()
        if self._current is not None:
            self.forms.append(self._current)
            self._current = None


@dataclass
class CrawlResult:
    base: str
    pages: list[dict] = field(default_factory=list)
    urls: list[str] = field(default_factory=list)
    forms: list[Form] = field(default_factory=list)
    param_urls: list[str] = field(default_factory=list)
    scripts: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "base": self.base,
            "page_count": len(self.pages),
            "pages": self.pages[:40],
            "url_count": len(self.urls),
            "forms": [
                {"action": f.action, "method": f.method, "inputs": [i["name"] for i in f.inputs], "source": f.source}
                for f in self.forms[:40]
            ],
            "param_urls": self.param_urls[:40],
            "scripts": self.scripts[:40],
        }


def _same_origin(url: str, base: str) -> bool:
    try:
        a, b = urlparse(url), urlparse(base)
    except ValueError:
        return False
    if a.scheme not in ("http", "https"):
        return False
    return a.hostname == b.hostname and (a.port or (443 if a.scheme == "https" else 80)) == (
        b.port or (443 if b.scheme == "https" else 80)
    )


def _clean(url: str) -> str:
    parts = urlsplit(url)
    return urlunsplit((parts.scheme, parts.netloc, parts.path or "/", parts.query, ""))


def _skip(url: str) -> bool:
    path = urlparse(url).path.lower()
    return path.endswith(SKIP_EXTENSIONS)


def crawl(client, base: str, max_pages: int = 12) -> CrawlResult:
    """Fetch the entry page and up to ``max_pages - 1`` same-origin links."""
    result = CrawlResult(base=base)
    queue: list[str] = [base.rstrip("/") + "/"]
    seen: set[str] = set()
    while queue and len(result.pages) < max_pages:
        url = queue.pop(0)
        if url in seen or len(seen) > max_pages * 6:
            continue
        seen.add(url)
        response = client.get(url)
        if response.error:
            result.errors.append(f"{url}: {response.error}")
            if len(result.pages) == 0:
                continue
            continue
        parser = _Parser()
        try:
            parser.feed(response.text)
            parser.close()
        except Exception as exc:  # malformed HTML must not abort a scan
            result.errors.append(f"{url}: parse error {exc}")
        result.pages.append(
            {
                "url": response.url,
                "status": response.status,
                "title": _title(response.text),
                "content_type": response.header("content-type"),
                "bytes": len(response.text),
                "server": response.header("server"),
            }
        )
        for href in parser.links:
            absolute = _resolve(href, response.url)
            if not absolute or not _same_origin(absolute, base) or _skip(absolute):
                continue
            absolute = _clean(absolute)
            if urlparse(absolute).query:
                if absolute not in result.param_urls:
                    result.param_urls.append(absolute)
                continue
            if absolute not in seen and absolute not in queue:
                queue.append(absolute)
                if absolute not in result.urls:
                    result.urls.append(absolute)
        for form in parser.forms:
            form.source = response.url
            form.action = _resolve(form.action or response.url, response.url) or response.url
            if _same_origin(form.action, base):
                result.forms.append(form)
        for src in parser.scripts:
            absolute = _resolve(src, response.url)
            if absolute and _same_origin(absolute, base) and absolute not in result.scripts:
                result.scripts.append(absolute)
    return result


def _resolve(href: str, page: str) -> str:
    href = (href or "").strip()
    if not href or href.startswith(("javascript:", "mailto:", "tel:", "data:", "#")):
        return ""
    try:
        return urljoin(page, href)
    except ValueError:
        return ""


def _title(body: str) -> str:
    lowered = body.lower()
    start = lowered.find("<title")
    if start == -1:
        return ""
    start = lowered.find(">", start)
    end = lowered.find("</title", start)
    if start == -1 or end == -1:
        return ""
    return " ".join(body[start + 1: end].split())[:120]


def with_param(url: str, name: str, value: str) -> str:
    parts = urlsplit(url)
    query = [(k, v) for k, v in parse_qsl(parts.query, keep_blank_values=True) if k != name]
    query.append((name, value))
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(query), ""))


def params_of(url: str) -> list[tuple[str, str]]:
    return parse_qsl(urlparse(url).query, keep_blank_values=True)
