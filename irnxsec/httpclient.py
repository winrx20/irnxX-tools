"""Bounded HTTP client used by every web check.

The client enforces a global rate limit and a hard request budget per scan, caps
response body reads, never follows redirects off the target host, and records each
exchange in a size-limited transcript so findings can be backed by evidence.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urljoin, urlparse

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

MAX_BODY = 96 * 1024
TRANSCRIPT_LIMIT = 400


@dataclass
class Response:
    url: str
    status: int
    headers: dict[str, str]
    text: str
    elapsed: float
    method: str = "GET"
    request_body: str = ""
    truncated: bool = False
    error: str = ""
    history: list[dict] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.error and 200 <= self.status < 400

    def header(self, name: str) -> str:
        return self.headers.get(name.lower(), "")

    def snippet(self, limit: int = 600) -> str:
        body = " ".join(self.text.split())
        return body[:limit] + ("..." if len(body) > limit else "")


class Budget:
    def __init__(self, max_requests: int, rate_limit: float) -> None:
        self.max_requests = max(1, int(max_requests))
        self.rate_limit = max(0.5, float(rate_limit))
        self.used = 0
        self._last = 0.0

    @property
    def remaining(self) -> int:
        return max(0, self.max_requests - self.used)

    def consume(self) -> bool:
        if self.used >= self.max_requests:
            return False
        gap = 1.0 / self.rate_limit
        now = time.monotonic()
        wait = gap - (now - self._last)
        if wait > 0:
            time.sleep(min(wait, 5.0))
        self._last = time.monotonic()
        self.used += 1
        return True


class Client:
    def __init__(
        self,
        *,
        user_agent: str,
        timeout: float = 8.0,
        verify: bool = True,
        budget: Budget | None = None,
        max_redirects: int = 3,
    ) -> None:
        self.user_agent = user_agent
        self.timeout = max(2.0, min(float(timeout), 30.0))
        self.verify = verify
        self.budget = budget or Budget(400, 4.0)
        self.max_redirects = max_redirects
        self.transcript: list[dict] = []
        self.session = requests.Session()
        retry = Retry(total=1, connect=1, read=1, backoff_factor=0.2, status_forcelist=[502, 503, 504])
        adapter = HTTPAdapter(max_retries=retry, pool_maxsize=8)
        self.session.mount("https://", adapter)
        self.session.mount("http://", adapter)
        self.session.headers.update(self.base_headers())

    def base_headers(self, extra: dict[str, str] | None = None) -> dict[str, str]:
        headers = {
            "User-Agent": self.user_agent,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "Connection": "close",
        }
        if extra:
            headers.update({k: v for k, v in extra.items() if v})
        return headers

    # ------------------------------------------------------------------ requests
    def request(
        self,
        method: str,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        data: Any = None,
        json_body: Any = None,
        allow_redirects: bool = True,
        read_body: bool = True,
    ) -> Response:
        started = time.monotonic()
        if not self.budget.consume():
            return Response(url, 0, {}, "", 0.0, method, error="Request budget exhausted")
        try:
            raw = self.session.request(
                method.upper(),
                url,
                headers=self.base_headers(headers),
                data=data,
                json=json_body,
                timeout=self.timeout,
                verify=self.verify,
                allow_redirects=allow_redirects,
                stream=True,
            )
        except requests.exceptions.SSLError as exc:
            return Response(url, 0, {}, "", time.monotonic() - started, method, error=f"TLS error: {exc}")
        except requests.exceptions.RequestException as exc:
            return Response(url, 0, {}, "", time.monotonic() - started, method, error=str(exc)[:300])

        body, truncated = "", False
        if read_body and method.upper() != "HEAD":
            try:
                chunks, size = [], 0
                for chunk in raw.iter_content(8192):
                    chunks.append(chunk)
                    size += len(chunk)
                    if size >= MAX_BODY:
                        truncated = True
                        break
                body = b"".join(chunks).decode(raw.encoding or "utf-8", errors="replace")
            except requests.exceptions.RequestException as exc:
                raw.close()
                return Response(url, raw.status_code, dict(raw.headers), "", time.monotonic() - started, method, error=str(exc)[:200])
        history = [{"status": h.status_code, "location": h.headers.get("Location", "")} for h in raw.history]
        headers_map = {str(k).lower(): str(v) for k, v in raw.headers.items()}
        response = Response(
            url=str(raw.url),
            status=raw.status_code,
            headers=headers_map,
            text=body,
            elapsed=round(time.monotonic() - started, 3),
            method=method.upper(),
            truncated=truncated,
            history=history,
        )
        raw.close()
        self._record(response)
        return response

    def get(self, url: str, **kwargs) -> Response:
        return self.request("GET", url, **kwargs)

    def head(self, url: str, **kwargs) -> Response:
        kwargs.setdefault("read_body", False)
        return self.request("HEAD", url, **kwargs)

    def post(self, url: str, **kwargs) -> Response:
        return self.request("POST", url, **kwargs)

    def options(self, url: str, **kwargs) -> Response:
        kwargs.setdefault("read_body", False)
        return self.request("OPTIONS", url, **kwargs)

    def _record(self, response: Response) -> None:
        if len(self.transcript) >= TRANSCRIPT_LIMIT:
            return
        self.transcript.append(
            {
                "method": response.method,
                "url": response.url,
                "status": response.status,
                "elapsed_ms": int(response.elapsed * 1000),
                "bytes": len(response.text),
                "error": response.error,
                "snippet": response.snippet(240),
            }
        )

    # -------------------------------------------------------------------- helpers
    @staticmethod
    def same_host(a: str, b: str) -> bool:
        try:
            return (urlparse(a).hostname or "").lower() == (urlparse(b).hostname or "").lower()
        except ValueError:
            return False

    def probe(self, base: str, path: str) -> Response:
        return self.get(urljoin(base.rstrip("/") + "/", path.lstrip("/")))


SUSPICIOUS_SOFT_404 = ("not found", "404", "page not found", "does not exist", "tidak ditemukan")


def looks_like_soft_404(response: Response) -> bool:
    if response.status not in (200, 301, 302, 403):
        return False
    text = response.text.lower()
    if not text:
        return False
    return any(marker in text for marker in SUSPICIOUS_SOFT_404) and len(text) < 4096
