"""Web assessment engine: transport/header/TLS posture, exposure and validation canaries.

Design rules enforced here:
* every request goes through the budgeted, rate-limited client;
* checks are non-destructive (GET/POST/OPTIONS only, no auth attacks, no brute force);
* findings distinguish what was observed (evidence) from what is inferred (confidence);
* a soft-404 baseline prevents reporting generic catch-all pages as exposure.
"""
from __future__ import annotations

import re
from urllib.parse import urljoin, urlparse

from .. import config, crawl, payloads
from ..httpclient import Budget, Client, looks_like_soft_404
from ..models import Finding, ScanRequest, ScanResult

TLS_WEAK = ("TLSv1", "TLSv1.1", "SSLv2", "SSLv3")
SERVER_DISCLOSURE_RE = re.compile(r"([A-Za-z][\w.-]*)[ /]?(\d+\.\d+(?:\.\d+)?)")
META_GENERATOR_RE = re.compile(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)', re.I)


class WebScan:
    def __init__(self, request: ScanRequest, result: ScanResult) -> None:
        self.request = request
        self.result = result
        self.settings = config.load()
        prof = config.profile(request.profile)
        self.max_paths = int(request.options.get("max_paths", prof["max_paths"]))
        self.max_forms = int(request.options.get("forms", prof["forms"]))
        self.max_params = int(request.options.get("params", prof["params"]))
        budget = Budget(
            request.max_requests or int(220 + self.max_paths * 6),
            request.rate_limit or self.settings.rate_limit,
        )
        self.client = Client(
            user_agent=self.settings.user_agent(),
            timeout=request.timeout or self.settings.timeout,
            verify=(self.settings.verify_tls if request.verify_tls is None else bool(request.verify_tls)),
            budget=budget,
        )
        self.base = request.target
        self.token = payloads.new_token()
        self.root = None

    # ------------------------------------------------------------------- driver
    def run(self) -> ScanResult:
        self.result.observe("engine", "profile", self.request.profile, f"max_paths={self.max_paths}")
        self.result.observe("engine", "canary_token", self.token, "scan-unique reflection marker")
        self._transport()
        self._headers_and_cookies()
        self._methods()
        crawled = None
        if self.root is not None and not self.root.error:
            try:
                crawled = crawl.crawl(self.client, self.base, max_pages=max(3, min(self.max_paths, 14)))
                self.result.observe("crawl", "pages_discovered", crawled.to_dict())
            except Exception as exc:  # crawler must never break a scan
                self.result.error(f"crawl: {exc}")
        self._exposure()
        self._disclosure()
        self._dns_context()
        if crawled is not None:
            self._reflection_canaries(crawled)
        else:
            self.result.error("Input-validation canaries skipped: entry page was unreachable.")
        self.result.metadata["requests_made"] = self.client.budget.used
        self.result.metadata["request_budget"] = self.client.budget.max_requests
        self.result.metadata["transcript"] = self.client.transcript[:120]
        return self.result.finish()

    # ---------------------------------------------------------------- transport
    def _transport(self) -> None:
        self.root = self.client.get(self.base.rstrip("/") + "/")
        if self.root.error:
            self.result.error(f"Entry request failed: {self.root.error}")
            self._try_http_fallback()
            return
        parsed = urlparse(self.root.url)
        self.result.observe(
            "http",
            "entry_response",
            {
                "requested": self.base,
                "final_url": self.root.url,
                "status": self.root.status,
                "elapsed_ms": int(self.root.elapsed * 1000),
                "bytes": len(self.root.text),
                "redirects": self.root.history,
            },
        )
        if self.base.startswith("https://") and parsed.scheme == "http":
            self.result.add(
                Finding(
                    title="HTTPS request downgraded to plaintext HTTP",
                    severity="high",
                    category="Transport",
                    detail=(
                        "The requested HTTPS origin answered over HTTP after a redirect, so the first "
                        "hop was unauthenticated and could be intercepted or modified in transit."
                    ),
                    evidence=f"GET {self.base}/ -> {self.root.status} {self.root.url}",
                    remediation="Serve the site only over HTTPS and issue a permanent 301 redirect from HTTP to HTTPS at the edge.",
                    confidence="confirmed",
                    location=self.base,
                    cwe="CWE-319",
                    cvss=7.4,
                )
            )
        if self.base.startswith("http://"):
            self.result.add(
                Finding(
                    title="Origin served over unencrypted HTTP",
                    severity="medium",
                    category="Transport",
                    detail="The target scheme is http://, so credentials and session cookies travel in cleartext.",
                    evidence=f"GET {self.base}/ -> HTTP {self.root.status}",
                    remediation="Enable HTTPS (HSTS with max-age >= 15552000) and redirect HTTP to HTTPS.",
                    confidence="confirmed",
                    location=self.base,
                    cwe="CWE-319",
                    cvss=5.9,
                )
            )
        if self.root.status >= 500:
            self.result.add(
                Finding(
                    title="Server error on the root document",
                    severity="low",
                    category="Availability",
                    detail=f"The entry page returned HTTP {self.root.status}, which usually indicates an unstable deployment.",
                    evidence=f"GET {self.root.url} -> {self.root.status}",
                    remediation="Investigate application logs for the root route; do not expose stack traces to clients.",
                    confidence="confirmed",
                    location=self.root.url,
                )
            )
        self._tls_posture()

    def _try_http_fallback(self) -> None:
        if not self.base.startswith("https://"):
            return
        alt = "http://" + self.base[len("https://"):]
        response = self.client.get(alt.rstrip("/") + "/")
        if response.error:
            self.result.error(f"HTTP fallback also failed: {response.error}")
            return
        self.result.observe("http", "http_fallback", {"url": response.url, "status": response.status})
        self.result.add(
            Finding(
                title="HTTPS unavailable but HTTP is served",
                severity="medium",
                category="Transport",
                detail=("The HTTPS endpoint could not be reached while plaintext HTTP answered, so any client "
                        "falling back to HTTP transmits data unencrypted."),
                evidence=f"HTTPS failed, GET {alt}/ -> HTTP {response.status}",
                remediation="Restore a valid TLS certificate on 443 and redirect HTTP to HTTPS.",
                confidence="confirmed",
                location=alt,
                cwe="CWE-319",
                cvss=5.9,
            )
        )
        self.root = response

    def _tls_posture(self) -> None:
        parsed = urlparse(self.base)
        if parsed.scheme != "https":
            return
        import socket
        import ssl

        host = parsed.hostname or ""
        port = parsed.port or 443
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((host, port), timeout=self.settings.connect_timeout * 5) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as tls:
                    cert = tls.getpeercert() or {}
                    version = tls.version()
                    cipher = tls.cipher()
                    self.result.observe(
                        "tls",
                        "handshake",
                        {
                            "version": version,
                            "cipher": cipher[0] if cipher else "",
                            "subject": dict(x[0] for x in cert.get("subject", [])),
                            "issuer": dict(x[0] for x in cert.get("issuer", [])),
                            "not_after": cert.get("notAfter", ""),
                            "san": [v for k, v in cert.get("subjectAltName", []) if k == "DNS"][:25],
                        },
                    )
                    if version in TLS_WEAK:
                        self.result.add(
                            Finding(
                                title=f"Deprecated TLS version negotiated ({version})",
                                severity="medium",
                                category="Transport",
                                detail=f"The TLS handshake completed with {version}, which is deprecated and no longer considered secure.",
                                evidence=f"TLS handshake to {host}:{port} negotiated {version} {cipher[0] if cipher else ''}",
                                remediation="Disable TLS 1.0/1.1 and SSLv3; require TLS 1.2+ with AEAD cipher suites.",
                                confidence="confirmed",
                                location=f"{host}:{port}",
                                cwe="CWE-327",
                                cvss=5.3,
                            )
                        )
        except ssl.SSLCertVerificationError as exc:
            self.result.add(
                Finding(
                    title="Invalid or untrusted TLS certificate",
                    severity="medium",
                    category="Transport",
                    detail="Standard certificate validation failed, so browsers show an interstitial and clients may be trained to click through warnings.",
                    evidence=f"TLS validation error for {host}:{port}: {exc}",
                    remediation="Install a certificate from a trusted CA matching the hostname and keep the chain complete.",
                    confidence="confirmed",
                    location=f"{host}:{port}",
                    cwe="CWE-295",
                    cvss=5.9,
                )
            )
        except Exception as exc:
            self.result.observe("tls", "handshake_error", str(exc))

    # ------------------------------------------------------- headers and cookies
    def _headers_and_cookies(self) -> None:
        if self.root is None or self.root.error:
            return
        headers = self.root.headers
        present = {k: headers.get(k, "") for k in payloads.SECURITY_HEADERS if headers.get(k)}
        self.result.observe("headers", "security_headers_present", present)
        csp = headers.get("content-security-policy", "")
        for key, meta in payloads.SECURITY_HEADERS.items():
            if key == "x-frame-options" and ("frame-ancestors" in csp):
                continue
            if headers.get(key):
                continue
            self.result.add(
                Finding(
                    title=f"Missing {meta['label']} header",
                    severity=meta["severity"],
                    category="Hardening: headers",
                    detail=(
                        f"The response for the entry document did not include the {key} header. "
                        "This is a defence-in-depth control; impact depends on what the application renders."
                    ),
                    evidence=f"GET {self.root.url} -> {self.root.status}; response headers: "
                             + ", ".join(sorted(headers)[:40]),
                    remediation=meta["remediation"],
                    confidence="confirmed",
                    location=self.root.url,
                    cwe=meta["cwe"],
                    cvss=meta["cvss"],
                    references=list(meta["refs"]),
                )
            )
        if csp and ("unsafe-inline" in csp or "unsafe-eval" in csp):
            self.result.add(
                Finding(
                    title="Content-Security-Policy allows unsafe-inline/unsafe-eval",
                    severity="low",
                    category="Hardening: headers",
                    detail="The CSP is present but relaxes script restrictions with unsafe-inline or unsafe-eval, which weakens its XSS mitigation value.",
                    evidence=f"Content-Security-Policy: {csp[:400]}",
                    remediation="Move inline script into files or use nonces/hashes and remove unsafe-eval.",
                    confidence="confirmed",
                    location=self.root.url,
                    cwe="CWE-693",
                    cvss=3.7,
                )
            )
        server = headers.get("server", "")
        powered = headers.get("x-powered-by", "")
        banner = " / ".join(x for x in (server, powered) if x)
        self.result.observe("headers", "banner", banner)
        if banner and SERVER_DISCLOSURE_RE.search(banner):
            self.result.add(
                Finding(
                    title="Server banner discloses product and version",
                    severity="info",
                    category="Hardening: disclosure",
                    detail="Version banners lower the cost of matching the deployment to known CVEs.",
                    evidence=f"Server: {server or '-'}; X-Powered-By: {powered or '-'}",
                    remediation="Suppress Server/X-Powered-By version tokens at the web server or proxy.",
                    confidence="confirmed",
                    location=self.root.url,
                    cwe="CWE-200",
                )
            )
        self._cookies()

    def _cookies(self) -> None:
        if self.root is None or self.root.error:
            return
        raw = self.root.headers.get("set-cookie", "")
        if not raw:
            return
        lowered = raw.lower()
        missing = [flag for flag in ("secure", "httponly", "samesite") if flag not in lowered]
        self.result.observe("cookies", "set_cookie_attributes", {"raw": raw[:300], "missing": missing})
        if self.base.startswith("https://") and missing:
            self.result.add(
                Finding(
                    title="Session cookie missing security attributes",
                    severity="medium" if "secure" in missing else "low",
                    category="Session",
                    detail=("A Set-Cookie header on the entry response omits: " + ", ".join(missing)
                            + ". Without Secure/HttpOnly/SameSite a stolen cookie can be replayed over HTTP or read by script."),
                    evidence=f"Set-Cookie: {raw[:300]}",
                    remediation="Set Secure, HttpOnly and SameSite=Lax (or Strict) on all session cookies.",
                    confidence="firm",
                    location=self.root.url,
                    cwe="CWE-614",
                    cvss=4.3,
                )
            )

    # ---------------------------------------------------------------- HTTP verbs
    def _methods(self) -> None:
        if self.root is None or self.root.error:
            return
        allow = self.root.headers.get("allow", "")
        response = self.client.options(self.root.url)
        advertised = sorted({m.strip().upper() for m in (allow or response.headers.get("allow", "")).split(",") if m.strip()})
        self.result.observe("http", "methods_advertised", advertised)
        risky = [m for m in advertised if m in payloads.DANGEROUS_METHODS]
        if risky:
            self.result.add(
                Finding(
                    title=f"Sensitive HTTP methods advertised: {', '.join(risky)}",
                    severity="low" if "TRACE" in risky else "info",
                    category="Configuration",
                    detail=("The origin advertises state-changing or diagnostic methods on the root resource. "
                            "Confirm each is required and authenticated; this scan did not invoke them."),
                    evidence=f"Allow: {', '.join(advertised) or '-'}",
                    remediation="Restrict allowed methods per route and disable TRACE/TRACK at the edge.",
                    confidence="firm",
                    location=self.root.url,
                    cwe="CWE-650",
                )
            )
        if "TRACE" in advertised:
            trace = self.client.request("TRACE", self.root.url, read_body=True)
            if trace.status == 200 and not trace.error:
                self.result.add(
                    Finding(
                        title="HTTP TRACE enabled (Cross-Site Tracing precondition)",
                        severity="low",
                        category="Configuration",
                        detail="TRACE returned 200; combined with other weaknesses it can enable cookie theft via XST.",
                        evidence=f"TRACE {self.root.url} -> 200, {len(trace.text)} bytes",
                        remediation="Disable TRACE/TRACK on the web server.",
                        confidence="confirmed",
                        location=self.root.url,
                        cwe="CWE-693",
                        cvss=3.1,
                    )
                )

    # ------------------------------------------------------------------ exposure
    def _exposure(self) -> None:
        baseline_path = f"/irnx-baseline-{payloads.new_token(10)}.txt"
        baseline = self.client.probe(self.base, baseline_path)
        soft_404 = looks_like_soft_404(baseline) or baseline.status in (200, 301, 302) and len(baseline.text) > 0
        self.result.observe("exposure", "soft_404_baseline", {"status": baseline.status, "bytes": len(baseline.text), "soft_404": soft_404})
        base_len = len(baseline.text)
        for entry in payloads.SENSITIVE_PATHS[: self.max_paths]:
            if self.client.budget.remaining <= 1:
                self.result.error("Exposure checks truncated: request budget exhausted.")
                break
            response = self.client.probe(self.base, entry["path"])
            if response.error or response.status not in (200, 401, 403):
                continue
            body = response.text or ""
            signature = entry.get("signature", "")
            signature_hit = bool(signature) and signature.lower() in body.lower()
            if response.status == 200:
                if soft_404 and not signature_hit:
                    self.result.observe("exposure", f"suppressed {entry['path']}", {"status": 200, "reason": "catch-all page"})
                    continue
                if base_len and abs(len(body) - base_len) < 24 and not signature_hit:
                    continue
            if not signature_hit and response.status == 200 and not body.strip():
                continue
            severity = entry["severity"] if (signature_hit or response.status in (401, 403)) else "low"
            confidence = "confirmed" if signature_hit else "firm"
            self.result.add(
                Finding(
                    title=f"Sensitive path reachable: {entry['path']}",
                    severity=severity,
                    category="Exposure",
                    detail=(
                        f"{entry['path']} returned HTTP {response.status}."
                        + (" A content signature matched, so the resource appears to be the real artefact." if signature_hit
                           else " No content signature matched; confirm manually before reporting to the asset owner.")
                    ),
                    evidence=(
                        f"GET {response.url} -> {response.status}, {len(body)} bytes\n"
                        f"signature '{signature}' matched: {signature_hit}\n"
                        f"Body excerpt: {response.snippet(400)}"
                    ),
                    remediation=(
                        "Remove the file from the document root, block the path at the edge, and rotate any "
                        "credentials it contained." if severity in ("critical", "high") else
                        "Restrict access to this resource or remove it if it is not required in production."
                    ),
                    confidence=confidence,
                    location=response.url,
                    cwe=entry.get("cwe", ""),
                    cvss=float(entry.get("cvss", 0) or 0),
                )
            )

    def _disclosure(self) -> None:
        robots = self.client.probe(self.base, "/robots.txt")
        if robots.status == 200 and "disallow" in robots.text.lower():
            entries = [line.strip() for line in robots.text.splitlines() if line.strip().lower().startswith("disallow")]
            self.result.observe("disclosure", "robots_disallow", entries[:40])
            interesting = [e for e in entries if not e.lower().startswith("disallow: /") and e.split(":", 1)[-1].strip() not in ("", "/")]
            if interesting:
                self.result.add(
                    Finding(
                        title="robots.txt lists restricted paths",
                        severity="info",
                        category="Disclosure",
                        detail="robots.txt names paths the operator would rather not be crawled; it is not an access control and reveals interesting locations.",
                        evidence="\n".join(interesting[:25]),
                        remediation="Do not rely on robots.txt for access control; enforce authorization server-side.",
                        confidence="confirmed",
                        location=urljoin(self.base + "/", "robots.txt"),
                        cwe="CWE-200",
                    )
                )

    def _dns_context(self) -> None:
        parsed = urlparse(self.base)
        host = parsed.hostname or ""
        try:
            import dns.resolver

            resolver = dns.resolver.Resolver()
            resolver.lifetime = 4
            addresses = sorted({r.address for r in resolver.resolve(host, "A")}) if host else []
            self.result.observe("dns", "a_records", addresses)
            try:
                txt = [b"".join(r.strings).decode("utf-8", "replace") for r in resolver.resolve(host, "TXT")]
                self.result.observe("dns", "txt_records", txt[:10])
                joined = " ".join(txt).lower()
                for record, label in (("v=spf1", "SPF"), ("v=dmarc1", "DMARC"), ("v=dkim1", "DKIM")):
                    if record in joined:
                        self.result.observe("dns", f"{label}_present", True)
            except Exception:
                pass
        except Exception as exc:
            self.result.observe("dns", "resolution_error", str(exc)[:200])

    # ---------------------------------------------------------- input validation
    def _reflection_canaries(self, crawled: crawl.CrawlResult) -> None:
        token = self.token
        targets: list[tuple[str, str, str]] = []  # (label, url, parameter)
        for url in crawled.param_urls[: self.max_params]:
            for name, _value in crawl.params_of(url)[:3]:
                targets.append(("query", url, name))
        for form in [f for f in crawled.forms if f.is_safe() and f.text_inputs][: self.max_forms]:
            for field in form.text_inputs[:2]:
                targets.append(("form", form.action, field["name"]))
        self.result.observe("canary", "injection_points", [{"kind": k, "url": u, "param": p} for k, u, p in targets])
        if not targets:
            self.result.observe("canary", "note", "No parameterised links or safe forms were discovered; input-validation checks were not applicable.")
            return
        tested = 0
        for kind, url, param in targets:
            if self.client.budget.remaining <= 2:
                self.result.error("Canary phase truncated: request budget exhausted.")
                break
            tested += 1
            if kind == "query":
                self._canary_query(url, param)
            else:
                self._canary_form(url, param)
        self.result.observe("canary", "points_tested", tested)

    def _canary_query(self, url: str, param: str) -> None:
        token = self.token
        baseline = self.client.get(url)
        mark = payloads.CANARIES[0].render(token)
        probe = self.client.get(crawl.with_param(url, param, mark))
        if probe.error:
            self.result.error(f"canary {url} [{param}]: {probe.error}")
            return
        if mark in probe.text:
            self.result.add(
                Finding(
                    title=f"Input reflected without encoding in parameter '{param}'",
                    severity="low",
                    category="Input handling",
                    detail=(
                        "A scan-unique marker submitted in a query parameter was returned verbatim. "
                        "Reflection alone is not cross-site scripting; it confirms the parameter is echoed "
                        "and is worth manual context review."
                    ),
                    evidence=f"GET {probe.url} -> {probe.status}\nmarker '{mark}' present in response body",
                    remediation="Encode output for the sink context (HTML, attribute, JS, URL) and apply a restrictive CSP.",
                    confidence="firm",
                    location=probe.url,
                    cwe="CWE-79",
                    cvss=3.7,
                    meta={"parameter": param, "baseline_status": baseline.status},
                )
            )
        self._sql_canary(probe, baseline, param, crawl.with_param(url, param, payloads.CANARIES[3].render(token)))
        self._redirect_canary(url, param)

    def _canary_form(self, action: str, param: str) -> None:
        token = self.token
        mark = payloads.CANARIES[0].render(token)
        data = {param: mark}
        response = self.client.request("POST", action, data=data)
        if response.error:
            response = self.client.get(action)
            if response.error:
                self.result.error(f"form canary {action} [{param}]: {response.error}")
                return
        if mark in response.text:
            self.result.add(
                Finding(
                    title=f"Form field '{param}' echoed back unencoded",
                    severity="low",
                    category="Input handling",
                    detail="A unique marker submitted to a safe test form was rendered back verbatim; review the output context manually.",
                    evidence=f"POST {action} field={param} value={mark} -> {response.status}; marker present in body",
                    remediation="Apply context-aware output encoding and a restrictive CSP.",
                    confidence="firm",
                    location=action,
                    cwe="CWE-79",
                    cvss=3.7,
                    meta={"parameter": param},
                )
            )
        self._sql_canary(response, None, param, None, form=(action, payloads.CANARIES[3].render(token)))

    def _sql_canary(self, probe, baseline, param: str, alt_url: str, form: tuple[str, str] | None = None) -> None:
        if alt_url:
            probe = self.client.get(alt_url)
        elif form:
            action, value = form
            probe = self.client.request("POST", action, data={param: value})
        if probe.error:
            return
        lowered = probe.text.lower()
        hits = [sig for sig in payloads.SQL_ERROR_SIGNATURES if sig in lowered]
        baseline_hits = [sig for sig in payloads.SQL_ERROR_SIGNATURES if baseline is not None and sig in baseline.text.lower()]
        new_hits = [h for h in hits if h not in baseline_hits]
        if new_hits:
            self.result.add(
                Finding(
                    title=f"Database error disclosed for parameter '{param}'",
                    severity="medium",
                    category="Input handling",
                    detail=(
                        "A single-quote canary produced a database error signature that was absent from the baseline "
                        "response. This indicates unsanitised SQL construction but does not prove data extraction."
                    ),
                    evidence=f"Response {probe.status} contained: {', '.join(new_hits)}\nSnippet: {probe.snippet(400)}",
                    remediation="Use parameterised queries, disable detailed error output in production, and validate input types.",
                    confidence="firm",
                    location=probe.url or (form[0] if form else ""),
                    cwe="CWE-89",
                    cvss=6.5,
                    meta={"parameter": param, "signatures": new_hits},
                )
            )

    def _redirect_canary(self, url: str, param: str) -> None:
        canary = payloads.CANARIES[8].render(self.token)
        probe_url = crawl.with_param(url, param, canary)
        response = self.client.get(probe_url, allow_redirects=False)
        if response.error or response.status not in (301, 302, 303, 307, 308):
            return
        location = response.header("location")
        if "irnx-canary.invalid" in location:
            self.result.add(
                Finding(
                    title=f"Open redirect via parameter '{param}'",
                    severity="medium",
                    category="Input handling",
                    detail=("The parameter controls the Location header and accepts an arbitrary external host, "
                            "which enables credible phishing links on the trusted domain."),
                    evidence=f"GET {probe_url} -> {response.status}, Location: {location}",
                    remediation="Validate redirect targets against an allow-list of internal paths.",
                    confidence="confirmed",
                    location=probe_url,
                    cwe="CWE-601",
                    cvss=4.3,
                    meta={"parameter": param},
                )
            )


def run(request: ScanRequest, result: ScanResult) -> ScanResult:
    return WebScan(request, result).run()
