"""DNS engine: record inventory, mail authentication posture, delegation and subdomain sweep.

All queries are read-only lookups. The subdomain sweep uses a small internal wordlist
and a hard query budget; zone transfer is attempted only in the deep profile and only
as a read request to the authoritative nameservers.
"""
from __future__ import annotations

import re
from concurrent.futures import ThreadPoolExecutor, as_completed

from .. import config
from ..models import Finding, ScanRequest, ScanResult

COMMON_SUBDOMAINS = (
    "www", "mail", "webmail", "smtp", "pop", "imap", "mx", "ns1", "ns2", "dns", "api",
    "app", "apps", "admin", "portal", "vpn", "remote", "gateway", "gw", "proxy", "cdn",
    "static", "assets", "img", "images", "media", "files", "download", "upload", "dev",
    "test", "staging", "stage", "uat", "qa", "demo", "sandbox", "beta", "alpha", "pre",
    "prod", "internal", "intranet", "corp", "office", "support", "help", "docs", "wiki",
    "blog", "shop", "store", "pay", "payment", "billing", "invoice", "crm", "erp", "hr",
    "git", "gitlab", "jenkins", "ci", "build", "deploy", "registry", "docker", "k8s",
    "grafana", "kibana", "prometheus", "monitor", "status", "metrics", "logs", "db",
    "mysql", "postgres", "redis", "mongo", "backup", "old", "legacy", "archive",
    "autodiscover", "autoconfig", "lyncdiscover", "sip", "meet", "chat", "sso", "auth",
    "id", "login", "accounts", "oauth", "api-dev", "api-test", "api-staging", "m",
    "mobile", "wap", "news", "forum", "community", "careers", "jobs", "partner",
)

TAKEOVER_FINGERPRINTS = (
    ("github.io", "github pages"),
    ("herokuapp.com", "heroku"),
    ("cloudfront.net", "cloudfront"),
    ("azurewebsites.net", "azure app service"),
    ("trafficmanager.net", "azure traffic manager"),
    ("s3.amazonaws.com", "aws s3"),
    ("elasticbeanstalk.com", "aws elastic beanstalk"),
    ("netlify.app", "netlify"),
    ("vercel.app", "vercel"),
    ("pages.dev", "cloudflare pages"),
    ("wordpress.com", "wordpress"),
    ("myshopify.com", "shopify"),
    ("surge.sh", "surge"),
    ("readthedocs.io", "readthedocs"),
    ("ghost.io", "ghost"),
    ("zendesk.com", "zendesk"),
    ("statuspage.io", "statuspage"),
    ("fastly.net", "fastly"),
    ("pantheonsite.io", "pantheon"),
)


class DnsScan:
    def __init__(self, request: ScanRequest, result: ScanResult) -> None:
        self.request = request
        self.result = result
        self.settings = config.load()
        prof = config.profile(request.profile)
        self.wordlist_limit = int(request.options.get("subdomains", prof["subdomains"]))
        self.timeout = float(request.timeout or 4.0)
        self.domain = request.target.lower().rstrip(".")
        self._resolver = None
        self.records: dict[str, list[str]] = {}

    def resolver(self):
        import dns.resolver

        if self._resolver is None:
            resolver = dns.resolver.Resolver()
            resolver.timeout = min(self.timeout, 5.0)
            resolver.lifetime = min(self.timeout * 1.5, 8.0)
            self._resolver = resolver
        return self._resolver

    # -------------------------------------------------------------------- driver
    def run(self) -> ScanResult:
        if not re.match(r"^[a-z0-9._-]+$", self.domain):
            self.result.error("Target is not a valid DNS name.")
            return self.result.finish()
        self.result.observe("engine", "domain", self.domain)
        inventory = self._inventory()
        if not inventory:
            self.result.add(
                Finding(
                    title="Domain does not resolve",
                    severity="info",
                    category="DNS",
                    detail="No A/AAAA/NS records were returned; the name may be unregistered, parked or internal-only.",
                    evidence=f"DNS lookups for {self.domain} returned no usable records",
                    confidence="confirmed",
                    location=self.domain,
                )
            )
            return self.result.finish()
        self._mail_posture()
        self._caa_and_dnssec()
        self._wildcard()
        self._takeover_hints()
        self._subdomain_sweep()
        if self.request.profile == "deep":
            self._zone_transfer()
        return self.result.finish()

    # ------------------------------------------------------------------ inventory
    def _inventory(self) -> dict[str, list[str]]:
        for rtype in ("A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA", "CAA"):
            values = self._query(self.domain, rtype)
            if values:
                self.records[rtype] = values
        self.result.observe("dns", "records", {k: v[:12] for k, v in self.records.items()})
        return self.records

    def _query(self, name: str, rtype: str) -> list[str]:
        try:
            answers = self.resolver().resolve(name, rtype, raise_on_no_answer=False)
        except Exception:
            return []
        out: list[str] = []
        if answers.rrset is None:
            return out
        for answer in answers:
            text = answer.to_text().strip('"')
            if rtype == "MX":
                text = text.split()[-1].rstrip(".")
            elif rtype in ("NS", "CNAME", "SOA"):
                text = " ".join(x.rstrip(".") for x in text.split())
            elif rtype == "TXT":
                text = text.replace('" "', "")
            out.append(text)
        return out

    # --------------------------------------------------------------- mail posture
    def _mail_posture(self) -> None:
        txt = " ".join(self.records.get("TXT", [])).lower()
        mx = self.records.get("MX", [])
        self.result.observe("dns", "mail", {"mx": mx, "has_spf": "v=spf1" in txt})
        if mx and "v=spf1" not in txt:
            self.result.add(
                Finding(
                    title="No SPF record while mail is accepted",
                    severity="medium",
                    category="Email authentication",
                    detail=(
                        "MX records exist but no SPF policy was published in TXT records, so receivers cannot "
                        "distinguish legitimate senders from spoofed ones."
                    ),
                    evidence=f"MX: {', '.join(mx[:6])}; TXT: {', '.join(self.records.get('TXT', [])[:4]) or 'none'}",
                    remediation="Publish an SPF record listing authorised senders and end with -all.",
                    confidence="confirmed",
                    location=self.domain,
                    cwe="CWE-290",
                    cvss=5.3,
                    references=["https://www.rfc-editor.org/rfc/rfc7208"],
                )
            )
        if mx:
            dmarc = self._query(f"_dmarc.{self.domain}", "TXT")
            dmarc_text = " ".join(dmarc).lower()
            self.result.observe("dns", "dmarc", dmarc or "missing")
            if not dmarc:
                self.result.add(
                    Finding(
                        title="No DMARC record published",
                        severity="medium",
                        category="Email authentication",
                        detail="Without DMARC, receivers have no instruction for handling SPF/DKIM failures, so spoofed mail is delivered.",
                        evidence=f"TXT _dmarc.{self.domain} -> no record",
                        remediation="Publish _dmarc TXT with p=reject (or p=quarantine during rollout) plus rua reporting.",
                        confidence="confirmed",
                        location=self.domain,
                        cwe="CWE-290",
                        cvss=5.3,
                        references=["https://www.rfc-editor.org/rfc/rfc7489"],
                    )
                )
            elif "p=none" in dmarc_text:
                self.result.add(
                    Finding(
                        title="DMARC policy is p=none (monitor only)",
                        severity="low",
                        category="Email authentication",
                        detail="A DMARC policy of p=none collects reports but does not stop spoofed mail from being delivered.",
                        evidence=f"TXT _dmarc.{self.domain}: {dmarc_text[:200]}",
                        remediation="Move to p=quarantine and then p=reject once alignment is confirmed.",
                        confidence="confirmed",
                        location=self.domain,
                        cwe="CWE-290",
                        cvss=3.7,
                    )
                )
            if "v=spf1" in txt:
                spf = [t for t in self.records.get("TXT", []) if "v=spf1" in t.lower()][0]
                policy = spf.lower()
                if "+all" in policy:
                    self.result.add(
                        Finding(
                            title="SPF record allows all senders (+all)",
                            severity="high",
                            category="Email authentication",
                            detail="An +all mechanism authorises every host on the internet to send mail as this domain.",
                            evidence=f"TXT {self.domain}: {spf[:300]}",
                            remediation="Replace +all with an explicit sender list ending in -all.",
                            confidence="confirmed",
                            location=self.domain,
                            cwe="CWE-290",
                            cvss=7.5,
                        )
                    )
                elif "~all" in policy or "?all" in policy:
                    self.result.add(
                        Finding(
                            title="SPF policy is soft (~all/?all)",
                            severity="low",
                            category="Email authentication",
                            detail="A soft SPF qualifier marks unauthorised mail but does not reject it.",
                            evidence=f"TXT {self.domain}: {spf[:300]}",
                            remediation="Use -all once all legitimate senders are enumerated.",
                            confidence="confirmed",
                            location=self.domain,
                            cwe="CWE-290",
                            cvss=3.7,
                        )
                    )

    # ------------------------------------------------------------------- CAA/DNSSEC
    def _caa_and_dnssec(self) -> None:
        caa = self.records.get("CAA")
        self.result.observe("dns", "caa", caa or "missing")
        if not caa:
            self.result.add(
                Finding(
                    title="No CAA record published",
                    severity="info",
                    category="DNS",
                    detail="Without CAA, any public CA may issue certificates for this domain, so a single misissuance is harder to contain.",
                    evidence=f"CAA {self.domain} -> no record",
                    remediation="Publish CAA records naming only the CAs you actually use.",
                    confidence="confirmed",
                    location=self.domain,
                    cwe="CWE-295",
                    references=["https://www.rfc-editor.org/rfc/rfc8659"],
                )
            )
        try:
            import dns.dnssec
            import dns.message
            import dns.query

            ns = (self.records.get("NS") or [""])
            if ns and ns[0]:
                addr = self._query(ns[0], "A")
                if addr:
                    message = dns.message.make_query(self.domain, "DNSKEY", want_dnssec=True)
                    response = dns.query.udp(message, addr[0], timeout=min(self.timeout, 4.0))
                    signed = bool(response.answer)
                    self.result.observe("dns", "dnssec", "signed" if signed else "unsigned")
                    if not signed:
                        self.result.add(
                            Finding(
                                title="DNSSEC not enabled",
                                severity="low",
                                category="DNS",
                                detail="No DNSKEY records were returned, so DNS answers are not cryptographically signed and spoofing is undetectable by resolvers.",
                                evidence=f"DNSKEY query to {ns[0]} ({addr[0]}) returned no answer section",
                                remediation="Enable DNSSEC signing on the zone and publish DS records at the registrar.",
                                confidence="firm",
                                location=self.domain,
                                cwe="CWE-345",
                                cvss=3.7,
                            )
                        )
        except Exception as exc:
            self.result.observe("dns", "dnssec_error", str(exc)[:200])

    def _wildcard(self) -> None:
        probe = f"irnx-{re.sub(r'[^a-z0-9]', '', self.domain)[:8]}-wildcard-check.{self.domain}"
        addresses = self._query(probe, "A")
        self.result.observe("dns", "wildcard_dns", addresses or "none")
        if addresses:
            self.result.add(
                Finding(
                    title="Wildcard DNS resolves arbitrary hostnames",
                    severity="low",
                    category="DNS",
                    detail=("A random subdomain resolved, so host enumeration results must be validated against this wildcard "
                            "before they are treated as real infrastructure."),
                    evidence=f"A {probe} -> {', '.join(addresses[:4])}",
                    remediation="Remove the wildcard record or scope it to a dedicated catch-all that does not expose services.",
                    confidence="confirmed",
                    location=self.domain,
                    cwe="CWE-200",
                )
            )

    def _takeover_hints(self) -> None:
        cnames = self.records.get("CNAME", [])
        for value in cnames:
            target = value.split()[-1].lower()
            for fingerprint, product in TAKEOVER_FINGERPRINTS:
                if fingerprint in target:
                    self.result.add(
                        Finding(
                            title=f"CNAME points to {product} (subdomain takeover candidate)",
                            severity="low",
                            category="DNS",
                            detail=(
                                f"{self.domain} is an alias of {target}. If that resource is released by the owner, anyone "
                                "can claim it and serve content on the trusted domain. This is a candidate, not a confirmed takeover."
                            ),
                            evidence=f"CNAME {self.domain} -> {value}",
                            remediation="Verify the target resource still exists and is owned; remove dangling aliases.",
                            confidence="tentative",
                            location=self.domain,
                            cwe="CWE-350",
                            cvss=0.0,
                        )
                    )
                    break

    # ------------------------------------------------------------------ subdomains
    def _subdomain_sweep(self) -> None:
        limit = max(0, min(self.wordlist_limit, 400))
        if limit == 0:
            self.result.observe("dns", "subdomain_sweep", "skipped for this profile")
            return
        words = list(dict.fromkeys(COMMON_SUBDOMAINS))[:limit]
        found: list[dict] = []
        errors = 0

        def probe(word: str) -> dict | None:
            name = f"{word}.{self.domain}"
            a = self._query_local(name, "A")
            if a:
                return {"name": name, "type": "A", "value": a[:3]}
            c = self._query_local(name, "CNAME")
            if c:
                return {"name": name, "type": "CNAME", "value": c[:2]}
            return None

        with ThreadPoolExecutor(max_workers=12) as pool:
            futures = {pool.submit(probe, word): word for word in words}
            for future in as_completed(futures):
                try:
                    hit = future.result()
                except Exception:
                    errors += 1
                    continue
                if hit:
                    found.append(hit)
        found.sort(key=lambda h: h["name"])
        self.result.observe("dns", "subdomains", {"checked": len(words), "found": found[:120], "errors": errors})
        if found:
            interesting = [h for h in found if h["name"].split(".")[0] in (
                "admin", "dev", "test", "staging", "git", "jenkins", "grafana", "kibana",
                "db", "backup", "old", "legacy", "internal", "vpn", "ci", "registry",
            )]
            if interesting:
                self.result.add(
                    Finding(
                        title="Non-production or administrative subdomains resolve publicly",
                        severity="low",
                        category="DNS",
                        detail=(
                            "Hostnames that usually hold pre-production or management services resolve on the public "
                            "DNS, enlarging the reachable attack surface without authentication being verified here."
                        ),
                        evidence="\n".join(f"{h['name']} {h['type']} {', '.join(h['value'])}" for h in interesting[:20]),
                        remediation="Remove public records for internal-only services or put them behind an authenticated access proxy.",
                        confidence="firm",
                        location=self.domain,
                        cwe="CWE-200",
                        cvss=3.7,
                    )
                )

    def _query_local(self, name: str, rtype: str) -> list[str]:
        try:
            answers = self.resolver().resolve(name, rtype, raise_on_no_answer=False)
        except Exception:
            return []
        if answers.rrset is None:
            return []
        return [a.to_text().strip('"') for a in answers]

    # ---------------------------------------------------------------- zone transfer
    def _zone_transfer(self) -> None:
        ns_records = self.records.get("NS", [])
        if not ns_records:
            return
        import dns.query
        import dns.zone

        for ns in ns_records[:2]:
            addresses = self._query(ns, "A")
            if not addresses:
                continue
            try:
                zone = dns.zone.from_xfr(dns.query.xfr(addresses[0], self.domain, timeout=min(self.timeout, 6.0)))
            except Exception as exc:
                self.result.observe("dns", f"axfr {ns}", f"refused/failed: {str(exc)[:120]}")
                continue
            names = sorted(str(n) for n in zone.nodes.keys())[:60]
            self.result.observe("dns", f"axfr {ns}", names)
            self.result.add(
                Finding(
                    title="DNS zone transfer (AXFR) permitted",
                    severity="high",
                    category="DNS",
                    detail=(
                        f"Authoritative server {ns} ({addresses[0]}) returned the full zone to an unauthenticated "
                        "transfer request, disclosing every internal hostname and record."
                    ),
                    evidence=f"AXFR {self.domain} @ {addresses[0]} -> {len(names)} nodes; sample: {', '.join(names[:15])}",
                    remediation="Restrict AXFR to listed secondary nameservers via TSIG or an ACL.",
                    confidence="confirmed",
                    location=f"{ns} ({addresses[0]})",
                    cwe="CWE-200",
                    cvss=7.5,
                )
            )
            break


def run(request: ScanRequest, result: ScanResult) -> ScanResult:
    return DnsScan(request, result).run()
