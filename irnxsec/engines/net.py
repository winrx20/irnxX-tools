"""Network exposure engine: bounded TCP connect discovery, banners and TLS posture.

Non-destructive by construction: a plain TCP connect (no half-open SYN packets),
no service exploitation, no credential guessing, no UDP flood. Host count and port
set are hard-capped, and every probe has a short timeout.
"""
from __future__ import annotations

import ipaddress
import socket
import ssl
from concurrent.futures import ThreadPoolExecutor, as_completed


from .. import config
from ..models import Finding, ScanRequest, ScanResult

PORT_SETS: dict[str, list[int]] = {
    "top20": [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 5432, 6379, 8080, 8443, 9200, 27017, 5900, 11211],
    "top100": [
        21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 161, 389, 443, 445, 465, 512, 513, 514,
        587, 636, 873, 993, 995, 1080, 1433, 1521, 1723, 1883, 2049, 2082, 2083, 2181, 2222, 2375,
        2376, 3000, 3128, 3260, 3306, 3389, 3690, 4000, 4444, 5000, 5432, 5601, 5672, 5900, 5901,
        5984, 6000, 6379, 6443, 7001, 7077, 8000, 8008, 8009, 8010, 8080, 8081, 8082, 8088, 8090,
        8161, 8443, 8880, 8888, 8983, 9000, 9001, 9042, 9090, 9092, 9200, 9300, 9418, 9999, 10000,
        10250, 11211, 15672, 25565, 27017, 27018, 50000, 50070, 61616,
    ],
    "top1000": [],  # filled lazily from a compact common-service list
}

# A pragmatic 1k-ish list: common service ports + web/proxy/admin ranges.
PORT_SETS["top1000"] = sorted(
    set(
        PORT_SETS["top100"]
        + list(range(8000, 8100))
        + list(range(8443, 8500))
        + list(range(9000, 9100))
        + list(range(3000, 3100))
        + list(range(5000, 5100))
        + list(range(6000, 6100))
        + [p for p in range(1, 1025)]
    )
)[:1100]

SERVICE_HINTS: dict[int, str] = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http", 110: "pop3",
    111: "rpcbind", 135: "msrpc", 139: "netbios", 143: "imap", 161: "snmp", 389: "ldap",
    443: "https", 445: "smb", 465: "smtps", 587: "submission", 636: "ldaps", 873: "rsync",
    993: "imaps", 995: "pop3s", 1080: "socks", 1433: "mssql", 1521: "oracle", 1723: "pptp",
    1883: "mqtt", 2049: "nfs", 2181: "zookeeper", 2375: "docker", 2376: "docker-tls",
    3000: "http-alt", 3306: "mysql", 3389: "rdp", 5432: "postgres", 5601: "kibana",
    5672: "amqp", 5900: "vnc", 5984: "couchdb", 6379: "redis", 6443: "k8s-api",
    7001: "weblogic", 8000: "http-alt", 8080: "http-proxy", 8081: "http-alt",
    8443: "https-alt", 8888: "http-alt", 8983: "solr", 9000: "http-alt", 9042: "cassandra",
    9090: "prometheus", 9200: "elasticsearch", 9300: "elasticsearch", 9418: "git",
    10000: "webmin", 10250: "kubelet", 11211: "memcached", 15672: "rabbitmq-mgmt",
    25565: "minecraft", 27017: "mongodb", 27018: "mongodb", 50000: "sap", 61616: "activemq",
}

# Ports that should never be reachable from an untrusted network.
CRITICAL_EXPOSURE = {
    23: ("high", "Telnet exposes credentials and session data in cleartext."),
    445: ("high", "SMB reachable from the scanned network; ransomware tooling depends on this."),
    2375: ("critical", "Unauthenticated Docker API: container escape and host compromise follow directly."),
    2376: ("high", "Docker API over TLS exposed; confirm mutual TLS is enforced."),
    3306: ("high", "MySQL reachable; database ports belong behind the application tier."),
    3389: ("high", "RDP exposed to the network is a primary ransomware entry point."),
    5432: ("high", "PostgreSQL reachable; restrict to trusted application hosts."),
    5900: ("high", "VNC exposed; remote desktop without network segmentation."),
    6379: ("high", "Redis reachable; unauthenticated Redis permits data theft and write access."),
    9200: ("high", "Elasticsearch exposed; usually unauthenticated with full index access."),
    9300: ("medium", "Elasticsearch transport port exposed."),
    11211: ("medium", "Memcached exposed; usable for amplification and cache disclosure."),
    27017: ("high", "MongoDB exposed; default installs accept unauthenticated connections."),
    10250: ("critical", "Kubelet API exposed; commonly allows command execution in pods."),
    6443: ("medium", "Kubernetes API server reachable from the scanned network."),
    21: ("medium", "FTP exposed; credentials and files transit in cleartext."),
    139: ("medium", "NetBIOS session service exposed."),
    161: ("medium", "SNMP exposed; community strings are frequently default."),
}


class NetScan:
    def __init__(self, request: ScanRequest, result: ScanResult) -> None:
        self.request = request
        self.result = result
        self.settings = config.load()
        prof = config.profile(request.profile)
        self.max_hosts = int(request.max_hosts or min(self.settings.max_hosts, 64))
        self.connect_timeout = float(request.timeout or self.settings.connect_timeout)
        port_key = (request.ports or prof["ports"] or "top20").lower()
        self.ports = self._parse_ports(request.ports) or PORT_SETS.get(port_key, PORT_SETS["top20"])
        self.hosts = self._expand(request.target)

    # ------------------------------------------------------------------ target set
    def _expand(self, target: str) -> list[str]:
        text = target.strip()
        if "/" in text:
            try:
                network = ipaddress.ip_network(text, strict=False)
            except ValueError:
                return []
            if network.num_addresses > 4096:
                self.result.error(f"Range {network} is larger than 4096 addresses; scanning the first {self.max_hosts} hosts only.")
            hosts = []
            for ip in network.hosts():
                hosts.append(str(ip))
                if len(hosts) >= self.max_hosts:
                    break
            return hosts
        return [text]

    @staticmethod
    def _parse_ports(raw: str) -> list[int]:
        if not raw:
            return []
        out: set[int] = set()
        for chunk in raw.split(","):
            chunk = chunk.strip()
            if not chunk:
                continue
            if "-" in chunk:
                start, _, end = chunk.partition("-")
                try:
                    lo, hi = int(start), int(end)
                except ValueError:
                    continue
                for port in range(max(1, lo), min(65535, hi) + 1):
                    out.add(port)
                    if len(out) >= 2048:
                        return sorted(out)
            else:
                try:
                    port = int(chunk)
                except ValueError:
                    continue
                if 1 <= port <= 65535:
                    out.add(port)
        return sorted(out)[:2048]

    # -------------------------------------------------------------------- driver
    def run(self) -> ScanResult:
        self.result.observe(
            "engine",
            "scan_plan",
            {"hosts": self.hosts[:20], "host_count": len(self.hosts), "port_count": len(self.ports), "profile": self.request.profile},
        )
        if not self.hosts:
            self.result.error("No scannable hosts were derived from the target.")
            return self.result.finish()
        if len(self.ports) * len(self.hosts) > 4096:
            self.result.error(
                f"{len(self.ports) * len(self.hosts)} probe attempts requested; capped to stay polite. Use a smaller port set or range."
            )
            self.ports = self.ports[: max(1, 4096 // max(1, len(self.hosts)))]
        open_port_map: dict[str, list[dict]] = {}
        workers = min(48, max(8, len(self.ports)))
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = {
                pool.submit(self._probe, host, port): (host, port)
                for host in self.hosts
                for port in self.ports
            }
            for future in as_completed(futures):
                host, port = futures[future]
                try:
                    info = future.result()
                except Exception as exc:  # a probe failure is an observation, not a crash
                    self.result.error(f"{host}:{port} probe error: {exc}")
                    continue
                if info:
                    open_port_map.setdefault(host, []).append(info)
        total_open = 0
        for host in self.hosts:
            entries = sorted(open_port_map.get(host, []), key=lambda x: x["port"])
            total_open += len(entries)
            self.result.observe("host", f"open_ports {host}", entries)
            self._host_findings(host, entries)
        self.result.metadata.update(
            {
                "hosts_scanned": len(self.hosts),
                "ports_per_host": len(self.ports),
                "open_ports": total_open,
                "probes": len(self.hosts) * len(self.ports),
            }
        )
        if total_open == 0 and not self.result.findings:
            self.result.observe("host", "note", "No TCP ports answered from the configured set. This is not proof the host is closed.")
        return self.result.finish()

    def _probe(self, host: str, port: int) -> dict | None:
        sock = socket.socket(socket.AF_INET6 if ":" in host else socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.connect_timeout)
        try:
            if sock.connect_ex((host, port)) != 0:
                return None
        finally:
            try:
                sock.close()
            except OSError:
                pass
        entry = {
            "port": port,
            "service": SERVICE_HINTS.get(port, "unknown"),
            "banner": self._banner(host, port),
            "tls": None,
        }
        if port in (443, 465, 636, 993, 995, 8443, 2376, 6443, 9443) or entry["service"] in ("https", "https-alt", "imaps", "pop3s", "smtps", "ldaps", "docker-tls"):
            entry["tls"] = self._tls(host, port)
        return entry

    def _banner(self, host: str, port: int) -> str:
        try:
            with socket.create_connection((host, port), timeout=self.connect_timeout) as sock:
                sock.settimeout(self.connect_timeout)
                if port in (80, 8000, 8080, 8081, 8888, 9000, 3000, 5000, 7001, 9090, 9200, 5601, 8983):
                    sock.sendall(f"HEAD / HTTP/1.0\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode())
                data = sock.recv(512)
                return data.decode("utf-8", "replace").strip().replace("\r\n", " | ")[:200]
        except OSError:
            return ""

    def _tls(self, host: str, port: int) -> dict | None:
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((host, port), timeout=max(2.0, self.connect_timeout * 2)) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as tls:
                    cert = tls.getpeercert() or {}
                    version = tls.version()
                    cipher = tls.cipher()
                    info = {
                        "version": version,
                        "cipher": cipher[0] if cipher else "",
                        "subject": dict(x[0] for x in cert.get("subject", [])),
                        "issuer": dict(x[0] for x in cert.get("issuer", [])),
                        "not_after": cert.get("notAfter", ""),
                        "san": [v for k, v in cert.get("subjectAltName", []) if k == "DNS"][:20],
                        "verified": self._verify_hostname(host, port),
                    }
                    return info
        except Exception as exc:
            return {"error": str(exc)[:200]}

    def _verify_hostname(self, host: str, port: int) -> bool:
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((host, port), timeout=max(2.0, self.connect_timeout * 2)) as sock:
                with ctx.wrap_socket(sock, server_hostname=host):
                    return True
        except Exception:
            return False

    # ------------------------------------------------------------------ findings
    def _host_findings(self, host: str, entries: list[dict]) -> None:
        if not entries:
            return
        for entry in entries:
            port = entry["port"]
            service = entry["service"]
            if port in CRITICAL_EXPOSURE:
                severity, why = CRITICAL_EXPOSURE[port]
                self.result.add(
                    Finding(
                        title=f"Sensitive service exposed: {service} on {port}/tcp",
                        severity=severity,
                        category="Network exposure",
                        detail=f"A TCP connection to {host}:{port} succeeded. {why}",
                        evidence=(
                            f"TCP connect {host}:{port} -> open; service hint: {service}"
                            + (f"; banner: {entry['banner'][:120]}" if entry["banner"] else "")
                        ),
                        remediation=(
                            f"Restrict {port}/tcp to trusted management networks with a firewall or security group, "
                            "and require authentication plus TLS where the service supports it."
                        ),
                        confidence="confirmed",
                        location=f"{host}:{port}",
                        cwe="CWE-284",
                        cvss={"critical": 9.1, "high": 7.5, "medium": 5.3}.get(severity, 4.0),
                    )
                )
            if entry.get("tls"):
                tls = entry["tls"]
                if tls.get("error"):
                    continue
                if tls.get("version") in ("TLSv1", "TLSv1.1", "SSLv3", "SSLv2"):
                    self.result.add(
                        Finding(
                            title=f"Deprecated TLS on {service} {host}:{port}",
                            severity="medium",
                            category="Transport",
                            detail=f"{port}/tcp negotiated {tls['version']}, which is deprecated.",
                            evidence=f"TLS handshake {host}:{port} -> {tls['version']} {tls.get('cipher','')}",
                            remediation="Require TLS 1.2+ and disable legacy protocol versions.",
                            confidence="confirmed",
                            location=f"{host}:{port}",
                            cwe="CWE-327",
                            cvss=5.3,
                        )
                    )
                if tls.get("verified") is False and port in (443, 8443):
                    self.result.add(
                        Finding(
                            title=f"TLS certificate not trusted for {host}:{port}",
                            severity="medium",
                            category="Transport",
                            detail="Certificate validation failed against the system trust store for this hostname.",
                            evidence=f"verified=false; subject={tls.get('subject')}; issuer={tls.get('issuer')}",
                            remediation="Deploy a certificate from a trusted CA covering the hostname and keep the chain complete.",
                            confidence="firm",
                            location=f"{host}:{port}",
                            cwe="CWE-295",
                            cvss=5.9,
                        )
                    )
        http_entries = [e for e in entries if e["service"] in ("http", "http-alt", "http-proxy", "https", "https-alt")]
        if http_entries:
            self.result.observe(
                "host",
                f"http_surface {host}",
                [f"{'https' if e['service'] in ('https','https-alt') or e['port'] in (443,8443) else 'http'}://{host}:{e['port']}/" for e in http_entries],
                "Run a web assessment against these origins for application-layer results.",
            )
        if len(entries) >= 12:
            self.result.add(
                Finding(
                    title=f"Large open port footprint on {host}",
                    severity="low",
                    category="Network exposure",
                    detail=f"{len(entries)} TCP ports answered on this host, which increases attack surface and suggests the host is not fronted by a filtering layer.",
                    evidence="open: " + ", ".join(str(e['port']) for e in entries[:30]),
                    remediation="Apply default-deny ingress and expose only the ports each service requires.",
                    confidence="firm",
                    location=host,
                    cwe="CWE-284",
                    cvss=3.7,
                )
            )


def run(request: ScanRequest, result: ScanResult) -> ScanResult:
    return NetScan(request, result).run()
