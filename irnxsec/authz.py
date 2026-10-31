"""Authorization guard and signed engagement certificates.

Every active scan must pass :func:`guard.authorize` before any packet is sent.
Loopback and private-lab ranges are always permitted because they cannot reach a
third party; anything else requires an active, unexpired, unrevoked authorization
scope (an engagement record) on file.

The certificate layer turns a scope into a signed document: an Ed25519 key pair is
generated on first use, the authorization payload is signed, and both a JSON and a
PDF certificate are written to ``~/.irnxsec/certs``. The signature is verifiable
with the exported public key, so the scope file can be handed to a client or an
asset owner as proof of authorization.
"""
from __future__ import annotations

import base64
import ipaddress
import json
import re
import socket
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable
from urllib.parse import urlparse

from . import config, store
from .models import GuardDecision, utcnow

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

DOMAIN_RE = re.compile(r"^(?:\*\.)?(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$", re.I)
LAB_SUFFIXES = ("localhost", ".localhost", ".local", ".test", ".invalid", ".example", ".internal")


# ------------------------------------------------------------------ target parsing
def normalize_target(raw: str, kind: str = "web") -> str:
    """Return a canonical target string or raise ValueError for bad input."""
    text = (raw or "").strip()
    if not text:
        raise ValueError("Target is required.")
    if kind == "network":
        return _normalize_network(text)
    if kind == "dns":
        host = _strip_scheme(text)
        if not host or "/" in host or " " in host:
            raise ValueError("DNS target must be a bare hostname.")
        return host.lower().rstrip(".")
    return _normalize_web(text)


def _strip_scheme(text: str) -> str:
    if "://" in text:
        text = text.split("://", 1)[1]
    return text.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]


def _normalize_web(text: str) -> str:
    if "://" not in text:
        text = "https://" + text
    parsed = urlparse(text)
    if parsed.scheme not in ("http", "https"):
        raise ValueError("Only http and https targets are supported.")
    if not parsed.hostname:
        raise ValueError("Target has no hostname.")
    if parsed.username or parsed.password:
        raise ValueError("Do not embed credentials in the target URL.")
    host = parsed.hostname.lower()
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError("Invalid port.") from exc
    if port and port not in (80, 443, 8080, 8443, 8000, 8888, 3000, 5000):
        if not (1 <= port <= 65535):
            raise ValueError("Invalid port.")
    netloc = host if not port else f"{host}:{port}"
    return f"{parsed.scheme}://{netloc}"


def _normalize_network(text: str) -> str:
    text = text.strip()
    if "://" in text:
        text = text.split("://", 1)[1]
    text = text.split("?", 1)[0].split("#", 1)[0].rstrip("/")
    if "/" in text:
        try:
            return str(ipaddress.ip_network(text, strict=False))
        except ValueError as exc:
            raise ValueError("Invalid CIDR range.") from exc
    try:
        ip = ipaddress.ip_address(text)
        return str(ipaddress.ip_network(f"{ip}/{ip.max_prefixlen}", strict=False))
    except ValueError:
        pass
    if DOMAIN_RE.match(text):
        return text.lower().rstrip(".")
    raise ValueError("Use an IP address, a CIDR range or a domain name.")


def normalize_scope_target(raw: str, kind: str = "all") -> str:
    """Normalise one authorization-scope entry while preserving its pattern.

    A scope entry is a *pattern*, not a scan target: ``*.example.com`` and
    ``10.0.0.0/24`` must survive unchanged or scope matching breaks. Only a full URL
    is reduced to its host, and a bare host keeps its scheme off.
    """
    text = (raw or "").strip()
    if not text:
        raise ValueError("Empty target in scope.")
    if "://" in text:
        parsed = urlparse(text)
        if parsed.scheme not in ("http", "https"):
            raise ValueError(f"Unsupported scheme in '{raw}'.")
        if not parsed.hostname:
            raise ValueError(f"'{raw}' has no hostname.")
        text = parsed.hostname
    text = text.rstrip("/").lower()
    if text.startswith("*."):
        base = text[2:]
        if not base or "*" in base or not DOMAIN_RE.match(base):
            raise ValueError(f"Invalid wildcard pattern '{raw}'.")
        return text
    if "*" in text:
        raise ValueError(f"Wildcard must be the whole left label, e.g. '*.example.com' in '{raw}'.")
    try:
        return str(ipaddress.ip_network(text, strict=False))
    except ValueError:
        pass
    if DOMAIN_RE.match(text) or re.match(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?$", text):
        return text
    raise ValueError(f"'{raw}' is not a hostname, wildcard, URL or CIDR range.")


def host_of(target: str, kind: str = "web") -> str:
    if kind == "web" and "://" in target:
        return (urlparse(target).hostname or "").lower()
    return _strip_scheme(target).split("/", 1)[0].split(":", 1)[0].lower()


def is_lab_target(host: str) -> bool:
    """Loopback, private, link-local and reserved names never leave the machine."""
    host = (host or "").strip().lower().strip("[]")
    if not host:
        return False
    if host in ("localhost", "127.0.0.1", "::1", "0.0.0.0"):
        return True
    if host.endswith(LAB_SUFFIXES):
        return True
    if host.endswith(".lan") or host.endswith(".home") or host.endswith(".corp"):
        return True
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    return (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_reserved
        or ip.is_multicast
        or ip.is_unspecified
    )


# ------------------------------------------------------------------------ matching
def _pattern_matches(pattern: str, host: str) -> bool:
    pattern = (pattern or "").strip().lower().rstrip(".")
    host = (host or "").strip().lower().rstrip(".")
    if not pattern or not host:
        return False
    if pattern == host:
        return True
    if pattern.startswith("*."):
        suffix = pattern[1:]
        return host.endswith(suffix) or host == pattern[2:]
    if pattern.startswith("."):
        return host.endswith(pattern)
    try:
        net = ipaddress.ip_network(pattern, strict=False)
    except ValueError:
        return False
    try:
        return ipaddress.ip_address(host) in net
    except ValueError:
        return False


def scope_covers(scope: dict, host: str, kind: str) -> bool:
    if not scope or not scope.get("usable"):
        return False
    scope_kind = (scope.get("kind") or "all").lower()
    if scope_kind not in ("all", kind):
        return False
    for raw in scope.get("targets") or []:
        entry = str(raw).strip()
        candidate = host
        if entry.startswith("http://") or entry.startswith("https://"):
            entry_host = (urlparse(entry).hostname or "").lower()
            if entry_host == host:
                return True
            continue
        if kind == "network" and "/" in entry:
            try:
                if ipaddress.ip_address(host) in ipaddress.ip_network(entry, strict=False):
                    return True
            except ValueError:
                pass
        if _pattern_matches(entry, candidate):
            return True
    return False


@dataclass
class Guard:
    require_authz: bool = True

    def authorize(self, target: str, kind: str = "web", scope_id: str = "", confirm: bool = False) -> GuardDecision:
        host = host_of(target, kind)
        if not host:
            return GuardDecision(False, "Target has no resolvable host.", host)
        if is_lab_target(host):
            return GuardDecision(True, "Loopback/private lab target - no external scope required.", host, None, "LAB")
        if not confirm:
            return GuardDecision(
                False,
                "Authorization confirmation is required. Tick the confirmation box or pass --confirm-authorized.",
                host,
            )
        if not self.require_authz:
            return GuardDecision(True, "Scope enforcement is disabled in settings.", host)
        if scope_id:
            scope = store.get_scope(scope_id)
            if not scope:
                return GuardDecision(False, f"Scope {scope_id} does not exist.", host)
            if not scope.get("usable"):
                return GuardDecision(False, f"Scope {scope_id} is revoked or expired.", host, scope_id=scope_id)
            if scope_covers(scope, host, kind):
                return GuardDecision(True, f"Covered by scope {scope_id} ({scope['name']}).", host, scope_id=scope_id)
            return GuardDecision(False, f"Host {host} is not listed in scope {scope_id}.", host, scope_id=scope_id)
        for scope in store.list_scopes(include_revoked=False):
            if scope_covers(scope, host, kind):
                return GuardDecision(True, f"Covered by scope {scope['id']} ({scope['name']}).", host, scope_id=scope["id"])
        return GuardDecision(
            False,
            f"No active authorization scope covers {host}. Register the engagement (with written permission) first.",
            host,
        )


guard = Guard(require_authz=True)


def resolvable(host: str, timeout: float = 3.0) -> bool:
    try:
        socket.setdefaulttimeout(timeout)
        socket.getaddrinfo(host, None)
        return True
    except OSError:
        return False
    finally:
        socket.setdefaulttimeout(None)


def expand_targets(targets: Iterable[str]) -> list[str]:
    return [t.strip() for t in targets if str(t).strip()]


# -------------------------------------------------------------------- certificates
def _key_paths() -> tuple[Path, Path]:
    certs = config.certs_dir()
    return certs / "irnxsec-signing-key.pem", certs / "irnxsec-signing-key.pub.pem"


def signing_key() -> Ed25519PrivateKey:
    private_path, public_path = _key_paths()
    if private_path.exists():
        return serialization.load_pem_private_key(private_path.read_bytes(), password=None)
    key = Ed25519PrivateKey.generate()
    private_path.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    private_path.chmod(0o600)
    public_path.write_bytes(
        key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    return key


def public_key_pem() -> str:
    private_path, public_path = _key_paths()
    if public_path.exists():
        return public_path.read_text(encoding="utf-8")
    signing_key()
    return public_path.read_text(encoding="utf-8")


def _canonical(payload: dict) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def issue_certificate(scope_id: str) -> dict:
    scope = store.get_scope(scope_id)
    if not scope:
        raise ValueError(f"Scope {scope_id} does not exist.")
    if not scope.get("usable"):
        raise ValueError("Refusing to certify a revoked or expired scope.")
    payload = {
        "certificate_id": "IRNX-CERT-" + uuid.uuid4().hex[:12].upper(),
        "scope_id": scope["id"],
        "engagement": scope["name"],
        "organization": scope.get("organization") or "",
        "client_contact": scope.get("contact") or "",
        "authorization_basis": scope.get("authorization") or "owner",
        "reference": scope.get("reference") or "",
        "targets": scope.get("targets") or [],
        "scope_kind": scope.get("kind") or "all",
        "issued_at": utcnow(),
        "valid_until": scope.get("expires_at") or "until revoked",
        "issuer": f"{config.APP_NAME} {config.VERSION}",
        "statement": (
            "The named engagement authorizes the limited, non-destructive assessment activity "
            "described in the engagement notes. Testing must stop immediately if the scope is "
            "revoked, if a system becomes unstable, or if data beyond the agreed scope is reached."
        ),
    }
    signature = signing_key().sign(_canonical(payload))
    key = signing_key().public_key()
    certificate = {
        "payload": payload,
        "algorithm": "Ed25519",
        "signature": base64.b64encode(signature).decode("ascii"),
        "public_key_fingerprint": base64.b64encode(
            key.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )
        ).decode("ascii"),
    }
    certs = config.certs_dir()
    json_path = certs / f"{payload['certificate_id']}.json"
    json_path.write_text(json.dumps(certificate, indent=2), encoding="utf-8")
    pdf_path = certs / f"{payload['certificate_id']}.pdf"
    try:
        from .pdf import render_certificate

        render_certificate(certificate, pdf_path)
        certificate["pdf"] = str(pdf_path)
    except Exception as exc:  # pragma: no cover - optional PDF backend
        certificate["pdf_error"] = str(exc)
    certificate["json"] = str(json_path)
    store.audit("certificate.issue", payload["certificate_id"], scope_id)
    return certificate


def verify_certificate(certificate: dict) -> dict:
    try:
        payload = certificate["payload"]
        signature = base64.b64decode(certificate["signature"])
        signing_key().public_key().verify(signature, _canonical(payload))
    except Exception as exc:
        return {"valid": False, "reason": f"Signature verification failed: {exc}"}
    scope = store.get_scope(payload.get("scope_id", ""))
    if not scope:
        return {"valid": False, "reason": "Scope no longer exists in this installation.", "payload": payload}
    if not scope.get("usable"):
        return {"valid": False, "reason": "Scope has been revoked or has expired.", "payload": payload, "scope": scope}
    return {"valid": True, "reason": "Signature valid and scope active.", "payload": payload, "scope": scope}


def list_certificates() -> list[dict]:
    certs = config.certs_dir()
    out = []
    for path in sorted(certs.glob("IRNX-CERT-*.json"), reverse=True):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        payload = data.get("payload", {})
        out.append(
            {
                "certificate_id": payload.get("certificate_id"),
                "scope_id": payload.get("scope_id"),
                "engagement": payload.get("engagement"),
                "issued_at": payload.get("issued_at"),
                "valid_until": payload.get("valid_until"),
                "targets": payload.get("targets", []),
                "path": str(path),
                "pdf": str(path.with_suffix(".pdf")),
            }
        )
    return out


def certificate_path(certificate_id: str, suffix: str = "") -> Path | None:
    """Resolve an issued certificate artefact (``json`` or ``pdf``)."""
    if not re.match(r"^IRNX-CERT-[A-Z0-9]{12}$", certificate_id or ""):
        return None
    suffixes = (suffix,) if suffix else ("pdf", "json")
    for candidate_suffix in suffixes:
        candidate = config.certs_dir() / f"{certificate_id}.{candidate_suffix}"
        if candidate.exists():
            return candidate
    return None
