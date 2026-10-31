"""Shared data model. Every engine, report writer and API handler uses these types."""
from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Iterable

SEVERITY_ORDER = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
SCAN_KINDS = ("web", "network", "dns")


def utcnow() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _jsonable(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(k): _jsonable(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_jsonable(v) for v in value]
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return str(value)


@dataclass
class Finding:
    """A single assessment result row.

    ``confidence`` mirrors evidence quality: ``confirmed`` means the condition was
    directly observed, ``firm`` means strongly indicated by observed behaviour,
    ``tentative`` means a heuristic that still needs manual validation.
    """

    title: str
    severity: str
    category: str
    detail: str = ""
    evidence: str = ""
    remediation: str = ""
    confidence: str = "tentative"
    location: str = ""
    cwe: str = ""
    cvss: float = 0.0
    references: list[str] = field(default_factory=list)
    meta: dict[str, Any] = field(default_factory=dict)
    id: str = ""

    def __post_init__(self) -> None:
        self.severity = (self.severity or "info").lower()
        if self.severity not in SEVERITY_ORDER:
            self.severity = "info"
        self.confidence = (self.confidence or "tentative").lower()
        if not self.id:
            basis = f"{self.category}|{self.title}|{self.location}|{self.detail[:120]}"
            self.id = hashlib.sha256(basis.encode("utf-8")).hexdigest()[:16]

    @property
    def rank(self) -> int:
        return SEVERITY_ORDER[self.severity]

    def to_dict(self) -> dict:
        return _jsonable(asdict(self))


@dataclass
class Observation:
    """Neutral facts collected during a scan (kept out of the findings list)."""

    kind: str
    label: str
    value: Any = None
    detail: str = ""

    def to_dict(self) -> dict:
        return _jsonable(asdict(self))


@dataclass
class ScanResult:
    kind: str
    target: str
    profile: str = "standard"
    scope_id: str = ""
    scan_id: str = ""
    started_at: str = field(default_factory=utcnow)
    finished_at: str = ""
    requests_made: int = 0
    findings: list[Finding] = field(default_factory=list)
    observations: list[Observation] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    authorization: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.scan_id:
            basis = f"{self.kind}|{self.target}|{self.started_at}"
            self.scan_id = hashlib.sha256(basis.encode("utf-8")).hexdigest()[:12]
        self.kind = (self.kind or "web").lower()

    # ------------------------------------------------------------- collection
    def add(self, finding: Finding) -> None:
        for existing in self.findings:
            if existing.id == finding.id:
                return
        self.findings.append(finding)

    def observe(self, kind: str, label: str, value: Any = None, detail: str = "") -> None:
        self.observations.append(Observation(kind, label, value, detail))

    def error(self, message: str) -> None:
        if message not in self.errors:
            self.errors.append(message)

    # ---------------------------------------------------------------- summary
    def sort_findings(self) -> None:
        self.findings.sort(key=lambda f: (-f.rank, f.category, f.title))

    def summary(self) -> dict[str, int]:
        counts = {key: 0 for key in SEVERITY_ORDER}
        for finding in self.findings:
            counts[finding.severity] += 1
        counts["total"] = len(self.findings)
        return counts

    @property
    def risk_score(self) -> float:
        """0-100 heuristic exposure score, weighted by severity and confidence."""
        weights = {"critical": 34, "high": 16, "medium": 6, "low": 2, "info": 0}
        conf = {"confirmed": 1.0, "firm": 0.7, "tentative": 0.45}
        score = sum(weights[f.severity] * conf.get(f.confidence, 0.5) for f in self.findings)
        return round(min(100.0, score), 1)

    def finish(self) -> "ScanResult":
        self.finished_at = utcnow()
        self.sort_findings()
        self.requests_made = int(self.metadata.get("requests_made", self.requests_made) or 0)
        return self

    # ------------------------------------------------------------- conversion
    def observations_as_list(self) -> list[dict]:
        return [o.to_dict() for o in self.observations]

    def to_dict(self) -> dict:
        payload = _jsonable(asdict(self))
        payload["findings"] = [f.to_dict() for f in self.findings]
        payload["observations"] = self.observations_as_list()
        payload["summary"] = self.summary()
        payload["risk_score"] = self.risk_score
        return payload

    @staticmethod
    def from_dict(data: dict) -> "ScanResult":
        findings = [Finding(**{k: v for k, v in f.items() if k in Finding.__dataclass_fields__}) for f in data.get("findings", [])]
        observations = [
            Observation(**{k: v for k, v in o.items() if k in Observation.__dataclass_fields__})
            for o in data.get("observations", [])
            if isinstance(o, dict)
        ]
        known = {k: v for k, v in data.items() if k in ScanResult.__dataclass_fields__}
        known["findings"] = findings
        known["observations"] = observations
        return ScanResult(**known)


@dataclass
class ScanRequest:
    """Normalized scan request accepted from the CLI or the dashboard API."""

    target: str
    kind: str = "web"
    profile: str = "standard"
    scope_id: str = ""
    confirm_authorized: bool = False
    timeout: float | None = None
    rate_limit: float | None = None
    max_requests: int | None = None
    max_hosts: int | None = None
    ports: str = ""
    verify_tls: bool | None = None
    options: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return _jsonable(asdict(self))


@dataclass
class GuardDecision:
    allowed: bool
    reason: str = ""
    host: str = ""
    port: int | None = None
    scope_id: str = ""

    def to_dict(self) -> dict:
        return _jsonable(asdict(self))


def merged_summary(results: Iterable[ScanResult]) -> dict[str, Any]:
    results = list(results)
    totals = {key: 0 for key in SEVERITY_ORDER}
    for result in results:
        for finding in result.findings:
            totals[finding.severity] += 1
    totals["total"] = sum(totals.values())
    return {
        "scans": len(results),
        "findings": totals,
        "risk_score": round(sum(r.risk_score for r in results) / len(results), 1) if results else 0.0,
    }


def dumps(value: Any, indent: int = 2) -> str:
    return json.dumps(value, indent=indent, ensure_ascii=False, default=str)
