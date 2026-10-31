"""SQLite persistence: authorized scopes, scan history and the audit trail."""
from __future__ import annotations

import json
import sqlite3
import threading
import uuid
from contextlib import contextmanager
from typing import Any, Iterator

from . import config
from .models import ScanResult, utcnow

_lock = threading.RLock()

SCHEMA = """
CREATE TABLE IF NOT EXISTS scopes (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    kind TEXT NOT NULL DEFAULT 'all',
    targets TEXT NOT NULL,
    organization TEXT DEFAULT '',
    contact TEXT DEFAULT '',
    authorization TEXT NOT NULL DEFAULT 'owner',
    reference TEXT DEFAULT '',
    notes TEXT DEFAULT '',
    status TEXT NOT NULL DEFAULT 'active',
    created_at TEXT NOT NULL,
    expires_at TEXT DEFAULT '',
    revoked_at TEXT DEFAULT ''
);
CREATE TABLE IF NOT EXISTS scans (
    id TEXT PRIMARY KEY,
    kind TEXT NOT NULL,
    target TEXT NOT NULL,
    profile TEXT,
    scope_id TEXT,
    status TEXT NOT NULL DEFAULT 'queued',
    started_at TEXT,
    finished_at TEXT,
    risk_score REAL DEFAULT 0,
    summary TEXT,
    result TEXT,
    error TEXT
);
CREATE TABLE IF NOT EXISTS audit (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    actor TEXT DEFAULT 'local',
    action TEXT NOT NULL,
    detail TEXT DEFAULT '',
    scope_id TEXT DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_scans_started ON scans(started_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit(ts DESC);
"""


@contextmanager
def connect() -> Iterator[sqlite3.Connection]:
    with _lock:
        conn = sqlite3.connect(config.db_path(), timeout=30)
        conn.row_factory = sqlite3.Row
        try:
            conn.executescript(SCHEMA)
            yield conn
            conn.commit()
        finally:
            conn.close()


def audit(action: str, detail: str = "", scope_id: str = "", actor: str = "local") -> None:
    with connect() as conn:
        conn.execute(
            "INSERT INTO audit(ts, actor, action, detail, scope_id) VALUES(?,?,?,?,?)",
            (utcnow(), actor, action, detail, scope_id),
        )


def audit_trail(limit: int = 200) -> list[dict]:
    with connect() as conn:
        rows = conn.execute(
            "SELECT ts, actor, action, detail, scope_id FROM audit ORDER BY id DESC LIMIT ?",
            (min(max(int(limit), 1), 1000),),
        ).fetchall()
    return [dict(r) for r in rows]


# ------------------------------------------------------------------ scopes
def create_scope(data: dict) -> dict:
    scope_id = data.get("id") or "SC-" + uuid.uuid4().hex[:10].upper()
    record = {
        "id": scope_id,
        "name": (data.get("name") or "Untitled engagement").strip()[:120],
        "kind": (data.get("kind") or "all").strip().lower(),
        "targets": json.dumps(data.get("targets") or []),
        "organization": (data.get("organization") or "").strip()[:160],
        "contact": (data.get("contact") or "").strip()[:160],
        "authorization": (data.get("authorization") or "owner").strip().lower(),
        "reference": (data.get("reference") or "").strip()[:160],
        "notes": (data.get("notes") or "").strip()[:4000],
        "status": "active",
        "created_at": utcnow(),
        "expires_at": (data.get("expires_at") or "").strip(),
    }
    with connect() as conn:
        conn.execute(
            "INSERT INTO scopes(id,name,kind,targets,organization,contact,authorization,reference,notes,status,created_at,expires_at)"
            " VALUES(:id,:name,:kind,:targets,:organization,:contact,:authorization,:reference,:notes,:status,:created_at,:expires_at)",
            record,
        )
    audit("scope.create", f"{record['name']} targets={record['targets']}", scope_id)
    return get_scope(scope_id) or {}


def get_scope(scope_id: str) -> dict | None:
    with connect() as conn:
        row = conn.execute("SELECT * FROM scopes WHERE id=?", (scope_id,)).fetchone()
    return _scope_row(row) if row else None


def list_scopes(include_revoked: bool = True) -> list[dict]:
    query = "SELECT * FROM scopes" + ("" if include_revoked else " WHERE status='active'") + " ORDER BY created_at DESC"
    with connect() as conn:
        rows = conn.execute(query).fetchall()
    return [_scope_row(r) for r in rows]


def revoke_scope(scope_id: str) -> bool:
    with connect() as conn:
        cur = conn.execute(
            "UPDATE scopes SET status='revoked', revoked_at=? WHERE id=? AND status='active'",
            (utcnow(), scope_id),
        )
        changed = cur.rowcount > 0
    if changed:
        audit("scope.revoke", "authorization revoked", scope_id)
    return changed


def delete_scope(scope_id: str) -> bool:
    with connect() as conn:
        cur = conn.execute("DELETE FROM scopes WHERE id=?", (scope_id,))
        changed = cur.rowcount > 0
    if changed:
        audit("scope.delete", "scope removed after revocation", scope_id)
    return changed


def _scope_row(row: sqlite3.Row) -> dict:
    record: dict[str, Any] = dict(row)
    try:
        record["targets"] = json.loads(record.get("targets") or "[]")
    except ValueError:
        record["targets"] = []
    record["expired"] = _is_expired(record.get("expires_at") or "")
    record["usable"] = record.get("status") == "active" and not record["expired"]
    return record


def _is_expired(expires_at: str) -> bool:
    if not expires_at:
        return False
    from datetime import datetime, timezone

    text = expires_at.strip().replace("Z", "+00:00")
    for fmt in (None, "%Y-%m-%d"):
        try:
            stamp = datetime.fromisoformat(text) if fmt is None else datetime.strptime(text, fmt)
        except ValueError:
            continue
        if stamp.tzinfo is None:
            stamp = stamp.replace(tzinfo=timezone.utc)
        return stamp < datetime.now(timezone.utc)
    return False


# ------------------------------------------------------------------- scans
def save_scan(result: ScanResult, reports: dict | None = None, status: str = "complete") -> str:
    payload = json.dumps(result.to_dict(), ensure_ascii=False, default=str)
    with connect() as conn:
        conn.execute(
            "INSERT OR REPLACE INTO scans(id,kind,target,profile,scope_id,status,started_at,finished_at,risk_score,summary,result)"
            " VALUES(?,?,?,?,?,?,?,?,?,?,?)",
            (
                result.scan_id,
                result.kind,
                result.target,
                result.profile,
                result.scope_id,
                status,
                result.started_at,
                result.finished_at,
                result.risk_score,
                json.dumps(result.summary()),
                payload,
            ),
        )
    if reports:
        with connect() as conn:
            row = conn.execute("SELECT summary FROM scans WHERE id=?", (result.scan_id,)).fetchone()
            summary = json.loads(row["summary"] or "{}") if row else {}
            summary["reports"] = reports
            conn.execute("UPDATE scans SET summary=? WHERE id=?", (json.dumps(summary), result.scan_id))
    audit("scan.complete", f"{result.kind} {result.target} risk={result.risk_score}", result.scope_id)
    return result.scan_id


def update_scan_status(scan_id: str, status: str, error: str = "") -> None:
    with connect() as conn:
        conn.execute("UPDATE scans SET status=?, error=? WHERE id=?", (status, error or None, scan_id))


def list_scans(limit: int = 50, kind: str = "") -> list[dict]:
    query = "SELECT id,kind,target,profile,scope_id,status,started_at,finished_at,risk_score,summary FROM scans"
    params: list[Any] = []
    if kind:
        query += " WHERE kind=?"
        params.append(kind)
    query += " ORDER BY started_at DESC LIMIT ?"
    params.append(min(max(int(limit), 1), 500))
    with connect() as conn:
        rows = conn.execute(query, params).fetchall()
    out = []
    for row in rows:
        record = dict(row)
        try:
            record["summary"] = json.loads(record.get("summary") or "{}")
        except ValueError:
            record["summary"] = {}
        out.append(record)
    return out


def get_scan(scan_id: str) -> dict | None:
    with connect() as conn:
        row = conn.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone()
    if not row:
        return None
    record = dict(row)
    try:
        record["result"] = json.loads(record.get("result") or "null")
        record["summary"] = json.loads(record.get("summary") or "{}")
    except ValueError:
        pass
    return record


def delete_scan(scan_id: str) -> bool:
    with connect() as conn:
        cur = conn.execute("DELETE FROM scans WHERE id=?", (scan_id,))
        changed = cur.rowcount > 0
    if changed:
        audit("scan.delete", scan_id)
    return changed


def stats() -> dict:
    with connect() as conn:
        scans = conn.execute("SELECT COUNT(*) c, AVG(risk_score) r FROM scans").fetchone()
        scopes = conn.execute("SELECT COUNT(*) c FROM scopes WHERE status='active'").fetchone()
        by_kind = conn.execute("SELECT kind, COUNT(*) c FROM scans GROUP BY kind").fetchall()
        rows = conn.execute("SELECT result FROM scans ORDER BY started_at DESC LIMIT 200").fetchall()
    severity = {k: 0 for k in ("critical", "high", "medium", "low", "info")}
    for row in rows:
        try:
            data = json.loads(row["result"] or "{}")
        except ValueError:
            continue
        for finding in data.get("findings", []):
            key = str(finding.get("severity", "info")).lower()
            if key in severity:
                severity[key] += 1
    return {
        "scans": scans["c"] if scans else 0,
        "avg_risk": round(scans["r"] or 0, 1) if scans else 0.0,
        "active_scopes": scopes["c"] if scopes else 0,
        "by_kind": {r["kind"]: r["c"] for r in by_kind},
        "severity": severity,
        "recent": list_scans(limit=8),
        "audit": audit_trail(limit=25),
    }
