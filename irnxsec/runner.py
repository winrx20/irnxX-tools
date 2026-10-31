"""Scan orchestration: authorization gate, job registry, execution and persistence."""
from __future__ import annotations

import threading
import traceback
from dataclasses import dataclass, field

from . import authz, config, store
from .engines import ENGINES
from .models import ScanRequest, ScanResult


@dataclass
class Job:
    scan_id: str
    request: dict
    status: str = "queued"
    error: str = ""
    thread: threading.Thread | None = None
    lock: threading.Lock = field(default_factory=threading.Lock)


class Runner:
    """In-process job manager. Single-machine, no broker, no daemon."""

    def __init__(self) -> None:
        self._jobs: dict[str, Job] = {}
        self._lock = threading.Lock()
        self._active: set[str] = set()

    # ------------------------------------------------------------------ submit
    def submit(self, request: ScanRequest) -> tuple[str, str]:
        """Validate, authorize and start a scan. Returns (scan_id, status)."""
        kind = (request.kind or "web").lower()
        if kind not in ENGINES:
            raise ValueError(f"Unsupported scan kind '{kind}'. Choose one of: {', '.join(ENGINES)}.")
        target = authz.normalize_target(request.target, kind)
        settings = config.load()
        decision = authz.Guard(require_authz=settings.require_authz).authorize(
            target, kind, scope_id=request.scope_id, confirm=request.confirm_authorized
        )
        if not decision.allowed:
            store.audit("scan.blocked", f"{kind} {target}: {decision.reason}", request.scope_id)
            raise PermissionError(decision.reason)
        request.target = target
        result = ScanResult(kind=kind, target=target, profile=request.profile, scope_id=decision.scope_id)
        result.authorization = {
            "scope_id": decision.scope_id,
            "reason": decision.reason,
            "confirmed_at": result.started_at,
            "lab_target": decision.scope_id == "LAB",
        }
        store.update_scan_status(result.scan_id, "queued")
        self._persist_placeholder(result, request)
        job = Job(scan_id=result.scan_id, request=request.to_dict())
        with self._lock:
            self._jobs[result.scan_id] = job
        thread = threading.Thread(target=self._run, args=(job, request, result), name=f"irnx-{result.scan_id}", daemon=True)
        job.thread = thread
        thread.start()
        store.audit("scan.start", f"{kind} {target} profile={request.profile}", decision.scope_id)
        return result.scan_id, "running"

    def run_sync(self, request: ScanRequest) -> ScanResult:
        """Blocking execution for the CLI."""
        kind = (request.kind or "web").lower()
        if kind not in ENGINES:
            raise ValueError(f"Unsupported scan kind '{kind}'.")
        target = authz.normalize_target(request.target, kind)
        settings = config.load()
        decision = authz.Guard(require_authz=settings.require_authz).authorize(
            target, kind, scope_id=request.scope_id, confirm=request.confirm_authorized
        )
        if not decision.allowed:
            store.audit("scan.blocked", f"{kind} {target}: {decision.reason}", request.scope_id)
            raise PermissionError(decision.reason)
        request.target = target
        result = ScanResult(kind=kind, target=target, profile=request.profile, scope_id=decision.scope_id)
        result.authorization = {
            "scope_id": decision.scope_id,
            "reason": decision.reason,
            "confirmed_at": result.started_at,
            "lab_target": decision.scope_id == "LAB",
        }
        self._persist_placeholder(result, request)
        store.audit("scan.start", f"{kind} {target} profile={request.profile}", decision.scope_id)
        return self._execute(request, result)

    # ------------------------------------------------------------------ internal
    def _persist_placeholder(self, result: ScanResult, request: ScanRequest) -> None:
        result.metadata["request"] = request.to_dict()
        store.save_scan(result, status="queued")

    def _run(self, job: Job, request: ScanRequest, result: ScanResult) -> None:
        with job.lock:
            job.status = "running"
        store.update_scan_status(result.scan_id, "running")
        try:
            self._execute(request, result)
            with job.lock:
                job.status = "complete"
        except Exception as exc:  # a scan crash must be visible, never silent
            message = f"{type(exc).__name__}: {exc}"
            store.update_scan_status(result.scan_id, "failed", message)
            store.audit("scan.failed", message, result.scope_id)
            with job.lock:
                job.status = "failed"
                job.error = message
            config.logs_dir().joinpath(f"{result.scan_id}.error.log").write_text(
                traceback.format_exc(), encoding="utf-8"
            )
        finally:
            with self._lock:
                self._active.discard(result.scan_id)

    def _execute(self, request: ScanRequest, result: ScanResult) -> ScanResult:
        engine = ENGINES[(request.kind or "web").lower()]
        engine(request, result)
        from .reports import write_reports

        reports = write_reports(result)
        store.save_scan(result, reports=reports, status="complete")
        return result

    # ---------------------------------------------------------------- accessors
    def status(self, scan_id: str) -> str:
        record = store.get_scan(scan_id)
        return (record or {}).get("status", "unknown")

    def active(self) -> list[str]:
        return sorted(self._active)


runner = Runner()


def scan(request: ScanRequest) -> ScanResult:
    """Convenience wrapper used by the CLI and tests."""
    return runner.run_sync(request)
