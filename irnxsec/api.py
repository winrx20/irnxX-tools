"""Localhost-only HTTP API and dashboard host.

Binding policy: the server refuses to start on a non-loopback address unless the
operator explicitly passes ``--allow-remote`` AND their settings already allow it, because
the dashboard holds engagement data and can launch scans. Requests must come from a
loopback client and must carry the installation token (header ``X-IRNX-Token`` or query
``token=`` for downloads). Every mutating action is written to the audit trail.
"""
from __future__ import annotations

import ipaddress
import json
import os
from pathlib import Path
from typing import Any

from fastapi import Body, FastAPI, HTTPException, Query, Request
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, Response
from pydantic import BaseModel, Field

from . import authz, config, payloads, reports, store
from .models import ScanRequest
from .runner import runner

UI_PATH = Path(__file__).parent / "webui" / "index.html"
LOOPBACK = {"127.0.0.1", "::1", "localhost"}

app = FastAPI(title=f"{config.APP_NAME} API", version=config.VERSION, docs_url=None, redoc_url=None)


# ------------------------------------------------------------------- request models
class ScopeIn(BaseModel):
    name: str = Field(min_length=2, max_length=120)
    organization: str = ""
    contact: str = ""
    authorization: str = "written-permission"
    reference: str = ""
    notes: str = ""
    kind: str = "all"
    targets: list[str] = Field(default_factory=list)
    expires_at: str = ""


class ScanIn(BaseModel):
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


class SettingsIn(BaseModel):
    host: str | None = None
    port: int | None = None
    contact: str | None = None
    timeout: float | None = None
    verify_tls: bool | None = None
    rate_limit: float | None = None
    max_requests: int | None = None
    max_hosts: int | None = None
    require_authz: bool | None = None
    theme: str | None = None


class TargetIn(BaseModel):
    target: str
    kind: str = "web"


# ------------------------------------------------------------------------ security
def _client_is_local(request: Request) -> bool:
    client = request.client.host if request.client else ""
    if client in LOOPBACK:
        return True
    try:
        return ipaddress.ip_address(client).is_loopback
    except ValueError:
        return False


@app.middleware("http")
async def enforce_local_and_token(request: Request, call_next):
    if not _client_is_local(request):
        return JSONResponse({"detail": "This dashboard only accepts loopback connections."}, status_code=403)
    if request.url.path.startswith("/api/"):
        settings = config.load()
        supplied = request.headers.get("x-irnx-token") or request.query_params.get("token", "")
        if not supplied or supplied != settings.api_token:
            return JSONResponse({"detail": "API token rejected. Reload the dashboard from its printed URL."}, status_code=401)
    return await call_next(request)


@app.exception_handler(Exception)
async def unhandled(request: Request, exc: Exception):  # pragma: no cover - safety net
    return JSONResponse({"detail": f"Internal error: {type(exc).__name__}: {exc}"}, status_code=500)


# ------------------------------------------------------------------------ dashboard
@app.get("/", response_class=HTMLResponse)
def index() -> HTMLResponse:
    settings = config.load()
    if not UI_PATH.exists():
        return HTMLResponse(
            "<h1>Dashboard asset missing</h1><p>Expected irnxsec/webui/index.html. "
            "The CLI still works: <code>irnxsec scan &lt;target&gt; --confirm-authorized</code>.</p>",
            status_code=500,
        )
    html = UI_PATH.read_text(encoding="utf-8")
    html = html.replace("__IRNX_TOKEN__", settings.api_token)
    html = html.replace("__IRNX_VERSION__", config.VERSION)
    response = HTMLResponse(html)
    response.headers["Cache-Control"] = "no-store"
    response.headers["Referrer-Policy"] = "no-referrer"
    return response


@app.get("/favicon.ico")
def favicon() -> Response:
    return Response(status_code=204)


# ----------------------------------------------------------------------------- API
@app.get("/api/health")
def health() -> dict:
    return {"ok": True, "app": config.APP_NAME, "version": config.VERSION}


@app.get("/api/overview")
def overview() -> dict:
    return store.stats()


@app.get("/api/scopes")
def list_scopes(active_only: bool = False) -> dict:
    scopes = store.list_scopes(include_revoked=not active_only)
    return {"scopes": scopes}


@app.post("/api/scopes")
def create_scope(payload: ScopeIn) -> dict:
    targets = [t.strip() for t in payload.targets if str(t).strip()]
    if not targets:
        raise HTTPException(400, "At least one in-scope target is required.")
    if payload.kind.lower() not in ("all", "web", "network", "dns"):
        raise HTTPException(400, "kind must be one of: all, web, network, dns.")
    normalized = []
    for target in targets:
        try:
            normalized.append(authz.normalize_scope_target(target, payload.kind))
        except ValueError as exc:
            raise HTTPException(400, f"Invalid target '{target}': {exc}") from exc
    if not normalized:
        raise HTTPException(400, "At least one valid in-scope target is required.")
    scope = store.create_scope({**payload.model_dump(), "targets": normalized})
    return {"scope": scope}


@app.post("/api/scopes/{scope_id}/revoke")
def revoke_scope(scope_id: str) -> dict:
    if not store.revoke_scope(scope_id):
        raise HTTPException(404, "Scope not found or already revoked.")
    return {"ok": True, "scope": store.get_scope(scope_id)}


@app.delete("/api/scopes/{scope_id}")
def delete_scope(scope_id: str) -> dict:
    scope = store.get_scope(scope_id)
    if not scope:
        raise HTTPException(404, "Scope not found.")
    if scope.get("usable"):
        raise HTTPException(409, "Revoke the scope before deleting it, so the audit trail shows the authorization ended.")
    store.delete_scope(scope_id)
    return {"ok": True}


@app.get("/api/scopes/{scope_id}/sheet")
def scope_sheet(scope_id: str):
    scope = store.get_scope(scope_id)
    if not scope:
        raise HTTPException(404, "Scope not found.")
    try:
        from .pdf import render_scope_sheet

        path = render_scope_sheet(scope)
    except RuntimeError as exc:
        raise HTTPException(503, str(exc)) from exc
    return FileResponse(path, media_type="application/pdf", filename=path.name)


@app.post("/api/scopes/{scope_id}/certificate")
def issue_certificate(scope_id: str) -> dict:
    try:
        certificate = authz.issue_certificate(scope_id)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    return {"certificate": certificate}


@app.get("/api/certificates")
def list_certificates() -> dict:
    return {"certificates": authz.list_certificates()}


@app.get("/api/certificates/{certificate_id}/pdf")
def certificate_pdf(certificate_id: str):
    path = authz.certificate_path(certificate_id, "pdf")
    if not path:
        raise HTTPException(404, "Certificate PDF not found. Re-issue the certificate to regenerate it.")
    return FileResponse(path, media_type="application/pdf", filename=path.name)


@app.get("/api/certificates/{certificate_id}/json")
def certificate_json(certificate_id: str):
    path = authz.certificate_path(certificate_id, "json")
    if not path:
        raise HTTPException(404, "Certificate not found.")
    return FileResponse(path, media_type="application/json", filename=path.name)


@app.post("/api/targets/validate")
def validate_target(payload: TargetIn) -> dict:
    """Parse a target and report whether an active scope would authorize it.

    ``valid`` answers "is this a usable target string"; ``covered`` answers "would a scan
    be allowed right now". Both are returned so the UI can tell the operator the truth
    before they submit.
    """
    try:
        normalized = authz.normalize_target(payload.target, payload.kind)
    except ValueError as exc:
        return {"valid": False, "covered": False, "normalized": "", "host": "", "lab": False, "reason": str(exc)}
    host = authz.host_of(normalized, payload.kind)
    lab = authz.is_lab_target(host)
    decision = authz.Guard(require_authz=config.load().require_authz).authorize(
        normalized, payload.kind, confirm=True
    )
    return {
        "valid": True,
        "covered": decision.allowed,
        "normalized": normalized,
        "host": host,
        "lab": lab,
        "reason": decision.reason,
        "scope_id": decision.scope_id,
    }


@app.post("/api/scans")
def start_scan(payload: ScanIn) -> dict:
    request = ScanRequest(
        target=payload.target,
        kind=payload.kind,
        profile=payload.profile,
        scope_id=payload.scope_id,
        confirm_authorized=payload.confirm_authorized,
        timeout=payload.timeout,
        rate_limit=payload.rate_limit,
        max_requests=payload.max_requests,
        max_hosts=payload.max_hosts,
        ports=payload.ports,
        verify_tls=payload.verify_tls,
    )
    try:
        scan_id, status = runner.submit(request)
    except PermissionError as exc:
        raise HTTPException(403, str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    return {"scan_id": scan_id, "status": status}


@app.get("/api/scans")
def list_scans(limit: int = Query(50, ge=1, le=200), kind: str = "") -> dict:
    return {"scans": store.list_scans(limit=limit, kind=kind)}


@app.get("/api/scans/{scan_id}")
def get_scan(scan_id: str) -> dict:
    record = store.get_scan(scan_id)
    if not record:
        raise HTTPException(404, "Scan not found.")
    return {
        "id": record["id"],
        "kind": record["kind"],
        "target": record["target"],
        "profile": record["profile"],
        "scope_id": record["scope_id"],
        "status": record["status"],
        "started_at": record["started_at"],
        "finished_at": record["finished_at"],
        "risk_score": record["risk_score"],
        "summary": record.get("summary") or {},
        "result": record.get("result") or {},
        "error": record.get("error") or "",
    }


@app.delete("/api/scans/{scan_id}")
def delete_scan(scan_id: str) -> dict:
    if not store.delete_scan(scan_id):
        raise HTTPException(404, "Scan not found.")
    return {"ok": True}


@app.get("/api/scans/{scan_id}/report")
def scan_report(scan_id: str, format: str = Query("json")):  # noqa: A002 - matches API contract
    record = store.get_scan(scan_id)
    if not record or not record.get("result"):
        raise HTTPException(404, "Scan not found or has no stored result.")
    result = __import__("irnxsec.models", fromlist=["ScanResult"]).ScanResult.from_dict(record["result"])
    fmt = format.lower()
    if fmt == "json":
        return Response(
            json.dumps(result.to_dict(), indent=2, ensure_ascii=False),
            media_type="application/json",
            headers={"Content-Disposition": f'attachment; filename="{scan_id}.json"'},
        )
    if fmt in ("md", "markdown"):
        return Response(
            reports.render_markdown(result),
            media_type="text/markdown",
            headers={"Content-Disposition": f'attachment; filename="{scan_id}.md"'},
        )
    if fmt == "html":
        return Response(
            reports.render_html(result),
            media_type="text/html",
            headers={"Content-Disposition": f'attachment; filename="{scan_id}.html"'},
        )
    if fmt == "csv":
        return Response(
            reports.csv_rows(result),
            media_type="text/csv",
            headers={"Content-Disposition": f'attachment; filename="{scan_id}.csv"'},
        )
    if fmt == "pdf":
        try:
            path = config.reports_dir() / f"{scan_id}.pdf"
            reports.render_pdf(result, path)
        except RuntimeError as exc:
            raise HTTPException(503, str(exc)) from exc
        return FileResponse(path, media_type="application/pdf", filename=path.name)
    raise HTTPException(400, "format must be json, md, html, csv or pdf.")


@app.get("/api/payloads")
def canary_catalogue() -> dict:
    return {
        "canaries": [
            {
                "name": c.name,
                "category": c.category,
                "purpose": c.purpose,
                "render": c.render(payloads.new_token()),
            }
            for c in payloads.CANARIES
        ],
        "note": (
            "Non-exploiting validation markers only. Each is rendered with a scan-unique token so a "
            "reflection can be attributed to this run. They do not extract data, execute code or bypass auth."
        ),
    }


@app.get("/api/settings")
def get_settings() -> dict:
    settings = config.load()
    data = {
        "host": settings.host,
        "port": settings.port,
        "contact": settings.contact,
        "timeout": settings.timeout,
        "verify_tls": settings.verify_tls,
        "rate_limit": settings.rate_limit,
        "max_requests": settings.max_requests,
        "max_hosts": settings.max_hosts,
        "require_authz": settings.require_authz,
        "theme": settings.theme,
    }
    token = settings.api_token
    return {
        "settings": data,
        "public_key": authz.public_key_pem(),
        "token_hint": f"{token[:4]}...{token[-4:]}" if len(token) > 8 else "****",
    }


@app.post("/api/settings")
def update_settings(payload: SettingsIn) -> dict:
    changes = {k: v for k, v in payload.model_dump().items() if v is not None}
    if "port" in changes and not (1 <= int(changes["port"]) <= 65535):
        raise HTTPException(400, "port must be between 1 and 65535.")
    if "host" in changes and changes["host"] not in LOOPBACK and not config.load().allow_remote:
        raise HTTPException(400, "Host must stay on loopback for this installation.")
    if "rate_limit" in changes:
        changes["rate_limit"] = max(0.5, min(float(changes["rate_limit"]), 20.0))
    if "timeout" in changes:
        changes["timeout"] = max(2.0, min(float(changes["timeout"]), 30.0))
    settings = config.update(**changes)
    store.audit("settings.update", ", ".join(sorted(changes)) or "no-op")
    return {
        "settings": {
            "host": settings.host,
            "port": settings.port,
            "contact": settings.contact,
            "timeout": settings.timeout,
            "verify_tls": settings.verify_tls,
            "rate_limit": settings.rate_limit,
            "max_requests": settings.max_requests,
            "max_hosts": settings.max_hosts,
            "require_authz": settings.require_authz,
            "theme": settings.theme,
        },
        "restart_required": bool({"host", "port"} & set(changes)),
    }


@app.get("/api/audit")
def audit(limit: int = Query(200, ge=1, le=1000)) -> dict:
    return {"audit": store.audit_trail(limit)}


@app.get("/api/engines")
def engines() -> dict:
    return {
        "engines": [
            {"kind": "web", "label": "Web application", "description": "Transport, headers, TLS, exposure, crawl and input-validation canaries."},
            {"kind": "network", "label": "Network / ports", "description": "Bounded TCP connect discovery, service hints, TLS posture."},
            {"kind": "dns", "label": "DNS / domain", "description": "Records, mail authentication, delegation, subdomain sweep."},
        ],
        "profiles": {name: {"label": prof["label"], **prof} for name, prof in config.PROFILES.items()},
    }


# ------------------------------------------------------------------------- launcher
def serve(host: str | None = None, port: int | None = None, open_browser: bool = True, allow_remote: bool = False) -> None:
    import threading
    import webbrowser

    import uvicorn

    settings = config.load()
    bind_host = host or settings.host or config.DEFAULT_HOST
    bind_port = int(port or settings.port or config.DEFAULT_PORT)
    remote = bind_host not in LOOPBACK
    if remote and not allow_remote:
        raise SystemExit(
            f"Refusing to bind {bind_host}: the dashboard exposes engagement data and scan control. "
            "Use --allow-remote only on a trusted host, and put it behind your own access control."
        )
    if remote:
        print("WARNING: binding to a non-loopback interface. The API token is your only access control.")
    url = f"http://{'127.0.0.1' if remote else bind_host}:{bind_port}/"
    print(f"{config.APP_NAME} {config.VERSION}")
    print(f"  data dir : {config.home()}")
    print(f"  dashboard: {url}")
    print("  the dashboard embeds its API token at load time; open it in the browser on this machine")
    print("  stop with Ctrl+C")
    if open_browser:
        threading.Timer(1.2, lambda: webbrowser.open(url)).start()
    uvicorn.run(app, host=bind_host, port=bind_port, log_level="warning", access_log=False)
