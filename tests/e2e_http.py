#!/usr/bin/env python3
"""End-to-end smoke test: start the real uvicorn server on loopback, exercise the
HTTP API and the dashboard page, then shut it down. Nothing leaves the machine."""
import json
import os
import re
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request

ROOT = "/workspace/tasks/4cb6d836-71f4-4bed-b20d-52863c6595da"
PY = f"{ROOT}/.venv/bin/python"
HOME = "/tmp/irnx-e2e"
os.environ["IRNXSEC_HOME"] = HOME
os.environ["PYTHONPATH"] = f"{ROOT}/build/irnxsec-pro"

sys.path.insert(0, f"{ROOT}/build/irnxsec-pro")
from irnxsec import config  # noqa: E402

TOKEN = config.load().api_token


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


PORT = free_port()
BASE = f"http://127.0.0.1:{PORT}"

def call(path, method="GET", body=None, token=True, raw=False):
    data = json.dumps(body).encode() if body is not None else None
    headers = {"Content-Type": "application/json"}
    if token:
        headers["X-IRNX-Token"] = TOKEN
    req = urllib.request.Request(BASE + path, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            payload = resp.read()
            return resp.status, (payload if raw else json.loads(payload or b"{}"))
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read() or b"{}")


print(f"starting uvicorn on {BASE} (data dir {HOME})")
proc = subprocess.Popen(
    [PY, "-m", "uvicorn", "irnxsec.api:app", "--host", "127.0.0.1", "--port", str(PORT), "--log-level", "warning"],
    cwd=f"{ROOT}/build/irnxsec-pro",
    env={**os.environ},
    stdout=subprocess.PIPE,
    stderr=subprocess.STDOUT,
)

failures = []

def check(label, condition, detail=""):
    print(f"  {'PASS' if condition else 'FAIL'}  {label}{(' :: ' + str(detail)) if detail and not condition else ''}")
    if not condition:
        failures.append(label)

try:
    for _ in range(60):
        try:
            if call("/api/health")[0] == 200:
                break
        except Exception:
            pass
        time.sleep(0.25)
    else:
        raise SystemExit("server never became ready")

    print("\n[dashboard]")
    status, _ = call("/api/health", token=False)
    check("unauthenticated API call is rejected", status == 401, status)
    page = urllib.request.urlopen(BASE + "/", timeout=10).read().decode()
    check("dashboard renders HTML", "<html" in page.lower() and len(page) > 50000, len(page))
    check("token placeholder is substituted", "__IRNX_TOKEN__" not in page)
    check("dashboard embeds the API token", TOKEN in page)
    check("dashboard has no external asset references", not re.search(r'(src|href)="(https?:)?//', page))

    print("\n[scopes + certificates]")
    status, body = call("/api/scopes", "POST", {
        "name": "E2E engagement", "organization": "Lab Corp", "contact": "sec@lab.example",
        "authorization": "written-permission", "reference": "E2E-2026-1", "kind": "all",
        "targets": ["localhost", "127.0.0.1"],
    })
    check("scope created", status == 200 and body.get("scope", {}).get("id"), (status, body))
    scope_id = body["scope"]["id"]
    status, body = call(f"/api/scopes/{scope_id}/certificate", "POST")
    cert_id = body.get("certificate", {}).get("payload", {}).get("certificate_id")
    check("certificate issued with signature", status == 200 and cert_id and len(body["certificate"]["signature"]) > 40, status)
    status, pdf = call(f"/api/certificates/{cert_id}/pdf", raw=True)
    check("certificate PDF downloads", status == 200 and pdf[:5] == b"%PDF-", (status, pdf[:8]))
    status, body = call("/api/certificates")
    check("certificate listed", any(c["certificate_id"] == cert_id for c in body["certificates"]))

    print("\n[scan lifecycle]")
    status, body = call("/api/scans", "POST", {"target": "https://not-covered-by-any-scope.org", "kind": "web", "confirm_authorized": True})
    check("out-of-scope scan refused", status == 403, (status, body))
    status, body = call("/api/scans", "POST", {"target": "http://127.0.0.1:8899", "kind": "web", "profile": "quick", "confirm_authorized": True})
    check("in-scope lab scan accepted", status == 200 and body.get("scan_id"), (status, body))
    scan_id = body["scan_id"]
    state = {}
    for _ in range(120):
        state = call(f"/api/scans/{scan_id}")[1]
        if state.get("status") in ("complete", "failed"):
            break
        time.sleep(0.5)
    check("scan completed", state.get("status") == "complete", (state.get("status"), state.get("error")))
    findings = state.get("result", {}).get("findings", [])
    check("findings produced", len(findings) > 3, len(findings))
    check("every finding has evidence or a detail", all(f.get("evidence") or f.get("detail") for f in findings))
    check("summary counts match findings", state["summary"]["total"] == len(findings), state.get("summary"))
    for fmt in ("json", "md", "html", "pdf", "csv"):
        status, blob = call(f"/api/scans/{scan_id}/report?format={fmt}", raw=True)
        ok = status == 200 and len(blob) > 100
        if fmt == "pdf":
            ok = ok and blob[:5] == b"%PDF-"
        check(f"report {fmt} downloads", ok, (status, len(blob)))

    print("\n[observability]")
    status, body = call("/api/overview")
    check("overview builds", status == 200 and body["scans"] >= 1 and "severity" in body)
    status, body = call("/api/audit")
    actions = {row["action"] for row in body["audit"]}
    check("audit trail records the engagement", "scope.create" in actions and "certificate.issue" in actions, sorted(actions))
    status, body = call("/api/payloads")
    check("canary catalogue served", status == 200 and len(body["canaries"]) >= 9)
    status, body = call("/api/settings")
    check("settings expose public key only", status == 200 and "BEGIN PUBLIC KEY" in body["public_key"] and "api_token" not in body)

    print("\n[cleanup]")
    check("scan delete works", call(f"/api/scans/{scan_id}", "DELETE")[0] == 200)

finally:
    proc.terminate()
    try:
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        proc.kill()

print("\n" + ("ALL E2E CHECKS PASSED" if not failures else f"FAILURES: {failures}"))
sys.exit(1 if failures else 0)
