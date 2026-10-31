#!/usr/bin/env python3
"""Render the dashboard in headless Chrome against the live API and capture screenshots.

Verifies real browser behaviour: every screen paints, no JavaScript errors, and each
screenshot is a real image of the operator UI. Writes PNGs to artifacts/screenshots.
"""
import json
import os
import re
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

ROOT = "/workspace/tasks/4cb6d836-71f4-4bed-b20d-52863c6595da"
PY = f"{ROOT}/.venv/bin/python"
HOME = "/tmp/irnx-visual"
OUT = f"{ROOT}/artifacts/screenshots"
os.environ["IRNXSEC_HOME"] = HOME
os.environ["PYTHONPATH"] = f"{ROOT}/build/irnxsec-pro"
os.makedirs(OUT, exist_ok=True)

sys.path.insert(0, f"{ROOT}/build/irnxsec-pro")
from irnxsec import config  # noqa: E402

TOKEN = config.load().api_token

with socket.socket() as sock:
    sock.bind(("127.0.0.1", 0))
    PORT = sock.getsockname()[1]
BASE = f"http://127.0.0.1:{PORT}"


def api(path, method="GET", body=None):
    data = json.dumps(body).encode() if body is not None else None
    request = urllib.request.Request(
        BASE + path,
        data=data,
        method=method,
        headers={"Content-Type": "application/json", "X-IRNX-Token": TOKEN},
    )
    with urllib.request.urlopen(request, timeout=60) as response:
        return json.loads(response.read() or b"{}")


proc = subprocess.Popen(
    [PY, "-m", "uvicorn", "irnxsec.api:app", "--host", "127.0.0.1", "--port", str(PORT), "--log-level", "error"],
    cwd=f"{ROOT}/build/irnxsec-pro",
    env={**os.environ},
    stdout=subprocess.DEVNULL,
    stderr=subprocess.DEVNULL,
)

try:
    for _ in range(120):
        try:
            urllib.request.urlopen(BASE + "/api/health", timeout=2)
        except urllib.error.HTTPError as exc:
            if exc.code == 401:
                break
        except Exception:
            time.sleep(0.25)

    print("seeding demo engagement")
    scope = api("/api/scopes", "POST", {
        "name": "ACME external Q4",
        "organization": "ACME Corp",
        "contact": "security@acme.example",
        "authorization": "written-permission",
        "reference": "CTR-2026-014",
        "kind": "all",
        "targets": ["localhost", "127.0.0.1", "acme.example", "*.acme.example"],
        "expires_at": "2026-12-31",
        "notes": "External perimeter review, non-destructive only.",
    })["scope"]
    cert = api(f"/api/scopes/{scope['id']}/certificate", "POST")["certificate"]
    print("  scope", scope["id"], "certificate", cert["payload"]["certificate_id"])

    web = api("/api/scans", "POST", {
        "target": "http://127.0.0.1:8899",
        "kind": "web",
        "profile": "standard",
        "scope_id": scope["id"],
        "confirm_authorized": True,
    })
    scan_id = web["scan_id"]
    state = {}
    for _ in range(160):
        state = api(f"/api/scans/{scan_id}")
        if state.get("status") in ("complete", "failed"):
            break
        time.sleep(0.5)
    print("  web scan", scan_id, state.get("status"), "findings", len(state.get("result", {}).get("findings", [])))

    net = api("/api/scans", "POST", {"target": "127.0.0.1", "kind": "network", "ports": "8899,22,80", "confirm_authorized": True})
    for _ in range(80):
        if api(f"/api/scans/{net['scan_id']}").get("status") in ("complete", "failed"):
            break
        time.sleep(0.4)

    routes = {
        "01-dashboard": "#/dashboard",
        "02-new-scan": "#/new",
        "03-scan-detail": f"#/scan/{scan_id}",
        "04-scopes": "#/scopes",
        "05-certificates": "#/certificates",
        "06-history": "#/history",
        "07-canaries": "#/payloads",
        "08-settings": "#/settings",
        "09-audit": "#/audit",
    }
    profile_dir = tempfile.mkdtemp(prefix="chrome-")
    failures = []
    for name, route in routes.items():
        shot = f"{OUT}/{name}.png"
        if os.path.exists(shot):
            os.remove(shot)
        cmd = [
            "google-chrome", "--headless=new", "--disable-gpu", "--no-sandbox", "--hide-scrollbars",
            "--virtual-time-budget=7000", "--window-size=1500,1000",
            f"--user-data-dir={profile_dir}", f"--screenshot={shot}", f"{BASE}/{route}",
            "--enable-logging=stderr", "--log-level=0",
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        log = (result.stderr or "") + (result.stdout or "")
        with open(f"{OUT}/{name}.console.txt", "w", encoding="utf-8") as handle:
            handle.write(log)
        errors = [
            line for line in log.splitlines()
            if re.search(r"Uncaught|SEVERE.*(javascript|CONSOLE)", line) and "favicon" not in line.lower()
        ]
        size = os.path.getsize(shot) if os.path.exists(shot) else 0
        ok = size > 30000 and not errors
        print(f"  {'PASS' if ok else 'FAIL'}  {name:18s} {size:7d} bytes  {route}")
        if not ok:
            failures.append(name)
            for line in errors[:5]:
                print("        ", line[:220])
    print("\n" + ("VISUAL PASS: all screens rendered" if not failures else f"FAILURES: {failures}"))
    sys.exit(1 if failures else 0)
finally:
    proc.terminate()
    try:
        proc.wait(timeout=8)
    except subprocess.TimeoutExpired:
        proc.kill()
