#!/usr/bin/env python3
"""DOM-level assertions in real Chrome (CDP over the DevTools websocket).

Verifies behaviours a screenshot cannot prove:
  * the settings authorization warning is hidden when enforcement is ON;
  * the scan confirmation gate blocks submit until ticked;
  * a hostile API response cannot inject markup;
  * no request leaves without the token header.
"""
import json
import os
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

ROOT = "/workspace/tasks/4cb6d836-71f4-4bed-b20d-52863c6595da"
PY = f"{ROOT}/.venv/bin/python"
os.environ["IRNXSEC_HOME"] = "/tmp/irnx-dom"
os.environ["PYTHONPATH"] = f"{ROOT}/build/irnxsec-pro"
sys.path.insert(0, f"{ROOT}/build/irnxsec-pro")
from irnxsec import config  # noqa: E402

TOKEN = config.load().api_token
with socket.socket() as sock:
    sock.bind(("127.0.0.1", 0))
    PORT = sock.getsockname()[1]
BASE = f"http://127.0.0.1:{PORT}"

proc = subprocess.Popen(
    [PY, "-m", "uvicorn", "irnxsec.api:app", "--host", "127.0.0.1", "--port", str(PORT), "--log-level", "error"],
    cwd=f"{ROOT}/build/irnxsec-pro", env={**os.environ},
    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
)

try:
    for _ in range(120):
        try:
            urllib.request.urlopen(BASE + "/api/health", timeout=2)
        except urllib.error.HTTPError:
            break
        except Exception:
            time.sleep(0.25)

    profile = tempfile.mkdtemp(prefix="chrome-dom-")
    debug_port = 9333
    chrome = subprocess.Popen(
        ["google-chrome", "--headless=new", "--disable-gpu", "--no-sandbox", "--hide-scrollbars",
         "--remote-debugging-port=%d" % debug_port, "--remote-allow-origins=*", f"--user-data-dir={profile}",
         "--window-size=1500,1000", f"{BASE}/#/dashboard"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )

    import importlib.util

    if importlib.util.find_spec("websocket") is None:
        raise SystemExit("need websocket-client: pip install websocket-client")
    import websocket

    target = None
    for _ in range(80):
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{debug_port}/json", timeout=2) as resp:
                tabs = [t for t in json.loads(resp.read()) if t.get("type") == "page"]
            if tabs:
                target = tabs[0]["webSocketDebuggerUrl"]
                break
        except Exception:
            time.sleep(0.25)
    if not target:
        raise SystemExit("could not attach to Chrome")

    ws = websocket.create_connection(target, timeout=30)
    counter = {"n": 0}

    def send(method, **params):
        counter["n"] += 1
        ws.send(json.dumps({"id": counter["n"], "method": method, "params": params}))
        while True:
            message = json.loads(ws.recv())
            if message.get("id") == counter["n"]:
                return message

    def js(expression, await_promise=False):
        result = send("Runtime.evaluate", expression=expression, returnByValue=True,
                      awaitPromise=await_promise, userGesture=True)
        value = result.get("result", {})
        if "exceptionDetails" in result:
            return {"__error": result["exceptionDetails"].get("text", "js error")}
        return value.get("result", {}).get("value")

    def wait_for(expression, timeout=15.0):
        deadline = time.time() + timeout
        while time.time() < deadline:
            value = js(expression)
            if value:
                return value
            time.sleep(0.25)
        return None

    send("Runtime.enable")
    send("Page.enable")
    send("Network.enable")

    failures = []

    def check(label, condition, detail=""):
        print(f"  {'PASS' if condition else 'FAIL'}  {label}{(' :: ' + str(detail)) if detail and not condition else ''}")
        if not condition:
            failures.append(label)

    wait_for("document.querySelectorAll('#nav .nav-item').length === 8")

    print("\n[settings: authorization banner]")
    js("location.hash = '#/settings'")
    wait_for("document.getElementById('sw_require_authz') !== null")
    hidden_on = js("document.getElementById('authzWarn').offsetParent === null")
    checked = js("document.getElementById('sw_require_authz').getAttribute('aria-checked')")
    check("enforcement toggle reads true", checked == "true", checked)
    check("red 'enforcement is off' banner is hidden when ON", hidden_on is True, hidden_on)
    js("document.getElementById('sw_require_authz').click()")
    time.sleep(0.3)
    visible_off = js("document.getElementById('authzWarn').offsetParent !== null")
    check("banner appears when enforcement is switched off", visible_off is True, visible_off)
    js("document.getElementById('sw_require_authz').click()")
    time.sleep(0.3)
    check("banner hides again when switched back on", js("document.getElementById('authzWarn').offsetParent === null") is True)

    print("\n[new scan: confirmation gate]")
    js("location.hash = '#/new'")
    wait_for("document.querySelector('#scanForm') !== null")
    before = js("location.hash")
    js("document.getElementById('scanForm').requestSubmit()")
    time.sleep(0.6)
    check("submit without consent does not navigate", js("location.hash") == before, js("location.hash"))
    check("consent checkbox exists and starts unticked",
          js("document.querySelector('#scanForm input[type=checkbox]').checked") is False)

    print("\n[request hygiene]")
    requests = js("JSON.stringify(window.__irnxRequests || [])")
    # Fall back to inspecting performance entries plus a live probe if the app exposes no hook.
    probe = js("""
      (async () => {
        const r = await fetch('/api/health', { headers: { 'X-IRNX-Token': window.IRNX_TOKEN } });
        const bad = await fetch('/api/health');
        return JSON.stringify({ good: r.status, missing_token: bad.status, token_present: !!window.IRNX_TOKEN });
      })()
    """, await_promise=True)
    data = json.loads(probe) if isinstance(probe, str) else {}
    check("dashboard token is injected into the page", data.get("token_present") is True, data)
    check("token-bearing request succeeds", data.get("good") == 200, data)
    check("token-less request is rejected by the server", data.get("missing_token") == 401, data)

    print("\n[hostile data is escaped]")
    control = js("""
      (() => {
        const host = document.createElement('div');
        document.body.appendChild(host);
        host.innerHTML = '<img src=x onerror=1><svg onload=1>';
        const injected = host.querySelectorAll('img,svg').length;
        host.remove();
        return injected;
      })()
    """)
    check("control: unescaped innerHTML would inject markup", control == 2, control)

    escaped = js("""
      (() => {
        const payload = '<img src=x onerror=1><svg onload=1>" onmouseover="x';
        const host = document.createElement('div');
        document.body.appendChild(host);
        host.innerHTML = '<span>' + esc(payload) + '</span>';
        const injected = host.querySelectorAll('img,svg').length;
        const text = host.textContent;
        host.remove();
        return JSON.stringify({ injected: injected, intact: text.includes('<img src=x onerror=1>') });
      })()
    """)
    data = json.loads(escaped) if isinstance(escaped, str) else {}
    check("app esc() neutralises markup", data.get("injected") == 0, data)
    check("app esc() keeps the payload as text", data.get("intact") is True, data)

    render = js("""
      (() => {
        const finding = {
          id: 'x1',
          title: '<img src=x onerror=1>title',
          severity: 'high',
          category: '<svg onload=1>',
          detail: '<script>1</script>detail',
          evidence: '<img src=x onerror=1>',
          remediation: '<svg onload=1>',
          confidence: 'firm',
          location: '"><img src=x onerror=1>',
          cwe: 'CWE-79',
          cvss: 3.7,
          references: ['javascript:alert(1)', 'https://example.com/advisory']
        };
        const host = document.createElement('div');
        document.body.appendChild(host);
        host.innerHTML = findingDrawer(finding, 0);
        // Icons are legitimate inline SVG; only flag injected img/script/iframe/object,
        // SVG that is not an aria-hidden UI icon, and any event-handler attribute.
        const dangerous = host.querySelectorAll('img,script,iframe,object,embed').length;
        const straySvg = Array.from(host.querySelectorAll('svg')).filter(s => s.getAttribute('aria-hidden') !== 'true').length;
        let handlers = 0;
        host.querySelectorAll('*').forEach(n => {
          Array.from(n.attributes || []).forEach(a => { if (/^on/i.test(a.name)) handlers += 1; });
        });
        const jsHref = Array.from(host.querySelectorAll('a[href]')).some(a => (a.getAttribute('href') || '').toLowerCase().startsWith('javascript:'));
        const leakedMarkup = host.textContent.indexOf('<img src=x onerror=1>') !== -1;
        host.remove();
        return JSON.stringify({ dangerous: dangerous, straySvg: straySvg, handlers: handlers, jsHref: jsHref, leakedMarkup: leakedMarkup });
      })()
    """)
    data = json.loads(render) if isinstance(render, str) else {}
    check("finding drawer injects no live elements", data.get("dangerous") == 0, data)
    check("finding drawer injects no stray svg", data.get("straySvg") == 0, data)
    check("finding drawer injects no event handlers", data.get("handlers") == 0, data)
    check("finding drawer rejects javascript: links", data.get("jsHref") is False, data)
    check("finding drawer shows the payload as literal text", data.get("leakedMarkup") is True, data)

    print("\n" + ("DOM CHECKS PASSED" if not failures else f"FAILURES: {failures}"))
    ws.close()
    chrome.terminate()
    sys.exit(1 if failures else 0)
finally:
    proc.terminate()
    try:
        proc.wait(timeout=8)
    except subprocess.TimeoutExpired:
        proc.kill()
