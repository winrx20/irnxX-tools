# IRNXSEC Pro

**Authorized web & network assessment toolkit with a localhost dashboard and signed engagement certificates.**

IRNXSEC Pro is a single-operator security assessment workbench. It runs only on your
own machine (`127.0.0.1`), refuses to test anything that is not covered by a registered
authorization scope, and produces client-ready reports plus a cryptographically signed
proof-of-authorization certificate for every engagement.

```
  ___ ____  _  ___  __ _____ ____    ____  ____   ___
 |_ _|  _ \| \| \ \/ /| ____/ ___|  |  _ \|  _ \ / _ \
  | || |_) | .` |\  / |  _| \___ \  | |_) | |_) | | | |
  | ||  _ <| |\ |/  \ | |___ ___) | |  __/|  _ <| |_| |
 |___|_| \_\_| \_/_/\_\|_____|____/  |_|   |_| \_\\___/
```

> **Legal first.** Every scan requires (a) a ticked confirmation that you own the target
> or hold written permission, **and** (b) an active, unexpired authorization scope that
> lists the target. Loopback and private lab ranges are always allowed because they can
> never reach a third party. This is enforceable software behaviour, not a README promise.

---

## What it actually does

| Engine | Kind | Checks |
| --- | --- | --- |
| **Web** | `web` | HTTP posture, redirect/downgrade detection, TLS handshake & certificate validation, missing security headers (CSP/HSTS/XCTO/XFO/Referrer/Permissions), CSP weakness, cookie flags, advertised HTTP methods + TRACE, sensitive file exposure (`.env`, `.git/HEAD`, backups, `phpinfo`, Spring actuator…) with content signatures and a soft-404 baseline, `robots.txt` disclosure, DNS context, same-origin crawl, and non-exploiting input-validation canaries (reflection encoding, SQL error triage, open redirect). |
| **Network** | `network` | Bounded TCP connect discovery over a port profile or custom list/range, service hints, banner grab, TLS posture per port, and severity-weighted findings for services that should never be internet-reachable (Redis, Mongo, Docker API, RDP, Elasticsearch, Kubelet…). Hard caps on hosts, ports and total probes. |
| **DNS** | `dns` | Record inventory (A/AAAA/CNAME/MX/NS/TXT/SOA/CAA), SPF/DMARC analysis, CAA presence, DNSSEC check, wildcard DNS detection, subdomain-takeover *candidates*, bounded subdomain sweep, and AXFR zone-transfer test in the deep profile. |

Everything is **non-destructive by construction**: GET/POST/OPTIONS to a bounded path set,
plain TCP connects (no SYN flood, no exploitation), read-only DNS queries. No brute force,
no credential attacks, no denial of service, no exploit chains, no data extraction.

### Findings are graded by evidence quality

Every finding carries `confidence`:

* `confirmed` – directly observed (e.g. `/.env` returned 200 **and** the body matched its signature)
* `firm` – strongly indicated by observed behaviour (e.g. a quote canary produced a new database error)
* `tentative` – heuristic that needs a human (e.g. dangling CNAME to a SaaS provider)

A reflection is reported as **low**, with the caveat that reflection alone is not XSS.
Missing headers are hardening, not vulnerabilities. Nothing is upgraded to "exploitable"
without direct observation.

---

## Install

### Linux / macOS / WSL

```bash
git clone https://github.com/winrx20/irnxX-tools.git
cd irnxX-tools
./install.sh              # creates .venv, installs full extras, runs the test suite
```

### Windows (PowerShell)

```powershell
git clone https://github.com/winrx20/irnxX-tools.git
cd irnxX-tools
.\install.ps1
```

### Termux (Android)

```bash
pkg update && pkg install python git -y
git clone https://github.com/winrx20/irnxX-tools.git
cd irnxX-tools && bash install_termux.sh
```

### Manual

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -e '.[full]'        # full = pdf + dns + certificates
irnxsec --help
```

Minimum install (`pip install -e .`) works for web/network scanning and HTML/JSON/Markdown
reports; PDF, DNS engine and signed certificates need the `full` extras.

---

## Use it

### 1. Register the engagement first

```bash
irnxsec scope add \
  --name 'ACME Q4 external' \
  --targets acme.example '*.acme.example' \
  --authorization written-permission \
  --reference CTR-2026-014 \
  --organization 'ACME Corp' \
  --contact security@acme.example \
  --expires 2026-12-31
# -> Scope created: SC-40CC7D8B3F
```

Targets accept exact hosts, `*.wildcard`, CIDR ranges and full URLs. Kind can be
`all`, `web`, `network` or `dns`.

### 2. Issue the signed authorization certificate

```bash
irnxsec certificate issue SC-40CC7D8B3F
#  json : ~/.irnxsec/certs/IRNX-CERT-XXXXXXXXXXXX.json
#  pdf  : ~/.irnxsec/certs/IRNX-CERT-XXXXXXXXXXXX.pdf
```

You get a landscape-A4 PDF you can hand to the asset owner **before** testing, plus a JSON
record with an **Ed25519** signature over the scope payload. Verification:

```bash
irnxsec certificate verify ~/.irnxsec/certs/IRNX-CERT-XXXXXXXXXXXX.json
# {"valid": true, "reason": "Signature valid and scope active."}
```

Tampering with the payload, revoking the scope or letting it expire all make verification
fail. A scope sheet with signature lines for both parties: `irnxsec scope sheet SC-…`.

### 3. Scan

```bash
# web application
irnxsec scan https://acme.example --confirm-authorized --report

# deep web assessment, faster rate, snapshot to JSON only
irnxsec scan https://acme.example --profile deep --rate 8 --json > acme.json

# network exposure over a customer subnet
irnxsec scan 203.0.113.0/28 --kind network --ports 22,80,443,3306,3389,6379,9200

# domain / DNS posture
irnxsec scan acme.example --kind dns --profile deep

# your own local lab needs no scope
irnxsec scan http://127.0.0.1:8080 --confirm-authorized
```

Without a covering scope:

```
[AUTHORIZATION BLOCKED] No active authorization scope covers acme.example. Register the
engagement (with written permission) first.
# exit code 3
```

### 4. Dashboard

```bash
irnxsec serve            # opens http://127.0.0.1:8787/
```

Nine screens: **Dashboard** (risk + severity chart + recent scans), **New scan** (live
progress), **Scan detail** (findings drawer with evidence, observations, report downloads),
**Scopes** (the authorization registry), **Certificates**, **History**, **Canaries**,
**Settings**, **Audit**.

The dashboard binds to loopback, rejects non-loopback clients at the middleware, and
requires the installation token that is injected into the page at load time. Binding to a
non-loopback interface requires both `--allow-remote` and `allow_remote = true` in settings.

### Useful commands

```bash
irnxsec history --limit 20          # recorded scans
irnxsec audit --limit 50            # who did what, and when
irnxsec settings                    # show configuration + token hint
irnxsec settings --set rate_limit=6 timeout=10
irnxsec payloads                    # the non-exploiting canary catalogue
irnxsec scope list | revoke <id> | sheet <id>
```

---

## Reports

Written to `~/.irnxsec/reports/` (and downloadable from the dashboard): **JSON** (full
machine record), **Markdown**, **self-contained HTML** (dark, no external assets) and
**PDF** (A4, severity summary, per-finding evidence and remediation). Every report carries
the scan id, the authorization reason, the profile, request count and an explicit
"validate manually" caveat.

---

## How the guard works

```
scan request
   │
   ├─ normalize the target (scheme, host, CIDR)
   ├─ loopback / private / .lab / .test?  →  allowed as LAB, no scope
   ├─ confirmation ticked?               →  no  →  blocked
   ├─ scope given?  →  covers host+kind? →  yes →  run, else blocked
   └─ otherwise any active scope covering host+kind? → run, else blocked
```

* Scopes expire (`expires_at`) and can be revoked; both instantly close the gate.
* Deleting a scope requires revocation first, so the audit trail never loses the fact that
  authorization ended.
* Every blocked attempt is written to the audit log.

---

## Data & privacy

* Everything lives in `~/.irnxsec/` — SQLite database, reports, certificates, signing key,
  error logs. Override with `IRNXSEC_HOME=/path`.
* The signing private key is `chmod 600` and never leaves your machine.
* Cookie values are never recorded; only the missing flags are reported.
* Reports state that automated checks are indicative and must be validated manually.

---

## Development

```bash
python -m unittest discover -s tests -t . -v
python -m compileall -q irnxsec tests
```

31 tests cover the authorization gate (fail-closed, wildcard, CIDR, kind, expiry,
revocation), certificate issue/verify/tamper/revoke, engine behaviour against a local
fixture server, report generation, and API authentication.

Layout:

```
irnxsec/
  authz.py       guard + Ed25519 certificates
  httpclient.py  budgeted, rate-limited HTTP client
  crawl.py       same-origin crawler (links, forms, params)
  payloads.py    canaries, header catalogue, sensitive paths
  engines/       webscan.py, net.py, dns.py
  runner.py      job registry, sync + async execution
  reports.py     JSON / Markdown / HTML
  pdf.py         PDF reports, certificates, scope sheets
  store.py       SQLite: scopes, scans, audit
  api.py         FastAPI localhost API + dashboard host
  cli.py         argparse CLI
  webui/         single-file dashboard
```

---

## Limits (read this before trusting output)

* Automated checks are **indicative**. Every finding needs human validation before it goes
  into a client deliverable.
* No JavaScript rendering: single-page apps will look thin to the crawler. Use the browser
  or ZAP/Burp alongside it.
* The web engine does not authenticate. Put the tool in front of a logged-in session with
  curl/Burp for authenticated areas.
* The canaries prove input handling, not exploitation. No payload ever extracts data.
* Port discovery is TCP-connect based and profile-limited; "no ports" is not proof of a
  closed host.
* Subdomain sweep uses a small built-in wordlist, not a full DNS dataset. Pair it with
  ProjectDiscovery `subfinder` if you need breadth.

---

## Related tooling this pairs with

ZAP (proxy + passive rules), Burp Suite Community (manual HTTP), Nmap (deeper port work),
Nuclei (template checks), Subfinder/dnsx/httpx (surface discovery), OWASP WSTG (methodology).
None are bundled — IRNXSEC Pro stays dependency-light on purpose.

---

## License

MIT. Use it only on systems you own or are explicitly authorized in writing to test.
