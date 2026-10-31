"""Command-line interface.

Two families of commands:
* ``scan``  - run an assessment (web / network / dns) and print or save results;
* ``scope`` - manage engagements and certificates (the authorization registry).

The CLI prints human output by default and JSON with ``--json`` for automation.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import authz, config, payloads, reports, store
from .models import SEVERITY_ORDER, ScanRequest, ScanResult
from .runner import runner

BANNER = r"""
  ___ ____  _  ___  __ _____ ____    ____  ____   ___
 |_ _|  _ \| \| \ \/ /| ____/ ___|  |  _ \|  _ \ / _ \
  | || |_) | .` |\  / |  _| \___ \  | |_) | |_) | | | |
  | ||  _ <| |\ |/  \ | |___ ___) | |  __/|  _ <| |_| |
 |___|_| \_\_| \_/_/\_\|_____|____/  |_|   |_| \_\\___/
"""

SEV_ICON = {"critical": "!!", "high": "! ", "medium": "~ ", "low": "- ", "info": "i "}


def _echo(text: str = "") -> None:
    print(text)


def _print_banner() -> None:
    print(BANNER)
    print(f"  {config.APP_NAME} {config.VERSION} - authorized web & network assessment")
    print("  Localhost only. Test systems you own or hold written permission for.\n")


# ------------------------------------------------------------------------- commands
def cmd_scan(args, settings) -> int:
    request = ScanRequest(
        target=args.target,
        kind=args.kind,
        profile=args.profile,
        scope_id=args.scope or "",
        confirm_authorized=args.confirm_authorized,
        timeout=args.timeout,
        rate_limit=args.rate,
        max_requests=args.max_requests,
        max_hosts=args.max_hosts,
        ports=args.ports or "",
        verify_tls=False if args.insecure else None,
    )
    if not args.quiet and not args.json:
        _print_banner()
        _echo(f"  target  : {args.target}")
        _echo(f"  kind    : {args.kind}   profile: {args.profile}")
        _echo("  running ...")
    try:
        result = runner.run_sync(request)
    except PermissionError as exc:
        if args.json:
            print(json.dumps({"error": "authorization_blocked", "detail": str(exc)}, indent=2))
            return 3
        _echo(f"\n[AUTHORIZATION BLOCKED] {exc}")
        _echo("\nRegister the engagement first:")
        _echo("  irnxsec scope add --name 'Client Q4' --targets example.com --authorization written-permission --reference <contract-url>")
        return 3
    except ValueError as exc:
        if args.json:
            print(json.dumps({"error": "invalid_input", "detail": str(exc)}, indent=2))
            return 2
        _echo(f"\n[INPUT ERROR] {exc}")
        return 2
    if args.json:
        print(json.dumps(result.to_dict(), indent=2, ensure_ascii=False))
        return 0
    _print_result(result)
    if args.report:
        paths = reports.write_reports(result)
        store.save_scan(result, reports=paths, status="complete")
        _echo("\n  reports:")
        for key, path in paths.items():
            _echo(f"    {key:9s} {path}")
    return 0


def _print_result(result: ScanResult) -> None:
    summary = result.summary()
    _echo("")
    _echo("  " + "=" * 68)
    _echo(f"  RESULT  {result.target}")
    _echo(f"  scan id {result.scan_id}   risk {result.risk_score}/100   requests {result.requests_made or result.metadata.get('requests_made', 0)}")
    _echo("  " + "=" * 68)
    _echo(
        "  "
        + "  ".join(f"{key.upper()}:{summary[key]}" for key in ("critical", "high", "medium", "low", "info"))
        + f"  TOTAL:{summary['total']}"
    )
    _echo("")
    if not result.findings:
        _echo("  No findings from the configured checks. Not proof of security.")
    for finding in result.findings:
        _echo(f"  [{SEV_ICON.get(finding.severity, '  ')}] {finding.severity.upper():8s} {finding.title}")
        _echo(f"        {finding.category} | confidence={finding.confidence} | {finding.cwe or 'no-cwe'}")
        if finding.location:
            _echo(f"        at {finding.location}")
        if finding.detail:
            _echo(f"        {finding.detail[:300]}")
        _echo("")
    if result.errors:
        _echo("  limitations:")
        for error in result.errors[:12]:
            _echo(f"    - {error}")
    _echo(f"  observations recorded: {len(result.observations)}")
    _echo(f"  reports: irnxsec scan ... --report   (written to {config.reports_dir()})")


def cmd_scopes(args, settings) -> int:
    if args.action == "list":
        scopes = store.list_scopes()
        if args.json:
            print(json.dumps({"scopes": scopes}, indent=2))
            return 0
        if not scopes:
            _echo("No scopes registered. Add one with: irnxsec scope add --name ... --targets ...")
            return 0
        _echo(f"{'ID':16s} {'STATUS':10s} {'KIND':8s} {'EXPIRES':12s} NAME / TARGETS")
        for scope in scopes:
            status = "REVOKED" if scope["status"] == "revoked" else ("EXPIRED" if scope["expired"] else "ACTIVE")
            _echo(
                f"{scope['id']:16s} {status:10s} {scope['kind']:8s} {(scope['expires_at'] or '-'):12s} "
                f"{scope['name']}  [{', '.join(scope['targets'][:4])}]"
            )
        return 0
    if args.action == "add":
        targets = [t for raw in (args.targets or []) for t in raw.split(",") if t.strip()]
        if not targets:
            _echo("[INPUT ERROR] --targets is required (comma separated or repeated).")
            return 2
        scope = store.create_scope(
            {
                "name": args.name,
                "organization": args.organization or "",
                "contact": args.contact or "",
                "authorization": args.authorization,
                "reference": args.reference or "",
                "notes": args.notes or "",
                "kind": args.kind,
                "targets": [t.strip() for t in targets],
                "expires_at": args.expires or "",
            }
        )
        if args.json:
            print(json.dumps(scope, indent=2))
            return 0
        _echo(f"Scope created: {scope['id']}")
        _echo(f"  engagement  : {scope['name']}")
        _echo(f"  targets     : {', '.join(scope['targets'])}")
        _echo(f"  authorization: {scope['authorization']} ({scope['reference'] or 'no reference'})")
        _echo(f"  expires     : {scope['expires_at'] or 'until revoked'}")
        _echo(f"\nIssue a signed certificate:  irnxsec certificate issue {scope['id']}")
        return 0
    if args.action == "revoke":
        if not args.scope_id:
            _echo("[INPUT ERROR] scope id required.")
            return 2
        ok = store.revoke_scope(args.scope_id)
        _echo("Scope revoked; further scans against its targets are blocked." if ok else "Scope not found or already revoked.")
        return 0 if ok else 1
    if args.action == "sheet":
        if not args.scope_id:
            _echo("[INPUT ERROR] scope id required.")
            return 2
        scope = store.get_scope(args.scope_id)
        if not scope:
            _echo("Scope not found.")
            return 1
        try:
            from .pdf import render_scope_sheet

            path = render_scope_sheet(scope)
        except RuntimeError as exc:
            _echo(f"[PDF UNAVAILABLE] {exc}")
            return 1
        _echo(f"Scope sheet written: {path}")
        return 0
    _echo("Unknown action.")
    return 2


def cmd_certificate(args, settings) -> int:
    if args.action == "list":
        certs = authz.list_certificates()
        if args.json:
            print(json.dumps({"certificates": certs}, indent=2))
            return 0
        if not certs:
            _echo("No certificates issued yet.")
            return 0
        for cert in certs:
            _echo(f"{cert['certificate_id']}  {cert['engagement']}  issued {cert['issued_at']}  pdf {cert['pdf']}")
        return 0
    if args.action == "issue":
        if not args.scope_id:
            _echo("[INPUT ERROR] scope id required.")
            return 2
        try:
            certificate = authz.issue_certificate(args.scope_id)
        except ValueError as exc:
            _echo(f"[REFUSED] {exc}")
            return 1
        if args.json:
            print(json.dumps(certificate, indent=2))
            return 0
        payload = certificate["payload"]
        _echo(f"Certificate issued: {payload['certificate_id']}")
        _echo(f"  engagement : {payload['engagement']}")
        _echo(f"  targets    : {', '.join(payload['targets'])}")
        _echo(f"  valid until: {payload['valid_until']}")
        _echo(f"  json       : {certificate.get('json')}")
        _echo(f"  pdf        : {certificate.get('pdf', certificate.get('pdf_error', 'unavailable'))}")
        return 0
    if args.action == "verify":
        path = Path(args.file).expanduser()
        if not path.exists():
            _echo("File not found.")
            return 1
        try:
            certificate = json.loads(path.read_text(encoding="utf-8"))
        except ValueError as exc:
            _echo(f"[INVALID] {exc}")
            return 1
        verdict = authz.verify_certificate(certificate)
        _echo(json.dumps(verdict, indent=2, default=str))
        return 0 if verdict.get("valid") else 1
    return 2


def cmd_history(args, settings) -> int:
    records = store.list_scans(limit=args.limit, kind=args.kind or "")
    if args.json:
        print(json.dumps({"scans": records}, indent=2, default=str))
        return 0
    if not records:
        _echo("No scans recorded yet.")
        return 0
    for record in records:
        summary = record.get("summary") or {}
        _echo(
            f"{record['started_at']}  {record['kind']:8s} {record['status']:9s} risk {str(record['risk_score']):5s}  "
            f"{record['target']}  (id {record['id']})"
        )
        _echo(f"    findings: {summary.get('total', 0)}  crit {summary.get('critical', 0)} / high {summary.get('high', 0)}")
    return 0


def cmd_payloads(args, settings) -> int:
    token = payloads.new_token()
    if args.json:
        print(json.dumps([{**c.__dict__, "render": c.render(token)} for c in payloads.CANARIES], indent=2))
        return 0
    _echo("Non-exploiting canaries (rendered once, per run):\n")
    for canary in payloads.CANARIES:
        _echo(f"  [{canary.category:9s}] {canary.name}")
        _echo(f"      value : {canary.render(token)}")
        _echo(f"      use   : {canary.purpose}\n")
    _echo("These markers prove handling, not exploitation. They do not extract data or execute code.")
    return 0


def cmd_serve(args, settings) -> int:
    from .api import serve

    serve(host=args.host, port=args.port, open_browser=not args.no_browser, allow_remote=args.allow_remote)
    return 0


def cmd_settings(args, settings) -> int:
    if args.set:
        changes = {}
        for pair in args.set:
            if "=" not in pair:
                _echo(f"[INPUT ERROR] expected key=value, got '{pair}'")
                return 2
            key, _, value = pair.partition("=")
            key = key.strip()
            if not hasattr(settings, key):
                _echo(f"[INPUT ERROR] unknown setting '{key}'")
                return 2
            current = getattr(settings, key)
            if isinstance(current, bool):
                changes[key] = value.strip().lower() in ("1", "true", "yes", "on")
            elif isinstance(current, int):
                changes[key] = int(value)
            elif isinstance(current, float):
                changes[key] = float(value)
            else:
                changes[key] = value
        settings = config.update(**changes)
    data = {
        "host": settings.host, "port": settings.port, "contact": settings.contact,
        "timeout": settings.timeout, "verify_tls": settings.verify_tls,
        "rate_limit": settings.rate_limit, "max_requests": settings.max_requests,
        "max_hosts": settings.max_hosts, "require_authz": settings.require_authz,
        "theme": settings.theme, "data_dir": str(config.home()),
        "api_token_hint": f"{settings.api_token[:4]}...{settings.api_token[-4:]}",
    }
    print(json.dumps(data, indent=2))
    return 0


def cmd_audit(args, settings) -> int:
    rows = store.audit_trail(limit=args.limit)
    if args.json:
        print(json.dumps({"audit": rows}, indent=2))
        return 0
    for row in rows:
        _echo(f"{row['ts']}  {row['action']:20s} {row['detail'][:120]}")
    return 0


# ------------------------------------------------------------------------- parser
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="irnxsec",
        description=f"{config.APP_NAME} - authorized web & network assessment toolkit (localhost only)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "examples:\n"
            "  irnxsec scope add --name 'Client A' --targets example.com --authorization written-permission --reference C-2026-14\n"
            "  irnxsec certificate issue SC-XXXXXXXXXX\n"
            "  irnxsec scan https://example.com --confirm-authorized --report\n"
            "  irnxsec scan 10.0.0.0/29 --kind network --ports 22,80,443\n"
            "  irnxsec scan example.com --kind dns --profile deep\n"
            "  irnxsec serve\n"
        ),
    )
    # ``--json`` must work both before and after the subcommand: SUPPRESS stops the
    # subparser default from overwriting a value already parsed at the top level.
    parser.add_argument("--json", action="store_true", default=False, help="machine-readable output")
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument(
        "--json", action="store_true", default=argparse.SUPPRESS, help="machine-readable output"
    )
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", parents=[common], help="run an assessment against an authorized target")
    scan.add_argument("target", help="origin (https://host), CIDR/IP for network, or domain for dns")
    scan.add_argument("--kind", choices=["web", "network", "dns"], default="web")
    scan.add_argument("--profile", choices=["quick", "standard", "deep"], default="standard")
    scan.add_argument("--scope", help="scope id to authorize against (auto-detected when omitted)")
    scan.add_argument("--confirm-authorized", action="store_true", help="assert you own the target or hold written permission")
    scan.add_argument("--timeout", type=float, help="per-request timeout seconds")
    scan.add_argument("--rate", type=float, help="requests per second")
    scan.add_argument("--max-requests", type=int, dest="max_requests")
    scan.add_argument("--max-hosts", type=int, dest="max_hosts")
    scan.add_argument("--ports", help="network mode: 22,80,443 or 1-1024")
    scan.add_argument("--insecure", action="store_true", help="skip TLS verification for the web client")
    scan.add_argument("--report", action="store_true", help="write json/markdown/html/pdf reports")
    scan.add_argument("--quiet", action="store_true")

    scope = sub.add_parser("scope", parents=[common], help="manage engagements (authorization scopes)")
    scope.add_argument("action", choices=["list", "add", "revoke", "sheet"])
    scope.add_argument("scope_id", nargs="?")
    scope.add_argument("--name")
    scope.add_argument("--targets", nargs="+", help="exact host, *.wildcard, CIDR or URL")
    scope.add_argument("--kind", choices=["all", "web", "network", "dns"], default="all")
    scope.add_argument("--authorization", choices=["owner", "written-permission", "contract", "bug-bounty-program"], default="written-permission")
    scope.add_argument("--reference", help="contract id, ticket or program URL")
    scope.add_argument("--organization")
    scope.add_argument("--contact")
    scope.add_argument("--expires", help="ISO date, e.g. 2026-12-31")
    scope.add_argument("--notes")

    cert = sub.add_parser("certificate", parents=[common], help="issue and verify authorization certificates")
    cert.add_argument("action", choices=["list", "issue", "verify"])
    cert.add_argument("scope_id", nargs="?", help="scope id for 'issue'")
    cert.add_argument("--file", help="certificate json path for 'verify'")

    history = sub.add_parser("history", parents=[common], help="list recorded scans")
    history.add_argument("--limit", type=int, default=25)
    history.add_argument("--kind", choices=["web", "network", "dns"])

    sub.add_parser("payloads", parents=[common], help="show the non-exploiting validation canaries")

    serve = sub.add_parser("serve", parents=[common], help="run the localhost dashboard")
    serve.add_argument("--host", default=None)
    serve.add_argument("--port", type=int, default=None)
    serve.add_argument("--no-browser", action="store_true")
    serve.add_argument("--allow-remote", action="store_true", help="permit a non-loopback bind (not recommended)")

    settings_cmd = sub.add_parser("settings", parents=[common], help="show or change settings")
    settings_cmd.add_argument("--set", nargs="+", metavar="KEY=VALUE")

    audit = sub.add_parser("audit", parents=[common], help="show the audit trail")
    audit.add_argument("--limit", type=int, default=50)

    return parser


HANDLERS = {
    "scan": cmd_scan,
    "scope": cmd_scopes,
    "certificate": cmd_certificate,
    "history": cmd_history,
    "payloads": cmd_payloads,
    "serve": cmd_serve,
    "settings": cmd_settings,
    "audit": cmd_audit,
}


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not hasattr(args, "json"):
        args.json = False
    settings = config.load()
    handler = HANDLERS.get(args.command)
    if not handler:
        parser.print_help()
        return 2
    try:
        return handler(args, settings)
    except KeyboardInterrupt:
        _echo("\ninterrupted")
        return 130


if __name__ == "__main__":
    sys.exit(main())
