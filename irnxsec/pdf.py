"""PDF rendering for assessment reports and authorization certificates.

Uses reportlab when installed (full layout). If reportlab is unavailable the module
raises RuntimeError and the other report formats keep working, so a minimal install
stays usable.
"""
from __future__ import annotations

import json
from pathlib import Path

from . import config

PALETTE = {
    "critical": "#ff2d55",
    "high": "#ff6b3d",
    "medium": "#ffc93c",
    "low": "#4db8ff",
    "info": "#8b97a8",
}
PANEL = "#0d1117"
LINE = "#1e2630"
TEXT = "#e6edf3"
MUTED = "#8b97a8"
ACCENT = "#00ffa3"


def _require_reportlab():
    try:
        import reportlab  # noqa: F401
        from reportlab.lib import colors  # noqa: F401
        from reportlab.platypus import Paragraph, SimpleDocTemplate, Table  # noqa: F401
    except ImportError as exc:  # pragma: no cover - optional dependency
        raise RuntimeError(
            "PDF output needs reportlab. Install it with: pip install 'irnxsec-pro[pdf]'"
        ) from exc


def _styles():
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet

    base = getSampleStyleSheet()
    return {
        "title": ParagraphStyle(
            "irnxTitle", parent=base["Title"], fontName="Helvetica-Bold", fontSize=20,
            leading=24, textColor=TEXT, alignment=0, spaceAfter=2,
        ),
        "h2": ParagraphStyle(
            "irnxH2", parent=base["Heading2"], fontName="Helvetica-Bold", fontSize=11.5,
            leading=15, textColor=ACCENT, spaceBefore=14, spaceAfter=6,
        ),
        "h3": ParagraphStyle(
            "irnxH3", parent=base["Heading3"], fontName="Helvetica-Bold", fontSize=10.5,
            leading=14, textColor=TEXT, spaceAfter=3,
        ),
        "body": ParagraphStyle(
            "irnxBody", parent=base["BodyText"], fontName="Helvetica", fontSize=8.6,
            leading=12, textColor="#c3ccd6",
        ),
        "small": ParagraphStyle(
            "irnxSmall", parent=base["BodyText"], fontName="Helvetica", fontSize=7.6,
            leading=10.5, textColor=MUTED,
        ),
        "mono": ParagraphStyle(
            "irnxMono", parent=base["Code"], fontName="Courier", fontSize=6.9,
            leading=9, textColor="#9fb0c0",
        ),
    }


def _esc(text) -> str:
    return str(text or "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _hex(color: str, fallback: str = MUTED) -> str:
    value = (color or "").strip()
    if len(value) == 7 and value.startswith("#") and all(c in "0123456789abcdefABCDEF" for c in value[1:]):
        return value
    return fallback


def _multiline(text: str, limit: int | None = None) -> str:
    body = _esc(text)
    if limit:
        body = body[:limit]
    return body.replace("\n", "<br/>").replace("  ", "&nbsp;&nbsp;")


# --------------------------------------------------------------------- report PDF
def build_report_pdf(result, path: Path) -> Path:
    _require_reportlab()
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.units import mm
    from reportlab.platypus import HRFlowable, KeepTogether, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

    styles = _styles()
    path.parent.mkdir(parents=True, exist_ok=True)
    doc = SimpleDocTemplate(
        str(path), pagesize=A4, leftMargin=16 * mm, rightMargin=16 * mm,
        topMargin=16 * mm, bottomMargin=15 * mm,
        title=f"{config.APP_NAME} report {result.target}", author=config.APP_NAME,
    )
    summary = result.summary()
    story = [
        Paragraph(f"IRNXSEC <font color='{ACCENT}'>PRO</font>", styles["title"]),
        Paragraph("Authorized security assessment report", styles["small"]),
        Spacer(1, 4),
        HRFlowable(width="100%", thickness=0.6, color=LINE, spaceBefore=4, spaceAfter=8),
    ]

    meta = [
        ("Target", result.target),
        ("Kind / profile", f"{result.kind} / {result.profile}"),
        ("Scan ID", result.scan_id),
        ("Started (UTC)", result.started_at),
        ("Finished (UTC)", result.finished_at or "-"),
        ("Requests made", str(result.requests_made or result.metadata.get("requests_made", 0))),
        ("Risk score", f"{result.risk_score}/100"),
        ("Authorization", result.authorization.get("reason", "not recorded")),
    ]
    meta_table = Table(
        [[Paragraph(f"<b>{_esc(k)}</b>", styles["small"]), Paragraph(_esc(v), styles["small"])] for k, v in meta],
        colWidths=[38 * mm, 138 * mm],
    )
    meta_table.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("LINEBELOW", (0, 0), (-1, -2), 0.25, colors.HexColor(LINE)),
    ]))
    story.append(meta_table)

    story.append(Paragraph("Severity summary", styles["h2"]))
    cells = []
    for key in ("critical", "high", "medium", "low", "info", "total"):
        if key not in summary:
            continue
        color = _hex(PALETTE.get(key, MUTED))
        cells.append(Paragraph(
            f"<font size=7 color='{MUTED}'>{key.upper()}</font><br/>"
            f"<font size=15 color='{color}'><b>{summary[key]}</b></font>",
            styles["body"],
        ))
    if cells:
        grid = Table([cells], colWidths=[min(29.0, 176.0 / len(cells)) * mm] * len(cells))
        grid.setStyle(TableStyle([
            ("BOX", (0, 0), (-1, -1), 0.4, colors.HexColor(LINE)),
            ("INNERGRID", (0, 0), (-1, -1), 0.4, colors.HexColor(LINE)),
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor(PANEL)),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("TOPPADDING", (0, 0), (-1, -1), 7),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
        ]))
        story.append(grid)

    story.append(Paragraph(f"Findings ({summary['total']})", styles["h2"]))
    if not result.findings:
        story.append(Paragraph(
            "No findings from the configured checks. This is not proof that the target is secure.",
            styles["body"],
        ))
    for index, finding in enumerate(result.findings, start=1):
        color = _hex(PALETTE.get(finding.severity, MUTED))
        block = [
            Paragraph(
                f"<font size=7 color='{color}'><b>{finding.severity.upper()}</b></font> "
                f"<font size=7 color='{MUTED}'>{_esc(finding.category)} &middot; confidence: "
                f"{_esc(finding.confidence)} &middot; {_esc(finding.cwe or 'no CWE')} &middot; "
                f"CVSS {_esc(str(finding.cvss or '-'))}</font>",
                styles["small"],
            ),
            Paragraph(f"{index}. {_esc(finding.title)}", styles["h3"]),
            Paragraph(_esc(finding.detail), styles["body"]),
        ]
        if finding.evidence:
            block.append(Spacer(1, 2))
            block.append(Paragraph("<b>Evidence</b>", styles["small"]))
            block.append(Paragraph(_multiline(finding.evidence, 2400), styles["mono"]))
        if finding.remediation:
            block.append(Spacer(1, 2))
            block.append(Paragraph(f"<b>Remediation:</b> {_esc(finding.remediation)}", styles["small"]))
        if finding.references:
            block.append(Paragraph("References: " + _esc(", ".join(finding.references)), styles["small"]))
        block.append(Spacer(1, 6))
        story.append(KeepTogether(block))
        story.append(HRFlowable(width="100%", thickness=0.3, color=LINE, spaceBefore=2, spaceAfter=8))

    if result.observations:
        story.append(Paragraph("Observations", styles["h2"]))
        payload = json.dumps([o.to_dict() for o in result.observations], indent=1, default=str)
        story.append(Paragraph(_multiline(payload, 9000), styles["mono"]))
    if result.errors:
        story.append(Paragraph("Limitations and errors", styles["h2"]))
        for error in result.errors[:60]:
            story.append(Paragraph("&bull; " + _esc(error), styles["small"]))

    story.extend([
        Spacer(1, 10),
        Paragraph(
            f"Generated by {config.APP_NAME} {config.VERSION} on a localhost-only installation. "
            "Automated checks are indicative: validate each item manually before remediation or "
            "disclosure. Do not share this report outside the engagement without the asset owner's consent.",
            styles["small"],
        ),
    ])
    doc.build(story)
    return path


# ---------------------------------------------------------------- certificate PDF
def render_certificate(certificate: dict, path: Path) -> Path:
    _require_reportlab()
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4, landscape
    from reportlab.lib.styles import ParagraphStyle
    from reportlab.lib.units import mm
    from reportlab.platypus import HRFlowable, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

    styles = _styles()
    payload = certificate.get("payload", {})
    path.parent.mkdir(parents=True, exist_ok=True)
    doc = SimpleDocTemplate(
        str(path), pagesize=landscape(A4), leftMargin=18 * mm, rightMargin=18 * mm,
        topMargin=16 * mm, bottomMargin=16 * mm,
        title=f"Authorization certificate {payload.get('certificate_id', '')}", author=config.APP_NAME,
    )
    label = ParagraphStyle("certLabel", parent=styles["small"], fontSize=10, textColor=ACCENT, spaceAfter=10)
    statement = ParagraphStyle("stmt", parent=styles["body"], fontSize=9.5, leading=14)
    story = [
        Paragraph(f"IRNXSEC <font color='{ACCENT}'>PRO</font>", styles["title"]),
        Paragraph("AUTHORIZATION &amp; SCOPE CERTIFICATE", label),
        HRFlowable(width="100%", thickness=0.8, color=ACCENT, spaceAfter=14),
        Paragraph(_esc(payload.get("statement", "")), statement),
        Spacer(1, 12),
    ]
    rows = [
        ("Certificate ID", payload.get("certificate_id", "")),
        ("Engagement", payload.get("engagement", "")),
        ("Organization", payload.get("organization") or "-"),
        ("Client contact", payload.get("client_contact") or "-"),
        ("Authorization basis", str(payload.get("authorization_basis", "")).replace("-", " ").title()),
        ("Reference", payload.get("reference") or "-"),
        ("Scope kind", payload.get("scope_kind", "all")),
        ("In-scope targets", ", ".join(payload.get("targets", [])[:18]) or "-"),
        ("Issued at (UTC)", payload.get("issued_at", "")),
        ("Valid until", payload.get("valid_until") or "until revoked"),
        ("Issuer", payload.get("issuer", "")),
    ]
    table = Table(
        [[Paragraph(f"<b>{_esc(k)}</b>", styles["small"]), Paragraph(_esc(v), styles["body"])] for k, v in rows],
        colWidths=[48 * mm, 208 * mm],
    )
    table.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor(PANEL)),
        ("LINEBELOW", (0, 0), (-1, -1), 0.25, colors.HexColor(LINE)),
        ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor(LINE)),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]))
    story.extend([
        table,
        Spacer(1, 14),
        Paragraph("Ed25519 signature", ParagraphStyle("sig", parent=styles["small"], textColor=ACCENT)),
    ])
    signature = certificate.get("signature", "")
    story.append(Paragraph("<br/>".join(_esc(signature[i:i + 64]) for i in range(0, len(signature), 64)), styles["mono"]))
    story.extend([
        Spacer(1, 6),
        Paragraph(f"Public key fingerprint: {_esc(certificate.get('public_key_fingerprint', ''))}", styles["small"]),
        Spacer(1, 10),
        Paragraph(
            "This certificate records the scope on file in the operator's local installation at issue time. "
            "It is cryptographic evidence that the engagement and its stated targets were registered, and it "
            "can be verified locally with the issuer's public key. It does not replace the signed contract or "
            "written permission between the parties.",
            styles["small"],
        ),
    ])
    doc.build(story)
    return path


# -------------------------------------------------------------------- scope sheet
def build_scope_pdf(scope: dict, path: Path) -> Path:
    _require_reportlab()
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.units import mm
    from reportlab.platypus import HRFlowable, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

    styles = _styles()
    path.parent.mkdir(parents=True, exist_ok=True)
    doc = SimpleDocTemplate(
        str(path), pagesize=A4, leftMargin=16 * mm, rightMargin=16 * mm,
        topMargin=16 * mm, bottomMargin=14 * mm,
        title=f"Engagement scope {scope.get('id', '')}", author=config.APP_NAME,
    )
    rows = [
        ("Scope ID", scope.get("id", "")),
        ("Engagement", scope.get("name", "")),
        ("Organization", scope.get("organization") or "-"),
        ("Contact", scope.get("contact") or "-"),
        ("Authorization basis", str(scope.get("authorization", "")).replace("-", " ").title()),
        ("Reference", scope.get("reference") or "-"),
        ("Kind", scope.get("kind", "all")),
        ("Targets", ", ".join(scope.get("targets", [])[:40])),
        ("Created", scope.get("created_at", "")),
        ("Expires", scope.get("expires_at") or "until revoked"),
        ("Status", scope.get("status", "active")),
    ]
    body = Table(
        [[Paragraph(f"<b>{_esc(k)}</b>", styles["small"]), Paragraph(_esc(v), styles["body"])] for k, v in rows],
        colWidths=[44 * mm, 132 * mm],
    )
    body.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LINEBELOW", (0, 0), (-1, -1), 0.25, colors.HexColor(LINE)),
        ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor(LINE)),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]))
    signature_row = Table(
        [[Paragraph("Asset owner name / signature / date", styles["small"]),
          Paragraph("Tester name / signature / date", styles["small"])]],
        colWidths=[88 * mm, 88 * mm],
    )
    signature_row.setStyle(TableStyle([
        ("LINEABOVE", (0, 0), (-1, 0), 0.5, colors.HexColor(LINE)),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
    ]))
    doc.build([
        Paragraph(f"IRNXSEC <font color='{ACCENT}'>PRO</font> &mdash; engagement scope sheet", styles["title"]),
        HRFlowable(width="100%", thickness=0.6, color=LINE, spaceAfter=10),
        body,
        Spacer(1, 14),
        Paragraph("Notes", styles["h2"]),
        Paragraph(_multiline(scope.get("notes") or "No additional notes recorded."), styles["body"]),
        Spacer(1, 16),
        Paragraph(
            "Signatures: by signing, the asset owner confirms written permission for the limited, "
            "non-destructive testing described above.",
            styles["small"],
        ),
        Spacer(1, 18),
        signature_row,
    ])
    return path


def render_scope_sheet(scope: dict) -> Path:
    return build_scope_pdf(scope, config.certs_dir() / f"SCOPE-{scope.get('id', 'unknown')}.pdf")


__all__ = ["build_report_pdf", "render_certificate", "build_scope_pdf", "render_scope_sheet"]
