"""
generate_report.py
Turns a RangeCheck JSON assessment into a polished, client-ready PDF.

This is the paid deliverable for the "External Vulnerability Scan + Report" gig.
It reads the JSON that `rangecheck` already produces (reports/rangecheck-<target>.json)
and renders a branded PDF: cover page, executive summary, severity breakdown,
per-finding detail with CVSS + NIST 800-53 + MITRE ATT&CK, and prioritized
remediation. No cloud calls. Everything runs locally.

Usage:
    py generate_report.py <rangecheck.json> --client "Acme Coffee LLC" [--out report.pdf]

Requires: reportlab  (pip install reportlab)
"""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.pagesizes import LETTER
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import (
    HRFlowable,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

# ---- Brand palette -------------------------------------------------------
INK = colors.HexColor("#101820")
SLATE = colors.HexColor("#334155")
MUTE = colors.HexColor("#64748b")
ACCENT = colors.HexColor("#0d9488")  # teal
LINE = colors.HexColor("#e2e8f0")

SEV_COLORS = {
    "Critical": colors.HexColor("#b91c1c"),
    "High": colors.HexColor("#ea580c"),
    "Medium": colors.HexColor("#ca8a04"),
    "Low": colors.HexColor("#2563eb"),
    "Informational": colors.HexColor("#64748b"),
}
SEV_ORDER = ["Critical", "High", "Medium", "Low", "Informational"]

# ---- Analyst identity (edit once) ---------------------------------------
ANALYST_NAME = "Sergio Rodriguez"
ANALYST_TAGLINE = "Cybersecurity Analyst"
ANALYST_CREDS = "Cisco Certified in Cybersecurity | (ISC)\u00b2 Candidate | Blue Team Junior Analyst"
ANALYST_EMAIL = "sergio.w.rdz@gmail.com"
ANALYST_SITE = "sergrdz.pages.dev"


def _styles():
    ss = getSampleStyleSheet()
    ss.add(ParagraphStyle("CoverTitle", parent=ss["Title"], fontSize=30, textColor=INK, leading=34, spaceAfter=6))
    ss.add(ParagraphStyle("CoverSub", parent=ss["Normal"], fontSize=13, textColor=MUTE, alignment=TA_CENTER, leading=18))
    ss.add(ParagraphStyle("H2", parent=ss["Heading2"], fontSize=15, textColor=INK, spaceBefore=14, spaceAfter=6))
    ss.add(ParagraphStyle("H3", parent=ss["Heading3"], fontSize=12, textColor=SLATE, spaceBefore=8, spaceAfter=3))
    ss.add(ParagraphStyle("Body", parent=ss["Normal"], fontSize=10, textColor=SLATE, leading=15, spaceAfter=6))
    ss.add(ParagraphStyle("Small", parent=ss["Normal"], fontSize=8.5, textColor=MUTE, leading=12))
    ss.add(ParagraphStyle("FindingTitle", parent=ss["Normal"], fontSize=12, textColor=INK, leading=15, spaceAfter=2))
    ss.add(ParagraphStyle("CellHead", parent=ss["Normal"], fontSize=9, textColor=colors.white, leading=12))
    ss.add(ParagraphStyle("Cell", parent=ss["Normal"], fontSize=9, textColor=SLATE, leading=12))
    return ss


def _severity_badge(sev: str, style) -> Table:
    color = SEV_COLORS.get(sev, MUTE)
    t = Table([[Paragraph(f"<b>{sev.upper()}</b>", ParagraphStyle("b", fontSize=8, textColor=colors.white))]],
              colWidths=[1.0 * inch])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), color),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
    ]))
    return t


def _all_findings(data: dict) -> list[dict]:
    findings = []
    for host in data.get("hosts", []):
        for v in host.get("vulnerabilities", []):
            findings.append(v)
    def rank(f):
        try:
            return SEV_ORDER.index(f.get("severity", "Informational"))
        except ValueError:
            return len(SEV_ORDER)
    return sorted(findings, key=rank)


def build(data: dict, client: str, out_path: Path) -> Path:
    ss = _styles()
    story: list = []

    started = data.get("started_at", "")
    completed = data.get("completed_at", "")
    target = data.get("target", "the authorized target")
    sev = data.get("severity_counts", {})
    total_v = data.get("total_vulnerabilities", 0)
    total_s = data.get("total_services", 0)
    total_h = data.get("total_hosts", 0)
    report_date = datetime.now(timezone.utc).strftime("%B %d, %Y")

    # ---------- COVER ----------
    story.append(Spacer(1, 1.4 * inch))
    story.append(Paragraph("EXTERNAL VULNERABILITY ASSESSMENT", ss["CoverTitle"]))
    story.append(Spacer(1, 0.15 * inch))
    story.append(Paragraph(f"Prepared for <b>{client}</b>", ss["CoverSub"]))
    story.append(Paragraph(f"Scope: {target}", ss["CoverSub"]))
    story.append(Paragraph(report_date, ss["CoverSub"]))
    story.append(Spacer(1, 0.6 * inch))
    story.append(HRFlowable(width="60%", thickness=1, color=ACCENT, hAlign="CENTER"))
    story.append(Spacer(1, 0.3 * inch))
    story.append(Paragraph(f"<b>{ANALYST_NAME}</b> &mdash; {ANALYST_TAGLINE}", ss["CoverSub"]))
    story.append(Paragraph(ANALYST_CREDS, ss["Small"]))
    story.append(Paragraph(f"{ANALYST_EMAIL} &nbsp;|&nbsp; {ANALYST_SITE}", ss["Small"]))
    story.append(Spacer(1, 0.5 * inch))
    story.append(Paragraph(
        "CONFIDENTIAL &mdash; This report is prepared solely for the named client and contains "
        "sensitive security information. Distribution is restricted.", ss["Small"]))
    story.append(PageBreak())

    # ---------- EXECUTIVE SUMMARY ----------
    story.append(Paragraph("Executive Summary", ss["H2"]))
    action = ("No exposures requiring urgent action were identified."
              if sev.get("Critical", 0) + sev.get("High", 0) == 0
              else "One or more higher-severity exposures require prompt remediation (see below).")
    story.append(Paragraph(
        f"This assessment reviewed the externally reachable attack surface of <b>{client}</b> "
        f"at <b>{target}</b>. Across {total_h} host(s), {total_s} open service(s) were observed and "
        f"{total_v} finding(s) were classified and mapped to industry frameworks. {action}",
        ss["Body"]))

    # severity table
    rows = [[Paragraph("Severity", ss["CellHead"]), Paragraph("Count", ss["CellHead"])]]
    for s in SEV_ORDER:
        rows.append([
            Paragraph(f"<b>{s}</b>", ParagraphStyle("s", fontSize=9, textColor=SEV_COLORS[s])),
            Paragraph(str(sev.get(s, 0)), ss["Cell"]),
        ])
    tbl = Table(rows, colWidths=[2.5 * inch, 1.2 * inch])
    tbl.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), INK),
        ("GRID", (0, 0), (-1, -1), 0.5, LINE),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8fafc")]),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("LEFTPADDING", (0, 0), (-1, -1), 10),
    ]))
    story.append(Spacer(1, 0.1 * inch))
    story.append(tbl)

    story.append(Paragraph("Engagement Details", ss["H3"]))
    meta = [
        ["Assessment window", f"{started}  \u2192  {completed}"],
        ["Classification", data.get("classification", "UNCLASSIFIED")],
        ["Methodology", data.get("methodology", "Authorized external service discovery and exposure classification")],
        ["Tooling", f'{data.get("tool_name", "RangeCheck")} {data.get("tool_version", "")}'],
    ]
    mt = Table([[Paragraph(k, ss["Cell"]), Paragraph(str(v), ss["Cell"])] for k, v in meta],
               colWidths=[1.7 * inch, 4.6 * inch])
    mt.setStyle(TableStyle([
        ("GRID", (0, 0), (-1, -1), 0.5, LINE),
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#f1f5f9")),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
    ]))
    story.append(mt)
    story.append(PageBreak())

    # ---------- FINDINGS ----------
    story.append(Paragraph("Detailed Findings", ss["H2"]))
    findings = _all_findings(data)
    if not findings:
        story.append(Paragraph(
            "No vulnerabilities were classified against the ruleset for the observed services. "
            "The open services detected are listed in the appendix. A clean result still benefits "
            "from the hardening recommendations in the closing section.", ss["Body"]))
    for i, f in enumerate(findings, 1):
        story.append(Spacer(1, 0.05 * inch))
        story.append(_severity_badge(f.get("severity", "Informational"), ss))
        story.append(Paragraph(f"<b>{i}. {f.get('title', 'Finding')}</b>", ss["FindingTitle"]))
        loc = f"Host {f.get('host', '?')} : port {f.get('port', '?')}"
        cvss = f.get("cvss", {}) or {}
        story.append(Paragraph(
            f"<font color='#64748b'>{loc} &nbsp;|&nbsp; CVSS {cvss.get('version','')} "
            f"{cvss.get('score','')} &nbsp;|&nbsp; {cvss.get('vector','')}</font>", ss["Small"]))
        story.append(Spacer(1, 0.04 * inch))
        story.append(Paragraph(f"<b>What we found.</b> {f.get('description','')}", ss["Body"]))
        if f.get("evidence"):
            story.append(Paragraph(f"<b>Evidence.</b> {f.get('evidence')}", ss["Body"]))
        story.append(Paragraph(f"<b>Recommended fix.</b> {f.get('recommendation','')}", ss["Body"]))

        mp = f.get("mappings", {}) or {}
        nist = ", ".join(mp.get("nist_sp_800_53", []) or []) or "\u2014"
        attack = ", ".join(
            f"{a.get('id','')} {a.get('name','')}".strip() for a in (mp.get("mitre_attack", []) or [])
        ) or "\u2014"
        cwe = ", ".join(mp.get("cwe", []) or []) or "\u2014"
        map_tbl = Table([
            [Paragraph("<b>NIST 800-53</b>", ss["Cell"]), Paragraph(nist, ss["Cell"])],
            [Paragraph("<b>MITRE ATT&amp;CK</b>", ss["Cell"]), Paragraph(attack, ss["Cell"])],
            [Paragraph("<b>CWE</b>", ss["Cell"]), Paragraph(cwe, ss["Cell"])],
        ], colWidths=[1.3 * inch, 5.0 * inch])
        map_tbl.setStyle(TableStyle([
            ("GRID", (0, 0), (-1, -1), 0.4, LINE),
            ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#f8fafc")),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ]))
        story.append(Spacer(1, 0.03 * inch))
        story.append(map_tbl)
        story.append(Spacer(1, 0.12 * inch))
        story.append(HRFlowable(width="100%", thickness=0.5, color=LINE))

    # ---------- APPENDIX: services ----------
    story.append(PageBreak())
    story.append(Paragraph("Appendix A \u2014 Observed Services", ss["H2"]))
    srows = [[Paragraph(h, ss["CellHead"]) for h in ("Host", "Port", "Proto", "Service", "Banner")]]
    for host in data.get("hosts", []):
        for s in host.get("services", []):
            srows.append([
                Paragraph(str(s.get("host", "")), ss["Cell"]),
                Paragraph(str(s.get("port", "")), ss["Cell"]),
                Paragraph(str(s.get("protocol", "")), ss["Cell"]),
                Paragraph(str(s.get("service_name", "")), ss["Cell"]),
                Paragraph((str(s.get("banner", "")) or "\u2014")[:60], ss["Cell"]),
            ])
    if len(srows) == 1:
        srows.append([Paragraph("No open services observed.", ss["Cell"])] + [Paragraph("", ss["Cell"])] * 4)
    st = Table(srows, colWidths=[1.2 * inch, 0.6 * inch, 0.7 * inch, 1.4 * inch, 2.4 * inch], repeatRows=1)
    st.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), INK),
        ("GRID", (0, 0), (-1, -1), 0.4, LINE),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8fafc")]),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
    ]))
    story.append(st)

    # ---------- Scope & authorization notice ----------
    story.append(Spacer(1, 0.3 * inch))
    story.append(Paragraph("Scope, Authorization & Limitations", ss["H2"]))
    story.append(Paragraph(
        "This assessment was performed only against systems the client confirmed in writing they "
        "own or are authorized to test. It is a point-in-time, non-intrusive external review of "
        "reachable services; it does not include exploitation, password attacks, social engineering, "
        "or internal testing unless separately agreed. Absence of findings is not a guarantee of "
        "security. Findings should be validated in the client's environment before remediation.",
        ss["Body"]))
    story.append(Spacer(1, 0.2 * inch))
    story.append(Paragraph(
        f"Report generated {report_date} by {ANALYST_NAME}. Questions: {ANALYST_EMAIL}.", ss["Small"]))

    def _footer(canvas, doc):
        canvas.saveState()
        canvas.setFont("Helvetica", 7.5)
        canvas.setFillColor(MUTE)
        canvas.drawString(0.9 * inch, 0.5 * inch, f"CONFIDENTIAL \u2014 Prepared for {client}")
        canvas.drawRightString(LETTER[0] - 0.9 * inch, 0.5 * inch, f"Page {doc.page}")
        canvas.restoreState()

    doc = SimpleDocTemplate(
        str(out_path), pagesize=LETTER,
        leftMargin=0.9 * inch, rightMargin=0.9 * inch,
        topMargin=0.9 * inch, bottomMargin=0.8 * inch,
        title=f"External Vulnerability Assessment - {client}",
        author=ANALYST_NAME,
    )
    doc.build(story, onLaterPages=_footer, onFirstPage=lambda c, d: None)
    return out_path


def main() -> None:
    ap = argparse.ArgumentParser(description="Render a client-ready PDF from a RangeCheck JSON report.")
    ap.add_argument("json_report", help="Path to rangecheck-<target>.json")
    ap.add_argument("--client", required=True, help="Client / company name for the cover page")
    ap.add_argument("--out", default=None, help="Output PDF path")
    args = ap.parse_args()

    src = Path(args.json_report)
    if not src.exists():
        raise SystemExit(f"JSON report not found: {src}")
    data = json.loads(src.read_text(encoding="utf-8"))

    safe = "".join(ch if ch.isalnum() else "_" for ch in args.client).strip("_") or "client"
    out = Path(args.out) if args.out else Path("deliverables") / f"{safe}_vulnerability_assessment.pdf"
    out.parent.mkdir(parents=True, exist_ok=True)

    build(data, args.client, out)
    print(f"[+] PDF written: {out.resolve()}")


if __name__ == "__main__":
    main()
