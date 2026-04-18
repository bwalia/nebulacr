#!/usr/bin/env python3
"""Render a PDF summary of the nightly CVE scan.

Reads every ``*.json`` in the input directory (produced by
``nightly-scan-all.sh``) and emits a single PDF with:

  - cover page (timestamp, fleet totals, verdict)
  - per-image row table (severity counts + policy verdict)
  - top critical/high CVE listing per image

Uses ``reportlab`` — pip-installable, pure-Python rendering, no system
binaries. If reportlab is unavailable or no reports exist, exits 0 with a
message so the caller can keep going (Slack upload will then skip too).
"""

from __future__ import annotations

import datetime as _dt
import glob
import json
import os
import sys
from typing import Any


SEVERITY_ORDER = ("critical", "high", "medium", "low", "unknown")


def _load_reports(indir: str) -> list[dict[str, Any]]:
    reports = []
    for path in sorted(glob.glob(os.path.join(indir, "*.json"))):
        try:
            with open(path) as fh:
                reports.append(json.load(fh))
        except (json.JSONDecodeError, OSError) as exc:
            print(f"skip {path}: {exc}", file=sys.stderr)
    return reports


def _image_label(report: dict[str, Any]) -> str:
    r = report.get("result") or {}
    tenant = r.get("tenant") or "?"
    project = r.get("project") or "?"
    repo = r.get("repository") or "?"
    ref = r.get("reference") or "?"
    return f"{tenant}/{project}/{repo}:{ref}"


def _summary_row(report: dict[str, Any]) -> dict[str, Any]:
    r = report.get("result") or {}
    s = r.get("summary") or {}
    pe = r.get("policy_evaluation") or {}
    return {
        "image": _image_label(report),
        "status": report.get("status") or "?",
        "verdict": pe.get("status") or "-",
        **{k: int(s.get(k) or 0) for k in SEVERITY_ORDER},
    }


def _top_cves(report: dict[str, Any], n: int = 5) -> list[dict[str, Any]]:
    r = report.get("result") or {}
    vulns = r.get("vulnerabilities") or []
    picked = [
        v
        for v in vulns
        if not v.get("suppressed")
        and (v.get("severity") or "").upper() in ("CRITICAL", "HIGH")
    ]
    picked.sort(
        key=lambda v: (
            0 if (v.get("severity") or "").upper() == "CRITICAL" else 1,
            v.get("id") or "",
        )
    )
    return picked[:n]


def _render(reports: list[dict[str, Any]], outfile: str) -> None:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import mm
    from reportlab.platypus import (
        SimpleDocTemplate,
        Paragraph,
        Spacer,
        Table,
        TableStyle,
        PageBreak,
    )

    styles = getSampleStyleSheet()
    title = ParagraphStyle(
        "title", parent=styles["Title"], fontSize=18, leading=22, spaceAfter=6
    )
    h2 = ParagraphStyle(
        "h2", parent=styles["Heading2"], fontSize=13, leading=16, spaceAfter=4
    )
    body = ParagraphStyle(
        "body", parent=styles["BodyText"], fontSize=9, leading=11
    )
    mono = ParagraphStyle(
        "mono", parent=body, fontName="Courier", fontSize=8, leading=10
    )

    totals = {k: 0 for k in SEVERITY_ORDER}
    rows = [_summary_row(r) for r in reports]
    any_fail = False
    for row in rows:
        if row["verdict"] == "FAIL":
            any_fail = True
        for k in SEVERITY_ORDER:
            totals[k] += row[k]

    ts = _dt.datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    emoji = "FAIL" if any_fail else (
        "WARN" if (totals["critical"] + totals["high"]) > 0 else "PASS"
    )

    doc = SimpleDocTemplate(
        outfile,
        pagesize=A4,
        leftMargin=15 * mm,
        rightMargin=15 * mm,
        topMargin=15 * mm,
        bottomMargin=15 * mm,
        title="NebulaCR nightly CVE scan",
    )
    flow: list[Any] = []

    flow.append(Paragraph(f"NebulaCR nightly CVE scan — {ts}", title))
    flow.append(Paragraph(f"Overall: <b>{emoji}</b>  |  images scanned: {len(rows)}", body))
    flow.append(Spacer(1, 4 * mm))

    totals_table = Table(
        [
            ["Critical", "High", "Medium", "Low", "Unknown"],
            [str(totals[k]) for k in SEVERITY_ORDER],
        ],
        colWidths=[36 * mm] * 5,
    )
    totals_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1f2937")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 10),
                ("BOTTOMPADDING", (0, 0), (-1, 0), 6),
                ("GRID", (0, 0), (-1, -1), 0.4, colors.grey),
                ("TEXTCOLOR", (0, 1), (0, 1), colors.HexColor("#b91c1c")),
                ("TEXTCOLOR", (1, 1), (1, 1), colors.HexColor("#c2410c")),
            ]
        )
    )
    flow.append(totals_table)
    flow.append(Spacer(1, 6 * mm))

    if not rows:
        flow.append(Paragraph("<i>No images were scanned.</i>", body))
        doc.build(flow)
        return

    flow.append(Paragraph("Per-image summary", h2))
    table_data: list[list[Any]] = [
        ["Image", "Status", "Verdict", "C", "H", "M", "L", "U"]
    ]
    for row in rows:
        table_data.append(
            [
                Paragraph(row["image"], mono),
                row["status"],
                row["verdict"],
                row["critical"],
                row["high"],
                row["medium"],
                row["low"],
                row["unknown"],
            ]
        )
    t = Table(
        table_data,
        colWidths=[75 * mm, 20 * mm, 18 * mm, 10 * mm, 10 * mm, 10 * mm, 10 * mm, 10 * mm],
        repeatRows=1,
    )
    style = TableStyle(
        [
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1f2937")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("ALIGN", (1, 1), (-1, -1), "CENTER"),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("GRID", (0, 0), (-1, -1), 0.3, colors.grey),
        ]
    )
    for i, row in enumerate(rows, start=1):
        if row["verdict"] == "FAIL":
            style.add("BACKGROUND", (0, i), (-1, i), colors.HexColor("#fee2e2"))
        elif row["critical"] > 0:
            style.add("BACKGROUND", (0, i), (-1, i), colors.HexColor("#fef3c7"))
    t.setStyle(style)
    flow.append(t)
    flow.append(PageBreak())

    flow.append(Paragraph("Top critical/high CVEs per image", h2))
    for report in reports:
        label = _image_label(report)
        top = _top_cves(report, n=5)
        flow.append(Paragraph(f"<b>{label}</b>", body))
        if not top:
            flow.append(Paragraph("  (no critical/high findings)", body))
            flow.append(Spacer(1, 2 * mm))
            continue
        cve_rows: list[list[Any]] = [["Severity", "ID", "Package", "Installed", "Fixed"]]
        for v in top:
            cve_rows.append(
                [
                    (v.get("severity") or "").upper(),
                    v.get("id") or "-",
                    v.get("package") or "-",
                    v.get("installed_version") or "-",
                    v.get("fixed_version") or "—",
                ]
            )
        ct = Table(
            cve_rows,
            colWidths=[20 * mm, 38 * mm, 45 * mm, 30 * mm, 30 * mm],
            repeatRows=1,
        )
        ct.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#374151")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("FONTSIZE", (0, 0), (-1, -1), 8),
                    ("GRID", (0, 0), (-1, -1), 0.3, colors.grey),
                ]
            )
        )
        flow.append(ct)
        flow.append(Spacer(1, 4 * mm))

    doc.build(flow)


def main() -> int:
    if len(sys.argv) != 3:
        print("usage: nightly-report-pdf.py <reports-dir> <out.pdf>", file=sys.stderr)
        return 2
    indir, outfile = sys.argv[1], sys.argv[2]

    reports = _load_reports(indir)
    if not reports:
        print("no scan reports — skipping PDF generation", file=sys.stderr)
        return 0

    try:
        _render(reports, outfile)
    except ImportError:
        print(
            "reportlab not installed — skipping PDF generation. "
            "pip install reportlab to enable.",
            file=sys.stderr,
        )
        return 0

    print(f"wrote {outfile} ({os.path.getsize(outfile)} bytes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
