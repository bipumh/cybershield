"""Report generation engine (requirement #20).

Formats: PDF, HTML, CSV, JSON, Excel(XLSX). Types: executive, technical,
compliance. Mappings are evidence/curated only — never invented.
"""
from __future__ import annotations

import csv
import io
import json
from datetime import datetime, timezone
from typing import Any

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4, landscape, letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer, Table,
                                TableStyle, PageBreak)

from ..core.constants import ReportType


def _fmt(dt) -> str:
    return dt.strftime("%Y-%m-%d %H:%M UTC") if dt else "—"


def build_report_data(findings: list, assets: list, *, report_type: str, scope: dict) -> dict:
    now = datetime.now(timezone.utc)
    pass_ = {"executive": _executive, "technical": _technical,
             "compliance": _compliance}.get(report_type, _technical)
    result = pass_(findings, assets, scope)
    result["generated_at"] = now.isoformat()
    result["report_type"] = report_type
    result["scope"] = scope
    return result


def _executive(findings, assets, scope) -> dict:
    sev = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    kev = 0
    internet = 0
    for f in findings:
        sev[f.severity] = sev.get(f.severity, 0) + 1
        if f.is_kev:
            kev += 1
        if f.internet_exposed:
            internet += 1
    critical_items = sorted([f for f in findings if f.severity == "critical"],
                            key=lambda x: x.risk_score, reverse=True)[:10]
    return {
        "title": "CyberShield Executive Security Report",
        "summary": {
            "open_findings": len(findings),
            "severity": sev,
            "kev_exposure": kev,
            "internet_exposed_findings": internet,
            "assets_assessed": len(assets),
        },
        "critical_priorities": [
            {"finding_no": f.finding_no, "title": f.title, "risk_score": f.risk_score,
             "asset": f.asset.hostname if f.asset else "",
             "kev": f.is_kev, "internet": f.internet_exposed}
            for f in critical_items
        ],
        "narrative": (
            "This report summarizes the organization's current security posture from "
            "authorized assessments. The highest-priority exposures are internet-facing "
            "and/or actively-exploited (KEV) weaknesses on critical assets. Recommend "
            "immediate remediation of critical findings, then high, aligned to the SLA "
            "policy. AI-generated risk labels are advisory and must be confirmed by "
            "security analysts."
        ),
    }


def _technical(findings, assets, scope) -> dict:
    return {
        "title": "CyberShield Technical Vulnerability Report",
        "assets": [
            {"asset_key": a.asset_key, "hostname": a.hostname, "ip": a.ip_address,
             "criticality": a.criticality, "internet_facing": a.is_internet_facing,
             "risk_score": a.risk_score, "vuln_count": a.vulnerability_count}
            for a in assets
        ],
        "findings": [
            {
                "finding_no": f.finding_no, "title": f.title, "severity": f.severity,
                "cvss": f.cvss_score, "cve": f.cve, "cwe": f.cwe, "category": f.category,
                "affected_component": f.affected_component, "detected_version": f.detected_version,
                "fixed_version": f.fixed_version, "status": f.status,
                "risk_score": f.risk_score, "risk_band": f.risk_band, "is_kev": f.is_kev,
                "internet_exposed": f.internet_exposed, "evidence": f.evidence,
                "asset": (f.asset.hostname if f.asset else f.asset_id),
                "remediation": _plan_summary(f), "verification": _verification(f),
                "first_detected": _fmt(f.first_detected_at), "last_detected": _fmt(f.last_detected_at),
            }
            for f in sorted(findings, key=lambda x: x.risk_score, reverse=True)
        ],
    }


def _compliance(findings, assets, scope) -> dict:
    from .compliance import COMPLIANCE_BREAKDOWN, map_finding_to_standards
    breakdown = {"owasp_top10": {}, "nist_csf": {}, "cis_controls": {}, "iso_27001": {}}
    for f in findings:
        cat = f.category
        for std, controls in COMPLIANCE_BREAKDOWN.items():
            for control, cats in controls.items():
                if cat in cats:
                    key = control
                    breakdown.setdefault(std, {}).setdefault(key, []).append(f.finding_no)
    return {
        "title": "CyberShield Compliance Mapping Report",
        "disclaimer": "Mappings are defensible, evidence-based and curated. No compliance "
                      "conformity is claimed unless an explicit control mapping exists. "
                      "Audit against the authoritative standard."
        ,
        "mappings": {k: v for k, v in breakdown.items() if v},
        "sample_findings": [
            {"finding_no": f.finding_no, "title": f.title, "severity": f.severity,
             "standards": map_finding_to_standards(f.category, f.cwe)}
            for f in findings[:50]
        ],
    }


def _plan_summary(f) -> str:
    rem = json.loads(f.remediation_json or "{}")
    return rem.get("immediate_action") or rem.get("permanent_solution") or ""


def _verification(f) -> str:
    rem = json.loads(f.remediation_json or "{}")
    return rem.get("verification_procedure") or "Re-run the scanner to confirm the finding is resolved."


# ─── Format renderers ───────────────────────────────────────────────────
def render(data: dict, fmt: str) -> bytes:
    fmt = fmt.lower()
    if fmt == "json":
        return json.dumps(data, indent=2, default=str).encode("utf-8")
    if fmt == "csv":
        return _csv(data)
    if fmt == "xlsx":
        return _xlsx(data)
    if fmt == "html":
        return _html(data).encode("utf-8")
    if fmt == "pdf":
        return _pdf(data)
    return json.dumps(data, default=str).encode()


def _csv(data: dict) -> bytes:
    buf = io.StringIO()
    findings = data.get("findings", [])
    if findings:
        keys = list(findings[0].keys())
        writer = csv.DictWriter(buf, fieldnames=keys)
        writer.writeheader()
        writer.writerows(findings)
    else:
        buf.write(data.get("title", "report"))
    return buf.getvalue().encode("utf-8")


def _xlsx(data: dict) -> bytes:
    from openpyxl import Workbook
    wb = Workbook()
    ws = wb.active
    ws.title = "Findings"
    findings = data.get("findings", [])
    if findings:
        keys = list(findings[0].keys())
        ws.append(keys)
        for row in findings:
            ws.append([row.get(k, "") for k in keys])
    else:
        ws.title = "Summary"
        ws.append(["Key", "Value"])
        for k, v in data.get("summary", {}).items():
            ws.append([k, json.dumps(v, default=str)])
    buf = io.BytesIO()
    wb.save(buf)
    return buf.getvalue()


def _html(data: dict) -> str:
    findings = data.get("findings", [])
    rows = ""
    for f in findings:
        rows += f"<tr><td>{f.get('finding_no','')}</td><td>{f.get('title','')}</td>"
        rows += f"<td>{f.get('severity','')}</td><td>{f.get('cvss',0)}</td>"
        rows += f"<td>{f.get('cve','')}</td><td>{f.get('risk_score',0)}</td></tr>"
    table = (f"<h2>{data.get('title','Report')}</h2>"
             f"<p><em>Generated {data.get('generated_at','')}</em></p>"
             "<table border='1' cellpadding='4' cellspacing='0'><thead><tr>"
             "<th>ID</th><th>Title</th><th>Severity</th><th>CVSS</th><th>CVE</th><th>Risk</th>"
             "</tr></thead><tbody>" + rows + "</tbody></table>")
    return f"<!doctype html><html><head><meta charset='utf-8'></head><body>{table}</body></html>"


def _pdf(data: dict) -> bytes:
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=landscape(letter),
                            rightMargin=0.6 * inch, leftMargin=0.6 * inch,
                            topMargin=0.6 * inch, bottomMargin=0.6 * inch)
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle("TitleX", parent=styles["Title"], fontSize=18,
                                 textColor=colors.HexColor("#0b3d66"))
    elem = [Paragraph(data.get("title", "CyberShield Report"), title_style),
            Spacer(1, 6),
            Paragraph(f"Generated: {data.get('generated_at','')}", styles["Normal"])]

    summary = data.get("summary")
    if summary:
        elem.append(Spacer(1, 10))
        elem.append(Paragraph("Summary", styles["Heading2"]))
        rows = [[k.capitalize(), str(v) if not isinstance(v, dict) else
                 json.dumps(v, default=str)] for k, v in summary.items()]
        t = Table(rows, colWidths=[3 * inch, 6 * inch])
        t.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#eaf2fa")),
                               ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                               ("FONTNAME", (0, 0), (-1, -1), "Helvetica")]))
        elem.append(t)

    findings = data.get("findings", [])
    if findings:
        elem.append(Spacer(1, 12))
        elem.append(Paragraph("Findings", styles["Heading2"]))
        hdr = ["ID", "Title", "Severity", "CVSS", "CVE", "Risk"]
        cols = ["finding_no", "title", "severity", "cvss", "cve", "risk_score"]
        data_rows = [[str(f.get(c, "")) if c != "title" else
                     (f.get("title") or "")[:60] for c in cols] for f in findings[:200]]
        t2 = Table([hdr] + data_rows, repeatRows=1)
        t2.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0b3d66")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("GRID", (0, 0), (-1, -1), 0.4, colors.grey),
            ("FONTNAME", (0, 0), (-1, -1), "Helvetica"),
            ("FONTSIZE", (0, 0), (-1, -1), 7.5),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ]))
        elem.append(t2)

    doc.build(elem)
    return buf.getvalue()
