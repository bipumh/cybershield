"""Generate a professional PDF User Guide for CyberShield security engineers.

Run:  .venv\\Scripts\\python scripts\\generate_user_guide_pdf.py
Output:  D:\\LOCAL DATA BASE\\VA\\docs\\CyberShield_Security_Engineer_User_Guide.pdf
"""
from __future__ import annotations

import os
import sys
from datetime import datetime

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch, mm
from reportlab.platypus import (
    BaseDocTemplate, Frame, PageTemplate, Paragraph, Spacer, Table, TableStyle,
    PageBreak, ListFlowable, ListItem, Image, KeepTogether, HRFlowable,
)

OUT = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                   "..", "docs", "CyberShield_Security_Engineer_User_Guide.pdf")
OUT = os.path.abspath(OUT)

# ─── Palette ──────────────────────────────────────────────────────────────
NAVY = colors.HexColor("#0b3d66")
BLUE = colors.HexColor("#2176ae")
LIGHT = colors.HexColor("#eaf2fa")
GREY = colors.HexColor("#8ea4c8")
DARK = colors.HexColor("#1a2534")
AMBER = colors.HexColor("#f2a33c")
GREEN = colors.HexColor("#2fbf71")
RED = colors.HexColor("#c0392b")

styles = getSampleStyleSheet()

def S(name, **kw):
    base = {"fontName": "Helvetica", "fontSize": 9.5, "leading": 14,
            "textColor": DARK, "spaceAfter": 6}
    base.update(kw)
    return ParagraphStyle(name, **base)

st_title = S("Title", fontName="Helvetica-Bold", fontSize=26, leading=32,
             textColor=NAVY, spaceAfter=6)
st_sub = S("Sub", fontSize=13, leading=18, textColor=BLUE, spaceAfter=2)
st_h1 = S("H1", fontName="Helvetica-Bold", fontSize=16, leading=20,
          textColor=colors.white, spaceBefore=10, spaceAfter=8, alignment=TA_LEFT)
st_h2 = S("H2", fontName="Helvetica-Bold", fontSize=12, leading=16,
          textColor=NAVY, spaceBefore=10, spaceAfter=4)
st_body = S("Body", fontSize=9.5, leading=14)
st_bullet = S("Bullet", fontSize=9.5, leading=13.5, leftIndent=10, spaceAfter=3)
st_note = S("Note", fontSize=8.8, leading=12.5, textColor=colors.HexColor("#5a3b00"),
            backColor=colors.HexColor("#fff6e0"), borderPadding=6, spaceBefore=6, spaceAfter=6)
st_warn = S("Warn", fontSize=8.8, leading=12.5, textColor=colors.HexColor("#7a1f1f"),
            backColor=colors.HexColor("#ffecec"), borderPadding=6, spaceBefore=6, spaceAfter=6)
st_code = S("Code", fontName="Courier", fontSize=8, leading=11,
            backColor=colors.HexColor("#f4f6f8"), textColor=DARK, borderPadding=6,
            leftIndent=4, spaceBefore=4, spaceAfter=6)
st_sec = S("Sec", fontName="Helvetica-Bold", fontSize=9, leading=12, textColor=BLUE, spaceAfter=2)

def h1(text):
    t = Table([[Paragraph(text, st_h1)]], colWidths=[170 * mm])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), NAVY),
        ("LEFTPADDING", (0, 0), (-1, -1), 10),
        ("RIGHTPADDING", (0, 0), (-1, -1), 10),
        ("TOPPADDING", (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
    ]))
    return t

def para(text, style=st_body):
    return Paragraph(text, style)

def bullets(items):
    return ListFlowable([ListItem(Paragraph(i, st_bullet), leftIndent=12,
                                  value="•") for i in items],
                        bulletType="bullet", start="•", bulletFontSize=10,
                        bulletColor=BLUE, leftIndent=16)

def note(text, style=st_note):
    return Paragraph(text, style)

def table(headers, rows, widths=None):
    data = [[Paragraph("<b>" + h + "</b>", S("th", fontSize=8.5, textColor=colors.white, leading=11))
             for h in headers]]
    for r in rows:
        data.append([Paragraph(str(c), S("td", fontSize=8.3, leading=11)) for c in r])
    w = widths or [170 / len(headers) * mm] * len(headers)
    t = Table(data, colWidths=w, repeatRows=1)
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), BLUE),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#c9d4e4")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 5),
        ("RIGHTPADDING", (0, 0), (-1, -1), 5),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f7f9fc")]),
    ]))
    t.hAlign = "LEFT"
    return t

# ─── Page decoration ──────────────────────────────────────────────────────
def on_page(canvas, doc):
    canvas.saveState()
    # header band
    canvas.setFillColor(NAVY)
    canvas.rect(0, A4[1] - 0.55 * inch, A4[0], 0.55 * inch, fill=1, stroke=0)
    canvas.setFillColor(colors.white)
    canvas.setFont("Helvetica-Bold", 8)
    canvas.drawString(0.7 * inch, A4[1] - 0.38 * inch, "CyberShield  ·  Security Engineer User Guide")
    canvas.drawRightString(A4[0] - 0.7 * inch, A4[1] - 0.38 * inch, "Confidential / Authorized use only")
    # footer
    canvas.setStrokeColor(LIGHT)
    canvas.setLineWidth(0.5)
    canvas.line(0.7 * inch, 0.6 * inch, A4[0] - 0.7 * inch, 0.6 * inch)
    canvas.setFillColor(GREY)
    canvas.setFont("Helvetica", 7.5)
    canvas.drawString(0.7 * inch, 0.42 * inch, "© CyberShield — Internal Security Engineering")
    canvas.drawRightString(A4[0] - 0.7 * inch, 0.42 * inch, f"Page {doc.page}")
    canvas.restoreState()

# ─── Build ────────────────────────────────────────────────────────────────
def build():
    doc = BaseDocTemplate(OUT, pagesize=A4,
                          leftMargin=0.7 * inch, rightMargin=0.7 * inch,
                          topMargin=0.85 * inch, bottomMargin=0.8 * inch,
                          title="CyberShield Security Engineer User Guide",
                          author="CyberShield Platform")
    frame = Frame(doc.leftMargin, doc.bottomMargin,
                  doc.width, doc.height, id="main")
    doc.addPageTemplates([PageTemplate(id="all", frames=[frame], onPage=on_page)])

    story = []
    W = doc.width / inch

    # ── Title page ────────────────────────────────────────────────────────
    story.append(Spacer(1, 0.6 * inch))
    story.append(Paragraph("CyberShield", st_title))
    story.append(Paragraph("Vulnerability Assessment &amp; Exposure Management", st_sub))
    story.append(Spacer(1, 6))
    story.append(HRFlowable(width="100%", thickness=2, color=BLUE, spaceAfter=10))
    story.append(para("Security Engineer Operations Guide", S("T", fontName="Helvetica-Bold", fontSize=14, textColor=DARK)))
    story.append(para("A practical operator's manual for running authorized security "
                      "assessments, triaging findings, prioritizing risk, and executing the "
                      "remediation workflow.", st_body))
    story.append(Spacer(1, 10))
    story.append(para("Version 0.1  ·  " + datetime.now().strftime("%B %d, %Y"),
                      S("meta", fontSize=9, textColor=GREY)))
    story.append(Spacer(1, 26))
    guide = Table([[Paragraph("<b>About this guide</b>", S("h", fontSize=11, textColor=NAVY))]], colWidths=[W * inch])
    guide.setStyle(TableStyle([("BACKGROUND", (0,0), (-1,-1), LIGHT), ("LEFTPADDING",(0,0),(-1,-1),10),
                               ("TOPPADDING",(0,0),(-1,-1),8), ("BOTTOMPADDING",(0,0),(-1,-1),8)]))
    story.append(guide)
    story.append(Spacer(1, 8))
    story.append(para(
        "This guide walks a security engineer through day-to-day use of CyberShield: "
        "starting authorized scans, discovering assets, reviewing normalized findings, "
        "using the AI Security Analyst, prioritizing and remediating vulnerabilities, "
        "handling false positives, generating reports, and maintaining audit visibility. "
        "The platform is <b>defensive only</b> — it will not exploit, deny service, or "
        "disrupt systems.", st_body))
    story.append(Spacer(1, 10))
    story.append(note(
        "<b>Authorized use only.</b> Only assess assets you own or hold explicit written "
        "authorization to test. CyberShield's active scanners are sandboxed with scope, "
        "rate and timeout controls and cannot perform destructive actions.",
        S("callout", fontSize=9, textColor=colors.HexColor("#0b3d66"),
          backColor=LIGHT, borderPadding=8)))
    story.append(PageBreak())

    # ── Contents ──────────────────────────────────────────────────────────
    story.append(h1("Contents"))
    toc = [
        ("1.  Getting started", "Signing in, roles, navigation"),
        ("2.  Scan safety & scope", "The mandatory safety policy and controls"),
        ("3.  Domain / Web application scans", "Targets, discovery, approval, profiles"),
        ("4.  Infrastructure / network scans", "Asset types, CIDR, input methods"),
        ("5.  Reading findings", "Severity, CVSS, risk score, evidence, standards"),
        ("6.  AI Security Analyst", "Finding analysis and risk predictions"),
        ("7.  Prioritization", "Top 10 things to fix now"),
        ("8.  Remediation workflow", "Levels, approval, execute, verify, close"),
        ("9.  False positives & accepted risk", "Exceptions with evidence and expiry"),
        ("10. Reports", "Executive, technical, compliance exports"),
        ("11. Security Assistant chat", "Ask about your data"),
        ("12. Scheduling & integrations", "Recurring scans and SIEM/SOC"),
        ("13. Audit & SLA", "Logs, hash chain, SLA dashboard"),
        ("14. Troubleshooting", "Common issues"),
    ]
    rows = [[Paragraph(f"<b>{a}</b>", S("tt", fontSize=9)), Paragraph(b, S("tb", fontSize=9, textColor=GREY))]
            for a, b in toc]
    t = Table(rows, colWidths=[1.6 * inch, W * inch - 1.6 * inch])
    t.setStyle(TableStyle([
        ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#d5dde8")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 6), ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 5), ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]))
    story.append(t)
    story.append(PageBreak())

    # ── 1 Getting started ────────────────────────────────────────────────
    story.append(h1("1.  Getting started"))
    story.append(para("Open the CyberShield URL (e.g. <font face='Courier'>http://localhost:5173</font>) and sign in with your "
                      "organization credentials. Your role determines what you can see and do.", st_body))
    story.append(Spacer(1, 4))
    story.append(para("<b>Signing in</b>", st_h2))
    story.append(bullets([
        "Enter your email and password. Provide the 6-digit MFA code when prompted (if MFA is enabled).",
        "On success you land on the Executive Dashboard.",
        "The <b>user menu</b> (top-right) shows your profile and a Sign out option.",
    ]))
    story.append(para("<b>Roles &amp; permissions</b>", st_h2))
    story.append(table(
        ["Role", "Typical responsibilities"],
        [
            ["Security Analyst", "Run scans, assess findings, manage vulnerability lifecycle, create exclusions"],
            ["SOC Analyst", "Monitor findings and incidents; read dashboards"],
            ["Network / System Admin", "Assess and remediate network devices and servers"],
            ["App Security Analyst", "Assess web applications, APIs and compliance"],
            ["Remediation Engineer", "Execute approved remediation and verify"],
            ["CISO", "Full visibility, risk, reports, approvals"],
            ["Auditor", "Read-only audit/report access"],
            ["Management", "Executive dashboards and reports only"],
        ],
        widths=[1.7 * inch, (W - 1.7) * inch]))
    story.append(Spacer(1, 6))
    story.append(para("<b>Navigation</b>", st_h2))
    story.append(table(
        ["Menu", "Purpose"],
        [
            ["Dashboard", "Executive posture, top assets, KEV exposure, priorities"],
            ["Assets", "Central asset inventory and risk"],
            ["Vulnerabilities", "All findings with filters and lifecycle"],
            ["Scan Center", "Start domain/web or infrastructure scans, view history"],
            ["Remediation", "Approval workflow and execution status"],
            ["Reports", "Generate and download reports"],
            ["Security Advisor", "Ask questions grounded on your data"],
        ],
        widths=[1.5 * inch, (W - 1.5) * inch]))

    # ── 2 Scan safety ────────────────────────────────────────────────────
    story.append(h1("2.  Scan safety &amp; scope"))
    story.append(note(
        "<b>Mandatory Safety Policy.</b> Before any active scan you must confirm: "
        "<i>“This scan must only be performed against assets that you own or are explicitly "
        "authorized to assess.”</i> The platform will refuse to start a scan without this "
        "confirmation and an approved scope."))
    story.append(para("Every scan carries these configurable safety controls:", st_body))
    story.append(bullets([
        "<b>Scope</b> — authorized targets plus excluded IPs / domains; anything outside scope is blocked.",
        "<b>Profile</b> — Passive (no intrusive requests), Safe (low-impact), Standard (broader), Enterprise (strict rate limiting + maintenance windows).",
        "<b>Rate limit</b> — max requests per second (hard cap enforced).",
        "<b>Timeout</b> — per-request timeout.",
        "<b>Concurrency</b> — max parallel checks per scan (capped by platform).",
        "<b>Cancel</b> — emergency stop at any time.",
    ]))
    story.append(para("The platform will not perform exploitation, brute force, credential theft, "
                      "denial-of-service or malware actions. Active scanning only sends safe, "
                      "authorized inspection requests.", st_body))

    # ── 3 Domain / Web ───────────────────────────────────────────────────
    story.append(h1("3.  Domain / Web application scans"))
    story.append(para("Use the <b>Domain / Web Application Security</b> scanner to assess domains, "
                      "URLs, IPs, web applications and API endpoints.", st_body))
    story.append(para("<b>Step-by-step</b>", st_h2))
    story.append(bullets([
        "Open <b>Scan Center</b> and switch the mode to <b>Domain / Web Application Security</b>.",
        "Enter a target, e.g. <font face='Courier'>example.com</font>, <font face='Courier'>https://example.com/login</font>, or an IP.",
        "Optionally choose a <b>scan profile</b> (Safe is the default).",
        "Click <b>Discover subdomains</b> to enumerate associated subdomains passively (certificate transparency + common names).",
        "Review discovered subdomains — the platform marks each as <b>discovered / confirmed / responsive / unresponsive</b>, and only in-scope assets enter scanning.",
        "Confirm the <b>safety policy</b> and scope, then click <b>Start scan</b>.",
    ]))
    story.append(para("The scan runs <b>asynchronously</b>; you can monitor its <b>progress</b> in "
                      "Scan Center and stop it with <b>Cancel</b> at any time. When complete, "
                      "findings appear under <b>Vulnerabilities</b>.", st_body))
    story.append(para("<b>What the web/domain scanner checks</b>", st_h2))
    story.append(table(
        ["Area", "Examples"],
        [
            ["Web security headers", "CSP, HSTS (Strict-Transport-Security), X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy"],
            ["TLS / certificates", "Weak protocols, weak ciphers, expired or expiring certificates"],
            ["Cookies / sessions", "HttpOnly, Secure, SameSite flags"],
            ["App configuration", "CORS misconfiguration, CSRF protection gaps, Basic auth, exposed docs"],
            ["Content / disclosure", "Directory listing, technology fingerprint, debug/stack traces, sensitive files"],
            ["DNS security", "SPF, DMARC, DKIM, DNSSEC, MX, CAA, security.txt"],
        ],
        widths=[1.7 * inch, (W - 1.7) * inch]))

    # ── 4 Infrastructure ─────────────────────────────────────────────────
    story.append(h1("4.  Infrastructure / network scans"))
    story.append(para("Use the <b>Infrastructure / Endpoint / Network Security</b> scanner to assess "
                      "servers, workstations, network devices, databases, VMs, containers, storage and IoT assets.", st_body))
    story.append(para("<b>Asset types</b>: Server, Workstation, Router, Switch, Firewall, Wireless "
                      "Controller, Access Point, Network Appliance, Database Server, Application "
                      "Server, Virtual Machine, Container Host, Storage Device, IoT Device, Other.", st_body))
    story.append(para("<b>Input methods</b>", st_h2))
    story.append(bullets([
        "IP address — e.g. <font face='Courier'>192.168.10.10</font>",
        "Hostname / FQDN",
        "CIDR network range — e.g. <font face='Courier'>192.168.10.0/24</font>",
        "Asset inventory, CSV import and API integration (see Administration).",
    ]))
    story.append(note("<b>CIDR authorization.</b> Network ranges are bounded (max 256 hosts) and require "
                      "strict authorization and scope controls. Sweeping large ranges is intentionally limited to "
                      "protect production.", st_warn))
    story.append(para("The scanner checks open/exposed services (banner + service fingerprint), weak "
                      "protocols, outdated/end-of-life software, exposed management interfaces, and "
                      "ports like Telnet, FTP, RDP, Redis, MongoDB — with non-intrusive, bounded requests.", st_body))

    # ── 5 Reading findings ───────────────────────────────────────────────
    story.append(h1("5.  Reading findings"))
    story.append(para("Every finding is a fully normalized vulnerability record. Open <b>Vulnerabilities</b> "
                      "and use the filters to narrow by severity, status, asset, CVE, CWE, CISA KEV, "
                      "or search. Click any row to open the <b>Finding Detail</b> page.", st_body))
    story.append(para("<b>Fields you will see</b>", st_h2))
    story.append(table(
        ["Field", "Meaning"],
        [
            ["Finding number", "Unique ID, e.g. VUL-000001"],
            ["Severity", "Critical / High / Medium / Low (from CVSS + context)"],
            ["CVSS", "0–10 base score and vector"],
            ["CVE / CWE", "Standard identifiers when mapped"],
            ["Evidence", "The safe technical observation that justifies the finding"],
            ["Risk score", "0–100 composite (see §: risk model)"],
            ["Risk band", "Critical (90–100) / High (70–89) / Medium (40–69) / Low (1–39)"],
            ["KEV", "Whether it is in the CISA Known Exploited Vulnerabilities catalog"],
            ["Asset", "Affected asset name, IP and criticality"],
            ["Status", "Open, Investigating, Remediation Planned, In Progress, Resolved, Verified, Closed, etc."],
            ["Age / SLA", "Days since first detected and the SLA due date"],
        ],
        widths=[1.7 * inch, (W - 1.7) * inch]))
    story.append(para("<b>Standards mapping</b> — the finding maps (where defensible) to OWASP Top 10, "
                      "OWASP ASVS/WSTG, CWE, NIST CSF, CIS Controls, ISO 27001. Mappings are evidence-based "
                      "and never invented.", st_body))

    # ── 6 AI Security Analyst ───────────────────────────────────────────
    story.append(h1("6.  AI Security Analyst"))
    story.append(para("On the Finding Detail page, the <b>AI Security Analyst</b> panel provides:", st_body))
    story.append(bullets([
        "<b>Why it matters</b> — a plain-language explanation of the risk.",
        "<b>Potential impact</b> — confidentiality, integrity, availability, compliance, business.",
        "<b>Predicted risk</b> — likely Critical/High/Medium/Low based on threat intel, exposure, age, asset criticality, exploit availability.",
        "<b>Confidence</b> — an indication of certainty.",
    ]))
    story.append(note("AI output is clearly labelled <b>AI-generated risk assessment</b>. It is advisory "
                      "and must not be treated as confirmed fact. Always corroborate against the evidence "
                      "and your own triage.", st_warn))

    # ── 7 Prioritization ────────────────────────────────────────────────
    story.append(h1("7.  Prioritization — top things to fix now"))
    story.append(para("The <b>Dashboard → Top priorities — fix now</b> panel ranks the highest-impact "
                      "work using risk score plus weighted factors: actively-exploited (KEV), "
                      "internet-facing, critical/high-value assets, and age. Use it to direct effort.", st_body))
    story.append(table(
        ["Ranking signal", "Why it ranks high"],
        [
            ["CISA KEV", "The vulnerability is known to be actively exploited"],
            ["Internet-facing", "Remotely reachable — highest exposure"],
            ["Critical/high asset", "Impact on a business-critical system"],
            ["High risk score", "Composite of CVSS, exposure, age, criticality"],
            ["Long overdue", "Aging past the remediation SLA"],
        ],
        widths=[1.8 * inch, (W - 1.8) * inch]))

    # ── 8 Remediation ───────────────────────────────────────────────────
    story.append(h1("8.  Remediation workflow"))
    story.append(para("Workflow: <b>Finding → Recommendation → Risk Review → Approval → Execution → "
                      "Verification → Closure</b>. Create a Remediation plan from a finding (or let the "
                      "platform generate one), then walk it through the workflow under <b>Remediation</b>.", st_body))
    story.append(para("<b>Safe automation levels</b>", st_h2))
    story.append(table(
        ["Level", "Automation", "Examples"],
        [
            ["L1 — Safe Automatic", "Yes (reversible)", "Create ticket, notify owner, update status, propose config/patch, collect verification data"],
            ["L2 — Approval Required", "After approval", "Disable a service, change firewall rule, apply baseline, change auth, restart a service"],
            ["L3 — Manual", "Never auto-executed", "OS/firmware upgrades, database or production changes, anything that may interrupt business"],
        ],
        widths=[1.35 * inch, 1.15 * inch, (W - 2.5) * inch]))
    story.append(Spacer(1, 4))
    story.append(para("Each remediation records the requester, approver, timestamps, target asset, proposed "
                      "and previous configuration, backup status, execution status, verification result, "
                      "rollback option and an audit log.", st_body))
    story.append(para("<b>Approving and executing</b>", st_h2))
    story.append(bullets([
        "Submit a plan for approval. The approver (e.g. CISO) approves or rejects with a comment.",
        "For L2, execute after approval. The platform tracks execution; a privileged admin performs the actual system change.",
        "Verify by <b>re-running</b> the corresponding scanner/check on the asset — if the finding no longer appears, mark Verified, then Closed.",
        "Roll back if the change is undesirable or causes an outage.",
    ]))
    story.append(note("For Level 3 changes, a privileged engineer performs the change manually; the platform "
                      "records it only after verification. The platform never remotely mutates production systems.", st_note))

    # ── 9 False positives ───────────────────────────────────────────────
    story.append(h1("9.  False positives &amp; accepted risk"))
    story.append(para("On a Finding Detail page, you can mark an exception:", st_body))
    story.append(bullets([
        "<b>False Positive</b> — the finding is not genuine. Provide a reason and evidence.",
        "<b>Accepted Risk</b> — the risk is consciously accepted. Provide a reason, owner and expiry.",
        "<b>Compensating Control</b> — a control mitigates the risk. Describe the control.",
    ]))
    story.append(para("Exceptions require an <b>analyst</b>, an <b>approver</b>, an <b>expiration date</b> and "
                      "<b>evidence</b>. Approved exceptions suppress the finding and <b>auto-expire</b>, "
                      "forcing re-review.", st_body))

    # ── 10 Reports ──────────────────────────────────────────────────────
    story.append(h1("10.  Reports"))
    story.append(para("Generate reports under <b>Reports</b>. Choose the type and format, then Download.", st_body))
    story.append(table(
        ["Type", "Audience", "Content"],
        [
            ["Executive", "CISO / management", "Posture, risk score, critical findings, business impact, trends, recommended priorities"],
            ["Technical", "Admins / SOC / engineering", "Findings, evidence, CVEs, CVSS, affected assets, remediation, verification steps"],
            ["Compliance", "Auditors / compliance", "Defensible mappings to OWASP, NIST CSF, CIS Controls, ISO 27001"],
        ],
        widths=[1.2 * inch, 1.6 * inch, (W - 2.8) * inch]))
    story.append(Spacer(1, 4))
    story.append(para("Available formats: <b>PDF, HTML, CSV, JSON, Excel (XLSX)</b>.", st_body))

    # ── 11 Assistant chat ───────────────────────────────────────────────
    story.append(h1("11.  Security Assistant chat"))
    story.append(para("The <b>Security Advisor</b> answers questions <b>using your actual scan data</b>. "
                      "Try questions such as: “What should we fix first?”, “Which vulnerabilities are "
                      "internet-facing?”, “Which are actively exploited?”, “Which are overdue?”, or "
                      "“Explain this to a non-technical manager.”", st_body))
    story.append(note("The advisor is grounded on platform data and will not invent CVEs, assets or "
                      "remediation. It clearly distinguishes observed facts, scanner results, external "
                      "intelligence, AI inference and recommendations.", st_note))

    # ── 12 Scheduler & integrations ─────────────────────────────────────
    story.append(h1("12.  Scheduling &amp; integrations"))
    story.append(para("<b>Scheduled scans</b> — create recurring scans (one-time, daily, weekly, monthly, "
                      "custom) from the scheduler. Schedules only run within authorized scope and use the "
                      "same safety controls.", st_body))
    story.append(para("<b>SIEM / SOC integration</b> — register connectors (Wazuh, Splunk, Sentinel, "
                      "Elastic, syslog, webhook, API) so security events are forwarded, including: scan "
                      "started, scan completed, critical vulnerability detected, new internet-facing asset, "
                      "vulnerability status changed, remediation executed/failed.", st_body))

    # ── 13 Audit & SLA ─────────────────────────────────────────────────
    story.append(h1("13.  Audit &amp; SLA"))
    story.append(para("<b>Audit logs</b> record actor, action, target, source IP, timestamp, result and "
                      "previous/new state. The log is tamper-evident via a <b>hash chain</b> — you can verify "
                      "chain integrity in the Admin area. Audit access is permission-gated.", st_body))
    story.append(para("<b>SLA tracking</b> shows Critical/High/Medium SLA breaches, upcoming SLAs, average "
                      "remediation time, mean time to remediate and reopened vulnerabilities. Default SLAs: "
                      "Critical 7d, High 15d, Medium 30d, Low 60–90d (configurable).", st_body))

    # ── 14 Troubleshooting ───────────────────────────────────────────────
    story.append(h1("14.  Troubleshooting"))
    story.append(table(
        ["Problem", "Likely cause / resolution"],
        [
            ["Scan won't start / safety error", "You must confirm safety policy + scope; ensure target is in scope and not excluded"],
            ["Scan stuck at 0%", "Target may be unreachable; check DNS/host. Cancel and retry with a different profile"],
            ["No findings", "Target may be hardened or not HTTP; results may open wider ports or a different target"],
            ["Report has no data", "Ensure findings/assets exist; broaden the report scope filters"],
            ["Advisor not answering", "AI provider may be off (mocked fallback is used); check AI configuration"],
            ["Login rejected", "Confirm credentials and MFA code; check your account is active"],
        ],
        widths=[1.9 * inch, (W - 1.9) * inch]))
    story.append(Spacer(1, 10))
    story.append(HRFlowable(width="100%", thickness=1, color=LIGHT, spaceAfter=8))
    story.append(para("<b>Recommendation</b> — Always verify a finding before acting, prioritize "
                      "internet-facing and KEV items first, and track remediation against SLA. Confirm "
                      "AI-generated guidance against evidence.", st_body))

    doc.build(story)
    return OUT


if __name__ == "__main__":
    path = build()
    print("PDF written to:", path)
    print("Size:", os.path.getsize(path), "bytes")
