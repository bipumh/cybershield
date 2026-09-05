"""Demo/development seeder.

Loads a small set of *well-known public* CVEs + CISA KEV catalog entries and a
few demo assets/findings so dashboards and reports are populated for
evaluation. This is seed data for dev/lab only — the operational vulnerability
database should come from live feeds through connectors (see SCANNER docs).
"""
import sys
import os
import json
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.db.session import SessionLocal
from app.db.models import Asset, CveInfo, CisaKev, Finding
from app.services.bootstrap import bootstrap
from app.services.finding_service import finding_fingerprint
from app.engines import risk as risk_engine
from app.engines.intelligence import cvss31_base_score, severity_from_score
from app.engines.remediation import build_remediation_plan
from app.engines.compliance import map_finding_to_standards
from sqlalchemy import select

NOW = datetime.now(timezone.utc)


def seed():
    db = SessionLocal()
    try:
        bootstrap(db)
        _seed_kev(db)
        _seed_assets(db)
        _seed_findings(db)
        print("Demo seed complete.")
    finally:
        db.close()


def _seed_kev(db):
    rows = [
        ("CVE-2024-3094", "Apache", "XZ Utils", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
         "Backdoor in XZ Utils (liblzma) enabling unauthorized remote code execution.", "2024-04-01"),
        ("CVE-2023-34362", "Progress", "MOVEit Transfer", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
         "SQL injection leading to credential theft and data exfiltration.", "2023-06-02"),
        ("CVE-2021-44228", "Apache", "Log4j", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
         "Log4Shell remote code execution via JNDI lookup.", "2021-12-10"),
        ("CVE-2024-3400", "Palo Alto", "PAN-OS", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
         "Command injection in GlobalProtect portal leading to unauthenticated RCE.", "2024-04-12"),
        ("CVE-2023-44487", "HTTP/2", "HTTP/2", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
         "HTTP/2 rapid reset denial-of-service.", "2023-10-10"),
    ]
    for cve, vendor, product, vec, desc, dstr in rows:
        got = db.execute(select(CisaKev).where(CisaKev.cve_id == cve)).scalar_one_or_none()
        if not got:
            d = datetime.fromisoformat(dstr).replace(tzinfo=timezone.utc)
            db.add(CisaKev(cve_id=cve, vendor=vendor, product=product, name=desc[:80],
                           description=desc, required_action="Apply vendor patch/mitigation.",
                           date_added=d, due_date=d + timedelta(days=30),
                           cvss_score=cvss31_base_score(vec), source="cisa_kev"))
        ci = db.execute(select(CveInfo).where(CveInfo.cve_id == cve)).scalar_one_or_none()
        if not ci:
            db.add(CveInfo(cve_id=cve, description=desc, cvss_score=cvss31_base_score(vec),
                           cvss_vector=vec, severity=severity_from_score(cvss31_base_score(vec)),
                           references=json.dumps([f"https://nvd.nist.gov/vuln/detail/{cve}"]),
                           published_at=NOW, source="demo_feed"))
    db.commit()


def _seed_assets(db):
    demo = [
        ("edge-proxy-01", None, "domain", "Ubuntu", "Apache", "medium", True),
        ("web-app-01", "10.10.1.21", "web_application", "Ubuntu", "nginx", "critical", True),
        ("sql-db-01", "10.10.2.31", "database_server", "Rocky Linux", "MariaDB", "critical", False),
        ("switch-core-01", "10.10.0.10", "switch", None, "Cisco", "high", False),
        ("mail-gw-01", None, "domain", None, None, "high", True),
    ]
    for host, ip, typ, os_, vendor, crit, internet in demo:
        asset_key = "AST-DEMO-" + (host or ip).replace("-", "")[:6].upper()
        existing = db.execute(select(Asset).where(Asset.asset_key == asset_key)).scalar_one_or_none()
        if existing:
            continue
        db.add(Asset(
            tenant_id=1, asset_key=asset_key, hostname=host, ip_address=ip,
            asset_type=typ, os_name=os_, vendor=vendor, criticality=crit,
            is_internet_facing=internet, is_production=True, environment="production",
            department="IT Security", location="DC-East", owner="Security Team",
            tags=["demo"], metadata_json="{}",
        ))
    db.commit()


def _seed_findings(db):
    if db.execute(select(Finding).limit(1)).scalar_one_or_none():
        return
    assets = db.execute(select(Asset)).scalars().all()
    specs = [
        ("web-app-01", "CVE-2021-44228", "Apache Log4j remote code execution (Log4Shell)",
         "vulnerable_component", "critical", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
         "exploited_in_wild", "log4j-core", True, True, 400),
        ("web-app-01", None, "Missing security header: Strict-Transport-Security",
         "security_misconfiguration", "medium", "", "none", "HTTP headers", True, False, 30),
        ("sql-db-01", "CVE-2023-27163", "Unpatched MariaDB known vulnerability",
         "vulnerable_component", "high", "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
         "likely_exploitable", "mariadb-server", False, False, 150),
        ("switch-core-01", None, "Telnet service exposed on management interface",
         "exposed_service", "high", "", "none", "telnet", False, False, 90),
        ("mail-gw-01", None, "No DMARC enforcement (p=none)",
         "dns_configuration", "medium", "", "none", "DMARC", True, False, 200),
        ("edge-proxy-01", "CVE-2024-3400", "PAN-OS GlobalProtect command injection",
         "vulnerable_component", "critical", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
         "exploited_in_wild", "GlobalProtect", True, True, 120),
        ("sql-db-01", None, "TLS configured with weak cipher suites",
         "tls_configuration", "medium", "", "none", "OpenSSL", False, False, 60),
    ]
    n = 0
    for asset_host, cve, title, category, sev, vec, exploit, comp, internet, kev, age in specs:
        asset = next((a for a in assets if a.hostname == asset_host), None)
        if not asset:
            continue
        n += 1
        score = cvss31_base_score(vec) if vec else (8.1 if sev == "high" else 4.3)
        severity = sev if sev else severity_from_score(score)
        age_risk = risk_engine.compute_risk_score(
            cvss=score, exploitability=exploit, asset_criticality=asset.criticality,
            internet_exposed=internet or asset.is_internet_facing, is_kev=kev, age_days=age)
        plan = build_remediation_plan(category, severity, title, comp, None)
        standards = map_finding_to_standards(category, None)
        db.add(Finding(
            tenant_id=1, finding_no=f"VUL-{n:06d}", asset_id=asset.id,
            title=title, description=f"{title}. Demo seed finding for evaluation.",
            category=category, severity=severity, cvss_score=score,
            cvss_vector=vec or None, cve=cve,
            cwe="CWE-1104" if category == "vulnerable_component" else "CWE-693",
            evidence=f"Demo evidence from seeded assessment (CVE: {cve or 'n/a'}). Confirm via re-scan.",
            affected_component=comp, detected_version=comp, exploitability=exploit,
            internet_exposed=internet or asset.is_internet_facing,
            asset_criticality=asset.criticality, risk_score=age_risk,
            risk_band=risk_engine.band_from_score(age_risk), is_kev=kev,
            remediation_json=json.dumps(plan), remediation_level=plan.get("level", "level3_manual"),
            standards_json=json.dumps(standards),
            references=json.dumps([f"https://nvd.nist.gov/vuln/detail/{cve}"] if cve else []),
            status="open", first_detected_at=NOW - timedelta(days=age),
            last_detected_at=NOW - timedelta(days=max(0, age - 5)),
            sla_due_at=NOW + timedelta(days=7 if sev == "critical" else 15 if sev == "high" else 30),
            last_change="persistent",
        ))
    db.commit()
    print(f"Seeded {n} demo findings.")


if __name__ == "__main__":
    seed()
