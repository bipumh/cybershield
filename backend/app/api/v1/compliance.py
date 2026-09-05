"""Compliance & threat-intelligence reporting."""
from __future__ import annotations

from typing import List

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.orm import Session

from ...core.deps import get_current_user, get_db_dep, require_permission
from ...db.models import CisaKev, ThreatIntelEntry, User

router = APIRouter(tags=["Compliance & Intelligence"])


@router.get("/threat-intelligence/kev", summary="CISA KEV catalog")
def kev(db: Session = Depends(get_db_dep), user: User = Depends(require_permission("vulns:read"))):
    rows = db.execute(select(CisaKev).order_by(CisaKev.date_added.desc()).limit(200)).scalars().all()
    return [{"cve_id": r.cve_id, "vendor": r.vendor, "product": r.product, "name": r.name,
             "required_action": r.required_action, "date_added": r.date_added,
             "cvss": r.cvss_score} for r in rows]


@router.get("/compliance/coverage", summary="Compliance coverage of open findings")
def coverage(db: Session = Depends(get_db_dep), user: User = Depends(require_permission("compliance:read"))):
    from ...engines.compliance import COMPLIANCE_BREAKDOWN
    from ...db.models import Finding
    findings = db.execute(select(Finding).where(Finding.tenant_id == user.tenant_id)).scalars().all()
    counts = {}
    for f in findings:
        counts[f.category] = counts.get(f.category, 0) + 1
    out = {}
    for std, controls in COMPLIANCE_BREAKDOWN.items():
        total_mapped = 0
        for cats in controls.values():
            total_mapped += sum(counts.get(c, 0) for c in cats)
        out[std] = {"mapped_findings": total_mapped}
    return {"standards": out, "total_findings": len(findings)}
