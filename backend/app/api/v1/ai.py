"""AI Security Advisor chat (requirement #35)."""
from __future__ import annotations

import json
from datetime import datetime, timezone

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from ...core.constants import FindingStatus
from ...core.deps import get_current_user, get_db_dep, require_permission
from ...db.models import Asset, Finding, User
from ...engines.ai import AiEngine

router = APIRouter(prefix="/ai", tags=["AI Security Analyst"])


class AdvisorQuestion(BaseModel):
    question: str


@router.post("/advisor", summary="Ask the CyberShield Security Advisor (grounded on scan data)")
def advisor(body: AdvisorQuestion, db: Session = Depends(get_db_dep),
            user: User = Depends(require_permission("ai:read"))):
    ai = AiEngine()
    findings = db.execute(select(Finding).where(
        Finding.tenant_id == user.tenant_id,
        Finding.status.notin_(FindingStatus.CLOSED_STATES))).scalars().all()
    assets = db.execute(select(Asset).where(
        Asset.tenant_id == user.tenant_id, Asset.deleted_at.is_(None))).scalars().all()

    sev = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    kev = []
    internet = []
    overdue = []
    now = datetime.now(timezone.utc)
    for f in findings:
        sev[f.severity] = sev.get(f.severity, 0) + 1
        if f.is_kev:
            kev.append({"finding_no": f.finding_no, "title": f.title})
        if f.internet_exposed:
            internet.append({"finding_no": f.finding_no, "title": f.title})
        if f.sla_due_at and f.sla_due_at < now:
            overdue.append({"finding_no": f.finding_no, "title": f.title})

    context = {
        "severity_counts": sev,
        "top_priorities": sorted(
            [{"title": f.title, "risk_score": f.risk_score} for f in findings],
            key=lambda x: x["risk_score"], reverse=True)[:8],
        "internet_facing": internet,
        "kev_findings": kev,
        "overdue": overdue,
        "asset_count": len(assets),
        "open_findings": len(findings),
    }
    answer = ai.advisor(body.question, context)
    return {"answer": answer, "is_ai_generated": True, "sources": "Platform scan data"}
