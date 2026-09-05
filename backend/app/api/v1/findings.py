"""Vulnerability findings: list, detail, status, exceptions, lifecycle."""
from __future__ import annotations

import json
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Query
from sqlalchemy import select
from sqlalchemy.orm import Session

from ...core.constants import ExceptionKind, FindingStatus
from ...core.deps import get_current_user, get_db_dep, require_permission, write_audit
from ...core.exceptions import NotFoundError, ValidationError
from ...db.models import Asset, ExceptionItem, Finding, User
from ...schemas.finding import (ExceptionCreate, ExceptionOut, FindingDetail, FindingOut,
                                FindingUpdate)
from ...services.finding_service import FindingService

router = APIRouter(prefix="/findings", tags=["Vulnerabilities"])


@router.get("", response_model=dict, summary="List vulnerability findings")
def list_findings(
    page: int = Query(1, ge=1), page_size: int = Query(20, ge=1, le=200),
    severity: str | None = None, status: str | None = None,
    asset_id: int | None = None, cve: str | None = None, cwe: str | None = None,
    is_kev: bool | None = None, risk_band: str | None = None, search: str | None = None,
    sort_by: str = "risk_score", sort_desc: bool = True,
    db: Session = Depends(get_db_dep), user: User = Depends(require_permission("vulns:read")),
):
    svc = FindingService(db)
    res = svc.query_list(tenant_id=user.tenant_id, page=page, page_size=page_size,
                         severity=severity, status=status, asset_id=asset_id, cve=cve,
                         cwe=cwe, is_kev=is_kev, risk_band=risk_band, search=search,
                         sort_by=sort_by, sort_desc=sort_desc)
    return {**res, "items": [_to_out(f) for f in res["items"]]}


@router.get("/{finding_id}", response_model=FindingDetail, summary="Finding detail")
def get_finding(finding_id: int, db: Session = Depends(get_db_dep),
                user: User = Depends(require_permission("vulns:read"))):
    f = db.get(Finding, finding_id)
    if not f or f.tenant_id != user.tenant_id:
        raise NotFoundError("Finding not found")
    asset = db.get(Asset, f.asset_id) if f.asset_id else None
    return _to_detail(f, asset)


@router.patch("/{finding_id}", response_model=FindingOut, summary="Update finding")
def update_finding(finding_id: int, body: FindingUpdate, db: Session = Depends(get_db_dep),
                   user: User = Depends(require_permission("vulns:manage"))):
    f = db.get(Finding, finding_id)
    if not f or f.tenant_id != user.tenant_id:
        raise NotFoundError("Finding not found")
    old = {"status": f.status, "severity": f.severity}
    if body.status is not None:
        if body.status not in FindingStatus.ALL:
            raise ValidationError("Invalid status")
        f.status = body.status
    if body.severity is not None:
        f.severity = body.severity
    db.commit()
    write_audit(db, actor=user, action="finding.update", target_type="finding",
                target_id=f.id, previous_state=old,
                new_state={"status": f.status, "severity": f.severity})
    return _to_out(f)


# ─── Lifecycle comparison (requirement #33) ─────────────────────────────
@router.get("/compare/{prev_scan}/{curr_scan}", summary="Compare two scans lifecycle")
def compare(prev_scan: int, curr_scan: int, db: Session = Depends(get_db_dep),
            user: User = Depends(require_permission("vulns:read"))):
    svc = FindingService(db)
    return svc.compare_scan(tenant_id=user.tenant_id, prev_scan_id=prev_scan,
                            curr_scan_id=curr_scan)


# ─── Exceptions / false-positive management (requirement #27) ──────────
@router.post("/{finding_id}/exceptions", response_model=ExceptionOut, status_code=201,
             summary="Mark exception (false positive / accepted risk / compensating)")
def create_exception(finding_id: int, body: ExceptionCreate, db: Session = Depends(get_db_dep),
                     user: User = Depends(require_permission("exceptions:create"))):
    if body.kind not in ExceptionKind.ALL:
        raise ValidationError(f"kind must be one of {ExceptionKind.ALL}")
    f = db.get(Finding, finding_id)
    if not f or f.tenant_id != user.tenant_id:
        raise NotFoundError("Finding not found")
    ex = ExceptionItem(
        tenant_id=user.tenant_id, finding_id=f.id, kind=body.kind, reason=body.reason,
        evidence=body.evidence, owner_id=user.id, status="pending",
        expires_at=body.expires_at, compensating_control_desc=body.compensating_control_desc,
    )
    db.add(ex)
    # Place finding into "investigating" pending review/approval
    f.status = FindingStatus.INVESTIGATING
    db.commit()
    db.refresh(ex)
    write_audit(db, actor=user, action="finding.exception_requested", target_type="finding",
                target_id=f.id, new_state={"kind": body.kind, "reason": body.reason})
    return ExceptionOut.model_validate(ex)


@router.post("/exceptions/{exception_id}/approve", response_model=ExceptionOut,
             summary="Approve an exception (CISO/approver)")
def approve_exception(exception_id: int, db: Session = Depends(get_db_dep),
                      user: User = Depends(require_permission("exceptions:approve"))):
    ex = db.get(ExceptionItem, exception_id)
    if not ex or ex.tenant_id != user.tenant_id:
        raise NotFoundError("Exception not found")
    ex.status = "approved"
    ex.approved_by = user.id
    f = db.get(Finding, ex.finding_id)
    if f:
        f.is_suppressed = True
        f.suppression_reason = ex.reason
        if ex.kind == ExceptionKind.ACCEPTED_RISK:
            f.status = FindingStatus.ACCEPTED_RISK
        elif ex.kind == ExceptionKind.FALSE_POSITIVE:
            f.status = FindingStatus.FALSE_POSITIVE
        else:
            f.status = FindingStatus.ACCEPTED_RISK
    db.commit()
    write_audit(db, actor=user, action="exception.approve", target_type="finding",
                target_id=ex.finding_id, previous_state={}, new_state={"status": ex.status})
    return ExceptionOut.model_validate(ex)


@router.get("/{finding_id}/ai", summary="AI analysis for a finding")
def ai_analysis(finding_id: int, db: Session = Depends(get_db_dep),
                user: User = Depends(require_permission("ai:read"))):
    f = db.get(Finding, finding_id)
    if not f or f.tenant_id != user.tenant_id:
        raise NotFoundError("Finding not found")
    from ...engines.ai import AiEngine
    ai = AiEngine()
    verdict = ai.analyze_finding({
        "title": f.title, "category": f.category, "severity": f.severity,
        "cvss_score": f.cvss_score, "internet_exposed": f.internet_exposed,
        "asset_criticality": f.asset_criticality, "is_kev": f.is_kev,
        "age_days": max(0, (datetime.now(timezone.utc) - f.first_detected_at).days),
        "exploitability": f.exploitability, "description": f.description,
    })
    return {"finding_id": f.id, "is_ai_generated": True,
            "analysis": verdict.analysis, "why_it_matters": verdict.why_it_matters,
            "potential_impact": verdict.potential_impact,
            "predicted_risk": verdict.predicted_risk, "confidence": verdict.confidence}


def _to_out(f: Finding) -> FindingOut:
    return FindingOut(
        id=f.id, finding_no=f.finding_no, asset_id=f.asset_id, scan_id=f.scan_id,
        title=f.title, description=f.description, category=f.category, severity=f.severity,
        cvss_score=f.cvss_score, cve=f.cve, cwe=f.cwe, exploitability=f.exploitability,
        internet_exposed=f.internet_exposed, asset_criticality=f.asset_criticality,
        risk_score=f.risk_score, risk_band=f.risk_band, is_kev=f.is_kev,
        remediation_level=f.remediation_level, status=f.status,
        first_detected_at=f.first_detected_at, last_detected_at=f.last_detected_at,
        sla_due_at=f.sla_due_at, last_change=f.last_change,
        age_days=max(0, (datetime.now(timezone.utc) - f.first_detected_at).days),
    )


def _to_detail(f: Finding, asset) -> FindingDetail:
    age = max(0, (datetime.now(timezone.utc) - f.first_detected_at).days)
    return FindingDetail(
        id=f.id, finding_no=f.finding_no, title=f.title, description=f.description,
        category=f.category, severity=f.severity, cvss_score=f.cvss_score,
        cvss_vector=f.cvss_vector, cve=f.cve, cwe=f.cwe, evidence=f.evidence,
        affected_component=f.affected_component, detected_version=f.detected_version,
        fixed_version=f.fixed_version, exploitability=f.exploitability,
        internet_exposed=f.internet_exposed, asset_criticality=f.asset_criticality,
        risk_score=f.risk_score, risk_band=f.risk_band, is_kev=f.is_kev,
        ai_analysis=json.loads(f.ai_analysis_json or "{}"),
        remediation_plan=_plan(f), remediation_level=f.remediation_level,
        standards=json.loads(f.standards_json or "{}"),
        references=json.loads(f.references or "[]"), status=f.status,
        first_detected_at=f.first_detected_at, last_detected_at=f.last_detected_at,
        sla_due_at=f.sla_due_at,
        asset={"id": asset.id, "name": asset.hostname or asset.ip_address or asset.asset_key,
               "criticality": asset.criticality} if asset else None,
    )


def _plan(f: Finding):
    from ...schemas.finding import RemediationPlan
    data = json.loads(f.remediation_json or "{}")
    return RemediationPlan(
        immediate_action=data.get("immediate_action", ""),
        permanent_solution=data.get("permanent_solution", ""),
        recommended_config=data.get("recommended_config", ""),
        patch_recommendation=data.get("patch_recommendation", ""),
        verification_procedure=data.get("verification_procedure", ""),
        rollback_procedure=data.get("rollback_procedure", ""),
        business_impact=data.get("business_impact", ""),
        complexity=data.get("complexity", "medium"),
    )
