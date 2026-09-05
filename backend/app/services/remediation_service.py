"""Remediation engine service + approval workflow (requirement #14).

Workflow: Finding -> Recommendation -> Risk Review -> Approval -> Execution ->
Verification -> Closure. Actual system changes are performed by system/network
administrators (Levels 2/3); this platform orchestrates approvals, tracks
execution state, and verifies via a re-scan rather than remotely mutating
systems (safe/defensive). Level 1 safe-automation is explicit and reversible.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..core.constants import (FindingStatus, RemediationLevel, RemediationStatus)
from ..core.exceptions import NotFoundError, ValidationError
from ..db.models import Asset, Finding, Remediation, RemediationApproval
from ..engines.remediation import build_remediation_plan


def auto_create_remediation(db: Session, *, tenant_id: int, finding: Finding,
                            unit: int | None = None, requester_id: int | None = None) -> Remediation:
    plan = build_remediation_plan(finding.category, finding.severity, finding.title,
                                  finding.detected_version, finding.fixed_version)
    level = finding.remediation_level or plan["level"]
    title = f"Remediate: {finding.title}"
    rem = Remediation(
        tenant_id=tenant_id, finding_id=finding.id, asset_id=finding.asset_id,
        level=level, title=title, immediate_action=plan["immediate_action"],
        permanent_solution=plan["permanent_solution"],
        recommended_config=plan["recommended_config"],
        patch_recommendation=plan["patch_recommendation"],
        verification_procedure=plan["verification_procedure"],
        rollback_procedure=plan["rollback_procedure"],
        business_impact=plan["business_impact"], complexity=plan["complexity"],
        risk_reduction=finding.risk_score * 0.8,
        status=RemediationStatus.PROPOSED, requester_id=requester_id or unit,
        audit_log_json="[]",
    )
    db.add(rem)
    db.flush()
    finding.status = FindingStatus.REMEDIATION_PLANNED
    db.add(finding)
    return rem


def propose(db: Session, rem: Remediation) -> Remediation:
    if rem.level == RemediationLevel.LEVEL1_SAFE_AUTO:
        rem.status = RemediationStatus.APPROVED
    else:
        rem.status = RemediationStatus.RISK_REVIEW
    db.add(rem)
    return rem


def submit_for_approval(db: Session, rem: Remediation) -> Remediation:
    if rem.status not in (RemediationStatus.PROPOSED, RemediationStatus.RISK_REVIEW):
        raise ValidationError("Remediation is not in a reviewable state")
    if rem.level == RemediationLevel.LEVEL3_MANUAL:
        # Manual-only: still require a documented approval to proceed anywhere
        rem.status = RemediationStatus.PENDING_APPROVAL
    elif rem.level == RemediationLevel.LEVEL2_APPROVAL_REQUIRED:
        rem.status = RemediationStatus.PENDING_APPROVAL
    else:
        rem.status = RemediationStatus.APPROVED
    db.add(rem)
    return rem


def decide(db: Session, *, rem: Remediation, approver_id: int, decision: str,
           comment: str = "") -> Remediation:
    if decision not in ("approve", "reject"):
        raise ValidationError("decision must be 'approve' or 'reject'")
    if rem.status != RemediationStatus.PENDING_APPROVAL:
        raise ValidationError("Remediation is not awaiting approval")
    approval = RemediationApproval(
        tenant_id=rem.tenant_id, remediation_id=rem.id, decision=decision,
        comment=comment, decided_by=approver_id, decided_at=datetime.now(timezone.utc),
    )
    db.add(approval)
    if decision == "approve":
        rem.status = RemediationStatus.APPROVED
        rem.approver_id = approver_id
        rem.approved_at = datetime.now(timezone.utc)
    else:
        rem.status = RemediationStatus.REJECTED
    db.add(rem)
    return rem


def execute(db: Session, *, rem: Remediation, user_id: int) -> Remediation:
    # Safety guard: manual-only changes can never be auto-executed.
    if rem.level == RemediationLevel.LEVEL3_MANUAL:
        raise ValidationError(
            "Manual-only change (Level 3). A privileged administrator must apply "
            "the change manually; the platform records it after verification.")
    if rem.status != RemediationStatus.APPROVED:
        raise ValidationError("Remediation must be approved before execution")
    rem.status = RemediationStatus.EXECUTING
    rem.execution_status = "executing"
    db.add(rem)
    db.flush()
    # Simulate controlled execution: status changes + workflow records.
    # Level 1 safe-auto may set the finding to remediation_in_progress.
    finding = db.get(Finding, rem.finding_id)
    if finding:
        finding.status = FindingStatus.REMEDIATION_IN_PROGRESS
        db.add(finding)
    rem.execution_status = "executed"
    rem.status = RemediationStatus.VERIFICATION_PENDING
    rem.auto_remediated = rem.level == RemediationLevel.LEVEL1_SAFE_AUTO
    rem.verification_result = "Pending verification re-scan."
    rem.audit_log_json = json.dumps([
        {"ts": datetime.now(timezone.utc).isoformat(), "actor": user_id, "event": "execute"}
    ])
    db.add(rem)
    return rem


def verify(db: Session, *, rem: Remediation, result: str) -> Remediation:
    rem.status = RemediationStatus.VERIFIED
    rem.verification_result = result
    finding = db.get(Finding, rem.finding_id)
    if finding:
        finding.status = FindingStatus.VERIFIED
        db.add(finding)
    db.add(rem)
    return rem


def close(db: Session, *, rem: Remediation) -> Remediation:
    if rem.status not in (RemediationStatus.VERIFIED, RemediationStatus.EXECUTED):
        raise ValidationError("Only verified/executed remediation can be closed")
    rem.status = RemediationStatus.CLOSED
    finding = db.get(Finding, rem.finding_id)
    if finding:
        finding.status = FindingStatus.CLOSED
        db.add(finding)
    db.add(rem)
    return rem


def rollback(db: Session, *, rem: Remediation) -> Remediation:
    rem.status = RemediationStatus.ROLLED_BACK
    finding = db.get(Finding, rem.finding_id)
    if finding:
        finding.status = FindingStatus.OPEN
        db.add(finding)
    db.add(rem)
    return rem


def list_remediations(db: Session, *, tenant_id: int, page: int = 1, page_size: int = 20,
                      status: str | None = None) -> dict:
    from sqlalchemy import func
    query = select(Remediation).where(Remediation.tenant_id == tenant_id)
    if status:
        query = query.where(Remediation.status == status)
    total = db.execute(select(func.count()).select_from(query.subquery())).scalar() or 0
    rows = db.execute(query.order_by(Remediation.created_at.desc())
                      .offset((page - 1) * page_size).limit(page_size)).scalars().all()
    return {"items": rows, "total": total, "page": page, "page_size": page_size,
            "pages": (total + page_size - 1) // page_size}
