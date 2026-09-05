"""Remediation endpoints with approval workflow (requirement #14, #31)."""
from __future__ import annotations

import json

from fastapi import APIRouter, Depends, Query
from sqlalchemy import select
from sqlalchemy.orm import Session

from ...core.constants import RemediationLevel, RemediationStatus
from ...core.deps import get_current_user, get_db_dep, require_permission, write_audit
from ...core.exceptions import NotFoundError, ValidationError
from ...db.models import Finding, Remediation, User
from ...schemas.remediation import (ApprovalDecision, ExecuteRequest, RemediationCreate,
                                    RemediationOut)
from ...services import remediation_service

router = APIRouter(prefix="/remediations", tags=["Remediation"])


@router.get("", response_model=dict, summary="List remediation plans")
def list_remediations(page: int = Query(1, ge=1), page_size: int = Query(20, ge=1, le=100),
                      status: str | None = None, db: Session = Depends(get_db_dep),
                      user: User = Depends(require_permission("remediation:read"))):
    res = remediation_service.list_remediations(db, tenant_id=user.tenant_id,
                                                page=page, page_size=page_size, status=status)
    return {**res, "items": [_to_out(r) for r in res["items"]]}


@router.post("", response_model=RemediationOut, status_code=201,
             summary="Create a remediation plan for a finding")
def create_remediation(body: RemediationCreate, db: Session = Depends(get_db_dep),
                       user: User = Depends(require_permission("remediation:modify"))):
    finding = db.get(Finding, body.finding_id)
    if not finding or finding.tenant_id != user.tenant_id:
        raise NotFoundError("Finding not found")
    rem = remediation_service.auto_create_remediation(db, tenant_id=user.tenant_id,
                                                      finding=finding, requester_id=user.id)
    # Override fields provided by caller
    rem.level = body.level
    rem.title = body.title
    rem.immediate_action = body.immediate_action or rem.immediate_action
    rem.permanent_solution = body.permanent_solution or rem.permanent_solution
    rem.recommended_config = body.recommended_config or rem.recommended_config
    rem.patch_recommendation = body.patch_recommendation or rem.patch_recommendation
    rem.verification_procedure = body.verification_procedure or rem.verification_procedure
    rem.rollback_procedure = body.rollback_procedure or rem.rollback_procedure
    rem.business_impact = body.business_impact or rem.business_impact
    rem.complexity = body.complexity or rem.complexity
    rem.backup_status = body.backup_status
    rem = remediation_service.propose(db, rem)
    db.commit()
    write_audit(db, actor=user, action="remediation.create", target_type="remediation",
                target_id=rem.id, new_state={"level": rem.level, "status": rem.status})
    return _to_out(rem)


@router.get("/{remediation_id}", response_model=RemediationOut, summary="Remediation detail")
def get_remediation(remediation_id: int, db: Session = Depends(get_db_dep),
                    user: User = Depends(require_permission("remediation:read"))):
    rem = db.get(Remediation, remediation_id)
    if not rem or rem.tenant_id != user.tenant_id:
        raise NotFoundError("Remediation not found")
    return _to_out(rem)


@router.post("/{remediation_id}/submit", response_model=RemediationOut,
             summary="Submit for approval")
def submit(remediation_id: int, db: Session = Depends(get_db_dep),
           user: User = Depends(require_permission("remediation:modify"))):
    rem = _get(db, user, remediation_id)
    rem = remediation_service.submit_for_approval(db, rem)
    db.commit()
    write_audit(db, actor=user, action="remediation.submit", target_type="remediation",
                target_id=rem.id, new_state={"status": rem.status})
    return _to_out(rem)


@router.post("/{remediation_id}/approve", response_model=RemediationOut,
             summary="Approve or reject (CISO/approver)")
def approve(remediation_id: int, body: ApprovalDecision, db: Session = Depends(get_db_dep),
            user: User = Depends(require_permission("remediation:approve"))):
    rem = _get(db, user, remediation_id)
    rem = remediation_service.decide(db, rem=rem, approver_id=user.id,
                                     decision=body.decision, comment=body.comment)
    db.commit()
    write_audit(db, actor=user, action=f"remediation.{body.decision}",
                target_type="remediation", target_id=rem.id,
                new_state={"status": rem.status, "comment": body.comment})
    return _to_out(rem)


@router.post("/{remediation_id}/execute", response_model=RemediationOut,
             summary="Execute approved remediation")
def execute(remediation_id: int, body: ExecuteRequest, db: Session = Depends(get_db_dep),
            user: User = Depends(require_permission("remediation:execute"))):
    rem = _get(db, user, remediation_id)
    if not body.force and rem.status not in (RemediationStatus.APPROVED,
                                             RemediationStatus.PENDING_APPROVAL):
        raise ValidationError("Remediation must be approved before execution")
    rem = remediation_service.execute(db, rem=rem, user_id=user.id)
    db.commit()
    write_audit(db, actor=user, action="remediation.execute", target_type="remediation",
                target_id=rem.id, new_state={"status": rem.status, "execution": rem.execution_status})
    return _to_out(rem)


@router.post("/{remediation_id}/verify", response_model=RemediationOut, summary="Mark verified")
def verify(remediation_id: int, db: Session = Depends(get_db_dep),
           user: User = Depends(require_permission("remediation:verify"))):
    rem = _get(db, user, remediation_id)
    rem = remediation_service.verify(db, rem=rem, result="Verified via re-scan (recommended).")
    db.commit()
    write_audit(db, actor=user, action="remediation.verify", target_type="remediation",
                target_id=rem.id)
    return _to_out(rem)


@router.post("/{remediation_id}/close", response_model=RemediationOut, summary="Close")
def close(remediation_id: int, db: Session = Depends(get_db_dep),
          user: User = Depends(require_permission("remediation:verify"))):
    rem = _get(db, user, remediation_id)
    rem = remediation_service.close(db, rem=rem)
    db.commit()
    write_audit(db, actor=user, action="remediation.close", target_type="remediation",
                target_id=rem.id)
    return _to_out(rem)


@router.post("/{remediation_id}/rollback", response_model=RemediationOut, summary="Rollback")
def rollback(remediation_id: int, db: Session = Depends(get_db_dep),
             user: User = Depends(require_permission("remediation:execute"))):
    rem = _get(db, user, remediation_id)
    rem = remediation_service.rollback(db, rem=rem)
    db.commit()
    write_audit(db, actor=user, action="remediation.rollback", target_type="remediation",
                target_id=rem.id)
    return _to_out(rem)


def _get(db: Session, user: User, remediation_id: int) -> Remediation:
    rem = db.get(Remediation, remediation_id)
    if not rem or rem.tenant_id != user.tenant_id:
        raise NotFoundError("Remediation not found")
    return rem


def _to_out(rem: Remediation) -> RemediationOut:
    return RemediationOut(
        id=rem.id, finding_id=rem.finding_id, asset_id=rem.asset_id, level=rem.level,
        title=rem.title, immediate_action=rem.immediate_action,
        permanent_solution=rem.permanent_solution, complexity=rem.complexity,
        status=rem.status, requester_id=rem.requester_id, approver_id=rem.approver_id,
        approved_at=rem.approved_at, backup_status=rem.backup_status,
        execution_status=rem.execution_status, verification_result=rem.verification_result,
        auto_remediated=rem.auto_remediated, due_at=rem.due_at, created_at=rem.created_at,
    )
