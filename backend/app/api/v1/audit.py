"""Audit log endpoints (access-controlled, reader-only for auditors)."""
from __future__ import annotations

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ...core.deps import get_current_user, get_db_dep, require_permission
from ...core.exceptions import NotFoundError
from ...db.models import AuditLog, User

router = APIRouter(prefix="/audit", tags=["Audit Logs"])


@router.get("", response_model=dict, summary="List audit logs (tamper-evident)")
def list_audit(page: int = Query(1, ge=1), page_size: int = Query(50, ge=1, le=200),
               action: str | None = None, actor: str | None = None,
               db: Session = Depends(get_db_dep), user: User = Depends(require_permission("audit:read"))):
    query = select(AuditLog).where(AuditLog.tenant_id == user.tenant_id)
    if action:
        query = query.where(AuditLog.action == action)
    if actor:
        query = query.where(AuditLog.actor_email.contains(actor))
    total = db.execute(select(func.count()).select_from(query.subquery())).scalar() or 0
    rows = db.execute(query.order_by(AuditLog.id.desc())
                      .offset((page - 1) * page_size).limit(page_size)).scalars().all()
    items = [{
        "id": r.id, "actor": r.actor_email, "action": r.action,
        "target_type": r.target_type, "target_id": r.target_id, "result": r.result,
        "source_ip": r.source_ip, "occurred_at": r.occurred_at,
        "record_hash": r.record_hash, "prev_hash": r.prev_hash,
    } for r in rows]
    return {"items": items, "total": total, "page": page, "page_size": page_size,
            "pages": (total + page_size - 1) // page_size}


@router.get("/verify-chain", summary="Verify audit hash chain integrity")
def verify_chain(db: Session = Depends(get_db_dep),
                 user: User = Depends(require_permission("audit:read"))):
    rows = db.execute(select(AuditLog).where(AuditLog.tenant_id == user.tenant_id)
                      .order_by(AuditLog.id.asc())).scalars().all()
    prev = None
    valid = True
    broken_at = None
    import json
    for r in rows:
        expected = r.record_hash
        recomputed = AuditLog.compute_hash(prev, {
            "tenant_id": r.tenant_id, "actor_id": r.actor_id, "actor_email": r.actor_email,
            "action": r.action, "target_type": r.target_type, "target_id": r.target_id,
            "result": r.result, "previous_state": json.loads(r.previous_state or "{}"),
            "new_state": json.loads(r.new_state or "{}"),
            "occurred_at": r.occurred_at.isoformat(),
        })
        if r.prev_hash != prev or expected != recomputed:
            valid = False
            broken_at = r.id
            break
        prev = expected
    return {"valid": valid, "records": len(rows), "broken_at": broken_at}
