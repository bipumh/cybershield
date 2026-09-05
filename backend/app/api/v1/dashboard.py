"""Executive dashboard, posture, SLA, prioritization."""
from __future__ import annotations

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from ...core.deps import get_current_user, get_db_dep, require_permission
from ...db.models import User
from ...services import dashboard_service

router = APIRouter(prefix="/dashboard", tags=["Dashboard"])


@router.get("/summary", response_model=dict, summary="Executive security summary")
def summary(db: Session = Depends(get_db_dep),
            user: User = Depends(require_permission("dashboard:read"))):
    return dashboard_service.executive_summary(db, tenant_id=user.tenant_id)


@router.get("/posture", response_model=dict, summary="Security posture score")
def posture(db: Session = Depends(get_db_dep),
            user: User = Depends(require_permission("dashboard:read"))):
    return dashboard_service.posture(db, tenant_id=user.tenant_id)


@router.get("/sla", response_model=dict, summary="SLA dashboard")
def sla(db: Session = Depends(get_db_dep), user: User = Depends(require_permission("dashboard:read"))):
    return dashboard_service.sla_dashboard(db, tenant_id=user.tenant_id)


@router.get("/top-priorities", response_model=list, summary="Top 10 things to fix now")
def top_priorities(limit: int = Query(10, ge=1, le=25), db: Session = Depends(get_db_dep),
                   user: User = Depends(require_permission("dashboard:read"))):
    return dashboard_service.top_priorities(db, tenant_id=user.tenant_id, limit=limit)
