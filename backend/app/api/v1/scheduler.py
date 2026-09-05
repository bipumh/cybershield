"""Scheduled scanning (requirement #32)."""
from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Query
from sqlalchemy import select
from sqlalchemy.orm import Session

from ...core.deps import get_current_user, get_db_dep, require_permission, write_audit
from ...core.exceptions import NotFoundError, ValidationError
from ...db.models import ScanSchedule, User
from ...schemas.scan import ScheduleCreate, ScheduleOut
from ...services.scheduler_service import compute_next_run

router = APIRouter(prefix="/schedules", tags=["Scheduler"])


@router.post("", response_model=ScheduleOut, status_code=201, summary="Create a scan schedule")
def create_schedule(body: ScheduleCreate, db: Session = Depends(get_db_dep),
                    user: User = Depends(require_permission("scans:create"))):
    if body.frequency not in ("onetime", "daily", "weekly", "monthly", "custom"):
        raise ValidationError("Invalid frequency")
    targets = [t.model_dump() for t in body.targets]
    sched = ScanSchedule(
        tenant_id=user.tenant_id, name=body.name, mode=body.mode, frequency=body.frequency,
        cron_expression=body.cron_expression, targets=targets, profile=body.profile,
        enabled=body.enabled, created_by=user.id,
        next_run_at=compute_next_run(body.frequency, body.cron_expression),
    )
    db.add(sched)
    db.commit()
    write_audit(db, actor=user, action="schedule.create", target_type="schedule",
                target_id=sched.id, new_state={"name": sched.name, "frequency": sched.frequency})
    return _to_out(sched)


@router.get("", response_model=list[ScheduleOut], summary="List schedules")
def list_schedules(db: Session = Depends(get_db_dep),
                   user: User = Depends(require_permission("scans:read"))):
    rows = db.execute(select(ScanSchedule).where(
        ScanSchedule.tenant_id == user.tenant_id).order_by(ScanSchedule.created_at.desc())).scalars().all()
    return [_to_out(s) for s in rows]


@router.patch("/{schedule_id}", response_model=ScheduleOut, summary="Enable/disable schedule")
def toggle_schedule(schedule_id: int, enabled: bool = Query(...), db: Session = Depends(get_db_dep),
                    user: User = Depends(require_permission("scans:create"))):
    s = db.get(ScanSchedule, schedule_id)
    if not s or s.tenant_id != user.tenant_id:
        raise NotFoundError("Schedule not found")
    s.enabled = enabled
    db.commit()
    return _to_out(s)


@router.delete("/{schedule_id}", summary="Delete schedule")
def delete_schedule(schedule_id: int, db: Session = Depends(get_db_dep),
                    user: User = Depends(require_permission("scans:create"))):
    s = db.get(ScanSchedule, schedule_id)
    if not s or s.tenant_id != user.tenant_id:
        raise NotFoundError("Schedule not found")
    db.delete(s)
    db.commit()
    return {"ok": True}


def _to_out(s: ScanSchedule) -> ScheduleOut:
    return ScheduleOut(
        id=s.id, name=s.name, mode=s.mode, frequency=s.frequency,
        cron_expression=s.cron_expression, targets=s.targets or [], profile=s.profile,
        enabled=s.enabled, last_run_at=s.last_run_at, next_run_at=s.next_run_at,
        created_at=s.created_at,
    )
