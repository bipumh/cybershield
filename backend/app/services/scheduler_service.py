"""Scheduling helpers + APScheduler integration (requirement #32)."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger
from apscheduler.triggers.interval import IntervalTrigger
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..db.session import SessionLocal
from ..db.models import Scan, ScanSchedule, ScanTarget
from . import scan_service


def compute_next_run(frequency: str, cron_expression: str | None) -> datetime | None:
    now = datetime.now(timezone.utc)
    if frequency == "daily":
        return (now + timedelta(days=1)).replace(hour=2, minute=0, second=0, microsecond=0)
    if frequency == "weekly":
        return (now + timedelta(days=7)).replace(hour=2, minute=0, second=0, microsecond=0)
    if frequency == "monthly":
        return (now + timedelta(days=30)).replace(hour=2, minute=0, second=0, microsecond=0)
    if frequency == "onetime":
        return now + timedelta(minutes=5)
    if frequency == "custom":
        return now + timedelta(hours=24)
    return None


_scheduler: BackgroundScheduler | None = None


def start_scheduler() -> None:
    global _scheduler
    if _scheduler is not None:
        return
    _scheduler = BackgroundScheduler(timezone="UTC")
    _scheduler.add_job(_run_due_schedules, "interval", minutes=1, id="schedules",
                       replace_existing=True, max_instances=1)
    _scheduler.start()


def _run_due_schedules() -> None:
    db = SessionLocal()
    try:
        now = datetime.now(timezone.utc)
        due = db.execute(select(ScanSchedule).where(
            ScanSchedule.enabled == True,  # noqa: E712
            ScanSchedule.next_run_at <= now)).scalars().all()
        for sched in due:
            _fire(db, sched)
            sched.next_run_at = compute_next_run(sched.frequency, sched.cron_expression)
            sched.last_run_at = now
            db.add(sched)
        db.commit()
    except Exception:
        db.rollback()
    finally:
        db.close()


def _fire(db: Session, sched: ScanSchedule) -> None:
    from ..core.config import settings
    from ..core.constants import ScanStatus
    import uuid as _uuid
    targets = sched.targets or []
    scan = Scan(
        tenant_id=sched.tenant_id,
        scan_key="SCN-" + _uuid.uuid4().hex[:14].upper(),
        name=sched.name, mode=sched.mode, profile=sched.profile,
        status=ScanStatus.PENDING, authorized=True, scope_confirmed=True,
        safety_confirmed=True, rate_limit=settings.scan_global_rate_limit,
        timeout=settings.scan_default_timeout, concurrency=2,
        options="{}",
    )
    db.add(scan)
    db.flush()
    for t in targets:
        db.add(ScanTarget(tenant_id=sched.tenant_id, scan_id=scan.id,
                          kind=t.get("kind", "domain"), value=t.get("value", ""),
                          in_scope=True))
    db.commit()
    scan_service.dispatch(scan)
