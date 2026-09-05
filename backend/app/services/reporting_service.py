"""Report orchestration: gather data, render, store, generate in background."""
from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.orm import Session, noload

from ..core.constants import FindingStatus, ReportFormat, ReportType
from ..core.exceptions import NotFoundError, ValidationError
from ..db.models import Asset, Finding, Report
from ..engines import reporting as reporting_engine
from ..schemas.report import ReportOut


def create_report(db: Session, *, tenant_id: int, requested_by: int | None, name: str,
                  report_type: str, format: str, scope: dict) -> Report:
    if report_type not in ReportType.ALL:
        raise ValidationError(f"report_type must be one of {ReportType.ALL}")
    if format not in ReportFormat.ALL:
        raise ValidationError(f"format must be one of {ReportFormat.ALL}")
    rep = Report(
        tenant_id=tenant_id,
        report_key="RPT-" + uuid.uuid4().hex[:14].upper(),
        name=name, report_type=report_type, format=format,
        scope=json.dumps(scope), status="pending", requested_by=requested_by,
    )
    db.add(rep)
    db.commit()
    return rep


def refresh_report(db: Session, rep: Report) -> Report:
    """Synchronously (re)generate a report. Used by worker + API."""
    scope = json.loads(rep.scope or "{}")
    findings = _load_findings(db, tenant_id=rep.tenant_id, scope=scope)
    assets = _load_assets(db, tenant_id=rep.tenant_id, scope=scope)
    data = reporting_engine.build_report_data(findings, assets,
                                              report_type=rep.report_type, scope=scope)
    content = reporting_engine.render(data, rep.format)
    path = Path("reports_output") / f"{rep.report_key}.{rep.format}"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)
    rep.file_path = str(path)
    rep.status = "completed"
    rep.generated_at = datetime.now(timezone.utc)
    rep.size_bytes = len(content)
    rep.content_preview = data.get("title", "")
    db.add(rep)
    db.commit()
    return rep


def _load_findings(db, *, tenant_id, scope):
    q = select(Finding).where(Finding.tenant_id == tenant_id)
    if scope.get("severity"):
        q = q.where(Finding.severity.in_(scope["severity"]))
    if scope.get("status"):
        q = q.where(Finding.status.in_(scope["status"]))
    if scope.get("asset_id"):
        q = q.where(Finding.asset_id == scope["asset_id"])
    if scope.get("kev"):
        q = q.where(Finding.is_kev == True)  # noqa: E712
    return list(db.execute(q).scalars().all())


def _load_assets(db, *, tenant_id, scope):
    q = select(Asset).options(noload(Asset.groups)).where(
        Asset.tenant_id == tenant_id, Asset.deleted_at.is_(None))
    if scope.get("asset_id"):
        q = q.where(Asset.id == scope["asset_id"])
    return list(db.execute(q).scalars().all())


def list_reports(db: Session, *, tenant_id: int, page: int = 1, page_size: int = 20,
                 report_type: str | None = None) -> dict:
    from sqlalchemy import func
    query = select(Report).where(Report.tenant_id == tenant_id)
    if report_type:
        query = query.where(Report.report_type == report_type)
    total = db.execute(select(func.count()).select_from(query.subquery())).scalar() or 0
    rows = db.execute(query.order_by(Report.created_at.desc())
                      .offset((page - 1) * page_size).limit(page_size)).scalars().all()
    return {"items": rows, "total": total, "page": page, "page_size": page_size,
            "pages": (total + page_size - 1) // page_size}
