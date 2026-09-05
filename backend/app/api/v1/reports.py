"""Report endpoints."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import FileResponse, Response
from sqlalchemy.orm import Session

from ...core.deps import get_current_user, get_db_dep, require_permission, write_audit
from ...core.exceptions import NotFoundError, ValidationError
from ...db.models import Report, User
from ...schemas.report import ReportCreate, ReportOut
from ...services import reporting_service

router = APIRouter(prefix="/reports", tags=["Reports"])


@router.post("", response_model=ReportOut, status_code=201, summary="Generate a report")
def create_report(body: ReportCreate, db: Session = Depends(get_db_dep),
                  user: User = Depends(require_permission("reports:create"))):
    rep = reporting_service.create_report(
        db, tenant_id=user.tenant_id, requested_by=user.id, name=body.name,
        report_type=body.report_type, format=body.format, scope=body.scope,
    )
    reporting_service.refresh_report(db, rep)
    write_audit(db, actor=user, action="report.create", target_type="report",
                target_id=rep.id, new_state={"name": rep.name, "type": rep.report_type})
    return _to_out(rep)


@router.get("", response_model=dict, summary="List reports")
def list_reports(page: int = Query(1, ge=1), page_size: int = Query(20, ge=1, le=100),
                 report_type: str | None = None, db: Session = Depends(get_db_dep),
                 user: User = Depends(require_permission("reports:read"))):
    res = reporting_service.list_reports(db, tenant_id=user.tenant_id, page=page,
                                         page_size=page_size, report_type=report_type)
    return {**res, "items": [_to_out(r) for r in res["items"]]}


@router.get("/{report_id}/download", summary="Download a generated report")
def download(report_id: int, db: Session = Depends(get_db_dep),
             user: User = Depends(require_permission("reports:read"))):
    rep = db.get(Report, report_id)
    if not rep or rep.tenant_id != user.tenant_id:
        raise NotFoundError("Report not found")
    if rep.status != "completed" or not rep.file_path:
        raise ValidationError("Report is not ready for download")
    media_type = {"pdf": "application/pdf", "html": "text/html", "csv": "text/csv",
                  "json": "application/json", "xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"}.get(rep.format, "application/octet-stream")
    return FileResponse(rep.file_path, media_type=media_type,
                        filename=f"{rep.report_key}.{rep.format}")


def _to_out(rep: Report) -> ReportOut:
    return ReportOut(id=rep.id, report_key=rep.report_key, name=rep.name,
                     report_type=rep.report_type, format=rep.format, status=rep.status,
                     generated_at=rep.generated_at, size_bytes=rep.size_bytes,
                     error=rep.error, created_at=rep.created_at)
