"""Scan endpoints: create, list, get, cancel, discovered-assets flow."""
from __future__ import annotations

import json

from fastapi import APIRouter, Depends, Query
from sqlalchemy import select
from sqlalchemy.orm import Session

from ...core.deps import get_current_user, get_db_dep, require_permission, write_audit
from ...core.exceptions import NotFoundError, ValidationError
from ...db.models import Scan, ScanTarget, Subdomain, User
from ...schemas.scan import (ApproveAssetsRequest, ScanCreate, ScanOut, ScanStatusOut,
                             DiscoveredAssetOut, ScanResultOut)
from ...services import scan_service
from ...services.target_service import parse_target
from ...scanners.web.discovery import SubdomainDiscovery

router = APIRouter(prefix="/scans", tags=["Scans"])


@router.post("", response_model=ScanOut, status_code=201, summary="Create & start a scan")
def create_scan(body: ScanCreate, db: Session = Depends(get_db_dep),
                user: User = Depends(require_permission("scans:create"))):
    scan = scan_service.create_scan(
        db, tenant_id=user.tenant_id, user_id=user.id, name=body.name, mode=body.mode,
        profile=body.profile, targets_data=body.targets, rate_limit=body.rate_limit,
        timeout=body.timeout, concurrency=body.concurrency,
        excluded_ips=body.excluded_ips, excluded_domains=body.excluded_domains,
        maintenance_window=body.maintenance_window, safety=body.safety.model_dump(),
        auto_approve_scope=body.auto_approve_scope,
    )
    scan_service.dispatch(scan)
    write_audit(db, actor=user, action="scan.create", target_type="scan",
                target_id=scan.id, new_state={"name": scan.name, "mode": scan.mode,
                                              "profile": scan.profile, "targets": len(body.targets)})
    return _to_out(scan)


@router.get("", response_model=dict, summary="List scans")
def list_scans(page: int = Query(1, ge=1), page_size: int = Query(20, ge=1, le=100),
               status: str | None = None, mode: str | None = None,
               db: Session = Depends(get_db_dep),
               user: User = Depends(require_permission("scans:read"))):
    res = scan_service.list_scans(db, tenant_id=user.tenant_id, page=page,
                                  page_size=page_size, status=status, mode=mode)
    return {**res, "items": [_to_out(s) for s in res["items"]]}


@router.get("/{scan_id}", response_model=ScanOut, summary="Scan detail")
def get_scan(scan_id: int, db: Session = Depends(get_db_dep),
             user: User = Depends(require_permission("scans:read"))):
    scan = db.get(Scan, scan_id)
    if not scan or scan.tenant_id != user.tenant_id:
        raise NotFoundError("Scan not found")
    return _to_out(scan)


@router.get("/{scan_id}/status", response_model=ScanStatusOut, summary="Scan status/progress")
def scan_status(scan_id: int, db: Session = Depends(get_db_dep),
                user: User = Depends(require_permission("scans:read"))):
    scan = db.get(Scan, scan_id)
    if not scan or scan.tenant_id != user.tenant_id:
        raise NotFoundError("Scan not found")
    return ScanStatusOut(id=scan.id, status=scan.status, progress=scan.progress,
                         message=scan.error)


@router.post("/{scan_id}/cancel", response_model=ScanStatusOut, summary="Cancel a running scan")
def cancel_scan(scan_id: int, db: Session = Depends(get_db_dep),
                user: User = Depends(require_permission("scans:read"))):
    scan = db.get(Scan, scan_id)
    if not scan or scan.tenant_id != user.tenant_id:
        raise NotFoundError("Scan not found")
    scan = scan_service.cancel_scan(db, scan)
    write_audit(db, actor=user, action="scan.cancel", target_type="scan",
                target_id=scan.id, new_state={"status": scan.status})
    return ScanStatusOut(id=scan.id, status=scan.status, progress=scan.progress,
                         message="Scan cancellation requested")


@router.get("/{scan_id}/results", response_model=list[ScanResultOut],
            summary="Scan results for assets")
def scan_results(scan_id: int, db: Session = Depends(get_db_dep),
                 user: User = Depends(require_permission("scans:read"))):
    from ...db.models import ScanResult
    scan = db.get(Scan, scan_id)
    if not scan or scan.tenant_id != user.tenant_id:
        raise NotFoundError("Scan not found")
    rows = db.execute(select(ScanResult).where(ScanResult.scan_id == scan_id)).scalars().all()
    return [ScanResultOut.model_validate(r) for r in rows]


# ─── Discovery / scope approval workflow (requirement #2) ───────────────
@router.post("/discover", response_model=list[DiscoveredAssetOut],
             summary="Discover subdomains for a domain (passive)")
def discover(target: dict, db: Session = Depends(get_db_dep),
             user: User = Depends(require_permission("scans:create"))):
    domain = target.get("domain") or target.get("target")
    if isinstance(domain, dict):
        domain = domain.get("value")
    if not domain:
        raise ValidationError("Provide a domain to discover subdomains for")
    try:
        t = parse_target(domain)
    except Exception as e:
        raise ValidationError(f"Invalid domain: {e}")
    disc = SubdomainDiscovery(t.host)
    found = disc.discover()
    results = []
    for item in found:
        ip = disc.resolve_ip(item["name"])
        status = "responsive" if ip else "unresponsive"
        results.append(DiscoveredAssetOut(name=item["name"], status=status,
                                          resolved_ip=ip, in_scope=True))
    write_audit(db, actor=user, action="scan.discover", target_type="domain",
                new_state={"domain": t.host, "count": len(results)})
    return results


@router.post("/{scan_id}/approve-assets", summary="Approve discovered assets for scanning")
def approve_assets(scan_id: int, body: ApproveAssetsRequest, db: Session = Depends(get_db_dep),
                   user: User = Depends(require_permission("scans:approve"))):
    scan = db.get(Scan, scan_id)
    if not scan or scan.tenant_id != user.tenant_id:
        raise NotFoundError("Scan not found")
    subs = body.subdomain_ids or []
    rows = db.execute(select(Subdomain).where(Subdomain.tenant_id == user.tenant_id,
                                              Subdomain.id.in_(subs))).scalars().all()
    for r in rows:
        r.is_in_scope = True
        r.status = "responsive" if r.is_responsive else "confirmed"
        # Register matching asset for scanning eligibility
        db.add(ScanTarget(tenant_id=user.tenant_id, scan_id=scan.id, kind="domain",
                          value=r.name, in_scope=True))
    db.commit()
    write_audit(db, actor=user, action="scan.approve_assets", target_type="scan",
                target_id=scan.id, new_state={"approved_count": len(rows)})
    return {"ok": True, "approved": len(rows)}


def _to_out(scan: Scan) -> ScanOut:
    import json
    return ScanOut(
        id=scan.id, scan_key=scan.scan_key, name=scan.name, mode=scan.mode,
        profile=scan.profile, status=scan.status, requested_by=scan.requested_by,
        authorized=scan.authorized, scope_confirmed=scan.scope_confirmed,
        safety_confirmed=scan.safety_confirmed, rate_limit=scan.rate_limit,
        timeout=scan.timeout, concurrency=scan.concurrency, progress=scan.progress,
        total_steps=scan.total_steps, started_at=scan.started_at,
        completed_at=scan.completed_at, cancelled=scan.cancelled, error=scan.error,
        summary=json.loads(scan.summary or "{}"), created_at=scan.created_at,
    )
