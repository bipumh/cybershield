"""Asset inventory endpoints."""
from __future__ import annotations

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from ...core.deps import get_current_user, get_db_dep, require_permission, write_audit
from ...core.exceptions import NotFoundError
from ...db.models import Asset, Finding, User
from ...schemas.asset import AssetCreate, AssetOut, AssetUpdate
from ...services import asset_service

router = APIRouter(prefix="/assets", tags=["Assets"])


@router.get("", response_model=dict, summary="List assets")
def list_assets(
    page: int = Query(1, ge=1), page_size: int = Query(20, ge=1, le=200),
    q: str | None = None, asset_type: str | None = None,
    criticality: str | None = None, internet_facing: bool | None = None,
    db: Session = Depends(get_db_dep), user: User = Depends(require_permission("assets:read")),
):
    res = asset_service.list_assets(db, tenant_id=user.tenant_id, page=page,
                                    page_size=page_size, q=q, asset_type=asset_type,
                                    criticality=criticality, internet_facing=internet_facing)
    return {**res, "items": [AssetOut.model_validate(a) for a in res["items"]]}


@router.post("", response_model=AssetOut, status_code=201, summary="Register an asset")
def create_asset(body: AssetCreate, db: Session = Depends(get_db_dep),
                 user: User = Depends(require_permission("assets:modify"))):
    a = asset_service.get_or_create_asset(
        db, tenant_id=user.tenant_id, host=body.hostname, ip=body.ip_address,
        domain=body.domain, asset_type=body.asset_type, criticality=body.criticality,
        internet_exposed=body.is_internet_facing, tags=body.tags,
    )
    a.os_name = body.os_name
    a.os_version = body.os_version
    a.vendor = body.vendor
    a.model = body.model
    a.firmware_version = body.firmware_version
    a.owner = body.owner
    a.department = body.department
    a.location = body.location
    a.environment = body.environment
    a.is_production = body.is_production
    db.commit()
    write_audit(db, actor=user, action="asset.create", target_type="asset",
                target_id=a.id, new_state={"asset_key": a.asset_key, "host": a.hostname})
    return AssetOut.model_validate(a)


@router.get("/{asset_id}", response_model=AssetOut, summary="Asset detail")
def get_asset(asset_id: int, db: Session = Depends(get_db_dep),
              user: User = Depends(require_permission("assets:read"))):
    a = db.get(Asset, asset_id)
    if not a or a.tenant_id != user.tenant_id or a.is_deleted:
        raise NotFoundError("Asset not found")
    return AssetOut.model_validate(a)


@router.patch("/{asset_id}", response_model=AssetOut, summary="Update asset")
def update_asset(asset_id: int, body: AssetUpdate, db: Session = Depends(get_db_dep),
                 user: User = Depends(require_permission("assets:modify"))):
    a = db.get(Asset, asset_id)
    if not a or a.tenant_id != user.tenant_id or a.is_deleted:
        raise NotFoundError("Asset not found")
    for field, value in body.model_dump(exclude_unset=True).items():
        if hasattr(a, field):
            setattr(a, field, value)
    db.commit()
    write_audit(db, actor=user, action="asset.update", target_type="asset",
                target_id=a.id, previous_state={"asset_key": a.asset_key},
                new_state=body.model_dump(exclude_unset=True, exclude={"tags"}))
    return AssetOut.model_validate(a)


@router.delete("/{asset_id}", response_model=dict, summary="Soft-delete asset")
def delete_asset(asset_id: int, db: Session = Depends(get_db_dep),
                 user: User = Depends(require_permission("assets:modify"))):
    a = db.get(Asset, asset_id)
    if not a or a.tenant_id != user.tenant_id:
        raise NotFoundError("Asset not found")
    from ..base_mixin import utcnow  # noqa: F401
    from ...db.models.base_mixin import utcnow as _utcnow
    a.deleted_at = _utcnow()
    db.commit()
    write_audit(db, actor=user, action="asset.delete", target_type="asset",
                target_id=a.id, new_state={"asset_key": a.asset_key})
    return {"ok": True, "message": "Asset deleted"}
