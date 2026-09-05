"""Asset inventory service: find-or-create, tagging, aggregation."""
from __future__ import annotations

import json
import uuid

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..core.constants import AssetCriticality
from ..core.exceptions import NotFoundError
from ..db.models import Asset


def make_asset_key(seed: str) -> str:
    return "AST-" + uuid.uuid4().hex[:14].upper()


def find_asset(db: Session, *, tenant_id: int, host: str | None = None,
               ip: str | None = None) -> Asset | None:
    q = select(Asset).where(Asset.tenant_id == tenant_id, Asset.deleted_at.is_(None))
    if host:
        q = q.where((Asset.hostname == host) | (Asset.domain == host))
    if ip:
        q = q.where(Asset.ip_address == ip)
    if host and ip:
        q = q.where((Asset.hostname == host) | (Asset.ip_address == ip))
    return db.execute(q.limit(1)).scalar_one_or_none()


def get_or_create_asset(db: Session, *, tenant_id: int, host: str | None = None,
                        ip: str | None = None, domain: str | None = None,
                        asset_type: str = "server",
                        criticality: str = AssetCriticality.MEDIUM,
                        internet_exposed: bool = False,
                        tags: dict | None = None) -> Asset:
    existing = find_asset(db, tenant_id=tenant_id, host=host or domain, ip=ip)
    if existing:
        if criticality and existing.criticality == AssetCriticality.MEDIUM:
            existing.criticality = criticality
        if internet_exposed:
            existing.is_internet_facing = True
        return existing

    asset = Asset(
        tenant_id=tenant_id,
        asset_key=make_asset_key(host or domain or ip or "asset"),
        hostname=host,
        domain=domain or host,
        ip_address=ip,
        asset_type=asset_type,
        criticality=criticality,
        is_internet_facing=internet_exposed,
        tags=tags or {},
    )
    db.add(asset)
    db.flush()
    return asset


def update_asset_metrics(db: Session, asset: Asset, *, risk_score: float,
                         vuln_count: int) -> None:
    asset.risk_score = round(risk_score, 1)
    asset.vulnerability_count = vuln_count
    db.add(asset)


def list_assets(db: Session, *, tenant_id: int, page: int = 1, page_size: int = 20,
                q: str | None = None, asset_type: str | None = None,
                criticality: str | None = None, internet_facing: bool | None = None) -> dict:
    query = select(Asset).where(Asset.deleted_at.is_(None))
    if tenant_id > 0:
        query = query.where(Asset.tenant_id == tenant_id)
    if q:
        like = f"%{q}%"
        query = query.where((Asset.hostname.ilike(like)) | (Asset.ip_address.ilike(like))
                            | (Asset.domain.ilike(like)) | (Asset.asset_key.ilike(like)))
    if asset_type:
        query = query.where(Asset.asset_type == asset_type)
    if criticality:
        query = query.where(Asset.criticality == criticality)
    if internet_facing is not None:
        query = query.where(Asset.is_internet_facing == internet_facing)

    total = db.execute(select(func.count()).select_from(query.subquery())).scalar() or 0
    rows = db.execute(query.order_by(Asset.created_at.desc())
                      .offset((page - 1) * page_size).limit(page_size)).scalars().all()
    return {"items": rows, "total": total, "page": page, "page_size": page_size,
            "pages": (total + page_size - 1) // page_size}
    if asset_type:
        q = q.where(Asset.asset_type == asset_type)
    if criticality:
        q = q.where(Asset.criticality == criticality)
    if internet_facing is not None:
        q = q.where(Asset.is_internet_facing == internet_facing)

    total = db.execute(select(func.count()).select_from(q.subquery())).scalar() or 0
    rows = db.execute(q.order_by(Asset.created_at.desc())
                      .offset((page - 1) * page_size).limit(page_size)).scalars().all()
    return {"items": rows, "total": total, "page": page, "page_size": page_size,
            "pages": (total + page_size - 1) // page_size}
