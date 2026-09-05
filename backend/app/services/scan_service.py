"""Scan orchestration service: create/validate/dispatch/cancel/approve scans."""
from __future__ import annotations

import json
import uuid

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..core.config import settings
from ..core.constants import ScanProfile, ScanStatus, ScanTargetKind
from ..core.exceptions import ScanSafetyError, ScopeViolationError, ValidationError, NotFoundError
from ..db.models import Scan, ScanTarget, Asset
from ..workers import queue
from ..workers.orchestrator import run_scan
from .target_service import parse_target, expand_scope


def build_options(*, excluded_ips, excluded_domains, maintenance_window) -> str:
    return json.dumps({"excluded_ips": excluded_ips, "excluded_domains": excluded_domains,
                       "maintenance_window": maintenance_window})


def validate_scan(mode: str, profile: str, targets_data: list, excluded_domains: list,
                  excluded_ips: list) -> list[ScanTarget]:
    """Validate targets, enforce scope + safety, return normalized targets."""
    if mode not in ("web", "network"):
        raise ValidationError("mode must be 'web' or 'network'")
    if profile not in ScanProfile.ALL:
        raise ValidationError(f"profile must be one of {ScanProfile.ALL}")

    parsed_targets = []
    for item in targets_data:
        raw = item.get("value") if isinstance(item, dict) else item.value
        kind = item.get("kind") if isinstance(item, dict) else item.kind
        try:
            target = parse_target(raw, kind)
        except Exception as e:
            raise ValidationError(f"Invalid target '{raw}': {e}")

        if _is_excluded(target.host, excluded_domains, excluded_ips):
            raise ScopeViolationError(f"Target '{target.host}' is excluded by scope")

        parsed_targets.append(target)

    if len(parsed_targets) > 200:
        raise ValidationError("Too many targets in a single scan (max 200)")

    return parsed_targets


def _is_excluded(host: str, domains: list, ips: list) -> bool:
    low = host.lower()
    for d in domains or []:
        if low == d.lower() or low.endswith("." + d.lower()):
            return True
    for ip in ips or []:
        if low == ip:
            return True
    return False


def create_scan(db: Session, *, tenant_id: int, user_id: int, name: str, mode: str,
                profile: str, targets_data: list, rate_limit, timeout, concurrency,
                excluded_ips, excluded_domains, maintenance_window,
                safety: dict, auto_approve_scope: bool) -> Scan:
    # ── Safety (requirement #15): require explicit confirmation ─────────
    safety = safety or {}
    if not safety.get("safety_confirmed"):
        raise ScanSafetyError("You must confirm the scan Safety Policy before running an active scan.")
    if not safety.get("scope_confirmed") and not auto_approve_scope:
        raise ScanSafetyError("Scan scope must be confirmed before active scanning.")

    targets = validate_scan(mode, profile, targets_data, excluded_domains or [],
                            excluded_ips or [])

    # Hard safety caps (cannot be bypassed)
    final_rate = rate_limit or settings.scan_global_rate_limit
    final_timeout = timeout or settings.scan_default_timeout
    final_concurrency = concurrency or 2
    if final_concurrency > settings.scan_max_concurrency:
        raise ScanSafetyError(f"Concurrency exceeds platform maximum ({settings.scan_max_concurrency})")

    active_scans = db.execute(select(Scan).where(
        Scan.tenant_id == tenant_id, Scan.status.in_(
            [ScanStatus.PENDING, ScanStatus.RUNNING, ScanStatus.DISCOVERING,
             ScanStatus.VALIDATING]))).scalars().all()
    if len(active_scans) >= settings.scan_max_active_scans:
        raise ScanSafetyError("Maximum concurrent active scans reached; retry later")

    scan = Scan(
        tenant_id=tenant_id,
        scan_key="SCN-" + uuid.uuid4().hex[:14].upper(),
        name=name, mode=mode, profile=profile, status=ScanStatus.PENDING,
        requested_by=user_id, authorized=True,
        scope_confirmed=bool(safety.get("scope_confirmed")) or auto_approve_scope,
        safety_confirmed=bool(safety.get("safety_confirmed")),
        rate_limit=final_rate, timeout=final_timeout, concurrency=final_concurrency,
        options=build_options(excluded_ips=excluded_ips or [], excluded_domains=excluded_domains or [],
                              maintenance_window=maintenance_window),
    )
    db.add(scan)
    db.flush()

    for t in targets:
        # Store the re-parseable original value; for URL targets this keeps the
        # scheme so the worker can reconstruct a full URL on re-parsing.
        db.add(ScanTarget(tenant_id=tenant_id, scan_id=scan.id, kind=t.kind,
                          value=t.raw or t.value, in_scope=True))
    db.commit()
    db.refresh(scan)
    return scan


def dispatch(scan: Scan) -> None:
    queue.schedule(run_scan, scan.id)


def cancel_scan(db: Session, scan: Scan) -> Scan:
    if scan.status in (ScanStatus.COMPLETED, ScanStatus.CANCELLED, ScanStatus.FAILED):
        raise ValidationError("Scan is already in a terminal state")
    scan.status = ScanStatus.CANCELLED
    scan.cancelled = True
    scan.completed_at = None
    db.add(scan)
    db.commit()
    return scan


def list_scans(db: Session, *, tenant_id: int, page: int = 1, page_size: int = 20,
               status: str | None = None, mode: str | None = None) -> dict:
    query = select(Scan).where(Scan.tenant_id == tenant_id)
    if status:
        query = query.where(Scan.status == status)
    if mode:
        query = query.where(Scan.mode == mode)
    from sqlalchemy import func
    total = db.execute(select(func.count()).select_from(query.subquery())).scalar() or 0
    rows = db.execute(query.order_by(Scan.created_at.desc())
                      .offset((page - 1) * page_size).limit(page_size)).scalars().all()
    return {"items": rows, "total": total, "page": page, "page_size": page_size,
            "pages": (total + page_size - 1) // page_size}
