"""Scan orchestrator: executes a scan asynchronously (requirement #24, #25).

Given a Scan record, it builds a safety guard, selects scanners by mode, runs
them per in-scope target, persists normalized findings, updates progress, and
handles cancellation/timeout/errors without crashing the application.
"""
from __future__ import annotations

import json
import logging
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session
from ..db.session import SessionLocal
from ..db.models import Asset, Scan, ScanResult, ScanTarget
from ..scanners import get_scanners
from ..scanners.base import ScanContext
from ..scanners.safety import build_guard
from ..services.finding_service import FindingService
from ..services.asset_service import get_or_create_asset, update_asset_metrics
from ..services.target_service import parse_target
from ..core.constants import ScanMode, ScanProfile, ScanStatus
from ..core.config import settings

logger = logging.getLogger("workers.orchestrator")

_MODE_SCANNERS = {
    ScanMode.WEB: ["web.headers", "web.tls", "web.cookies", "web.content",
                   "web.application", "web.dns_security"],
    ScanMode.NETWORK: ["network.ports", "network.banners", "network.dns",
                       "server.http"],
}
_ASSET_TYPE_MODE = {ScanMode.WEB: "web_application", ScanMode.NETWORK: "server"}


def run_scan(scan_id: int) -> None:
    db: Session = SessionLocal()
    try:
        _execute(db, scan_id)
    except Exception as e:  # noqa: BLE001
        logger.exception("Scan %s failed", scan_id)
        _mark_failed(db, scan_id, str(e))
    finally:
        db.close()


def _execute(db: Session, scan_id: int) -> None:
    scan = db.get(Scan, scan_id)
    if not scan:
        return
    if scan.cancelled:
        _update(db, scan, status=ScanStatus.CANCELLED)
        return

    _update(db, scan, status=ScanStatus.RUNNING, started_at=datetime.now(timezone.utc))

    guard = build_guard(
        profile=scan.profile, rate_limit=scan.rate_limit, timeout=scan.timeout,
        concurrency=scan.concurrency,
        excluded_ips=json.loads(scan.options or "{}").get("excluded_ips", []),
        excluded_domains=json.loads(scan.options or "{}").get("excluded_domains", []),
        allow_insecure=settings.scan_allow_insecure,
    )

    scanners = [s for s in get_scanners() if s.name in _MODE_SCANNERS.get(scan.mode, [])]
    targets = db.execute(select(ScanTarget).where(ScanTarget.scan_id == scan_id,
                                                  ScanTarget.in_scope == True)).scalars().all()  # noqa: E712

    total_steps = max(1, len(targets) * len(scanners))
    scan.total_steps = total_steps
    db.add(scan)
    db.commit()

    fservice = FindingService(db)
    completed = 0

    for target in targets:
        if scan.cancelled:
            break
        # re-load to observe cancel flag
        db.refresh(scan)
        if scan.cancelled:
            break

        try:
            t = parse_target(target.value)
        except Exception as e:
            target.status = "failed"
            db.add(target)
            db.commit()
            continue

        is_ip_target = t.kind in ("ip", "cidr", "range")
        asset = get_or_create_asset(
            db, tenant_id=scan.tenant_id,
            host=(t.host if not is_ip_target else None),
            domain=(t.host if t.kind == "domain" else None),
            ip=(t.host if is_ip_target else None),
            asset_type=_ASSET_TYPE_MODE.get(scan.mode, "server"),
            internet_exposed=_is_public(t.host),
        )

        for scanner in scanners:
            if scan.cancelled:
                break
            db.refresh(scan)
            if scan.cancelled:
                break

            ctx_url = _full_url(t)
            ctx = ScanContext(
                asset_id=asset.id, target=t.value, host=t.host,
                asset_criticality=asset.criticality,
                asset_type=asset.asset_type,
                internet_exposed=asset.is_internet_facing,
                profile=scan.profile, rate_limit=scan.rate_limit,
                timeout=scan.timeout,
                extra={"guard": guard, "url": ctx_url, "port": t.port},
            )
            try:
                scanner.initialize()
                if not scanner.validate_scope(ctx):
                    logger.info("Scanner %s rejected scope for %s", scanner.name, t.value)
                    continue
                out = scanner.scan(ctx)
                if out.error:
                    # Record error but still persist any valid findings.
                    scan.error = (scan.error or "") + f"{scanner.name}: {out.error}\n"
                    db.add(scan)

                if out.metadata.get("subdomains"):
                    _record_subdomains(db, scan, t, out.metadata["subdomains"])

                result = ScanResult(
                    tenant_id=scan.tenant_id, scan_id=scan.id, asset_id=asset.id,
                    target=t.value, checks_run=out.checks_run,
                    findings_count=len(out.normalized),
                    duration_ms=0, raw=json.dumps(out.metadata, default=str),
                )
                db.add(result)

                if out.normalized:
                    fservice.persist_scan_findings(
                        tenant_id=scan.tenant_id, scan_id=scan.id,
                        normalized_findings=out.normalized,
                        target_ctx={"asset_id": asset.id, "host": t.host,
                                    "asset_criticality": asset.criticality,
                                    "internet_exposed": asset.is_internet_facing},
                    )
            except Exception as e:  # noqa: BLE001
                logger.exception("Scanner %s errored on %s", scanner.name, t.value)
                scan.error = (scan.error or "") + f"{scanner.name} on {t.value}: {e}\n"
                db.add(scan)
            finally:
                scanner.cleanup()
                completed += 1
                _progress(db, scan, completed, total_steps)
                if completed % 5 == 0:
                    db.commit()

        asset.last_scan_at = datetime.now(timezone.utc)
        db.add(asset)
        db.commit()

    # Aggregate asset metrics for all assets touched by this scan
    _aggregate(db, scan)

    status = ScanStatus.CANCELLED if scan.cancelled else ScanStatus.COMPLETED
    _update(db, scan, status=status, progress=100 if not scan.cancelled else scan.progress,
            completed_at=datetime.now(timezone.utc))


def _full_url(t) -> str:
    if getattr(t, "scheme", None) and getattr(t, "host", None):
        if t.port and t.port not in (80, 443):
            return f"{t.scheme}://{t.host}:{t.port}"
        return f"{t.scheme}://{t.host}"
    if ":" not in t.host:
        return f"https://{t.host}"
    return t.host


def _is_public(host: str) -> bool:
    import ipaddress
    try:
        ip = ipaddress.ip_address(host)
        return not ip.is_private and not ip.is_loopback and not ip.is_link_local
    except ValueError:
        return True  # domain names assumed possibly public


def _record_subdomains(db, scan, target, subdomains: list) -> None:
    from ..db.models import Subdomain, Domain
    domain_name = target.host
    dom = db.execute(__import__("sqlalchemy").select(Domain).where(Domain.name == domain_name)).scalar_one_or_none()
    if not dom:
        dom = Domain(tenant_id=scan.tenant_id, name=domain_name, is_authorized=True)
        db.add(dom)
        db.flush()
    for item in subdomains:
        name = item["name"]
        status = "responsive" if item.get("status") == "responsive" else \
            ("unresponsive" if item.get("resolved_ip") is None else "confirmed")
        sub = db.execute(__import__("sqlalchemy").select(Subdomain).where(
            Subdomain.name == name)).scalar_one_or_none()
        if not sub:
            sub = Subdomain(
                tenant_id=scan.tenant_id, domain_id=dom.id, name=name,
                is_confirmed=status in ("confirmed", "responsive"),
                is_responsive=status == "responsive",
                is_in_scope=True, resolved_ip=item.get("resolved_ip"), status=status,
            )
            db.add(sub)


def _aggregate(db: Session, scan: Scan) -> None:
    from sqlalchemy import select
    from ..db.models import Finding
    assets = db.execute(select(Asset).where(Asset.tenant_id == scan.tenant_id)).scalars().all()
    for asset_row in assets:
        findings = db.execute(select(Finding).where(
            Finding.asset_id == asset_row.id,
            Finding.status != "false_positive",
            Finding.status != "closed",
        )).scalars().all()
        total = len(findings)
        aggregated_risk = max((f.risk_score for f in findings), default=0.0)
        update_asset_metrics(db, asset_row, risk_score=aggregated_risk, vuln_count=total)
    db.commit()


def _progress(db: Session, scan: Scan, done: int, total: int) -> None:
    if total:
        scan.progress = int(min(100, done / total * 100))
    db.add(scan)


def _update(db: Session, scan: Scan, **kwargs) -> None:
    for k, v in kwargs.items():
        setattr(scan, k, v)
    db.add(scan)
    db.commit()


def _mark_failed(db: Session, scan_id: int, error: str) -> None:
    scan = db.get(Scan, scan_id)
    if not scan:
        return
    if scan.cancelled:
        scan.status = ScanStatus.CANCELLED
    elif scan.status not in (ScanStatus.COMPLETED, ScanStatus.CANCELLED):
        scan.status = ScanStatus.FAILED
    scan.error = (scan.error or "") + error
    db.add(scan)
    db.commit()
