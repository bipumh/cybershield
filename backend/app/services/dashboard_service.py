"""Executive dashboard + analytics (requirement #16, #34, #29)."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..core.constants import FindingStatus, Severity
from ..db.models import Asset, Finding
from ..engines.posture import PostureInputs, compute_posture
from ..schemas.dashboard import (DashboardSummary, PostureOut, SeverityBreakdown,
                                 SlaSummary, TopAsset, TopPriorityItem, TrendPoint)


def executive_summary(db: Session, *, tenant_id: int) -> dict:
    now = datetime.now(timezone.utc)

    total_assets = _count(db, Asset, tenant_id)
    internet_facing = _count(db, Asset, tenant_id, Asset.is_internet_facing == True)  # noqa: E712
    internal = total_assets - internet_facing

    sev = _severity_counts(db, tenant_id)
    open_total = sum(sev.values())
    remediated = _count(db, Finding, tenant_id, Finding.status == FindingStatus.CLOSED)
    overdue = _overdue(db, tenant_id)
    kev = _count(db, Finding, tenant_id, Finding.is_kev == True)  # noqa: E712

    post = compute_posture(PostureInputs(
        critical_open=sev[Severity.CRITICAL], high_open=sev[Severity.HIGH],
        medium_open=sev[Severity.MEDIUM], low_open=sev[Severity.LOW],
        total_assets=total_assets, internet_exposed=internet_facing,
        kev_open=kev, remediated=remediated, assets_scanned=total_assets,
        sla_breach=overdue,
    ))

    score = round(_composite_risk(db, tenant_id, open_total), 1)
    patch_compliance = _patch_compliance(db, tenant_id, total_assets)

    top_assets = _top_vulnerable_assets(db, tenant_id)
    trend_vulns = _severity_trend(db, tenant_id)

    return DashboardSummary(
        total_assets=total_assets, internet_facing_assets=internet_facing,
        internal_assets=internal, open_vulnerabilities=open_total,
        critical=sev[Severity.CRITICAL], high=sev[Severity.HIGH],
        medium=sev[Severity.MEDIUM], low=sev[Severity.LOW], remediated=remediated,
        overdue=overdue, risk_score=score, posture_score=post["score"],
        kev_exposure=kev, patch_compliance=patch_compliance,
        top_vulnerable_assets=[TopAsset(**a) for a in top_assets],
        vulnerability_trend=trend_vulns,
    ).model_dump()


def posture(db: Session, *, tenant_id: int) -> dict:
    now = datetime.now(timezone.utc)
    sev = _severity_counts(db, tenant_id)
    total_assets = _count(db, Asset, tenant_id)
    internet_facing = _count(db, Asset, tenant_id, Asset.is_internet_facing == True)  # noqa: E712
    kev = _count(db, Finding, tenant_id, Finding.is_kev == True)  # noqa: E712
    mean_age = _mean_age(db, tenant_id)
    remediated = _count(db, Finding, tenant_id, Finding.status == FindingStatus.CLOSED)
    total_findings = _count(db, Finding, tenant_id, _all=True)
    overdue = _overdue(db, tenant_id)
    post = compute_posture(PostureInputs(
        critical_open=sev[Severity.CRITICAL], high_open=sev[Severity.HIGH],
        medium_open=sev[Severity.MEDIUM], low_open=sev[Severity.LOW],
        total_assets=total_assets, internet_exposed=internet_facing,
        kev_open=kev, mean_age_days=mean_age, remediated=remediated,
        total_findings=total_findings, sla_breach=overdue, assets_scanned=total_assets,
    ))
    return PostureOut(**post).model_dump()


def sla_dashboard(db: Session, *, tenant_id: int) -> dict:
    now = datetime.now(timezone.utc)
    findings = db.execute(select(Finding).where(
        Finding.tenant_id == tenant_id,
        Finding.status.notin_(FindingStatus.CLOSED_STATES))).scalars().all()
    critical_breach = high_breach = medium_breach = upcoming = reopened = 0
    total_days = 0
    closed_days = []
    for f in findings:
        if f.status == Severity.CRITICAL and f.sla_due_at and f.sla_due_at < now:
            critical_breach += 1
        if f.status == Severity.HIGH and f.sla_due_at and f.sla_due_at < now:
            high_breach += 1
        if f.status == Severity.MEDIUM and f.sla_due_at and f.sla_due_at < now:
            medium_breach += 1
        if f.sla_due_at and now < f.sla_due_at <= now + timedelta(days=7):
            upcoming += 1
        if f.last_change == "reopened":
            reopened += 1
        age = (now - f.first_detected_at).days
        total_days += age
    from ..db.models import Finding as F
    closed = db.execute(select(F).where(F.tenant_id == tenant_id,
                                        F.status == FindingStatus.CLOSED)).scalars().all()
    for f in closed:
        closed_days.append((now - f.first_detected_at).days)
    mttr = sum(closed_days) / len(closed_days) if closed_days else 0.0
    avg = total_days / len(findings) if findings else 0.0
    return SlaSummary(
        critical_breached=critical_breach, high_breached=high_breach,
        medium_breached=medium_breach, upcoming=upcoming, average_remediation_days=avg,
        mttr_days=round(mttr, 1), reopened=reopened,
    ).model_dump()


def top_priorities(db: Session, *, tenant_id: int, limit: int = 10) -> list[dict]:
    """Requirement #36: Automatic prioritization (Top 10 Things To Fix Now)."""
    findings = db.execute(select(Finding).where(
        Finding.tenant_id == tenant_id,
        Finding.status.notin_(FindingStatus.CLOSED_STATES))).scalars().all()

    def sort_key(f: Finding):
        kev_boost = 100000 if f.is_kev else 0
        internet_boost = 50000 if f.internet_exposed else 0
        crit_boost = 30000 if f.asset_criticality in ("critical", "high") else 0
        age_boost = f.risk_score
        return -(kev_boost + internet_boost + crit_boost + age_boost)

    findings.sort(key=sort_key)
    reasons = {
        "is_kev": "Listed in CISA Known Exploited Vulnerabilities (actively exploited)",
        "internet_exposed": "Internet-facing (remotely reachable)",
        "asset_criticality": "Critical/high-value asset",
    }
    items = []
    for f in findings[:limit]:
        reason_parts = [reasons[k] for k in reasons if _flag(f, k)]
        reason_parts.append(f"Risk score {f.risk_score}")
        items.append(TopPriorityItem(
            rank=len(items) + 1, finding_id=f.id, title=f.title, category=f.category,
            risk_score=f.risk_score, band=f.risk_band, reason="; ".join(reason_parts),
        ).model_dump())
    return items


def _flag(f, k):
    return {"is_kev": f.is_kev, "internet_exposed": f.internet_exposed,
            "asset_criticality": f.asset_criticality in ("critical", "high")}.get(k, False)


# ─── helpers ────────────────────────────────────────────────────────────
def _count(db, model, tenant_id, clause=None, _all=False):
    q = select(func.count()).select_from(model)
    if not _all:
        q = q.where(model.tenant_id == tenant_id)
    if clause is not None:
        q = q.where(clause)
    return db.execute(q).scalar() or 0


def _severity_counts(db, tenant_id) -> dict:
    counts = {Severity.CRITICAL: 0, Severity.HIGH: 0, Severity.MEDIUM: 0,
              Severity.LOW: 0, Severity.INFO: 0}
    active = list(FindingStatus.ACTIVE)
    rows = db.execute(select(Finding.severity, func.count())
                      .where(Finding.tenant_id == tenant_id,
                             Finding.status.in_(active))
                      .group_by(Finding.severity)).all()
    for sev, cnt in rows:
        counts[sev] = cnt
    return counts


def _overdue(db, tenant_id) -> int:
    now = datetime.now(timezone.utc)
    return _count(db, Finding, tenant_id, Finding.sla_due_at < now) or 0


def _mean_age(db, tenant_id) -> float:
    rows = db.execute(select(Finding).where(Finding.tenant_id == tenant_id,
                                            Finding.status.in_(FindingStatus.ACTIVE))).scalars().all()
    now = datetime.now(timezone.utc)
    if not rows:
        return 0.0
    return round(sum((now - f.first_detected_at).days for f in rows) / len(rows), 1)


def _composite_risk(db, tenant_id, open_total) -> float:
    findings = db.execute(select(Finding).where(
        Finding.tenant_id == tenant_id,
        Finding.status.in_(FindingStatus.ACTIVE))).scalars().all()
    if not findings:
        return 0.0
    weighted = sum(f.risk_score for f in findings)
    return weighted / len(findings)


def _patch_compliance(db, tenant_id, total_assets) -> float:
    if not total_assets:
        return 100.0
    scanned = _count(db, Asset, tenant_id, Asset.last_scan_at.isnot(None))
    return round(scanned / total_assets * 100, 1)


def _top_vulnerable_assets(db, tenant_id) -> list[dict]:
    assets = db.execute(select(Asset).where(Asset.tenant_id == tenant_id,
                                            Asset.deleted_at.is_(None))).scalars().all()
    out = []
    for a in assets:
        finds = [f for f in db.execute(select(Finding).where(
            Finding.asset_id == a.id, Finding.status.in_(FindingStatus.ACTIVE))).scalars().all()]
        if not finds:
            continue
        crit = sum(1 for f in finds if f.severity == Severity.CRITICAL)
        high = sum(1 for f in finds if f.severity == Severity.HIGH)
        out.append(TopAsset(
            asset_id=a.id, name=a.hostname or a.ip_address or a.asset_key,
            risk_score=max((f.risk_score for f in finds), default=0.0),
            critical_count=crit, high_count=high, total=len(finds),
        ).model_dump())
    out.sort(key=lambda x: (-x["risk_score"], -x["total"]))
    return out[:10]


def _severity_trend(db, tenant_id) -> list[TrendPoint]:
    days = 14
    start = datetime.now(timezone.utc) - timedelta(days=days)
    rows = db.execute(select(Finding.first_detected_at).where(
        Finding.tenant_id == tenant_id, Finding.first_detected_at >= start)).all()
    by_day: dict[str, int] = {}
    for (dt,) in rows:
        key = dt.date().isoformat()
        by_day[key] = by_day.get(key, 0) + 1
    points = []
    for i in range(days, -1, -1):
        day = (start + timedelta(days=i)).date().isoformat()
        points.append(TrendPoint(date=day, value=by_day.get(day, 0)).model_dump())
    return points
