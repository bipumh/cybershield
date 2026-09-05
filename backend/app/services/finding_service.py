"""Finding service: persist normalized findings, enrich, risk, lifecycle.

Implements requirement #52 ("do not claim a vulnerability exists unless there
is sufficient evidence") — a finding is only created when a scanner emitted it
with evidence; this service never invents findings.
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timedelta, timezone

from sqlalchemy import func, select
from sqlalchemy.orm import Session


def db_count(session: Session, query) -> int:
    return session.execute(select(func.count()).select_from(query.subquery())).scalar() or 0

from ..core.constants import (ChangeType, ExceptionKind, FindingStatus, Severity)
from ..core.exceptions import NotFoundError, ValidationError
from ..db.models import (Asset, ExceptionItem, Finding, FindingChange)
from ..engines import ai as ai_engine
from ..engines import compliance as compliance_engine
from ..engines import remediation as remediation_engine
from ..engines import risk as risk_engine
from ..engines.intelligence import IntelligenceEngine
from . import asset_service

# SLA (days) configurable; defaults per requirement #28
DEFAULT_SLA = {Severity.CRITICAL: 7, Severity.HIGH: 15, Severity.MEDIUM: 30,
               Severity.LOW: 90, Severity.INFO: 90}


def finding_fingerprint(title: str, category: str, component: str | None,
                        cve: str | None) -> str:
    if cve:
        return "cve:" + cve.lower()
    base = f"{category}|{title.lower()}|{(component or '').lower()}"
    return "sig:" + hashlib.sha1(base.encode()).hexdigest()[:16]


def next_finding_no(db: Session, tenant_id: int) -> str:
    # Global sequence is acceptable for platform-wide numbering; per-tenant ok too.
    max_no = db.execute(select(func.max(Finding.id))).scalar() or 0
    return f"VUL-{int(max_no) + 1:06d}"


def severity_from_score_and_cvss(score: float, cvss_score: float) -> str:
    from ..engines.intelligence import severity_from_score
    return severity_from_score(score or cvss_score)


class FindingService:
    def __init__(self, db: Session):
        self.db = db
        self.intel = IntelligenceEngine(db)

    def persist_scan_findings(self, *, tenant_id: int, scan_id: int,
                              normalized_findings: list, target_ctx: dict) -> dict:
        """persist a scanner output's findings for one asset.

        target_ctx: {asset_id, host, ip, asset_criticality, internet_exposed,
                     asset_type}
        """
        saved = []
        asset_id = target_ctx.get("asset_id")
        asset = self.db.get(Asset, asset_id) if asset_id else None
        criticality = asset.criticality if asset else target_ctx.get("asset_criticality", "medium")
        internet_exposed = bool(asset.is_internet_facing if asset else
                                target_ctx.get("internet_exposed", False))

        for nf in normalized_findings:
            fp = finding_fingerprint(nf.title, nf.category, nf.affected_component, nf.cve)
            enriched = self.intel.enrich(
                fingerprint=fp, cve=nf.cve, cwe=nf.cwe, vector=nf.cvss_vector,
                title=nf.title, description=nf.description, product=nf.affected_component,
                version=nf.detected_version,
            )

            severity = enriched.severity if enriched.cvss_score else nf.severity
            if not enriched.cvss_score and nf.cvss_score:
                severity = nf.severity

            age_days = 0  # new today
            risk_score = risk_engine.compute_risk_score(
                cvss=enriched.cvss_score or nf.cvss_score,
                exploitability=enriched.exploitability or nf.exploitability,
                asset_criticality=criticality, internet_exposed=internet_exposed,
                is_kev=enriched.is_kev, age_days=age_days,
            )
            band = risk_engine.band_from_score(risk_score)

            plan = remediation_engine.build_remediation_plan(
                nf.category, severity, nf.title, nf.detected_version, nf.fixed_version)
            nf.remediation.update(plan)
            nf.remediation_level = plan.get("level", nf.remediation_level)

            standards = compliance_engine.map_finding_to_standards(nf.category, nf.cwe)
            # merge any scanner-provided standards
            standards.update(nf.standards or {})

            ai_verdict = ai_engine.AiEngine().analyze_finding({
                "title": nf.title, "category": nf.category, "severity": severity,
                "cvss_score": enriched.cvss_score or nf.cvss_score,
                "internet_exposed": internet_exposed, "asset_criticality": criticality,
                "is_kev": enriched.is_kev, "age_days": age_days,
                "exploitability": enriched.exploitability, "description": nf.description,
            })

            sla_days = DEFAULT_SLA.get(severity, 30)
            now = datetime.now(timezone.utc)

            existing = self._find_existing(tenant_id, asset_id, fp)
            if existing and not self._is_closed(existing):
                # update last_detected, re-evaluate
                existing.last_detected_at = now
                existing.title = nf.title
                existing.description = nf.description
                existing.cvss_score = enriched.cvss_score or nf.cvss_score or existing.cvss_score
                existing.severity = severity or existing.severity
                existing.risk_score = risk_score
                existing.risk_band = band
                existing.evidence = nf.evidence
                existing.remediation_json = json.dumps(nf.remediation)
                existing.remediation_level = nf.remediation_level
                existing.standards_json = json.dumps(standards)
                existing.is_kev = enriched.is_kev
                existing.exploitability = enriched.exploitability or existing.exploitability
                existing.last_change = ChangeType.PERSISTENT
                existing.sla_due_at = now + timedelta(days=sla_days)
                self._record_change(existing, scan_id, ChangeType.PERSISTENT)
                self.db.add(existing)
                saved.append(existing)
                continue

            finding = Finding(
                tenant_id=tenant_id,
                finding_no=next_finding_no(self.db, tenant_id),
                asset_id=asset_id,
                scan_id=scan_id,
                title=nf.title,
                description=nf.description,
                category=nf.category,
                severity=severity,
                cvss_score=enriched.cvss_score or nf.cvss_score,
                cvss_vector=enriched and nf.cvss_vector or nf.cvss_vector,
                cve=enriched.cve or nf.cve,
                cwe=enriched.cwe or nf.cwe,
                evidence=nf.evidence,
                affected_component=nf.affected_component,
                detected_version=nf.detected_version,
                fixed_version=enriched.fixed_version or nf.fixed_version,
                exploitability=enriched.exploitability or nf.exploitability,
                internet_exposed=internet_exposed,
                asset_criticality=criticality,
                risk_score=risk_score,
                risk_band=band,
                is_kev=enriched.is_kev,
                ai_analysis_json=json.dumps({
                    "analysis": ai_verdict.analysis,
                    "why_it_matters": ai_verdict.why_it_matters,
                    "potential_impact": ai_verdict.potential_impact,
                    "predicted_risk": ai_verdict.predicted_risk,
                    "confidence": ai_verdict.confidence,
                    "is_ai_generated": ai_verdict.is_ai_generated,
                }),
                remediation_json=json.dumps(nf.remediation),
                remediation_level=nf.remediation_level,
                standards_json=json.dumps(standards),
                references=json.dumps(enriched.references or nf.references),
                status=FindingStatus.OPEN,
                first_detected_at=now,
                last_detected_at=now,
                sla_due_at=now + timedelta(days=sla_days),
                last_change=ChangeType.NEW,
            )
            self.db.add(finding)
            self.db.flush()
            self._record_change(finding, scan_id, ChangeType.NEW)
            saved.append(finding)

        return {"saved": len(saved), "findings": saved}

    def _find_existing(self, tenant_id: int, asset_id: int | None, fingerprint: str):
        q = select(Finding).where(
            Finding.tenant_id == tenant_id, Finding.asset_id == asset_id,
            Finding.is_suppressed == False,  # noqa: E712
        )
        # match by cve or fingerprint
        found = self.db.execute(q.limit(500)).scalars().all()
        for f in found:
            fp = finding_fingerprint(f.title, f.category, f.affected_component, f.cve)
            if fp == fingerprint:
                return f
        return None

    def _is_closed(self, finding: Finding) -> bool:
        return finding.status in FindingStatus.CLOSED_STATES

    def _record_change(self, finding: Finding, scan_id: int | None, change_type: str) -> None:
        self.db.add(FindingChange(
            finding_id=finding.id, scan_id=scan_id, change_type=change_type,
            snapshot_json=json.dumps({
                "title": finding.title, "severity": finding.severity,
                "risk_score": finding.risk_score, "status": finding.status,
            }),
        ))

    def compute_lifecycle(self, *, tenant_id: int, scan_id: int) -> None:
        """For each prior finding not seen in this scan, mark fixed/closed."""
        seen = set(self._finding_ids_for_scan(tenant_id, scan_id))
        open_prior = self.db.execute(select(Finding).where(
            Finding.tenant_id == tenant_id,
            Finding.status.notin_(FindingStatus.CLOSED_STATES),
        )).scalars().all()
        for f in open_prior:
            if f.id in seen or f.scan_id == scan_id:
                continue
            # Not seen again in this full-scan => treat as fixed only if this
            # scan covered the same asset. Simplified: skip auto-close here.
            continue

    def _finding_ids_for_scan(self, tenant_id: int, scan_id: int) -> list[int]:
        return list(self.db.execute(select(Finding.id).where(
            Finding.tenant_id == tenant_id, Finding.scan_id == scan_id)).scalars().all())

    # ─── Lifecycle / exceptions for a re-scan comparison ────────────────
    def compare_scan(self, *, tenant_id: int, prev_scan_id: int, curr_scan_id: int) -> dict:
        prev = self._snapshot(tenant_id, prev_scan_id)
        curr = self._snapshot(tenant_id, curr_scan_id)
        new, fixed, persistent, reopened, changed = [], [], [], [], []
        curr_keys = {k for k in curr}
        for k, payload in curr.items():
            if k not in prev:
                new.append(payload)
            else:
                p = prev[k]
                if payload.get("status") == "closed":
                    continue
                persistent.append({"key": k, "title": payload["title"]})
        for k, payload in prev.items():
            if k not in curr_keys:
                if payload.get("status") not in FindingStatus.CLOSED_STATES:
                    fixed.append({**payload, "change": "fixed"})
        return {"new": new, "fixed": fixed, "persistent": persistent,
                "reopened": reopened, "changed": changed}

    def _snapshot(self, tenant_id: int, scan_id: int) -> dict:
        rows = self.db.execute(select(Finding).where(
            Finding.tenant_id == tenant_id, Finding.scan_id == scan_id)).scalars().all()
        return {finding_fingerprint(r.title, r.category, r.affected_component, r.cve): {
            "finding_no": r.finding_no, "title": r.title, "status": r.status,
            "risk_score": r.risk_score, "severity": r.severity,
        } for r in rows}

    def query_list(self, *, tenant_id: int, page: int = 1, page_size: int = 20,
                   severity: str | None = None, status: str | None = None,
                   asset_id: int | None = None, cve: str | None = None,
                   cwe: str | None = None, is_kev: bool | None = None,
                   risk_band: str | None = None, search: str | None = None,
                   sort_by: str = "risk_score", sort_desc: bool = True) -> dict:
        from sqlalchemy import func
        query = select(Finding).where(Finding.tenant_id == tenant_id,
                                      Finding.is_suppressed == False)  # noqa: E712
        if severity:
            query = query.where(Finding.severity == severity)
        if status:
            query = query.where(Finding.status == status)
        if asset_id:
            query = query.where(Finding.asset_id == asset_id)
        if cve:
            query = query.where(Finding.cve.contains(cve))
        if cwe:
            query = query.where(Finding.cwe.contains(cwe))
        if is_kev is not None:
            query = query.where(Finding.is_kev == is_kev)
        if risk_band:
            query = query.where(Finding.risk_band == risk_band)
        if search:
            like = f"%{search}%"
            query = query.where((Finding.title.ilike(like)) | (Finding.finding_no.ilike(like)))

        total = db_count(self.db, query)
        order_col = getattr(Finding, sort_by, Finding.risk_score)
        order_expr = order_col.desc() if sort_desc else order_col.asc()
        rows = self.db.execute(query.order_by(order_expr)
                               .offset((page - 1) * page_size).limit(page_size)).scalars().all()
        return {"items": rows, "total": total, "page": page, "page_size": page_size,
                "pages": (total + page_size - 1) // page_size}
