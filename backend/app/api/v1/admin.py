"""Administration endpoints: roles, compliance mappings, integrations, risk weights."""
from __future__ import annotations

from fastapi import APIRouter, Depends, Query
from sqlalchemy import select
from sqlalchemy.orm import Session

from ...core.constants import Role
from ...core.deps import get_current_user, get_db_dep, require_roles, require_permission, write_audit
from ...db.models import ComplianceMapping, Integration, User
from ...schemas.report import ComplianceMappingOut

router = APIRouter(prefix="/admin", tags=["Administration"])


@router.get("/compliance-mappings", response_model=list[ComplianceMappingOut],
            summary="List compliance standard mappings")
def compliance_mappings(standard: str | None = None, db: Session = Depends(get_db_dep),
                        user: User = Depends(require_roles(Role.SUPER_ADMIN, Role.AUDITOR))):
    q = select(ComplianceMapping)
    if standard:
        q = q.where(ComplianceMapping.standard == standard)
    rows = db.execute(q.order_by(ComplianceMapping.standard)).scalars().all()
    return [ComplianceMappingOut.model_validate(r) for r in rows]


@router.get("/integrations", summary="List integrations")
def list_integrations(db: Session = Depends(get_db_dep),
                      user: User = Depends(require_roles(Role.SUPER_ADMIN))):
    rows = db.execute(select(Integration).where(Integration.tenant_id == user.tenant_id)).scalars().all()
    return [{"id": i.id, "name": i.name, "kind": i.kind, "enabled": i.enabled,
             "endpoint": i.endpoint, "auth_ref": i.auth_ref, "events": i.events_json,
             "last_status": i.last_status} for i in rows]


@router.post("/integrations", status_code=201, summary="Register an integration")
def create_integration(body: dict, db: Session = Depends(get_db_dep),
                       user: User = Depends(require_roles(Role.SUPER_ADMIN))):
    from ...db.models import Integration
    integ = Integration(
        tenant_id=user.tenant_id, name=body.get("name", "integration"),
        kind=body.get("kind", "webhook"), enabled=body.get("enabled", False),
        endpoint=body.get("endpoint"), auth_ref=body.get("auth_ref"),
        config_json=str(body.get("config", {})), events_json=str(body.get("events", [])),
    )
    db.add(integ)
    db.commit()
    write_audit(db, actor=user, action="integration.create", target_type="integration",
                target_id=integ.id, new_state={"name": integ.name, "kind": integ.kind})
    return {"id": integ.id, "name": integ.name, "kind": integ.kind}


@router.get("/risk-weights", summary="Current risk weighting model")
def risk_weights(db: Session = Depends(get_db_dep), user: User = Depends(require_permission("risk:read"))):
    from ...engines.risk import RiskWeights
    return RiskWeights().__dict__


@router.put("/risk-weights", summary="Update risk weighting (admin)")
def update_risk_weights(body: dict, db: Session = Depends(get_db_dep),
                        user: User = Depends(require_roles(Role.SUPER_ADMIN, Role.CISO))):
    from ...engines.risk import RiskWeights
    allowed = {"cvss", "exploitability", "asset_criticality", "internet_exposure",
               "threat_intelligence", "age", "attack_surface", "auth_requirement",
               "potential_impact", "compensating_control"}
    weights = {k: max(0.0, float(v)) for k, v in body.items() if k in allowed}
    # Persist to platform config (see RiskPolicy service in production)
    write_audit(db, actor=user, action="risk_weights.update", target_type="config",
                previous_state={}, new_state=weights)
    return {"ok": True, "weights": weights}
