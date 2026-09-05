"""Finding schemas: normalized vulnerability, detail, risk, AI, remediation plan."""
from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class FindingOut(BaseModel):
    id: int
    finding_no: str
    asset_id: int | None = None
    scan_id: int | None = None
    title: str
    description: str = ""
    category: str
    severity: str
    cvss_score: float
    cve: str | None = None
    cwe: str | None = None
    exploitability: str = "none"
    internet_exposed: bool
    asset_criticality: str
    risk_score: float
    risk_band: str
    is_kev: bool
    remediation_level: str
    status: str
    first_detected_at: datetime
    last_detected_at: datetime
    sla_due_at: datetime | None = None
    last_change: str
    age_days: int = 0

    model_config = {"from_attributes": True}


class RemediationPlan(BaseModel):
    immediate_action: str = ""
    permanent_solution: str = ""
    recommended_config: str = ""
    patch_recommendation: str = ""
    verification_procedure: str = ""
    rollback_procedure: str = ""
    business_impact: str = ""
    complexity: str = "medium"


class FindingDetail(BaseModel):
    id: int
    finding_no: str
    title: str
    description: str
    category: str
    severity: str
    cvss_score: float
    cvss_vector: str | None = None
    cve: str | None = None
    cwe: str | None = None
    evidence: str
    affected_component: str | None = None
    detected_version: str | None = None
    fixed_version: str | None = None
    exploitability: str
    internet_exposed: bool
    asset_criticality: str
    risk_score: float
    risk_band: str
    is_kev: bool
    ai_analysis: dict[str, Any] = {}
    remediation_plan: RemediationPlan = Field(default_factory=RemediationPlan)
    remediation_level: str
    standards: dict[str, Any] = {}
    references: list[str] = []
    status: str
    first_detected_at: datetime
    last_detected_at: datetime
    sla_due_at: datetime | None = None
    asset: dict | None = None


class FindingUpdate(BaseModel):
    status: str | None = None
    severity: str | None = None
    notes: str | None = None


class FindingChangeOut(BaseModel):
    finding_id: int
    change_type: str
    snapshot: dict = {}


class ExceptionCreate(BaseModel):
    kind: str  # false_positive | accepted_risk | compensating_control
    reason: str = Field(min_length=3)
    evidence: str = ""
    expires_at: datetime | None = None
    compensating_control_desc: str = ""


class ExceptionOut(BaseModel):
    id: int
    finding_id: int
    kind: str
    reason: str
    evidence: str = ""
    status: str
    expires_at: datetime | None = None
    is_auto_expired: bool

    model_config = {"from_attributes": True}
