"""Remediation schemas."""
from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class RemediationOut(BaseModel):
    id: int
    finding_id: int
    asset_id: int | None = None
    level: str
    title: str
    immediate_action: str = ""
    permanent_solution: str = ""
    complexity: str = "medium"
    status: str
    requester_id: int | None = None
    approver_id: int | None = None
    approved_at: datetime | None = None
    backup_status: str
    execution_status: str
    verification_result: str = ""
    auto_remediated: bool
    due_at: datetime | None = None
    created_at: datetime

    model_config = {"from_attributes": True}


class RemediationCreate(BaseModel):
    finding_id: int
    level: str
    title: str
    immediate_action: str = ""
    permanent_solution: str = ""
    recommended_config: str = ""
    patch_recommendation: str = ""
    verification_procedure: str = ""
    rollback_procedure: str = ""
    business_impact: str = ""
    complexity: str = "medium"
    backup_status: str = "not_required"


class ApprovalDecision(BaseModel):
    decision: str  # approve | reject | risky
    comment: str = ""


class ExecuteRequest(BaseModel):
    force: bool = False
    backup_first: bool = True
