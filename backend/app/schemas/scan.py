"""Scan request/response schemas including safety controls."""
from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field, conlist

from ..core.constants import ScanProfile, ScanTargetKind


class ScanTargetIn(BaseModel):
    kind: str = Field(..., description="Target kind: domain|url|ip|cidr|hostname|range|asset")
    value: str = Field(min_length=1, max_length=512)
    in_scope: bool = True


class ScanSafetyConfirmation(BaseModel):
    scope_confirmed: bool = False
    safety_confirmed: bool = False
    authorization_statement: str | None = None


class ScanCreate(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    mode: str  # web | network
    profile: str = "safe"
    targets: list[ScanTargetIn] = Field(..., max_length=500)
    rate_limit: int | None = Field(default=None, ge=1, le=200)
    timeout: int | None = Field(default=None, ge=2, le=120)
    concurrency: int | None = Field(default=None, ge=1, le=20)
    excluded_ips: list[str] = Field(default_factory=list)
    excluded_domains: list[str] = Field(default_factory=list)
    maintenance_window: str | None = None
    auto_approve_scope: bool = False
    safety: ScanSafetyConfirmation = Field(default_factory=ScanSafetyConfirmation)


class ScanTargetOut(BaseModel):
    id: int
    kind: str
    value: str
    asset_id: int | None = None
    in_scope: bool
    status: str

    model_config = {"from_attributes": True}


class ScanOut(BaseModel):
    id: int
    scan_key: str
    name: str
    mode: str
    profile: str
    status: str
    requested_by: int | None = None
    authorized: bool
    scope_confirmed: bool
    safety_confirmed: bool
    rate_limit: int
    timeout: int
    concurrency: int
    progress: int
    total_steps: int
    started_at: datetime | None = None
    completed_at: datetime | None = None
    cancelled: bool
    error: str | None = None
    summary: dict = {}
    created_at: datetime

    model_config = {"from_attributes": True}


class ScanResultOut(BaseModel):
    id: int
    scan_id: int
    asset_id: int | None = None
    target: str
    checks_run: int
    findings_count: int
    duration_ms: int

    model_config = {"from_attributes": True}


class ScanStatusOut(BaseModel):
    id: int
    status: str
    progress: int
    findings_count: int = 0
    message: str | None = None


class ScanCancelOut(BaseModel):
    id: int
    status: str
    cancelled: bool


class DiscoveredAssetOut(BaseModel):
    name: str
    status: str  # discovered|confirmed|responsive|unresponsive
    resolved_ip: str | None = None
    in_scope: bool = True
    authorized: bool = True


class ApproveAssetsRequest(BaseModel):
    subdomain_ids: list[int] = Field(default_factory=list)
    mark_all_scope: bool = False


class ScheduleCreate(BaseModel):
    name: str
    mode: str
    frequency: str  # onetime|daily|weekly|monthly|custom
    cron_expression: str | None = None
    targets: list[ScanTargetIn]
    profile: str = "safe"
    enabled: bool = True


class ScheduleOut(BaseModel):
    id: int
    name: str
    mode: str
    frequency: str
    cron_expression: str | None = None
    targets: list = []
    profile: str
    enabled: bool
    last_run_at: datetime | None = None
    next_run_at: datetime | None = None
    created_at: datetime

    model_config = {"from_attributes": True}
