"""Dashboard & analytics schemas."""
from __future__ import annotations

from typing import Any

from pydantic import BaseModel


class SummaryMetric(BaseModel):
    label: str
    value: int
    trend: float | None = None


class SeverityBreakdown(BaseModel):
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0


class TrendPoint(BaseModel):
    date: str
    value: int | float


class TopAsset(BaseModel):
    asset_id: int
    name: str
    risk_score: float
    critical_count: int
    high_count: int
    total: int


class DashboardSummary(BaseModel):
    total_assets: int
    internet_facing_assets: int
    internal_assets: int
    open_vulnerabilities: int
    critical: int
    high: int
    medium: int
    low: int
    remediated: int
    overdue: int
    risk_score: float
    posture_score: float
    kev_exposure: int
    patch_compliance: float
    top_vulnerable_assets: list[TopAsset] = []
    vulnerability_trend: list[TrendPoint] = []
    risk_trend: list[TrendPoint] = []


class PostureOut(BaseModel):
    score: float
    previous_score: float | None = None
    change: float | None = None
    factors: list[dict[str, Any]] = []


class SlaSummary(BaseModel):
    critical_breached: int = 0
    high_breached: int = 0
    medium_breached: int = 0
    upcoming: int = 0
    average_remediation_days: float = 0.0
    mttr_days: float = 0.0
    reopened: int = 0


class TopPriorityItem(BaseModel):
    rank: int
    finding_id: int | None = None
    title: str
    category: str
    risk_score: float
    band: str
    reason: str
