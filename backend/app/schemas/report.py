"""Report + compliance schemas."""
from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class ReportCreate(BaseModel):
    name: str
    report_type: str  # executive | technical | compliance
    format: str = "pdf"  # pdf | html | csv | json | xlsx
    scope: dict[str, Any] = Field(default_factory=dict)


class ReportOut(BaseModel):
    id: int
    report_key: str
    name: str
    report_type: str
    format: str
    status: str
    generated_at: datetime | None = None
    size_bytes: int
    error: str | None = None
    created_at: datetime

    model_config = {"from_attributes": True}


class ComplianceMappingOut(BaseModel):
    id: int
    standard: str
    control_id: str
    title: str
    description: str = ""
    is_defensible: bool

    model_config = {"from_attributes": True}
