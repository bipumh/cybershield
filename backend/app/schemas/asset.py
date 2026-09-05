"""Asset inventory schemas."""
from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field


class AssetCreate(BaseModel):
    hostname: str | None = None
    ip_address: str | None = None
    mac_address: str | None = None
    domain: str | None = None
    asset_type: str = "server"
    os_name: str | None = None
    os_version: str | None = None
    vendor: str | None = None
    model: str | None = None
    firmware_version: str | None = None
    owner: str | None = None
    department: str | None = None
    location: str | None = None
    environment: str | None = None
    criticality: str = "medium"
    is_production: bool = False
    is_internet_facing: bool = False
    tags: dict[str, str] = Field(default_factory=dict)


class AssetUpdate(BaseModel):
    hostname: str | None = None
    ip_address: str | None = None
    mac_address: str | None = None
    domain: str | None = None
    asset_type: str | None = None
    os_name: str | None = None
    os_version: str | None = None
    vendor: str | None = None
    model: str | None = None
    firmware_version: str | None = None
    owner: str | None = None
    department: str | None = None
    location: str | None = None
    environment: str | None = None
    criticality: str | None = None
    is_production: bool | None = None
    is_internet_facing: bool | None = None
    tags: dict[str, str] | None = None


class AssetOut(BaseModel):
    id: int
    asset_key: str
    hostname: str | None = None
    ip_address: str | None = None
    mac_address: str | None = None
    domain: str | None = None
    asset_type: str
    os_name: str | None = None
    os_version: str | None = None
    vendor: str | None = None
    model: str | None = None
    firmware_version: str | None = None
    owner: str | None = None
    department: str | None = None
    location: str | None = None
    environment: str | None = None
    criticality: str
    is_production: bool
    is_internet_facing: bool
    last_scan_at: datetime | None = None
    risk_score: float
    vulnerability_count: int
    tags: dict | list | None = None
    created_at: datetime

    model_config = {"from_attributes": True}


class AssetTagRequest(BaseModel):
    key: str
    value: str
