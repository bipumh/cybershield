"""Asset inventory: hosts, endpoints, network devices, applications."""
from __future__ import annotations

import json

from datetime import datetime

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Integer, JSON, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from ..base import Base
from .base_mixin import SoftDeleteMixin, TenantMixin, TimestampMixin


class Asset(Base, TimestampMixin, SoftDeleteMixin, TenantMixin):
    __tablename__ = "assets"

    id: Mapped[int] = mapped_column(primary_key=True)
    asset_key: Mapped[str] = mapped_column(String(64), nullable=False, unique=True, index=True)  # platform identifier
    hostname: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    ip_address: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    mac_address: Mapped[str | None] = mapped_column(String(32), nullable=True)
    domain: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    asset_type: Mapped[str] = mapped_column(String(64), nullable=False, index=True)  # AssetType
    os_name: Mapped[str | None] = mapped_column(String(128), nullable=True)
    os_version: Mapped[str | None] = mapped_column(String(128), nullable=True)
    vendor: Mapped[str | None] = mapped_column(String(128), nullable=True)
    model: Mapped[str | None] = mapped_column(String(128), nullable=True)
    firmware_version: Mapped[str | None] = mapped_column(String(128), nullable=True)
    owner: Mapped[str | None] = mapped_column(String(255), nullable=True)
    department: Mapped[str | None] = mapped_column(String(120), nullable=True, index=True)
    location: Mapped[str | None] = mapped_column(String(255), nullable=True)
    environment: Mapped[str | None] = mapped_column(String(64), nullable=True)
    criticality: Mapped[str] = mapped_column(String(32), default="medium", nullable=False, index=True)  # AssetCriticality
    is_production: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    is_internet_facing: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False, index=True)
    last_scan_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    risk_score: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    vulnerability_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    tags: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)  # {"key": "val"}
    metadata_json: Mapped[str] = mapped_column(Text, default="{}", nullable=False)

    groups: Mapped[list["AssetGroup"]] = relationship(secondary="asset_group_members",
                                                      back_populates="assets")

    @property
    def tag_map(self) -> dict:
        if isinstance(self.tags, list):
            return {}
        return self.tags or {}

    def set_metadata(self, **kwargs) -> None:
        base = json.loads(self.metadata_json or "{}")
        base.update(kwargs)
        self.metadata_json = json.dumps(base)


class AssetGroup(Base, TimestampMixin, TenantMixin):
    __tablename__ = "asset_groups"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    description: Mapped[str | None] = mapped_column(String(500), nullable=True)

    assets: Mapped[list[Asset]] = relationship(secondary="asset_group_members", back_populates="groups")


# association table
from sqlalchemy import Column, ForeignKey, Table  # noqa: E402

asset_group_members = Table(
    "asset_group_members",
    Base.metadata,
    Column("asset_id", ForeignKey("assets.id", ondelete="CASCADE"), primary_key=True),
    Column("group_id", ForeignKey("asset_groups.id", ondelete="CASCADE"), primary_key=True),
)
