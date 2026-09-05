"""Findings: normalized vulnerability findings + lifecycle deltas."""
from __future__ import annotations

from datetime import datetime

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from ..base import Base
from .base_mixin import TenantMixin, TimestampMixin


class Finding(Base, TimestampMixin, TenantMixin):
    __tablename__ = "findings"

    id: Mapped[int] = mapped_column(primary_key=True)
    finding_no: Mapped[str] = mapped_column(String(20), nullable=False, unique=True, index=True)
    asset_id: Mapped[int | None] = mapped_column(ForeignKey("assets.id", ondelete="SET NULL"),
                                                 nullable=True, index=True)
    scan_id: Mapped[int | None] = mapped_column(ForeignKey("scans.id", ondelete="SET NULL"),
                                                nullable=True, index=True)
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    description: Mapped[str] = mapped_column(Text, default="", nullable=False)
    category: Mapped[str] = mapped_column(String(200), nullable=False, index=True)
    severity: Mapped[str] = mapped_column(String(16), nullable=False, index=True)
    cvss_score: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    cvss_vector: Mapped[str | None] = mapped_column(String(64), nullable=True)
    cve: Mapped[str | None] = mapped_column(String(32), nullable=True, index=True)
    cwe: Mapped[str | None] = mapped_column(String(32), nullable=True, index=True)
    evidence: Mapped[str] = mapped_column(Text, default="", nullable=False)
    affected_component: Mapped[str | None] = mapped_column(String(255), nullable=True)
    detected_version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    fixed_version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    exploitability: Mapped[str] = mapped_column(String(32), default="none", nullable=False)
    internet_exposed: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    asset_criticality: Mapped[str] = mapped_column(String(32), default="medium", nullable=False)
    risk_score: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    risk_band: Mapped[str] = mapped_column(String(16), default="low", nullable=False, index=True)
    is_kev: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    ai_analysis_json: Mapped[str] = mapped_column(Text, default="{}", nullable=False)
    remediation_json: Mapped[str] = mapped_column(Text, default="{}", nullable=False)  # solution payload
    remediation_level: Mapped[str] = mapped_column(String(40), default="level3_manual", nullable=False)
    standards_json: Mapped[str] = mapped_column(Text, default="{}", nullable=False)  # standard mapping
    references: Mapped[str] = mapped_column(Text, default="[]", nullable=False)
    status: Mapped[str] = mapped_column(String(40), default="open", nullable=False, index=True)
    first_detected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_detected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    sla_due_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_change: Mapped[str] = mapped_column(String(32), default="new", nullable=False)
    is_suppressed: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    suppression_reason: Mapped[str | None] = mapped_column(Text, nullable=True)

    asset = relationship("Asset", lazy="joined", foreign_keys=[asset_id])


class FindingChange(Base, TimestampMixin):
    __tablename__ = "finding_changes"

    id: Mapped[int] = mapped_column(primary_key=True)
    finding_id: Mapped[int] = mapped_column(ForeignKey("findings.id", ondelete="CASCADE"),
                                            index=True, nullable=False)
    scan_id: Mapped[int | None] = mapped_column(ForeignKey("scans.id", ondelete="SET NULL"), nullable=True)
    change_type: Mapped[str] = mapped_column(String(32), nullable=False)  # new|fixed|persistent|reopened|changed
    snapshot_json: Mapped[str] = mapped_column(Text, default="{}", nullable=False)
