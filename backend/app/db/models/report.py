"""Reports + compliance mappings."""
from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from ..base import Base
from .base_mixin import TenantMixin, TimestampMixin


class Report(Base, TimestampMixin, TenantMixin):
    __tablename__ = "reports"

    id: Mapped[int] = mapped_column(primary_key=True)
    report_key: Mapped[str] = mapped_column(String(40), nullable=False, unique=True, index=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    report_type: Mapped[str] = mapped_column(String(32), nullable=False)  # executive|technical|compliance
    format: Mapped[str] = mapped_column(String(16), default="pdf", nullable=False)
    scope: Mapped[str] = mapped_column(Text, default="{}", nullable=False)  # filters
    file_path: Mapped[str | None] = mapped_column(String(512), nullable=True)
    status: Mapped[str] = mapped_column(String(32), default="pending", nullable=False)
    requested_by: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    generated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    size_bytes: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    content_preview: Mapped[str] = mapped_column(Text, default="", nullable=False)


class ComplianceMapping(Base, TimestampMixin):
    __tablename__ = "compliance_mappings"
    __table_args__ = (UniqueConstraint("standard", "control_id", name="uq_compliance_standard_control"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    standard: Mapped[str] = mapped_column(String(64), nullable=False, index=True)  # Standard
    control_id: Mapped[str] = mapped_column(String(120), nullable=False)
    title: Mapped[str] = mapped_column(String(600), nullable=False)
    description: Mapped[str] = mapped_column(Text, default="", nullable=False)
    finding_categories: Mapped[str] = mapped_column(Text, default="[]", nullable=False)
    is_defensible: Mapped[bool] = mapped_column(default=True, nullable=False)
    source: Mapped[str] = mapped_column(String(120), default="curated", nullable=False)
