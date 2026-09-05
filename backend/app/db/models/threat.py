"""Threat intelligence: KEV and vendor advisory feed entries."""
from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, Float, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from ..base import Base
from .base_mixin import TimestampMixin


class CisaKev(Base, TimestampMixin):
    """Known Exploited Vulnerabilities catalog."""
    __tablename__ = "cisa_kev"
    __table_args__ = (UniqueConstraint("cve_id", name="uq_cisa_kev_cve"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    cve_id: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    vendor: Mapped[str | None] = mapped_column(String(128), nullable=True)
    product: Mapped[str | None] = mapped_column(String(128), nullable=True)
    name: Mapped[str | None] = mapped_column(String(500), nullable=True)
    description: Mapped[str] = mapped_column(Text, default="", nullable=False)
    required_action: Mapped[str] = mapped_column(Text, default="", nullable=False)
    date_added: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    due_date: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    cvss_score: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    source: Mapped[str] = mapped_column(String(64), default="cisa_kev", nullable=False)


class ThreatIntelEntry(Base, TimestampMixin):
    __tablename__ = "threat_intelligence"

    id: Mapped[int] = mapped_column(primary_key=True)
    source: Mapped[str] = mapped_column(String(64), nullable=False)
    identifier: Mapped[str | None] = mapped_column(String(120), nullable=True)
    severity: Mapped[str] = mapped_column(String(16), default="medium", nullable=False)
    title: Mapped[str] = mapped_column(String(600), nullable=False)
    summary: Mapped[str] = mapped_column(Text, default="", nullable=False)
    indicators: Mapped[str] = mapped_column(Text, default="[]", nullable=False)
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    valid_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    raw: Mapped[str] = mapped_column(Text, default="{}", nullable=False)
