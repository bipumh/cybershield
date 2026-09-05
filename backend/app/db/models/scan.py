"""Scan orchestration: scans, targets, results, schedules."""
from __future__ import annotations

from datetime import datetime

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Integer, JSON, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from ..base import Base
from .base_mixin import TenantMixin, TimestampMixin


class Scan(Base, TimestampMixin, TenantMixin):
    __tablename__ = "scans"

    id: Mapped[int] = mapped_column(primary_key=True)
    scan_key: Mapped[str] = mapped_column(String(40), nullable=False, unique=True, index=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    mode: Mapped[str] = mapped_column(String(32), nullable=False)  # web | network
    profile: Mapped[str] = mapped_column(String(32), default="safe", nullable=False)
    status: Mapped[str] = mapped_column(String(32), default="pending", nullable=False, index=True)
    requested_by: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"),
                                              nullable=True, index=True)
    authorized: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    scope_confirmed: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    safety_confirmed: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    rate_limit: Mapped[int] = mapped_column(Integer, default=20, nullable=False)
    timeout: Mapped[int] = mapped_column(Integer, default=15, nullable=False)
    concurrency: Mapped[int] = mapped_column(Integer, default=2, nullable=False)
    progress: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    total_steps: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    cancelled: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    options: Mapped[str] = mapped_column(Text, default="{}", nullable=False)
    summary: Mapped[str] = mapped_column(Text, default="{}", nullable=False)


class ScanTarget(Base, TimestampMixin, TenantMixin):
    __tablename__ = "scan_targets"

    id: Mapped[int] = mapped_column(primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"),
                                         index=True, nullable=False)
    kind: Mapped[str] = mapped_column(String(32), nullable=False)  # domain|url|ip|cidr|hostname|range|asset
    value: Mapped[str] = mapped_column(String(512), nullable=False)
    asset_id: Mapped[int | None] = mapped_column(ForeignKey("assets.id", ondelete="SET NULL"),
                                                 nullable=True)
    in_scope: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    status: Mapped[str] = mapped_column(String(32), default="pending", nullable=False)


class ScanResult(Base, TimestampMixin, TenantMixin):
    __tablename__ = "scan_results"

    id: Mapped[int] = mapped_column(primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"),
                                         index=True, nullable=False)
    asset_id: Mapped[int | None] = mapped_column(ForeignKey("assets.id", ondelete="SET NULL"),
                                                 nullable=True)
    target: Mapped[str] = mapped_column(String(512), nullable=False)
    checks_run: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    findings_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    duration_ms: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    raw: Mapped[str] = mapped_column(Text, default="{}", nullable=False)  # normalized + evidence


class ScanSchedule(Base, TimestampMixin, TenantMixin):
    __tablename__ = "scan_schedules"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    mode: Mapped[str] = mapped_column(String(32), nullable=False)
    frequency: Mapped[str] = mapped_column(String(32), nullable=False)  # onetime|daily|weekly|monthly|custom
    cron_expression: Mapped[str | None] = mapped_column(String(120), nullable=True)  # custom
    targets: Mapped[str] = mapped_column(JSON, default=list, nullable=False)
    profile: Mapped[str] = mapped_column(String(32), default="safe", nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    last_run_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    next_run_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_by: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
