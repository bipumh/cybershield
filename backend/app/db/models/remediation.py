"""Remediation engine: plans, approvals, execution/verification steps."""
from __future__ import annotations

from datetime import datetime

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from ..base import Base
from .base_mixin import TenantMixin, TimestampMixin


class ApprovalStep(Base, TimestampMixin):
    __tablename__ = "approval_steps"

    id: Mapped[int] = mapped_column(primary_key=True)
    remediation_id: Mapped[int] = mapped_column(ForeignKey("remediations.id", ondelete="CASCADE"),
                                                index=True, nullable=False)
    step: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    level: Mapped[str] = mapped_column(String(40), nullable=False)  # RemediationLevel
    action: Mapped[str] = mapped_column(String(500), nullable=False)
    status: Mapped[str] = mapped_column(String(32), default="pending", nullable=False)  # pending|approved|rejected|executed|rolled_back|failed
    executed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    result_json: Mapped[str] = mapped_column(Text, default="{}", nullable=False)


class Remediation(Base, TimestampMixin, TenantMixin):
    __tablename__ = "remediations"

    id: Mapped[int] = mapped_column(primary_key=True)
    finding_id: Mapped[int] = mapped_column(ForeignKey("findings.id", ondelete="CASCADE"),
                                            index=True, nullable=False)
    asset_id: Mapped[int | None] = mapped_column(ForeignKey("assets.id", ondelete="SET NULL"), nullable=True)
    level: Mapped[str] = mapped_column(String(40), nullable=False)  # RemediationLevel
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    immediate_action: Mapped[str] = mapped_column(Text, default="", nullable=False)
    permanent_solution: Mapped[str] = mapped_column(Text, default="", nullable=False)
    recommended_config: Mapped[str] = mapped_column(Text, default="", nullable=False)
    patch_recommendation: Mapped[str] = mapped_column(Text, default="", nullable=False)
    verification_procedure: Mapped[str] = mapped_column(Text, default="", nullable=False)
    rollback_procedure: Mapped[str] = mapped_column(Text, default="", nullable=False)
    business_impact: Mapped[str] = mapped_column(Text, default="", nullable=False)
    complexity: Mapped[str] = mapped_column(String(32), default="medium", nullable=False)
    risk_reduction: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    status: Mapped[str] = mapped_column(String(40), default="proposed", nullable=False, index=True)
    requester_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    approver_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    approved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    backup_status: Mapped[str] = mapped_column(String(64), default="not_required", nullable=False)
    execution_status: Mapped[str] = mapped_column(String(32), default="pending", nullable=False)
    verification_result: Mapped[str] = mapped_column(Text, default="", nullable=False)
    auto_remediated: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    audit_log_json: Mapped[str] = mapped_column(Text, default="[]", nullable=False)
    due_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class RemediationApproval(Base, TimestampMixin, TenantMixin):
    __tablename__ = "remediation_approvals"

    id: Mapped[int] = mapped_column(primary_key=True)
    remediation_id: Mapped[int] = mapped_column(ForeignKey("remediations.id", ondelete="CASCADE"),
                                                index=True, nullable=False)
    decision: Mapped[str] = mapped_column(String(32), nullable=False)  # approve|reject|risky
    comment: Mapped[str] = mapped_column(Text, default="", nullable=False)
    decided_by: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    decided_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
