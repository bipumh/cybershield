"""Exceptions (false positive / accepted risk / compensating control)."""
from __future__ import annotations

from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from ..base import Base
from .base_mixin import TenantMixin, TimestampMixin


class ExceptionItem(Base, TimestampMixin, TenantMixin):
    __tablename__ = "exceptions"

    id: Mapped[int] = mapped_column(primary_key=True)
    finding_id: Mapped[int] = mapped_column(ForeignKey("findings.id", ondelete="CASCADE"),
                                            index=True, nullable=False)
    kind: Mapped[str] = mapped_column(String(40), nullable=False)  # false_positive|accepted_risk|compensating_control
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    evidence: Mapped[str] = mapped_column(Text, default="", nullable=False)
    owner_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    approved_by: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    status: Mapped[str] = mapped_column(String(32), default="pending", nullable=False)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    is_auto_expired: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    compensating_control_desc: Mapped[str] = mapped_column(Text, default="", nullable=False)
