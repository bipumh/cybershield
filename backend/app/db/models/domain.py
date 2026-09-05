"""Domain + subdomain discovery model."""
from __future__ import annotations

from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from ..base import Base
from .base_mixin import TimestampMixin


class Domain(Base, TimestampMixin):
    __tablename__ = "domains"

    id: Mapped[int] = mapped_column(primary_key=True)
    tenant_id: Mapped[int] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"),
                                           index=True, nullable=False)
    name: Mapped[str] = mapped_column(String(255), nullable=False, unique=True, index=True)
    is_authorized: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    registrar: Mapped[str | None] = mapped_column(String(255), nullable=True)
    notes: Mapped[str | None] = mapped_column(String(1000), nullable=True)
    last_checked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class Subdomain(Base, TimestampMixin):
    __tablename__ = "subdomains"

    id: Mapped[int] = mapped_column(primary_key=True)
    tenant_id: Mapped[int] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"),
                                           index=True, nullable=False)
    domain_id: Mapped[int] = mapped_column(ForeignKey("domains.id", ondelete="CASCADE"),
                                           index=True, nullable=False)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    is_confirmed: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    is_responsive: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    is_in_scope: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    resolved_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    status: Mapped[str] = mapped_column(String(32), default="discovered", nullable=False,
                                        index=True)  # discovered|confirmed|responsive|unresponsive
