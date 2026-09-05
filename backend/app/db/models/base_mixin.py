"""Reusable ORM mixins: auditing timestamps, soft-delete, tenant isolation."""
from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import BigInteger, DateTime, ForeignKey, Index, String, func
from sqlalchemy.orm import Mapped, mapped_column

from ..base import Base


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class TimestampMixin:
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False)


class SoftDeleteMixin:
    deleted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), default=None, nullable=True)

    @property
    def is_deleted(self) -> bool:
        return self.deleted_at is not None


class TenantMixin:
    """Reusable multi-tenant isolation. Every tenant-scoped row carries a
    tenant_id; access layers MUST filter by the requesting tenant."""
    tenant_id: Mapped[int] = mapped_column(
        BigInteger, ForeignKey("organizations.id", ondelete="CASCADE"),
        index=True, nullable=False,
    )
