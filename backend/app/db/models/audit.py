"""Tamper-resistant, access-controlled audit log."""
from __future__ import annotations

from datetime import datetime
from hashlib import sha256

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from ..base import Base
from .base_mixin import TenantMixin, TimestampMixin


class AuditLog(Base, TimestampMixin, TenantMixin):
    __tablename__ = "audit_logs"

    id: Mapped[int] = mapped_column(primary_key=True)
    actor_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"),
                                                 nullable=True, index=True)
    actor_email: Mapped[str | None] = mapped_column(String(255), nullable=True)
    action: Mapped[str] = mapped_column(String(120), nullable=False, index=True)
    target_type: Mapped[str | None] = mapped_column(String(80), nullable=True)
    target_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    source_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    result: Mapped[str] = mapped_column(String(32), default="success", nullable=False)
    previous_state: Mapped[str] = mapped_column(Text, default="{}", nullable=False)
    new_state: Mapped[str] = mapped_column(Text, default="{}", nullable=False)
    metadata_json: Mapped[str] = mapped_column(Text, default="{}", nullable=False)
    # Hash chain for tamper evidence: hash = sha256(prev_hash + canonical(record))
    prev_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    record_hash: Mapped[str] = mapped_column(String(64), nullable=True)
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    @staticmethod
    def compute_hash(prev_hash: str | None, payload: dict) -> str:
        import json
        canonical = json.dumps(payload, sort_keys=True, default=str)
        return sha256(f"{prev_hash or ''}{canonical}".encode()).hexdigest()
