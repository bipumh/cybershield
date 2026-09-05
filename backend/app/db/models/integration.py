"""Integrations: SIEM/webhook/API connectors (integration-ready)."""
from __future__ import annotations

from sqlalchemy import Boolean, ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from ..base import Base
from .base_mixin import TenantMixin, TimestampMixin


class Integration(Base, TimestampMixin, TenantMixin):
    __tablename__ = "integrations"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    kind: Mapped[str] = mapped_column(String(64), nullable=False)  # wazuh|splunk|sentinel|elastic|syslog|webhook|api
    enabled: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    endpoint: Mapped[str | None] = mapped_column(String(512), nullable=True)
    auth_ref: Mapped[str | None] = mapped_column(String(255), nullable=True)  # reference to vault, never plaintext
    config_json: Mapped[str] = mapped_column(Text, default="{}", nullable=False)
    events_json: Mapped[str] = mapped_column(Text, default="[]", nullable=False)  # forwarded event types
    last_status: Mapped[str | None] = mapped_column(String(64), nullable=True)
