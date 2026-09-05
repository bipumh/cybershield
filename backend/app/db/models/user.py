"""User + role models with RBAC permission holder."""
from __future__ import annotations

from sqlalchemy import Boolean, Column, ForeignKey, String, Table, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from ..base import Base
from .base_mixin import TimestampMixin


# Many-to-many user <-> role
user_roles = Table(
    "user_roles",
    Base.metadata,
    Column("user_id", ForeignKey("users.id", ondelete="CASCADE"), primary_key=True),
    Column("role_id", ForeignKey("roles.id", ondelete="CASCADE"), primary_key=True),
)


class Role(Base, TimestampMixin):
    __tablename__ = "roles"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(80), nullable=False, unique=True)
    description: Mapped[str | None] = mapped_column(String(500), nullable=True)
    # Permission identifiers, e.g. "scans:create". "*" = super permission.
    permissions: Mapped[str] = mapped_column(Text, nullable=False, default="[]")

    users: Mapped[list["User"]] = relationship(secondary=user_roles, back_populates="roles")


class User(Base, TimestampMixin):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True)
    tenant_id: Mapped[int] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"),
                                           index=True, nullable=False)
    full_name: Mapped[str] = mapped_column(String(255), nullable=False)
    email: Mapped[str] = mapped_column(String(255), nullable=False, unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    is_superuser: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    otp_secret: Mapped[str | None] = mapped_column(String(64), nullable=True)  # MFA-ready
    department: Mapped[str | None] = mapped_column(String(120), nullable=True)

    roles: Mapped[list[Role]] = relationship(secondary=user_roles, back_populates="users",
                                             lazy="selectin")

    @property
    def role_names(self) -> list[str]:
        return [r.name for r in self.roles]

    @property
    def permissions(self) -> set[str]:
        import json
        perms: set[str] = set()
        for role in self.roles:
            try:
                perms.update(json.loads(role.permissions))
            except (ValueError, TypeError):
                # legacy single-value format
                perms.add(role.permissions.strip())
        return perms
