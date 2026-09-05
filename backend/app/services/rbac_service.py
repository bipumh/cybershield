"""RBAC services: role seeding, permission resolution, tenant isolation."""
from __future__ import annotations

import json

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..core.constants import Role
from ..core.exceptions import ConflictError, NotFoundError
from ..db.models import Organization, RoleModel, User
from ..core.security import hash_password


def seed_roles(db: Session) -> dict[str, RoleModel]:
    """Idempotently create the built-in role catalog."""
    roles: dict[str, RoleModel] = {}
    for name in Role.ALL:
        existing = db.execute(select(RoleModel).where(RoleModel.name == name)).scalar_one_or_none()
        if not existing:
            existing = RoleModel(
                name=name,
                description=f"Built-in role: {name.replace('_', ' ').title()}",
                permissions=json.dumps(Role.PERMISSIONS.get(name, [])),
            )
            db.add(existing)
            db.flush()
        roles[name] = existing
    db.commit()
    return roles


def seed_default_tenant(db: Session, name: str) -> Organization:
    from ..core.config import settings
    slug = "org-default"
    tenant = db.execute(select(Organization).where(Organization.slug == slug)).scalar_one_or_none()
    if not tenant:
        tenant = Organization(name=name, slug=slug, description="Default organization (bootstrap)")
        db.add(tenant)
        db.flush()
    else:
        tenant.name = name
        db.flush()
    db.commit()
    return tenant


def get_or_create_user(db: Session, *, tenant: Organization, email: str,
                       password: str, full_name: str, role_name: str,
                       is_superuser: bool = False) -> User:
    user = db.execute(select(User).where(User.email == email)).scalar_one_or_none()
    if user:
        return user
    user = User(
        tenant_id=tenant.id,
        full_name=full_name,
        email=email,
        password_hash=hash_password(password),
        is_active=True,
        is_superuser=is_superuser,
    )
    db.add(user)
    db.flush()
    role_model = db.execute(select(RoleModel).where(RoleModel.name == role_name)).scalar_one_or_none()
    if role_model:
        user.roles.append(role_model)
    db.commit()
    return user


def create_user(db: Session, *, tenant_id: int, full_name: str, email: str,
                password: str, role_names: list[str], department: str | None = None) -> User:
    from ..core.config import settings
    if len(password) < settings.password_min_length:
        from ..core.exceptions import ValidationError
        raise ValidationError(f"Password must be at least {settings.password_min_length} characters")
    existing = db.execute(select(User).where(User.email == email)).scalar_one_or_none()
    if existing:
        raise ConflictError("A user with this email already exists")
    user = User(
        tenant_id=tenant_id,
        full_name=full_name,
        email=email,
        password_hash=hash_password(password),
        is_active=True,
        department=department,
    )
    db.add(user)
    db.flush()
    for role_name in role_names:
        role = db.execute(select(RoleModel).where(RoleModel.name == role_name)).scalar_one_or_none()
        if role:
            user.roles.append(role)
    db.commit()
    db.refresh(user)
    return user


def user_has_permission(user: User, permission: str) -> bool:
    perms = user.permissions
    return "*" in perms or permission in perms


def list_roles(db: Session) -> list[RoleModel]:
    return list(db.execute(select(RoleModel).order_by(RoleModel.name)).scalars().all())
