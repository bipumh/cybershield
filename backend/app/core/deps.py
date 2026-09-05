"""FastAPI dependencies: DB session, current user, RBAC, tenant scoping."""
from __future__ import annotations

from typing import Generator, Optional

from fastapi import Depends, Query, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session

from ..db.models import User
from ..db.session import get_db
from ..services import audit_service
from .config import settings
from .exceptions import ForbiddenError, UnauthorizedError
from .security import decode_token

oauth2_scheme = OAuth2PasswordBearer(tokenUrl=f"{settings.api_v1_prefix}/auth/login")


def get_db_dep() -> Generator[Session, None, None]:
    yield from get_db()


def get_current_user(
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db_dep),
) -> User:
    payload = decode_token(token)
    if not payload or payload.get("type") != "access":
        raise UnauthorizedError("Invalid or expired access token")
    user_id = payload.get("sub")
    user = db.get(User, int(user_id)) if user_id else None
    if not user or not user.is_active:
        raise UnauthorizedError("User is inactive or does not exist")
    return user


def get_current_tenant_id(user: User = Depends(get_current_user)) -> int:
    return user.tenant_id


class PermissionChecker:
    def __init__(self, permission: str):
        self.permission = permission

    def __call__(self, user: User = Depends(get_current_user)) -> User:
        perms = user.permissions
        if "*" in perms or self.permission in perms:
            return user
        raise ForbiddenError(f"Missing permission: {self.permission}")


def require_permission(permission: str):
    return PermissionChecker(permission)


def require_roles(*roles: str):
    """Roles used for coarse-grained access (RBAC names)."""
    def dep(user: User = Depends(get_current_user)) -> User:
        if user.is_superuser:
            return user
        if set(roles) & set(user.role_names):
            return user
        raise ForbiddenError("Insufficient role for this action")
    return dep


def pagination(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=200),
) -> dict:
    return {"page": page, "page_size": page_size}


def write_audit(
    db: Session, *, actor: User, action: str, target_type: str | None = None,
    target_id: int | None = None, previous_state: dict | None = None,
    new_state: dict | None = None, result: str = "success", request=None,
) -> None:
    source_ip = getattr(request.state, "client_ip", None) if request else None
    audit_service.record(
        db,
        tenant_id=actor.tenant_id,
        actor_id=actor.id,
        actor_email=actor.email,
        action=action,
        target_type=target_type,
        target_id=target_id,
        previous_state=previous_state or {},
        new_state=new_state or {},
        result=result,
        source_ip=source_ip,
    )
