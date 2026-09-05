"""User & role management (Super Admin only for writes; RBAC read for permitted)."""
from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.orm import Session

from ...core.constants import Role
from ...core.deps import get_current_user, get_db_dep, require_permission, require_roles, write_audit
from ...core.exceptions import NotFoundError
from ...db.models import User
from ...schemas.auth import UserOut
from ...schemas.user import UserCreate, UserUpdate
from ...services import rbac_service

router = APIRouter(prefix="/users", tags=["Users"])


@router.get("", response_model=list[UserOut], summary="List users")
def list_users(db: Session = Depends(get_db_dep), user: User = Depends(get_current_user)):
    rows = db.execute(select(User).where(User.tenant_id == user.tenant_id)).scalars().all()
    return [_to_out(u) for u in rows]


@router.post("", response_model=UserOut, status_code=201, summary="Create user")
def create_user(body: UserCreate, db: Session = Depends(get_db_dep),
                admin: User = Depends(require_roles(Role.SUPER_ADMIN))):
    u = rbac_service.create_user(db, tenant_id=admin.tenant_id, full_name=body.full_name,
                                 email=body.email, password=body.password,
                                 role_names=body.role_names, department=body.department)
    write_audit(db, actor=admin, action="user.create", target_type="user",
                target_id=u.id, new_state={"email": u.email, "roles": u.role_names})
    return _to_out(u)


@router.patch("/{user_id}", response_model=UserOut, summary="Update user")
def update_user(user_id: int, body: UserUpdate, db: Session = Depends(get_db_dep),
                admin: User = Depends(require_roles(Role.SUPER_ADMIN))):
    u = db.get(User, user_id)
    if not u or u.tenant_id != admin.tenant_id:
        raise NotFoundError("User not found")
    old = {"full_name": u.full_name, "is_active": u.is_active}
    if body.full_name is not None:
        u.full_name = body.full_name
    if body.department is not None:
        u.department = body.department
    if body.is_active is not None:
        u.is_active = body.is_active
    if body.role_names is not None:
        u.roles = []
        for rn in body.role_names:
            r = db.execute(select(rbac_service.RoleModel).where(
                rbac_service.RoleModel.name == rn)).scalar_one_or_none()
            if r:
                u.roles.append(r)
    db.commit()
    write_audit(db, actor=admin, action="user.update", target_type="user",
                target_id=u.id, previous_state=old,
                new_state={"full_name": u.full_name, "is_active": u.is_active,
                           "roles": u.role_names})
    return _to_out(u)


@router.get("/roles", summary="List roles / permissions catalog")
def list_roles(db: Session = Depends(get_db_dep), user: User = Depends(get_current_user)):
    roles = rbac_service.list_roles(db)
    return [{"id": r.id, "name": r.name, "description": r.description,
             "permissions": __import__("json").loads(r.permissions)} for r in roles]


def _to_out(u: User) -> UserOut:
    return UserOut(id=u.id, full_name=u.full_name, email=u.email, department=u.department,
                   is_active=u.is_active, is_superuser=u.is_superuser,
                   roles=u.role_names, permissions=sorted(u.permissions))
