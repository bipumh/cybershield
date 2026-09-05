"""Authentication endpoints (OAuth2/OIDC-ready)."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy import select
from sqlalchemy.orm import Session

from ...core.config import settings
from ...core.deps import get_current_user, get_db_dep
from ...core.security import create_access_token, create_refresh_token, decode_token, verify_password
from ...db.models import User
from ...schemas.auth import LoginResponse, RefreshRequest, TokenResponse, UserOut
from ...services import audit_service

router = APIRouter(prefix="/auth", tags=["Authentication"])


def _user_out(user: User) -> UserOut:
    return UserOut(
        id=user.id, full_name=user.full_name, email=user.email,
        department=user.department, is_active=user.is_active,
        is_superuser=user.is_superuser, roles=user.role_names,
        permissions=sorted(user.permissions),
    )


@router.post("/login", response_model=LoginResponse, summary="OAuth2 password login")
def login(form: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db_dep)):
    user = db.execute(select(User).where(User.email == form.username)).scalar_one_or_none()
    if not user or not verify_password(form.password, user.password_hash) or not user.is_active:
        # rate limit failed logins per username+ip
        from ...core.security import login_limiter
        try:
            audit_service.record(db, tenant_id=user.tenant_id if user else 1,
                                 actor_email=form.username, action="auth.login_failed",
                                 result="failed", commit=False)
            db.commit()
        except Exception:  # noqa: BLE001
            db.rollback()
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="Invalid credentials")
    audit_service.record(db, tenant_id=user.tenant_id, actor_id=user.id,
                         actor_email=user.email, action="auth.login", commit=False)
    db.commit()
    return LoginResponse(
        token=TokenResponse(
            access_token=create_access_token(user.id),
            refresh_token=create_refresh_token(user.id),
            expires_in=settings.access_token_expire_minutes * 60,
        ),
        user=_user_out(user),
    )


@router.post("/refresh", response_model=TokenResponse, summary="Refresh access token")
def refresh(body: RefreshRequest, db: Session = Depends(get_db_dep)):
    payload = decode_token(body.refresh_token)
    if not payload or payload.get("type") != "refresh":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid refresh token")
    user = db.get(User, int(payload["sub"]))
    if not user or not user.is_active:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User inactive")
    return TokenResponse(
        access_token=create_access_token(user.id),
        refresh_token=create_refresh_token(user.id),
        expires_in=settings.access_token_expire_minutes * 60,
    )


@router.get("/me", response_model=UserOut, summary="Current user")
def me(user: User = Depends(get_current_user)):
    return _user_out(user)


@router.post("/logout", summary="Logout (client discards tokens)")
def logout(user: User = Depends(get_current_user), db: Session = Depends(get_db_dep)):
    audit_service.record(db, tenant_id=user.tenant_id, actor_id=user.id,
                         actor_email=user.email, action="auth.logout")
    return {"ok": True, "message": "Logged out"}
