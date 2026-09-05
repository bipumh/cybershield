"""Authentication schemas."""
from __future__ import annotations

from pydantic import BaseModel, EmailStr, Field


class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=1)
    otp: str | None = None


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int


class RefreshRequest(BaseModel):
    refresh_token: str


class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str = Field(min_length=12)


class UserOut(BaseModel):
    id: int
    full_name: str
    email: EmailStr
    department: str | None = None
    is_active: bool
    is_superuser: bool
    roles: list[str] = []
    permissions: list[str] = []

    model_config = {"from_attributes": True}


class LoginResponse(BaseModel):
    token: TokenResponse
    user: UserOut
