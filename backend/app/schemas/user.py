"""User management schemas."""
from __future__ import annotations

from pydantic import BaseModel, EmailStr, Field

from .auth import UserOut


class UserCreate(BaseModel):
    full_name: str = Field(min_length=1, max_length=255)
    email: EmailStr
    password: str = Field(min_length=12)
    role_names: list[str] = Field(min_length=1)
    department: str | None = None


class UserUpdate(BaseModel):
    full_name: str | None = None
    department: str | None = None
    is_active: bool | None = None
    role_names: list[str] | None = None


class UserPaginated(BaseModel):
    items: list[UserOut]
    total: int
