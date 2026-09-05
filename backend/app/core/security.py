"""Security primitives: password hashing, JWT tokens, rate limiting.

Implements OWASP-aligned practices:
- bcrypt password hashing (adaptive, salted)
- short-lived signed access JWTs + refresh tokens
- configurable rate limiting (LoginRateLimiter is a safe in-memory impl;
  production can swap for Redis)
"""
from __future__ import annotations

import secrets
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

import bcrypt
from cachetools import TTLCache
from jose import JWTError, jwt

from .config import settings

_BCRYPT_MAX = 72  # bcrypt operates on the first 72 bytes


def hash_password(password: str) -> str:
    pw = password.encode("utf-8")[:_BCRYPT_MAX]
    return bcrypt.hashpw(pw, bcrypt.gensalt(rounds=12)).decode("utf-8")


def verify_password(plain: str, hashed: str) -> bool:
    try:
        pw = plain.encode("utf-8")[:_BCRYPT_MAX]
        return bcrypt.checkpw(pw, hashed.encode("utf-8"))
    except (ValueError, TypeError):
        return False


def create_access_token(subject: str | int, claims: dict[str, Any] | None = None) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "sub": str(subject),
        "iat": now,
        "exp": now + timedelta(minutes=settings.access_token_expire_minutes),
        "type": "access",
    }
    if claims:
        payload.update(claims)
    return jwt.encode(payload, settings.secret_key, algorithm=settings.algorithm)


def create_refresh_token(subject: str | int) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "sub": str(subject),
        "iat": now,
        "exp": now + timedelta(minutes=settings.refresh_token_expire_minutes),
        "type": "refresh",
        "jti": secrets.token_urlsafe(16),
    }
    return jwt.encode(payload, settings.secret_key, algorithm=settings.algorithm)


def decode_token(token: str) -> Optional[dict[str, Any]]:
    try:
        return jwt.decode(token, settings.secret_key, algorithms=[settings.algorithm])
    except JWTError:
        return None


def generate_otp() -> str:
    return secrets.token_hex(4)


# ─── Rate limiting (in-memory; swap for Redis in production) ────────────
class StorageLimiter:
    """Fixed-window limiter with bounded memory."""

    def __init__(self, max_items: int = 100_000):
        self._store: TTLCache[str, tuple[float, int]] = TTLCache(maxsize=max_items, ttl=settings.login_rate_limit_window)

    def hit(self, key: str, limit: int, window: int) -> int:
        now = time.monotonic()
        entry = self._store.get(key)
        if entry is None or now - entry[0] >= window:
            self._store[key] = (now, 1)
            return 1
        count = entry[1] + 1
        self._store[key] = (entry[0], count)
        return count


login_limiter = StorageLimiter()
