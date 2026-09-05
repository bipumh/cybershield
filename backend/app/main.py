"""CyberShield application entrypoint (FastAPI).

Secure-by-default: security headers middleware, CORS allow-list, request id,
client IP capture, centralized error handling, and startup bootstrap.
"""
from __future__ import annotations

import uuid
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware

from . import __version__
from .api.v1.router import api_router
from .core.config import settings
from .core.exceptions import register_exception_handlers
from .core.logging import configure_logging
from .db.session import SessionLocal


def _security_headers(response, request: Request):
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
    response.headers.setdefault("Cross-Origin-Opener-Policy", "same-origin")
    if settings.is_production:
        response.headers.setdefault(
            "Strict-Transport-Security", "max-age=31536000; includeSubDomains")
    response.headers.setdefault("X-XSS-Protection", "0")
    return response


@asynccontextmanager
async def lifespan(app: FastAPI):
    configure_logging()
    # Bootstrap only in dev/dev server; production relies on migrations + seed.
    db = SessionLocal()
    try:
        from .services.bootstrap import bootstrap
        bootstrap(db)
    except Exception:  # noqa: BLE001
        # Do not crash the app if DB not yet reachable; surface via logs
        import logging
        logging.getLogger("startup").exception("Bootstrap failed")
    finally:
        db.close()
    yield


app = FastAPI(
    title="CyberShield Vulnerability Assessment & Exposure Management",
    version=__version__,
    description="Defensive vulnerability & exposure management platform. "
                "Only scan assets you own or are authorized to assess.",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
)


# ─── CORS allow-list ─────────────────────────────────────────────────────
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ─── Middleware: request id, client IP, security headers ─────────────────
@app.middleware("http")
async def request_context(request: Request, call_next):
    request.state.request_id = request.headers.get("X-Request-ID") or uuid.uuid4().hex[:12]
    request.state.client_ip = _client_ip(request)
    response = await call_next(request)
    response.headers.setdefault("X-Request-ID", request.state.request_id)
    return _security_headers(response, request)


def _client_ip(request: Request) -> str | None:
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else None


# ─── Error handling ──────────────────────────────────────────────────────
register_exception_handlers(app)

# ─── Routes ──────────────────────────────────────────────────────────────
app.include_router(api_router, prefix=settings.api_v1_prefix)


@app.get("/", tags=["Root"], include_in_schema=False)
async def root() -> dict[str, Any]:
    return {"name": settings.app_name, "version": __version__,
            "docs": "/docs", "api": settings.api_v1_prefix}


@app.get("/health", tags=["Health"], summary="Liveness")
async def health() -> dict[str, Any]:
    return {"status": "ok", "version": __version__}
