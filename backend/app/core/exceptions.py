"""Centralized exception hierarchy + FastAPI error handlers.

Ensures a consistent, human-readable error envelope across the API and that
scanner/worker failures never crash the platform.
"""
from __future__ import annotations

from typing import Any

from fastapi import FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from .logging import get_logger

logger = get_logger("core.exceptions")


class AppError(Exception):
    """Base application error carried to the API layer."""

    status_code: int = status.HTTP_400_BAD_REQUEST
    code: str = "bad_request"
    detail: str = "Bad request"

    def __init__(self, detail: str | None = None,
                 code: str | None = None,
                 status_code: int | None = None,
                 context: dict[str, Any] | None = None):
        self.detail = detail or self.detail
        self.code = code or self.code
        if status_code:
            self.status_code = status_code
        self.context = context or {}

    def envelope(self) -> dict[str, Any]:
        return {
            "ok": False,
            "error": {
                "code": self.code,
                "message": self.detail,
                "context": self.context,
            },
        }


class NotFoundError(AppError):
    status_code = status.HTTP_404_NOT_FOUND
    code = "not_found"
    detail = "Resource not found"


class UnauthorizedError(AppError):
    status_code = status.HTTP_401_UNAUTHORIZED
    code = "unauthorized"
    detail = "Authentication required"


class ForbiddenError(AppError):
    status_code = status.HTTP_403_FORBIDDEN
    code = "forbidden"
    detail = "You do not have permission to perform this action"


class ConflictError(AppError):
    status_code = status.HTTP_409_CONFLICT
    code = "conflict"
    detail = "Resource conflict"


class ValidationError(AppError):
    status_code = status.HTTP_422_UNPROCESSABLE_CONTENT
    code = "validation_error"
    detail = "Validation failed"


class ScopeViolationError(ForbiddenError):
    code = "scope_violation"
    detail = "Target is outside the authorized scan scope"


class ScanSafetyError(AppError):
    status_code = status.HTTP_400_BAD_REQUEST
    code = "scan_safety"
    detail = "Scan rejected by safety controls"


class ScannerError(AppError):
    status_code = status.HTTP_502_BAD_GATEWAY
    code = "scanner_error"
    detail = "Scanner failed to process target"


class IntegrityError(AppError):
    status_code = status.HTTP_409_CONFLICT
    code = "integrity_error"
    detail = "Operation would violate data integrity"



def register_exception_handlers(app: FastAPI) -> None:
    @app.exception_handler(AppError)
    async def app_error_handler(request: Request, exc: AppError):
        return JSONResponse(
            status_code=exc.status_code,
            content=exc.envelope(),
        )

    @app.exception_handler(RequestValidationError)
    async def validation_handler(request: Request, exc: RequestValidationError):
        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            content={
                "ok": False,
                "error": {
                    "code": "validation_error",
                    "message": "Request validation failed",
                    "context": {"errors": exc.errors()},
                },
            },
        )

    @app.exception_handler(StarletteHTTPException)
    async def http_exception_handler(request: Request, exc: StarletteHTTPException):
        return JSONResponse(
            status_code=exc.status_code,
            content={
                "ok": False,
                "error": {
                    "code": "http_error",
                    "message": str(exc.detail),
                },
            },
        )

    @app.exception_handler(Exception)
    async def unhandled_handler(request: Request, exc: Exception):
        logger.exception("Unhandled exception during request: %s", exc)
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={
                "ok": False,
                "error": {
                    "code": "internal_error",
                    "message": "An unexpected error occurred. Please try again.",
                },
            },
        )
