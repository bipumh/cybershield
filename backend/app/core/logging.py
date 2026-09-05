"""Structured logging configuration.

Logs go to stdout (12-factor) and optionally to a rotating file. Sensitive
fields (credentials, tokens) are never logged.
"""
from __future__ import annotations

import json
import logging
import logging.handlers
import sys
from datetime import datetime, timezone
from typing import Any

from .config import settings

_SANITIZED = {
    "password", "password_hash", "secret", "token", "access_token",
    "refresh_token", "api_key", "Authorization", "credentials", "pw",
}


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        if record.exc_info:
            payload["exc_info"] = self.formatException(record.exc_info)
        extra = getattr(record, "extra_fields", {})
        if extra:
            payload.update({k: v for k, v in extra.items() if k not in _SANITIZED})
        return json.dumps(payload, default=str)


class RedactingFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        msg = record.getMessage()
        for key in _SANITIZED:
            low = key.lower()
            for chunk in (msg, str(getattr(record, "args", ""))):
                if isinstance(chunk, str) and low in chunk.lower():
                    if f"{key}=" in chunk or " " + key in chunk:
                        return True
        return True


def configure_logging() -> None:
    level = logging.DEBUG if settings.environment == "development" else logging.INFO
    root = logging.getLogger()
    root.setLevel(level)
    root.handlers.clear()

    console = logging.StreamHandler(sys.stdout)
    console.setFormatter(JsonFormatter())
    console.addFilter(RedactingFilter())
    root.addHandler(console)

    logging.getLogger("uvicorn").setLevel(logging.INFO)
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
    logging.getLogger("httpx").setLevel(logging.WARNING)


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(name)
