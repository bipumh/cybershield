"""Application configuration via pydantic-settings (12-factor).

All settings are read from environment variables (optionally a .env file).
The database URL is fully swappable: SQLite for local dev, PostgreSQL in
production, with NO code changes required.
"""
from __future__ import annotations

from functools import lru_cache
from typing import Annotated, List

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # ─── Core ───────────────────────────────────────────────────────────
    environment: str = "development"
    app_name: str = "CyberShield"
    app_version: str = "0.1.0"
    secret_key: str = "dev-insecure-secret-change-me"
    # NoDecode prevents pydantic-settings from JSON-parsing the comma-separated
    # env value; the validator below splits it into a list (see cors_origins_list).
    cors_origins: Annotated[List[str], NoDecode] = Field(default_factory=lambda: ["http://localhost:5173"])
    timezone: str = "UTC"
    api_v1_prefix: str = "/api/v1"

    # ─── Database ───────────────────────────────────────────────────────
    # sqlite:///./cybershield.db  OR  postgresql+psycopg://user:pass@host:5432/db
    database_url: str = "sqlite:///./cybershield.db"

    # ─── Auth / JWT ─────────────────────────────────────────────────────
    algorithm: str = "HS256"
    access_token_expire_minutes: int = 60
    refresh_token_expire_minutes: int = 1440
    mfa_enabled: bool = False
    password_min_length: int = 12
    password_max_age_days: int = 90
    login_rate_limit: int = 10
    login_rate_limit_window: int = 60

    # ─── Scanning safety (DEFAULTS; HARD limits enforced in code) ───────
    scan_global_rate_limit: int = 20
    scan_default_timeout: int = 15
    scan_max_concurrency: int = 10
    scan_max_active_scans: int = 5
    scan_allow_insecure: bool = False

    # ─── Scheduling ─────────────────────────────────────────────────────
    scheduler_enabled: bool = True

    # ─── AI Security Analyst (provider-independent) ─────────────────────
    ai_provider: str = "off"  # off | mocked | openai | anthropic | openai_compatible
    ai_model: str = ""
    ai_api_key: str = ""
    ai_base_url: str = ""
    ai_temperature: float = 0.2
    ai_max_tokens: int = 1200

    # ─── SIEM / webhook integration (optional) ──────────────────────────
    siem_webhook_url: str = ""
    siem_webhook_token: str = ""

    # ─── Admin bootstrap (first startup only) ───────────────────────────
    admin_email: str = "admin@cybershieldplatform.com"
    admin_password: str = "ChangeThis!Now12345"

    # ─── Tenant ─────────────────────────────────────────────────────────
    default_tenant_name: str = "Default Organization"

    @field_validator("cors_origins", mode="before")
    @classmethod
    def _split_origins(cls, v):
        # env provides a comma-separated string; also accept a JSON list.
        if isinstance(v, str):
            s = v.strip()
            if s.startswith("["):
                import json
                try:
                    return [o.strip() for o in json.loads(s)]
                except ValueError:
                    pass
            return [o.strip() for o in s.split(",") if o.strip()]
        return v

    @property
    def cors_origins_list(self) -> List[str]:
        """Return the parsed list (alias kept for convenience)."""
        return self.cors_origins

    @property
    def is_production(self) -> bool:
        return self.environment.lower() in {"production", "prod"}

    @property
    def database_is_sqlite(self) -> bool:
        return self.database_url.startswith("sqlite")


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
