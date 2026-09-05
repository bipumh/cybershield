"""Aggregate API v1 router (mounted under settings.api_v1_prefix)."""
from __future__ import annotations

from fastapi import APIRouter

from . import (auth, users, assets, scans, findings, remediations, reports,
               dashboard, scheduler, audit, admin, ai, compliance)

api_router = APIRouter()
api_router.include_router(auth.router)
api_router.include_router(users.router)
api_router.include_router(assets.router)
api_router.include_router(scans.router)
api_router.include_router(findings.router)
api_router.include_router(remediations.router)
api_router.include_router(reports.router)
api_router.include_router(dashboard.router)
api_router.include_router(scheduler.router)
api_router.include_router(audit.router)
api_router.include_router(admin.router)
api_router.include_router(ai.router)
api_router.include_router(compliance.router)
