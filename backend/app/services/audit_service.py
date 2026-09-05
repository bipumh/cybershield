"""Tamper-evident audit logging with a hash chain.

Each record's hash is computed from the previous record hash + canonical
payload, making silent modification detectable. Access is permission-gated
('audit:read' or super admin).
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..db.models import AuditLog

_LAST_CHAIN_KEY: dict[int, str] = {}


def _chain_head(db: Session, tenant_id: int) -> str | None:
    cached = _LAST_CHAIN_KEY.get(tenant_id)
    if cached:
        return cached
    head = db.execute(
        select(AuditLog.record_hash)
        .where(AuditLog.tenant_id == tenant_id)
        .order_by(AuditLog.id.desc())
        .limit(1)
    ).scalar_one_or_none()
    if head:
        _LAST_CHAIN_KEY[tenant_id] = head
    return head


def record(
    db: Session, *, tenant_id: int, actor_id: int | None = None,
    actor_email: str | None = None, action: str, target_type: str | None = None,
    target_id: int | None = None, previous_state: dict[str, Any] | None = None,
    new_state: dict[str, Any] | None = None, result: str = "success",
    metadata: dict[str, Any] | None = None, source_ip: str | None = None,
    commit: bool = True,
) -> AuditLog:
    import json as _json

    # Naive UTC so the value round-trips identically across SQLite/Postgres
    # (timezone-aware datetimes lose tzinfo on SQLite read-back, breaking the hash).
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    prev_hash = _chain_head(db, tenant_id)

    safe_prev = _redact(previous_state or {})
    safe_new = _redact(new_state or {})

    payload = {
        "tenant_id": tenant_id,
        "actor_id": actor_id,
        "actor_email": actor_email,
        "action": action,
        "target_type": target_type,
        "target_id": target_id,
        "result": result,
        "previous_state": safe_prev,
        "new_state": safe_new,
        "occurred_at": now.isoformat(),
    }
    record_hash = AuditLog.compute_hash(prev_hash, payload)

    entry = AuditLog(
        tenant_id=tenant_id,
        actor_id=actor_id,
        actor_email=actor_email,
        action=action,
        target_type=target_type,
        target_id=target_id,
        result=result,
        previous_state=_json.dumps(safe_prev),
        new_state=_json.dumps(safe_new),
        metadata_json=_json.dumps(metadata or {}),
        source_ip=source_ip,
        prev_hash=prev_hash,
        record_hash=record_hash,
        occurred_at=now,
    )
    db.add(entry)
    _LAST_CHAIN_KEY[tenant_id] = record_hash
    if commit:
        db.commit()
    return entry


def _redact(state: dict[str, Any]) -> dict[str, Any]:
    """Never persist credentials / secrets into the audit trail."""
    secret_keys = {"password", "password_hash", "secret", "token", "api_key",
                   "access_token", "refresh_token", "authorization", "credentials"}
    return {
        k: ("[REDACTED]" if any(s in k.lower() for s in secret_keys) else v)
        for k, v in state.items()
    }
