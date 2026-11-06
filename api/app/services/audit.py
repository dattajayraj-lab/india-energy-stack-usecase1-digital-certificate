"""Audit trail. Identifiers only, never names, addresses or mobile numbers."""

from __future__ import annotations

from fastapi import Request
from sqlalchemy.ext.asyncio import AsyncSession

from ..models import AuditLog
from ..security import mask_ip


def record(
    session: AsyncSession,
    actor: str,
    action: str,
    entity: str,
    entity_id: str | int,
    request: Request | None = None,
) -> None:
    ip = request.client.host if request is not None and request.client else None
    session.add(AuditLog(actor=actor, action=action, entity=entity, entity_id=str(entity_id), ip=mask_ip(ip)))
