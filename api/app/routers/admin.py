"""DISCOM staff console."""

from __future__ import annotations

from dataclasses import asdict
from datetime import date, datetime, time, timedelta
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import Select, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..api_models import (
    AuditOut,
    ConsumerSummary,
    DashboardOut,
    DayCount,
    FieldMappingOut,
    Page,
    PassportOut,
    PreviewOut,
    VerificationOut,
)
from ..db import read_session
from ..models import (
    AuditLog,
    Connection,
    ConsumerRef,
    FieldMappingRow,
    Passport,
    RevocationEvent,
    VerificationLog,
    utcnow,
)
from ..security import Principal, require_roles
from ..services.adapter import get_source, map_consumer
from .passports import _with_owner, passport_out

router = APIRouter(prefix="/admin", tags=["admin"])

_any_staff = require_roles("admin", "operator", "auditor")
_oversight = require_roles("admin", "auditor")


async def _latest_passports(session: AsyncSession, consumer_nos: list[str]) -> dict[str, Passport]:
    rows = await session.scalars(
        select(Passport)
        .join(Connection, Connection.id == Passport.connection_id)
        .join(ConsumerRef, ConsumerRef.id == Connection.consumer_ref_id)
        .where(ConsumerRef.consumer_no.in_(consumer_nos))
        .options(_with_owner())
        .order_by(Passport.id)
    )
    return {p.connection.consumer.consumer_no: p for p in rows}


@router.get("/consumers", response_model=list[ConsumerSummary])
async def search_consumers(
    q: str = Query("", max_length=64),
    _: Principal = Depends(_any_staff),
    session: AsyncSession = Depends(read_session),
) -> list[ConsumerSummary]:
    hits = get_source().search(q)
    latest = await _latest_passports(session, [h["CA_NUMBER"] for h in hits])
    results = []
    for hit in hits:
        passport = latest.get(hit["CA_NUMBER"])
        results.append(
            ConsumerSummary(
                consumer_no=hit["CA_NUMBER"],
                name=hit["CUST_NAME"],
                service_conn_no=hit["SERVICE_CONN_NO"],
                tariff_category=hit["TARIFF_CAT"],
                city=hit["CITY"],
                passport_status=passport.status if passport else None,
                passport_id=passport.id if passport else None,
            )
        )
    return results


@router.get("/consumers/{consumer_no}/preview", response_model=PreviewOut)
async def preview(
    consumer_no: str,
    _: Principal = Depends(_any_staff),
    session: AsyncSession = Depends(read_session),
) -> PreviewOut:
    mapped = await map_consumer(session, consumer_no)
    if mapped is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "No such consumer in the source systems.")
    latest = (await _latest_passports(session, [consumer_no])).get(consumer_no)
    active = passport_out(latest) if latest and latest.status == "active" else None
    return PreviewOut(
        consumer_no=consumer_no,
        issuable=mapped.issuable,
        flags=[asdict(f) for f in mapped.flags],
        subject=mapped.subject,
        active_passport=active,
    )


@router.get("/passports", response_model=Page[PassportOut])
async def list_passports(
    status_filter: str | None = Query(None, alias="status", pattern="^(active|revoked)$"),
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    _: Principal = Depends(_any_staff),
    session: AsyncSession = Depends(read_session),
) -> dict[str, Any]:
    query = select(Passport).options(_with_owner()).order_by(Passport.id.desc())
    if status_filter:
        query = query.where(Passport.status == status_filter)
    total, rows = await _paginate(session, query, page, page_size)
    return {"items": [passport_out(p) for p in rows], "total": total, "page": page, "page_size": page_size}


async def _paginate(session: AsyncSession, query: Select, page: int, page_size: int) -> tuple[int, list[Any]]:
    total = await session.scalar(select(func.count()).select_from(query.order_by(None).subquery()))
    rows = await session.scalars(query.limit(page_size).offset((page - 1) * page_size))
    return total or 0, list(rows)


def _range(column: Any, date_from: date | None, date_to: date | None) -> list[Any]:
    filters = []
    if date_from:
        filters.append(column >= datetime.combine(date_from, time.min))
    if date_to:
        filters.append(column <= datetime.combine(date_to, time.max))
    return filters


@router.get("/audit", response_model=Page[AuditOut])
async def audit_log(
    actor: str | None = Query(None, max_length=64),
    action: str | None = Query(None, max_length=64),
    date_from: date | None = None,
    date_to: date | None = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    _: Principal = Depends(_oversight),
    session: AsyncSession = Depends(read_session),
) -> dict[str, Any]:
    query = select(AuditLog).where(*_range(AuditLog.at, date_from, date_to)).order_by(AuditLog.id.desc())
    if actor:
        query = query.where(AuditLog.actor.contains(actor, autoescape=True))
    if action:
        query = query.where(AuditLog.action.contains(action, autoescape=True))
    total, rows = await _paginate(session, query, page, page_size)
    return {"items": rows, "total": total, "page": page, "page_size": page_size}


@router.get("/verifications", response_model=Page[VerificationOut])
async def verification_log(
    result: str | None = Query(None, pattern="^(pass|fail)$"),
    date_from: date | None = None,
    date_to: date | None = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    _: Principal = Depends(_oversight),
    session: AsyncSession = Depends(read_session),
) -> dict[str, Any]:
    query = (
        select(VerificationLog)
        .where(*_range(VerificationLog.checked_at, date_from, date_to))
        .order_by(VerificationLog.id.desc())
    )
    if result:
        query = query.where(VerificationLog.result == result)
    total, rows = await _paginate(session, query, page, page_size)
    return {"items": rows, "total": total, "page": page, "page_size": page_size}


@router.get("/dashboard", response_model=DashboardOut)
async def dashboard(
    _: Principal = Depends(_any_staff), session: AsyncSession = Depends(read_session)
) -> DashboardOut:
    async def count(model: Any, *where: Any) -> int:
        return await session.scalar(select(func.count()).select_from(model).where(*where)) or 0

    start = (utcnow() - timedelta(days=13)).date()
    issued_rows = await session.execute(
        select(func.date(Passport.issued_at), func.count())
        .where(func.date(Passport.issued_at) >= start.isoformat())
        .group_by(func.date(Passport.issued_at))
    )
    verified_rows = await session.execute(
        select(func.date(VerificationLog.checked_at), func.count())
        .where(func.date(VerificationLog.checked_at) >= start.isoformat())
        .group_by(func.date(VerificationLog.checked_at))
    )
    issued_by_day = {day: total for day, total in issued_rows}
    verified_by_day = {day: total for day, total in verified_rows}
    days = [(start + timedelta(days=i)).isoformat() for i in range(14)]
    reasons = await session.execute(
        select(RevocationEvent.reason, func.count()).group_by(RevocationEvent.reason)
    )
    return DashboardOut(
        issued=await count(Passport),
        active=await count(Passport, Passport.status == "active"),
        revoked=await count(Passport, Passport.status == "revoked"),
        verified_pass=await count(VerificationLog, VerificationLog.result == "pass"),
        verified_fail=await count(VerificationLog, VerificationLog.result == "fail"),
        pending_reissue=await count(Passport, Passport.reissue_pending.is_(True)),
        by_day=[DayCount(day=d, issued=issued_by_day.get(d, 0), verified=verified_by_day.get(d, 0)) for d in days],
        revocations_by_reason={reason: total for reason, total in reasons},
    )


@router.get("/field-mapping", response_model=list[FieldMappingOut])
async def field_mapping(
    _: Principal = Depends(_any_staff), session: AsyncSession = Depends(read_session)
) -> list[FieldMappingRow]:
    return list(await session.scalars(select(FieldMappingRow).order_by(FieldMappingRow.id)))
