"""Consumer OTP login and staff login."""

from __future__ import annotations

import hmac
import json
import logging
import secrets

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..api_models import AdminLogin, OtpRequest, OtpRequested, OtpVerify, Session
from ..cache import get_redis
from ..config import get_settings
from ..db import read_session
from ..models import AdminUser
from ..security import create_session, pii_hash, rate_limit, verify_password
from ..services.adapter import get_source

router = APIRouter(prefix="/auth", tags=["auth"])
logger = logging.getLogger("cep.auth")

OTP_TTL_SECONDS = 300
OTP_MAX_ATTEMPTS = 5
_INVALID_OTP = "The code is wrong or has expired."


def send_sms(mobile: str, message: str) -> None:
    """Integration point for the DISCOM's SMS gateway. Never log the number or the code."""
    logger.info("otp dispatched")


@router.post(
    "/otp/request",
    response_model=OtpRequested,
    response_model_exclude_none=True,
    dependencies=[Depends(rate_limit("otp-request", 5))],
)
async def request_otp(body: OtpRequest) -> OtpRequested:
    """Always answers the same way, so this cannot be used to discover consumer numbers."""
    settings = get_settings()
    record = get_source().fetch(body.consumer_no)
    mobile = record.cis.get("MOBILE") if record else None
    code: str | None = None
    if mobile:
        code = f"{secrets.randbelow(1_000_000):06d}"
        value = json.dumps({"hash": pii_hash(code), "attempts": 0})
        await get_redis().set(f"otp:{pii_hash(mobile)}", value, ex=OTP_TTL_SECONDS)
        send_sms(mobile, f"Your Energy Passport code is {code}")
    return OtpRequested(expires_in=OTP_TTL_SECONDS, dev_otp=None if settings.is_prod else code)


@router.post("/otp/verify", response_model=Session, dependencies=[Depends(rate_limit("otp-verify", 10))])
async def verify_otp(body: OtpVerify) -> Session:
    denied = HTTPException(status.HTTP_401_UNAUTHORIZED, _INVALID_OTP)
    record = get_source().fetch(body.consumer_no)
    mobile = record.cis.get("MOBILE") if record else None
    if not mobile:
        raise denied
    key = f"otp:{pii_hash(mobile)}"
    client = get_redis()
    raw = await client.get(key)
    if raw is None:
        raise denied
    stored = json.loads(raw)
    if not hmac.compare_digest(stored["hash"], pii_hash(body.otp)):
        stored["attempts"] += 1
        if stored["attempts"] >= OTP_MAX_ATTEMPTS:
            await client.delete(key)
        else:
            await client.set(key, json.dumps(stored), keepttl=True)
        raise denied
    await client.delete(key)
    minutes = get_settings().consumer_session_minutes
    return Session(
        access_token=create_session(body.consumer_no, "consumer", minutes),
        role="consumer",
        expires_in=minutes * 60,
    )


@router.post("/admin/login", response_model=Session, dependencies=[Depends(rate_limit("admin-login", 10))])
async def admin_login(
    body: AdminLogin, _request: Request, session: AsyncSession = Depends(read_session)
) -> Session:
    user = await session.scalar(select(AdminUser).where(AdminUser.username == body.username))
    if user is None or not verify_password(user.password_hash, body.password):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Wrong username or password.")
    minutes = get_settings().admin_session_minutes
    return Session(
        access_token=create_session(user.username, user.role, minutes),
        role=user.role,
        expires_in=minutes * 60,
    )
