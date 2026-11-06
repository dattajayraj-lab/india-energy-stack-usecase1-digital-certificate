"""Consumer shares.

The wallet builds the presentation on the consumer's device and picks what to reveal. The
DISCOM never receives anything that was not selected, in line with the guide ("the DISCOM
is not in the disclosure loop"). This service only relays what the wallet produced, behind
a time-limited, revocable link. A consumer who prefers to bypass the DISCOM entirely can
hand the presentation to a verifier directly (D-09).
"""

from __future__ import annotations

import secrets
from datetime import timedelta

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..cache import get_redis
from ..config import get_settings
from ..crypto.jose import JoseError, decode_compact
from ..crypto.sealed import seal, token_hash, unseal
from ..models import ConsentRecord, Passport, ShareSession, utcnow
from ..verifier import sdjwt
from . import audit
from .passports import PassportError


def _disclosed_paths(presentation: str, passport: Passport) -> list[str]:
    try:
        parsed = sdjwt.parse(presentation)
        _, payload, _, _ = decode_compact(parsed.issuer_jwt)
        rebuilt = sdjwt.reconstruct(payload, parsed.disclosures)
    except (sdjwt.SdJwtError, JoseError) as exc:
        raise PassportError(422, "The presentation is malformed.") from exc
    if payload.get("jti") != passport.credential_id:
        raise PassportError(422, "This presentation is for a different Passport.")
    return sorted(rebuilt.paths)


async def create_share(
    session: AsyncSession,
    passport: Passport,
    consumer_ref_id: int,
    presentation: str,
    intended_fields: list[str],
    ttl_seconds: int,
    verifier_hint: str | None,
    actor: str,
) -> tuple[ShareSession, str]:
    settings = get_settings()
    if passport.status != "active":
        raise PassportError(409, "This Passport is no longer active.")
    if not 60 <= ttl_seconds <= settings.share_max_seconds:
        raise PassportError(422, "Choose an expiry between one minute and seven days.")
    disclosed = _disclosed_paths(presentation, passport)
    # What the consumer ticked must be exactly what leaves the device.
    if disclosed != sorted(intended_fields):
        raise PassportError(422, "The presentation discloses different fields from the ones selected.")

    token = secrets.token_urlsafe(32)
    hashed = token_hash(token)
    expires = utcnow() + timedelta(seconds=ttl_seconds)
    share = ShareSession(
        passport_id=passport.id,
        token_hash=hashed,
        disclosed_fields=disclosed,
        verifier_hint=verifier_hint,
        expires_at=expires,
    )
    session.add(share)
    session.add(ConsentRecord(consumer_ref_id=consumer_ref_id, purpose="share", scope=disclosed))
    await session.flush()
    audit.record(session, actor, "share.create", "share_session", share.id)
    await session.commit()
    await get_redis().set(f"share:{hashed}", seal(token, presentation), ex=ttl_seconds)
    return share, token


async def open_share(session: AsyncSession, token: str) -> str | None:
    hashed = token_hash(token)
    blob = await get_redis().get(f"share:{hashed}")
    if blob is None:
        return None
    presentation = unseal(token, blob)
    if presentation is None:
        return None
    share = await session.scalar(select(ShareSession).where(ShareSession.token_hash == hashed))
    if share is None or share.revoked_at is not None:
        return None
    share.used_count += 1
    await session.commit()
    return presentation


async def revoke_share(session: AsyncSession, share: ShareSession, actor: str) -> None:
    share.revoked_at = utcnow()
    audit.record(session, actor, "share.revoke", "share_session", share.id)
    await session.commit()
    await get_redis().delete(f"share:{share.token_hash}")
