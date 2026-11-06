"""Machine-facing routes: did.json, adapter webhook, DigiLocker, and the dev DeDi mock."""

from __future__ import annotations

import hashlib
import hmac
from typing import Any

from fastapi import APIRouter, Depends, Header, HTTPException, Request, Response, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..api_models import SourceChangeIn, SourceChangeOut
from ..cache import get_redis
from ..config import get_settings
from ..crypto.keys import get_issuer_key
from ..db import read_session, write_session
from ..models import Passport
from ..security import rate_limit
from ..services import digilocker
from ..services import passports as svc

public_router = APIRouter(tags=["identity"])
webhook_router = APIRouter(tags=["webhooks"])
mock_dedi_router = APIRouter(prefix="/mock-dedi/dedi", tags=["dev: mock DeDi"])

XML = "application/xml"


@public_router.get("/.well-known/did.json")
async def did_document() -> dict[str, Any]:
    return get_issuer_key().did_document()


@webhook_router.post("/webhooks/source-change", response_model=SourceChangeOut)
async def source_change(
    request: Request,
    x_adapter_signature: str | None = Header(None),
    session: AsyncSession = Depends(write_session),
) -> SourceChangeOut:
    """Meter swap, load change or new DER in a source system. Signed by the adapter."""
    raw = await request.body()
    expected = hmac.new(get_settings().webhook_secret.encode(), raw, hashlib.sha256).hexdigest()
    if not x_adapter_signature or not hmac.compare_digest(expected, x_adapter_signature):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid signature.")
    body = SourceChangeIn.model_validate_json(raw)
    first_delivery = await get_redis().set(f"webhook:{body.event_id}", "1", nx=True, ex=86400)
    if not first_delivery:
        return SourceChangeOut(action="duplicate_event")
    try:
        passport = await svc.handle_source_change(session, body.consumer_no, body.event, "system:adapter")
    except svc.PassportError as exc:
        # Let the adapter retry: a change that was not applied must not count as delivered.
        await get_redis().delete(f"webhook:{body.event_id}")
        raise HTTPException(exc.status_code, exc.message) from exc
    if passport is None:
        return SourceChangeOut(action="no_active_passport")
    return SourceChangeOut(action="revoked_pending_reissue", passport_id=passport.id)


@public_router.post("/digilocker/pulluri", dependencies=[Depends(rate_limit("digilocker", 120))])
async def digilocker_pull(
    request: Request,
    x_digilocker_hmac: str | None = Header(None),
    session: AsyncSession = Depends(write_session),
) -> Response:
    body = await request.body()
    if not digilocker.verify_hmac(body, x_digilocker_hmac):
        return Response(status_code=status.HTTP_401_UNAUTHORIZED)
    try:
        parsed = digilocker.parse_request(body)
    except digilocker.PullError as exc:
        return Response(digilocker.error_response(None, exc.message), media_type=XML)
    return Response(await digilocker.pull(session, parsed), media_type=XML)


@mock_dedi_router.get("/lookup/{namespace}")
async def mock_namespace(namespace: str) -> dict[str, Any]:
    """Stands in for the real directory until the DISCOM has a verified namespace."""
    known = {get_settings().dedi_namespace, _did_namespace()}
    if namespace not in known:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Namespace not found.")
    return {"namespace": namespace, "verified": True, "mock": True}


def _did_namespace() -> str:
    from ..crypto.did import did_web_domain

    return did_web_domain(get_settings().issuer_did)


@mock_dedi_router.get("/lookup/{namespace}/vc-revocation-registry/{hash_value}")
async def mock_revocation(
    namespace: str, hash_value: str, session: AsyncSession = Depends(read_session)
) -> dict[str, Any]:
    """DeDi semantics: only revoked hashes exist, so 404 means not revoked."""
    revoked = await session.scalar(
        select(Passport.id).where(Passport.revocation_hash == hash_value, Passport.status == "revoked")
    )
    if revoked is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Record not found.")
    return {"status": "revoked", "hash": hash_value}
