"""Passport lifecycle and shares."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from ..api_models import (
    IssueIn,
    IssueOut,
    NonceOut,
    PassportDetail,
    PassportOut,
    ReissueIn,
    RevokeIn,
    ShareCreated,
    SharedPresentation,
    ShareIn,
    ShareOut,
)
from ..config import get_settings
from ..db import read_session, write_session
from ..models import Connection, ConsumerRef, Passport, ShareSession
from ..security import Principal, current_principal, rate_limit, require_roles
from ..services import passports as svc
from ..services import shares as share_svc

router = APIRouter(tags=["passports"])

_consumer_only = require_roles("consumer")
_staff = ("admin", "operator")


def passport_out(passport: Passport) -> PassportOut:
    data = {c.name: getattr(passport, c.name) for c in Passport.__table__.columns}
    return PassportOut(**data, consumer_no=passport.connection.consumer.consumer_no)


def _with_owner():  # noqa: ANN202
    return selectinload(Passport.connection).selectinload(Connection.consumer)


async def load_passport(session: AsyncSession, passport_id: int, principal: Principal) -> Passport:
    passport = await session.scalar(
        select(Passport)
        .where(Passport.id == passport_id)
        .options(
            _with_owner(),
            selectinload(Passport.connection).selectinload(Connection.meters),
            selectinload(Passport.connection).selectinload(Connection.assets),
        )
    )
    # A consumer asking about someone else's Passport gets the same answer as a missing one.
    if passport is None or (
        principal.role == "consumer" and passport.connection.consumer.consumer_no != principal.subject
    ):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Passport not found.")
    return passport


def _as_http(exc: svc.PassportError) -> HTTPException:
    detail = {"message": exc.message, "flags": exc.flags} if exc.flags else exc.message
    return HTTPException(exc.status_code, detail)


@router.post("/passports/nonce", response_model=NonceOut)
async def holder_nonce(principal: Principal = Depends(_consumer_only)) -> NonceOut:
    """Challenge the wallet signs to prove it controls its DID."""
    nonce = await svc.create_nonce(principal.subject)
    return NonceOut(nonce=nonce, audience=get_settings().issuer_did, expires_in=svc.NONCE_TTL_SECONDS)


@router.get("/passports/mine", response_model=list[PassportOut])
async def my_passports(
    principal: Principal = Depends(_consumer_only), session: AsyncSession = Depends(read_session)
) -> list[PassportOut]:
    rows = await session.scalars(
        select(Passport)
        .join(Connection, Connection.id == Passport.connection_id)
        .join(ConsumerRef, ConsumerRef.id == Connection.consumer_ref_id)
        .where(ConsumerRef.consumer_no == principal.subject)
        .options(_with_owner())
        .order_by(Passport.id.desc())
    )
    return [passport_out(p) for p in rows]


@router.post("/passports/issue", response_model=IssueOut, status_code=status.HTTP_201_CREATED)
async def issue_passport(
    body: IssueIn,
    principal: Principal = Depends(current_principal),
    session: AsyncSession = Depends(write_session),
) -> IssueOut:
    if not body.consent:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, "Consent is required to issue a Passport.")
    try:
        if principal.role == "consumer":
            if not body.holder_did or not body.holder_proof:
                raise svc.PassportError(422, "A wallet DID and proof are required.")
            consumer_no = principal.subject
            holder = await svc.verify_holder_proof(consumer_no, body.holder_did, body.holder_proof)
        elif principal.role in _staff:
            if not body.consumer_no:
                raise svc.PassportError(422, "A consumer number is required.")
            consumer_no = body.consumer_no
            holder = svc.discom_holder(consumer_no)
        else:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "Your role does not allow this.")
        passport, issued = await svc.issue(session, consumer_no, holder, principal.actor)
    except svc.PassportError as exc:
        raise _as_http(exc) from exc
    fresh = await load_passport(session, passport.id, principal)
    return IssueOut(passport=passport_out(fresh), credential=issued.credential, format=fresh.proof_format)


@router.get("/passports/{passport_id}", response_model=PassportDetail)
async def get_passport(
    passport_id: int,
    principal: Principal = Depends(current_principal),
    session: AsyncSession = Depends(read_session),
) -> PassportDetail:
    passport = await load_passport(session, passport_id, principal)
    return PassportDetail(**passport_out(passport).model_dump(), connection=passport.connection)


@router.post("/passports/{passport_id}/revoke", response_model=PassportOut)
async def revoke_passport(
    passport_id: int,
    body: RevokeIn,
    request: Request,
    principal: Principal = Depends(require_roles("admin")),
    session: AsyncSession = Depends(write_session),
) -> PassportOut:
    passport = await load_passport(session, passport_id, principal)
    try:
        await svc.revoke(session, passport, body.reason, principal.actor)
    except svc.PassportError as exc:
        raise _as_http(exc) from exc
    return passport_out(passport)


@router.post("/passports/{passport_id}/reissue", response_model=IssueOut, status_code=status.HTTP_201_CREATED)
async def reissue_passport(
    passport_id: int,
    body: ReissueIn,
    principal: Principal = Depends(current_principal),
    session: AsyncSession = Depends(write_session),
) -> IssueOut:
    """Staff re-issue after a change. A consumer re-binds to a new wallet with a fresh proof."""
    passport = await load_passport(session, passport_id, principal)
    consumer_no = passport.connection.consumer.consumer_no
    try:
        if principal.role == "consumer":
            if not body.holder_did or not body.holder_proof:
                raise svc.PassportError(422, "A wallet DID and proof are required.")
            holder = await svc.verify_holder_proof(consumer_no, body.holder_did, body.holder_proof)
        elif principal.role in _staff:
            holder = svc.discom_holder(consumer_no)
        else:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "Your role does not allow this.")
        new_passport, issued = await svc.reissue(
            session, passport, consumer_no, holder, body.reason, principal.actor
        )
    except svc.PassportError as exc:
        raise _as_http(exc) from exc
    fresh = await load_passport(session, new_passport.id, principal)
    return IssueOut(passport=passport_out(fresh), credential=issued.credential, format=fresh.proof_format)


@router.post(
    "/passports/{passport_id}/share", response_model=ShareCreated, status_code=status.HTTP_201_CREATED
)
async def create_share(
    passport_id: int,
    body: ShareIn,
    principal: Principal = Depends(_consumer_only),
    session: AsyncSession = Depends(write_session),
) -> ShareCreated:
    if not body.consent:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, "Consent is required to share.")
    passport = await load_passport(session, passport_id, principal)
    try:
        share, token = await share_svc.create_share(
            session,
            passport,
            passport.connection.consumer_ref_id,
            body.presentation,
            body.disclosed_fields,
            body.ttl_seconds,
            body.verifier_hint,
            principal.actor,
        )
    except svc.PassportError as exc:
        raise _as_http(exc) from exc
    # The token rides in the URL fragment, which browsers never send to a server.
    url = f"{get_settings().web_base_url}/verifier#share={token}"
    return ShareCreated(share=ShareOut.model_validate(share), url=url, token=token)


@router.get("/passports/{passport_id}/shares", response_model=list[ShareOut])
async def list_shares(
    passport_id: int,
    principal: Principal = Depends(_consumer_only),
    session: AsyncSession = Depends(read_session),
) -> list[ShareSession]:
    passport = await load_passport(session, passport_id, principal)
    rows = await session.scalars(
        select(ShareSession).where(ShareSession.passport_id == passport.id).order_by(ShareSession.id.desc())
    )
    return list(rows)


@router.delete("/shares/{share_id}", status_code=status.HTTP_204_NO_CONTENT)
async def revoke_share(
    share_id: int,
    principal: Principal = Depends(_consumer_only),
    session: AsyncSession = Depends(write_session),
) -> None:
    share = await session.get(ShareSession, share_id)
    if share is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Share not found.")
    await load_passport(session, share.passport_id, principal)
    await share_svc.revoke_share(session, share, principal.actor)


@router.post(
    "/shares/open",
    response_model=SharedPresentation,
    dependencies=[Depends(rate_limit("share-open", 30))],
)
async def open_share(
    body: dict[str, str], session: AsyncSession = Depends(write_session)
) -> SharedPresentation:
    """Public. POST keeps the token out of access logs."""
    presentation = await share_svc.open_share(session, body.get("token", ""))
    if presentation is None:
        raise HTTPException(status.HTTP_410_GONE, "This link has expired or was withdrawn.")
    return SharedPresentation(presentation=presentation)
