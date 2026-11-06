"""Issue, revoke and re-issue Passports.

A Passport is an ElectricityCredential v1.2 shaped for the consumer. The Consumer Energy
Passport guide sets two issuance rules: credentialSubject.id is the holder's identifier and
customerProfile.idRef carries an identity reference.
"""

from __future__ import annotations

import logging
import secrets
import uuid
from dataclasses import dataclass
from datetime import timedelta
from typing import Any

from ies_adapter import MappingResult
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from ..cache import get_redis
from ..config import get_settings
from ..crypto.did import DidError, holder_jwk, is_wallet_did
from ..crypto.jose import JoseError, verify_compact
from ..engine.base import EngineError, IssuedCredential, IssueRequest, get_engine_instance
from ..ies import prune_for_jsonld, schema_errors, subject_validator
from ..models import BtmAsset, ConsentRecord, Connection, ConsumerRef, Meter, Passport, RevocationEvent, utcnow
from ..security import pii_hash
from . import audit
from .adapter import get_source, map_consumer

logger = logging.getLogger("cep.passports")

NONCE_TTL_SECONDS = 300
REVOCATION_REASONS = ("meter_swap", "load_change", "der_change", "request", "holder_rebind", "superseded")


class PassportError(Exception):
    """A business-rule failure, surfaced to the caller with a status code."""

    def __init__(self, status_code: int, message: str, flags: list[dict[str, str]] | None = None) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.message = message
        self.flags = flags or []


@dataclass
class Holder:
    did: str
    binding: str  # wallet / discom-did / digilocker
    id_ref: dict[str, str]
    jwk: dict[str, Any] | None = None


def consumer_did(consumer_no: str) -> str:
    """Pattern 4: a stable, non-personal subject id under the DISCOM's own domain."""
    return f"{get_settings().issuer_did}:consumers:{consumer_no}"


def connection_id_ref(consumer_no: str) -> dict[str, str]:
    return {"issuedBy": get_settings().issuer_did, "subjectId": f"ca:{consumer_no}"}


async def create_nonce(consumer_no: str) -> str:
    nonce = secrets.token_urlsafe(24)
    await get_redis().set(f"nonce:{nonce}", consumer_no, ex=NONCE_TTL_SECONDS)
    return nonce


async def verify_holder_proof(consumer_no: str, holder_did: str, proof: str) -> Holder:
    """Proof of control at issue time. Without this, holder binding adds no security.

    The wallet signs a fresh single-use nonce with the key behind its DID.
    """
    if not is_wallet_did(holder_did):
        raise PassportError(422, "The wallet DID must be did:key or did:jwk.")
    try:
        jwk = holder_jwk(holder_did)
        _, claims = verify_compact(proof, jwk)
    except (DidError, JoseError) as exc:
        raise PassportError(401, "The wallet could not prove control of this DID.") from exc
    nonce = claims.get("nonce")
    if claims.get("aud") != get_settings().issuer_did or not isinstance(nonce, str):
        raise PassportError(401, "The wallet proof is not addressed to this issuer.")
    owner = await get_redis().getdel(f"nonce:{nonce}")
    if owner is None or owner.decode() != consumer_no:
        raise PassportError(401, "The wallet proof has expired. Try again.")
    return Holder(holder_did, "wallet", connection_id_ref(consumer_no), jwk)


def discom_holder(consumer_no: str) -> Holder:
    return Holder(consumer_did(consumer_no), "discom-did", connection_id_ref(consumer_no))


def digilocker_holder(consumer_no: str, digilocker_id: str) -> Holder:
    """NeGD requires the DigiLockerId in customerProfile.idRef."""
    return Holder(
        consumer_did(consumer_no),
        "digilocker",
        {"issuedBy": "did:web:digilocker.gov.in", "subjectId": f"digilocker.gov.in:{digilocker_id}"},
    )


async def _consumer_ref(session: AsyncSession, consumer_no: str) -> ConsumerRef:
    ref = await session.scalar(select(ConsumerRef).where(ConsumerRef.consumer_no == consumer_no))
    if ref is None:
        settings = get_settings()
        record = get_source().fetch(consumer_no)
        mobile = record.cis.get("MOBILE") if record else None
        ref = ConsumerRef(
            consumer_no=consumer_no,
            consumer_did=consumer_did(consumer_no),
            mobile_hash=pii_hash(mobile) if mobile else None,
            discom_id=settings.discom_id,
        )
        session.add(ref)
        await session.flush()
    return ref


def _capacity_kw(attributes: dict[str, Any]) -> float | None:
    power = attributes.get("maxExport") or attributes.get("maxImport")
    return float(power["value"]) if power else None


async def _snapshot(session: AsyncSession, ref: ConsumerRef, subject: dict[str, Any]) -> Connection:
    """Refresh the non-personal connection, meter and asset snapshot."""
    profile = subject["customerProfile"]
    consumption = profile["consumptionProfiles"][0]
    record = get_source().fetch(ref.consumer_no)
    connection = await session.scalar(
        select(Connection)
        .where(Connection.consumer_ref_id == ref.id)
        .options(selectinload(Connection.meters), selectinload(Connection.assets))
    )
    if connection is None:
        connection = Connection(consumer_ref_id=ref.id, meters=[], assets=[])
        session.add(connection)
    connection.service_conn_no = record.cis["SERVICE_CONN_NO"] if record else ""
    connection.tariff_category = consumption["tariffCategoryCode"]
    connection.sanctioned_load_kw = float(consumption["sanctionedLoad"]["value"])
    connection.status = consumption.get("serviceStatus", "active")
    connection.meters.clear()
    connection.assets.clear()
    for resource in profile["energyResources"]:
        attributes = resource.get("attributes", {})
        if resource["type"] == "METER":
            connection.meters.append(
                Meter(
                    meter_no=attributes.get("serialNumber", ""),
                    meter_did=resource["id"],
                    type="generation" if attributes.get("energyDirection") == "Reverse" else "consumption",
                )
            )
        else:
            inspection = attributes.get("inspection", {})
            connection.assets.append(
                BtmAsset(
                    asset_did=resource["id"],
                    asset_type=resource["type"],
                    capacity_kw=_capacity_kw(attributes),
                    inspection_status=inspection.get("result", "none"),
                    inspected_on=inspection.get("date"),
                )
            )
    await session.flush()
    return connection


async def active_passport(session: AsyncSession, connection_id: int) -> Passport | None:
    return await session.scalar(
        select(Passport).where(Passport.connection_id == connection_id, Passport.status == "active")
    )


async def require_issuable(session: AsyncSession, consumer_no: str) -> MappingResult:
    mapped = await map_consumer(session, consumer_no)
    if mapped is None:
        raise PassportError(404, "No such consumer in the source systems.")
    if not mapped.issuable:
        flags = [vars(f) for f in mapped.flags if f.severity == "blocker"]
        raise PassportError(409, "Data-quality issues block issuance.", flags)
    return mapped


async def _sign(
    session: AsyncSession,
    consumer_no: str,
    holder: Holder,
    proof_format: str,
    actor: str,
    mapped: MappingResult,
) -> tuple[Passport, IssuedCredential]:
    settings = get_settings()
    subject = {
        "id": holder.did,
        "customerProfile": {**mapped.subject["customerProfile"], "idRef": holder.id_ref},
        "customerDetails": mapped.subject["customerDetails"],
    }
    errors = schema_errors(subject_validator(), subject)
    if errors:
        # IES: schema validation is enforced on every outgoing payload.
        raise PassportError(422, "The mapped record does not conform to ElectricityCredential v1.2.")

    ref = await _consumer_ref(session, consumer_no)
    connection = await _snapshot(session, ref, subject)
    if proof_format == "jws-2020":
        subject, dropped = prune_for_jsonld(subject)
        if dropped:
            logger.info("jws-2020 omitted %d field(s) undefined in the IES context", len(dropped))
    version = (
        await session.scalar(
            select(func.coalesce(func.max(Passport.version), 0)).where(Passport.connection_id == connection.id)
        )
        or 0
    ) + 1
    now = utcnow().replace(microsecond=0)
    expires = now + timedelta(days=settings.credential_validity_days)
    try:
        issued = await get_engine_instance().issue(
            IssueRequest(
                credential_id=f"urn:uuid:{uuid.uuid4()}",
                subject=subject,
                valid_from=now,
                valid_until=expires,
                proof_format=proof_format,
                holder_jwk=holder.jwk,
            )
        )
    except EngineError as exc:
        raise PassportError(502, "The signing service is unavailable. Nothing was issued.") from exc
    passport = Passport(
        credential_id=issued.credential_id,
        connection_id=connection.id,
        version=version,
        revocation_hash=issued.revocation_hash,
        proof_format=proof_format,
        holder_did=holder.did,
        binding=holder.binding,
        issued_at=now,
        expires_at=expires,
        payload_hash=issued.payload_hash,
    )
    session.add(passport)
    await session.flush()
    audit.record(session, actor, "passport.issue", "passport", passport.id)
    return passport, issued


async def issue(
    session: AsyncSession,
    consumer_no: str,
    holder: Holder,
    actor: str,
    proof_format: str = "sd-jwt-vc",
    consent: bool = True,
) -> tuple[Passport, IssuedCredential]:
    """One active Passport per connection; changing it goes through re-issue."""
    mapped = await require_issuable(session, consumer_no)
    ref = await _consumer_ref(session, consumer_no)
    existing = await session.scalar(
        select(Passport)
        .join(Connection, Connection.id == Passport.connection_id)
        .where(Connection.consumer_ref_id == ref.id, Passport.status == "active")
    )
    if existing is not None:
        raise PassportError(409, "An active Passport exists for this connection. Re-issue it instead.")
    passport, issued = await _sign(session, consumer_no, holder, proof_format, actor, mapped)
    if consent:
        session.add(ConsentRecord(consumer_ref_id=ref.id, purpose="issue", scope=["passport"]))
    await _clear_pending(session, passport.connection_id)
    await session.commit()
    return passport, issued


async def _clear_pending(session: AsyncSession, connection_id: int) -> None:
    pending = await session.scalars(
        select(Passport).where(Passport.connection_id == connection_id, Passport.reissue_pending.is_(True))
    )
    for row in pending:
        row.reissue_pending = False


async def _revoke_row(session: AsyncSession, passport: Passport, reason: str, actor: str) -> None:
    if reason not in REVOCATION_REASONS:
        raise PassportError(422, "Unknown revocation reason.")
    if passport.status == "revoked":
        raise PassportError(409, "This Passport is already revoked.")
    try:
        await get_engine_instance().revoke(passport.revocation_hash, reason)
    except EngineError as exc:
        raise PassportError(502, "Revocation could not be published. The Passport is still active.") from exc
    passport.status = "revoked"
    session.add(RevocationEvent(passport_id=passport.id, reason=reason, actor=actor))
    audit.record(session, actor, "passport.revoke", "passport", passport.id)
    # A verifier must never see a stale pass.
    await get_redis().delete(f"status:{passport.revocation_hash}")


async def revoke(session: AsyncSession, passport: Passport, reason: str, actor: str) -> None:
    await _revoke_row(session, passport, reason, actor)
    await session.commit()


async def reissue(
    session: AsyncSession, passport: Passport, consumer_no: str, holder: Holder, reason: str, actor: str
) -> tuple[Passport, IssuedCredential]:
    """Revoke the old version, then issue the next one.

    Blockers are checked first, so a bad source record cannot leave the consumer with no
    Passport at all. Revocation comes before signing: a failure here must never leave two
    active versions.
    """
    mapped = await require_issuable(session, consumer_no)
    await _revoke_row(session, passport, reason, actor)
    new_passport, issued = await _sign(session, consumer_no, holder, passport.proof_format, actor, mapped)
    await _clear_pending(session, new_passport.connection_id)
    await session.commit()
    return new_passport, issued


async def handle_source_change(session: AsyncSession, consumer_no: str, reason: str, actor: str) -> Passport | None:
    """Revoke at once and flag for collection.

    The DISCOM keeps no copy of the credential, so a new one cannot be pushed to a wallet:
    the consumer collects it, which mirrors DigiLocker's Pull URI model (D-08).
    """
    ref = await session.scalar(select(ConsumerRef).where(ConsumerRef.consumer_no == consumer_no))
    if ref is None:
        return None
    passport = await session.scalar(
        select(Passport)
        .join(Connection, Connection.id == Passport.connection_id)
        .where(Connection.consumer_ref_id == ref.id, Passport.status == "active")
    )
    if passport is None:
        return None
    await _revoke_row(session, passport, reason, actor)
    passport.reissue_pending = True
    await session.commit()
    return passport
