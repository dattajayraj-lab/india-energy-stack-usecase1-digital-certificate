"""DigiLocker Pull URI for DocType NYCER, per the IES DigiLocker delivery guide."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
from dataclasses import dataclass
from typing import Any
from xml.sax.saxutils import escape, quoteattr

from defusedxml import ElementTree
from defusedxml.common import DefusedXmlException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..config import get_settings
from ..engine.base import EngineError, get_engine_instance
from ..models import Connection, ConsumerRef, Passport
from . import passports
from .adapter import get_source

DOC_TYPE = "NYCER"


class PullError(Exception):
    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message


@dataclass
class PullRequest:
    ts: str
    txn: str
    org_id: str
    doc_type: str
    digilocker_id: str
    consumer_no: str
    mobile: str
    full_name: str | None


def verify_hmac(body: bytes, signature: str | None) -> bool:
    key = get_settings().digilocker_api_key.encode()
    expected = base64.b64encode(hmac.new(key, body, hashlib.sha256).digest()).decode()
    return bool(signature) and hmac.compare_digest(expected, signature)


def parse_request(body: bytes) -> PullRequest:
    try:
        root = ElementTree.fromstring(body)
    except (ElementTree.ParseError, DefusedXmlException) as exc:
        raise PullError("Malformed request") from exc
    details = root.find("DocDetails")
    if root.tag != "PullURIRequest" or details is None:
        raise PullError("Malformed request")

    def text(tag: str) -> str:
        return (details.findtext(tag) or "").strip()

    return PullRequest(
        ts=root.get("ts", ""),
        txn=root.get("txn", ""),
        org_id=root.get("orgId", ""),
        doc_type=text("DocType"),
        digilocker_id=text("DigiLockerId"),
        consumer_no=text("UDF1"),
        mobile=text("UDF2"),
        full_name=text("FullName") or None,
    )


def error_response(request: PullRequest | None, message: str) -> str:
    ts, txn, org = (request.ts, request.txn, request.org_id) if request else ("", "", "")
    return (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        f'<PullURIResponse ver="3.0" ts={quoteattr(ts)} txn={quoteattr(txn)} orgId={quoteattr(org)}>'
        f'<ResponseStatus Status="0" ts={quoteattr(ts)} txn={quoteattr(txn)}>{escape(message)}</ResponseStatus>'
        "</PullURIResponse>"
    )


def _success(request: PullRequest, credential: dict[str, Any], issued_to: str, pdf: bytes) -> str:
    consumer_no = request.consumer_no
    uri = f"{get_settings().digilocker_org_id}-{DOC_TYPE}-{consumer_no}"
    vc_b64 = base64.b64encode(json.dumps(credential, ensure_ascii=False).encode("utf-8")).decode()
    pdf_b64 = base64.b64encode(pdf).decode()
    ts, txn, org = quoteattr(request.ts), quoteattr(request.txn), quoteattr(request.org_id)
    return (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        f'<PullURIResponse ver="3.0" ts={ts} txn={txn} orgId={org}>'
        f'<ResponseStatus Status="1" ts={ts} txn={txn}/>'
        "<DocDetails>"
        f"<DocType>{DOC_TYPE}</DocType>"
        f"<URI>{escape(uri)}</URI>"
        f"<IssuedTo>{escape(issued_to)}</IssuedTo>"
        f"<ValidFrom>{escape(credential['validFrom'])}</ValidFrom>"
        f"<ValidTo>{escape(credential['validUntil'])}</ValidTo>"
        f'<DocContent format="pdf">{pdf_b64}</DocContent>'
        f'<VcContent format="json-ld">{vc_b64}</VcContent>'
        "<VcType>application/ld+json</VcType>"
        "</DocDetails>"
        "</PullURIResponse>"
    )


async def _supersede(session: AsyncSession, consumer_no: str) -> None:
    """A refresh overwrites the last document, so the previous Passport must not stay live."""
    active = await session.scalar(
        select(Passport)
        .join(Connection, Connection.id == Passport.connection_id)
        .join(ConsumerRef, ConsumerRef.id == Connection.consumer_ref_id)
        .where(ConsumerRef.consumer_no == consumer_no, Passport.status == "active")
    )
    if active is not None:
        await passports.revoke(session, active, "superseded", "system:digilocker")


async def pull(session: AsyncSession, request: PullRequest) -> str:
    if request.doc_type != DOC_TYPE:
        return error_response(request, "Unsupported DocType")
    record = get_source().fetch(request.consumer_no)
    # One message for both, so this endpoint cannot be used to probe for valid accounts.
    if record is None or record.cis.get("MOBILE") != request.mobile:
        return error_response(request, "No matching record")
    issued_to = record.cis["CUST_NAME"]
    if request.full_name and request.full_name.casefold() != issued_to.casefold():
        return error_response(request, "No matching record")
    try:
        # Check first: a bad source record must not cost the consumer their current Passport.
        await passports.require_issuable(session, request.consumer_no)
        await _supersede(session, request.consumer_no)
        holder = passports.digilocker_holder(request.consumer_no, request.digilocker_id)
        _, issued = await passports.issue(
            session, request.consumer_no, holder, "system:digilocker", proof_format="jws-2020"
        )
        credential = issued.credential
        assert isinstance(credential, dict)  # noqa: S101 - jws-2020 is always a JSON document
        pdf = await get_engine_instance().render_pdf(credential, "Consumer Energy Passport")
    except passports.PassportError as exc:
        return error_response(request, exc.message)
    except EngineError:
        return error_response(request, "Issuer temporarily unavailable")
    return _success(request, credential, issued_to, pdf)
