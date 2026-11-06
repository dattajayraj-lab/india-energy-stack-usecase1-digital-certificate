"""In-process signing with the issuer key from the vault path."""

from __future__ import annotations

import io
from typing import Any

from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas

from ..config import Settings
from ..crypto.keys import IssuerKey
from ..crypto.sdjwt import issue_sd_jwt
from ..ies import CREDENTIAL_CONTEXTS, SCHEMA_URL
from ..models import utcnow
from ..verifier.jsonld import sign_jws2020
from .base import IssuedCredential, IssueRequest, credential_status, revocation_hash


class LocalEngine:
    def __init__(self, settings: Settings, key: IssuerKey) -> None:
        self._settings = settings
        self._key = key

    async def issue(self, request: IssueRequest) -> IssuedCredential:
        hash_value = revocation_hash(request.credential_id)
        if request.proof_format == "sd-jwt-vc":
            token = issue_sd_jwt(
                self._key,
                credential_id=request.credential_id,
                subject=request.subject,
                iat=int(utcnow().timestamp()),
                nbf=int(request.valid_from.timestamp()),
                exp=int(request.valid_until.timestamp()),
                credential_status=credential_status(self._settings, hash_value),
                holder_jwk=request.holder_jwk,
            )
            return IssuedCredential(token, request.credential_id, hash_value, has_status=True)
        return IssuedCredential(self._sign_jws2020(request), request.credential_id, hash_value, has_status=False)

    def _sign_jws2020(self, request: IssueRequest) -> dict[str, Any]:
        # credentialStatus is omitted on purpose: neither `dedi` nor `dediregistry` is defined
        # in the IES contexts, so it cannot be covered by a JSON-LD proof (D-06).
        credential: dict[str, Any] = {
            "@context": CREDENTIAL_CONTEXTS,
            "id": request.credential_id,
            "type": ["VerifiableCredential", "ElectricityCredential"],
            "issuer": self._key.did,
            "validFrom": request.valid_from.isoformat(),
            "validUntil": request.valid_until.isoformat(),
            "credentialSchema": {"id": SCHEMA_URL, "type": "JsonSchema"},
            "credentialSubject": request.subject,
        }
        proof = {
            "type": "JsonWebSignature2020",
            "created": utcnow().isoformat(),
            "verificationMethod": self._key.kid,
            "proofPurpose": "assertionMethod",
        }
        jws = sign_jws2020(credential, proof, self._key.private_key)
        return {**credential, "proof": {**proof, "jws": jws}}

    async def revoke(self, revocation_hash: str, reason: str) -> None:
        # The dev DeDi mock reads revocations from the passport table, so there is nothing to
        # publish. A production deployment always has OpenCred configured (see Settings).
        return None

    async def render_pdf(self, credential: dict[str, Any], title: str) -> bytes:
        subject = credential["credentialSubject"]
        buffer = io.BytesIO()
        page = canvas.Canvas(buffer, pagesize=A4)
        page.setTitle(title)
        page.setFont("Helvetica-Bold", 16)
        page.drawString(50, 790, title)
        page.setFont("Helvetica", 11)
        lines = [
            f"Issuer: {self._settings.issuer_name}",
            f"Consumer number: {subject['customerProfile']['customerNumber']}",
            f"Issued to: {subject.get('customerDetails', {}).get('fullName', '')}",
            f"Valid until: {credential['validUntil']}",
            f"Credential: {credential['id']}",
        ]
        for index, line in enumerate(lines):
            page.drawString(50, 760 - index * 18, line)
        page.save()
        return buffer.getvalue()
