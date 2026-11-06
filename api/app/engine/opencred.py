"""OpenCred client. OpenCred signs jws-2020 credentials and publishes revocations to DeDi.

sd-jwt-vc stays in-process (D-05) and uses the same key: the key file is mounted read-only
into both containers, so one did.json entry covers every credential.
"""

from __future__ import annotations

import base64
from typing import Any

import httpx

from ..config import Settings
from .base import EngineError, IssuedCredential, IssueRequest, revocation_hash
from .local import LocalEngine

SCHEMA_ID = "ies/electricity-credential/v1.2"
TIMEOUT_SECONDS = 20.0


class OpenCredEngine:
    def __init__(
        self, settings: Settings, local: LocalEngine, transport: httpx.AsyncBaseTransport | None = None
    ) -> None:
        self._settings = settings
        self._local = local
        self._client = httpx.AsyncClient(
            base_url=settings.opencred_url or "",
            headers={"Authorization": f"Bearer {settings.opencred_api_key}"},
            timeout=TIMEOUT_SECONDS,
            transport=transport,
        )

    async def _post(self, path: str, body: dict[str, Any]) -> dict[str, Any]:
        try:
            response = await self._client.post(path, json=body)
        except httpx.HTTPError as exc:
            raise EngineError(f"OpenCred is unreachable: {type(exc).__name__}") from exc
        if response.status_code >= 400:
            # The error code only: OpenCred's messages can echo credential fields.
            code = response.json().get("error", {}).get("code", "UNKNOWN")
            raise EngineError(f"OpenCred {path} failed with {response.status_code} {code}")
        return response.json()

    async def issue(self, request: IssueRequest) -> IssuedCredential:
        if request.proof_format == "sd-jwt-vc":
            return await self._local.issue(request)
        body = await self._post(
            "/v1/credentials/issue",
            {
                "schemaId": SCHEMA_ID,
                "issuerDid": self._settings.issuer_did,
                "additionalTypes": ["ElectricityCredential"],
                "proofFormat": "jws-2020",
                "validFrom": request.valid_from.isoformat(),
                "validUntil": request.valid_until.isoformat(),
                "subjectDid": request.subject.get("id"),
                "credentialSubject": request.subject,
            },
        )
        credential = body["credential"]
        # OpenCred assigns the id, and the credential must not be edited after signing.
        return IssuedCredential(credential, credential["id"], revocation_hash(credential["id"]), has_status=False)

    async def revoke(self, revocation_hash: str, reason: str) -> None:
        await self._post("/v1/credentials/revoke", {"hash": revocation_hash, "reason": reason})

    async def render_pdf(self, credential: dict[str, Any], title: str) -> bytes:
        body = await self._post(
            "/v1/credentials/package",
            {
                "credential": credential,
                "formats": ["pdf"],
                "customization": {"issuerDisplayName": self._settings.issuer_name, "footerText": title},
            },
        )
        output = next((o for o in body.get("outputs", []) if o.get("format") == "pdf"), None)
        if output is None:
            raise EngineError("OpenCred did not render a PDF")
        return base64.b64decode(output["data"])
