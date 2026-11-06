"""The credential engine: the single point where credentials get signed and revoked.

Two proof formats, for two delivery channels (docs/DECISIONS.md, D-04 and D-05):
    sd-jwt-vc  wallet delivery, field-level selective disclosure, always signed in-process
    jws-2020   DigiLocker NYCER, signed by OpenCred when configured, else in-process
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime
from functools import lru_cache
from typing import Any, Protocol

from ..config import Settings, get_settings
from ..crypto.keys import IssuerKey, get_issuer_key


class EngineError(RuntimeError):
    """The signing or revocation backend failed."""


@dataclass
class IssueRequest:
    credential_id: str  # urn:uuid:...
    subject: dict[str, Any]
    valid_from: datetime
    valid_until: datetime
    proof_format: str
    holder_jwk: dict[str, Any] | None = None


@dataclass
class IssuedCredential:
    credential: str | dict[str, Any]
    credential_id: str
    revocation_hash: str
    has_status: bool

    @property
    def payload_hash(self) -> str:
        body = self.credential if isinstance(self.credential, str) else json.dumps(self.credential, sort_keys=True)
        return hashlib.sha256(body.encode("utf-8")).hexdigest()


class CredentialEngine(Protocol):
    async def issue(self, request: IssueRequest) -> IssuedCredential: ...

    async def revoke(self, revocation_hash: str, reason: str) -> None: ...

    async def render_pdf(self, credential: dict[str, Any], title: str) -> bytes: ...


def revocation_hash(credential_id: str) -> str:
    """SHA-256 of the bare UUID: what OpenCred writes into credentialStatus.

    Confirmed against the real image on 2026-11-05 (the OpenCred concepts page describes a
    JCS hash instead). Sharing the formula lets one DeDi registry serve both proof formats.
    """
    return hashlib.sha256(credential_id.removeprefix("urn:uuid:").encode("ascii")).hexdigest()


def credential_status(settings: Settings, hash_value: str) -> dict[str, str]:
    base = f"{settings.dedi_base_url.rstrip('/')}/dedi"
    registry = f"{settings.dedi_namespace}/vc-revocation-registry"
    return {
        "id": f"{base}/lookup/{registry}/{hash_value}",
        "type": "dediregistry",
        "statusPurpose": "revocation",
        "statusListCredential": f"{base}/query/{registry}",
    }


@lru_cache
def get_engine_instance() -> CredentialEngine:
    from .local import LocalEngine
    from .opencred import OpenCredEngine

    settings = get_settings()
    key: IssuerKey = get_issuer_key()
    local = LocalEngine(settings, key)
    if settings.opencred_url:
        return OpenCredEngine(settings, local)
    return local
