"""Issuer signing key. Held outside SQLite and source control, per IES Register §1.2.

The P-256 key signs credentials. Beckn message signing would use a separate Ed25519 key.
In production point CEP_KEY_PATH at a mounted secret, or replace `IssuerKey` with a
KMS-backed signer; nothing else reads the private key.
"""

from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from ..config import get_settings
from .encoding import b64u_encode
from .jose import sign_compact


class IssuerKey:
    def __init__(self, private_key: ec.EllipticCurvePrivateKey, did: str) -> None:
        self._private_key = private_key
        self.did = did
        self.kid = f"{did}#key-0"

    @property
    def private_key(self) -> ec.EllipticCurvePrivateKey:
        return self._private_key

    def public_jwk(self) -> dict[str, Any]:
        numbers = self._private_key.public_key().public_numbers()
        return {
            "kty": "EC",
            "crv": "P-256",
            "x": b64u_encode(numbers.x.to_bytes(32, "big")),
            "y": b64u_encode(numbers.y.to_bytes(32, "big")),
        }

    def did_document(self) -> dict[str, Any]:
        """The exact shape from IES Register §1.3. JsonWebKey2020 is deliberate, see there."""
        return {
            "@context": ["https://www.w3.org/ns/did/v1", "https://w3id.org/security/suites/jws-2020/v1"],
            "id": self.did,
            "verificationMethod": [
                {
                    "id": self.kid,
                    "type": "JsonWebKey2020",
                    "controller": self.did,
                    "publicKeyJwk": self.public_jwk(),
                }
            ],
            "authentication": [self.kid],
            "assertionMethod": [self.kid],
        }

    def sign_jwt(self, header: dict[str, Any], payload: dict[str, Any]) -> str:
        return sign_compact(self._private_key, {"alg": "ES256", "kid": self.kid, **header}, payload)


def _load_or_create(path: Path, create: bool) -> ec.EllipticCurvePrivateKey:
    if path.exists():
        key = serialization.load_pem_private_key(path.read_bytes(), password=None)
        if not isinstance(key, ec.EllipticCurvePrivateKey) or key.curve.name != "secp256r1":
            raise ValueError("The issuer signing key must be EC P-256")
        return key
    if not create:
        raise FileNotFoundError(f"Issuer signing key not found at {path}")
    key = ec.generate_private_key(ec.SECP256R1())
    path.parent.mkdir(parents=True, exist_ok=True)
    pem = key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(pem)
    return key


@lru_cache
def get_issuer_key() -> IssuerKey:
    settings = get_settings()
    return IssuerKey(_load_or_create(settings.key_path, create=not settings.is_prod), settings.issuer_did)
