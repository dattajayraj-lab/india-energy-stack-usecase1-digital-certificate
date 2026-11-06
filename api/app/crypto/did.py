"""DID helpers: did:web addressing and offline did:key / did:jwk decoding."""

from __future__ import annotations

import json
from typing import Any
from urllib.parse import unquote

from cryptography.hazmat.primitives.asymmetric import ec

from .encoding import b64u_decode, b64u_encode

_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_P256_PUB = b"\x80\x24"  # multicodec varint 0x1200
_ED25519_PUB = b"\xed\x01"  # multicodec varint 0xed


class DidError(ValueError):
    """The DID is malformed or uses an unsupported method."""


def did_web_url(did: str, allow_http: bool = False) -> str:
    """Map a did:web to its document URL, per the did:web method and IES Register §1.1."""
    if not did.startswith("did:web:"):
        raise DidError("Not a did:web")
    segments = did.removeprefix("did:web:").split("#")[0].split(":")
    host = unquote(segments[0])
    if not host or "/" in host or "@" in host:
        raise DidError("Invalid did:web host")
    scheme = "http" if allow_http and host.split(":")[0] in {"localhost", "127.0.0.1"} else "https"
    if len(segments) == 1:
        return f"{scheme}://{host}/.well-known/did.json"
    return f"{scheme}://{host}/{'/'.join(unquote(s) for s in segments[1:])}/did.json"


def did_web_domain(did: str) -> str:
    return unquote(did.removeprefix("did:web:").split("#")[0].split(":")[0])


def _base58_decode(text: str) -> bytes:
    number = 0
    for char in text:
        index = _B58.find(char)
        if index < 0:
            raise DidError("Invalid base58 in did:key")
        number = number * 58 + index
    body = number.to_bytes((number.bit_length() + 7) // 8, "big")
    return b"\x00" * (len(text) - len(text.lstrip("1"))) + body


def holder_jwk(did: str) -> dict[str, Any]:
    """Resolve a self-describing wallet DID (did:jwk or did:key) with no network call."""
    bare = did.split("#")[0]
    if bare.startswith("did:jwk:"):
        try:
            jwk = json.loads(b64u_decode(bare.removeprefix("did:jwk:")))
        except ValueError as exc:
            raise DidError("Malformed did:jwk") from exc
        return {k: jwk[k] for k in ("kty", "crv", "x", "y") if k in jwk}
    if bare.startswith("did:key:z"):
        raw = _base58_decode(bare.removeprefix("did:key:z"))
        if raw.startswith(_ED25519_PUB):
            return {"kty": "OKP", "crv": "Ed25519", "x": b64u_encode(raw[2:])}
        if raw.startswith(_P256_PUB):
            try:
                key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), raw[2:])
            except ValueError as exc:
                raise DidError("Malformed P-256 did:key") from exc
            numbers = key.public_numbers()
            return {
                "kty": "EC",
                "crv": "P-256",
                "x": b64u_encode(numbers.x.to_bytes(32, "big")),
                "y": b64u_encode(numbers.y.to_bytes(32, "big")),
            }
        raise DidError("Unsupported did:key type")
    raise DidError("Holder DID must be did:key or did:jwk")


def is_wallet_did(did: str | None) -> bool:
    return bool(did) and did.startswith(("did:key:", "did:jwk:"))
