"""Minimal compact-JWS sign and verify for the algorithms IES credentials use.

The algorithm is taken from the verification key, never trusted from the header alone,
which closes the classic alg-confusion and alg=none attacks.
"""

from __future__ import annotations

import json
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature

from .encoding import b64u_decode, b64u_encode, json_b64u


class JoseError(ValueError):
    """The token is malformed or its signature does not verify."""


def public_key_from_jwk(jwk: dict[str, Any]) -> ec.EllipticCurvePublicKey | ed25519.Ed25519PublicKey:
    try:
        if jwk.get("kty") == "EC" and jwk.get("crv") == "P-256":
            x = int.from_bytes(b64u_decode(jwk["x"]), "big")
            y = int.from_bytes(b64u_decode(jwk["y"]), "big")
            return ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1()).public_key()
        if jwk.get("kty") == "OKP" and jwk.get("crv") == "Ed25519":
            return ed25519.Ed25519PublicKey.from_public_bytes(b64u_decode(jwk["x"]))
    except (KeyError, ValueError) as exc:
        raise JoseError(f"Invalid public key: {exc}") from exc
    raise JoseError("Unsupported key type; expected EC P-256 or Ed25519")


def expected_alg(jwk: dict[str, Any]) -> str:
    return "ES256" if jwk.get("kty") == "EC" else "EdDSA"


def verify_signature(jwk: dict[str, Any], signing_input: bytes, signature: bytes) -> bool:
    key = public_key_from_jwk(jwk)
    try:
        if isinstance(key, ec.EllipticCurvePublicKey):
            if len(signature) != 64:
                return False
            der = encode_dss_signature(
                int.from_bytes(signature[:32], "big"), int.from_bytes(signature[32:], "big")
            )
            key.verify(der, signing_input, ec.ECDSA(hashes.SHA256()))
        else:
            key.verify(signature, signing_input)
    except InvalidSignature:
        return False
    return True


def sign_es256(private_key: ec.EllipticCurvePrivateKey, signing_input: bytes) -> bytes:
    r, s = decode_dss_signature(private_key.sign(signing_input, ec.ECDSA(hashes.SHA256())))
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def sign_compact(
    private_key: ec.EllipticCurvePrivateKey, header: dict[str, Any], payload: dict[str, Any]
) -> str:
    signing_input = f"{json_b64u(header)}.{json_b64u(payload)}"
    return f"{signing_input}.{b64u_encode(sign_es256(private_key, signing_input.encode('ascii')))}"


def decode_compact(token: str) -> tuple[dict[str, Any], dict[str, Any], bytes, bytes]:
    """Split a compact JWS without verifying it. Returns header, payload, input, signature."""
    parts = token.split(".")
    if len(parts) != 3:
        raise JoseError("Not a compact JWS")
    try:
        header = json.loads(b64u_decode(parts[0]))
        payload = json.loads(b64u_decode(parts[1]))
        signature = b64u_decode(parts[2])
    except (ValueError, UnicodeDecodeError) as exc:
        raise JoseError("Malformed JWS") from exc
    if not isinstance(header, dict) or not isinstance(payload, dict):
        raise JoseError("Malformed JWS")
    return header, payload, f"{parts[0]}.{parts[1]}".encode("ascii"), signature


def verify_compact(token: str, jwk: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    header, payload, signing_input, signature = decode_compact(token)
    if header.get("alg") != expected_alg(jwk):
        raise JoseError("Algorithm does not match the verification key")
    if not verify_signature(jwk, signing_input, signature):
        raise JoseError("Signature does not verify")
    return header, payload
