"""Share payload sealing.

A share link must resolve to a presentation, but Redis must not hold personal data.
The presentation is encrypted under a key derived from the share token, and Redis is
keyed by the token's hash. The token exists only in the consumer's link, so a Redis
dump alone reveals nothing.
"""

from __future__ import annotations

import hashlib
import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _key(token: str) -> bytes:
    return HKDF(hashes.SHA256(), 32, salt=None, info=b"cep-share-v1").derive(token.encode("utf-8"))


def seal(token: str, plaintext: str) -> bytes:
    nonce = os.urandom(12)
    return nonce + AESGCM(_key(token)).encrypt(nonce, plaintext.encode("utf-8"), None)


def unseal(token: str, blob: bytes) -> str | None:
    try:
        return AESGCM(_key(token)).decrypt(blob[:12], blob[12:], None).decode("utf-8")
    except (InvalidTag, ValueError):
        return None
