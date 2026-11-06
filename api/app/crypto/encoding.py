"""Base64url helpers shared by the issuer and the verifier."""

from __future__ import annotations

import base64
import hashlib
import json
from typing import Any


def b64u_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64u_decode(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def json_b64u(value: Any) -> str:
    return b64u_encode(json.dumps(value, separators=(",", ":"), ensure_ascii=False).encode("utf-8"))


def sha256_b64u(text: str) -> str:
    return b64u_encode(hashlib.sha256(text.encode("ascii")).digest())
