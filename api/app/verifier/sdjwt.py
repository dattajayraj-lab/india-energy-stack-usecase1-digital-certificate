"""SD-JWT parsing and disclosure reconstruction. Holds no issuer state."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

from ..crypto.encoding import b64u_decode, sha256_b64u


class SdJwtError(ValueError):
    """The presentation is structurally invalid."""


@dataclass
class ParsedSdJwt:
    issuer_jwt: str
    disclosures: list[str]
    key_binding_jwt: str | None

    @property
    def sd_hash_input(self) -> str:
        return "~".join([self.issuer_jwt, *self.disclosures]) + "~"


def parse(token: str) -> ParsedSdJwt:
    parts = token.strip().split("~")
    if len(parts) < 2 or not parts[0]:
        raise SdJwtError("Not an SD-JWT")
    return ParsedSdJwt(parts[0], [p for p in parts[1:-1] if p], parts[-1] or None)


@dataclass
class Reconstruction:
    claims: dict[str, Any]
    paths: list[str] = field(default_factory=list)


def reconstruct(payload: dict[str, Any], disclosures: list[str]) -> Reconstruction:
    """Apply disclosures to the signed payload, per RFC 9901 §7.1.

    Every disclosure must be referenced by a digest under the issuer's signature, exactly
    once. That is what stops a holder from adding or swapping in a field.
    """
    if payload.get("_sd_alg", "sha-256") != "sha-256":
        raise SdJwtError("Unsupported _sd_alg")
    by_digest: dict[str, list[Any]] = {}
    for encoded in disclosures:
        digest = sha256_b64u(encoded)
        if digest in by_digest:
            raise SdJwtError("Duplicate disclosure")
        try:
            decoded = json.loads(b64u_decode(encoded))
        except (ValueError, UnicodeDecodeError) as exc:
            raise SdJwtError("Malformed disclosure") from exc
        if not isinstance(decoded, list) or len(decoded) not in (2, 3):
            raise SdJwtError("Malformed disclosure")
        by_digest[digest] = decoded

    used: set[str] = set()
    paths: list[str] = []

    def take(digest: str) -> list[Any] | None:
        if digest in used:
            raise SdJwtError("Digest referenced twice")
        found = by_digest.get(digest)
        if found is not None:
            used.add(digest)
        return found

    def walk(node: Any, path: str) -> Any:
        if isinstance(node, dict):
            output: dict[str, Any] = {}
            for digest in node.get("_sd", []):
                found = take(digest)
                if found is None:
                    continue
                if len(found) != 3:
                    raise SdJwtError("Object disclosure must name a claim")
                _, name, value = found
                if name in ("_sd", "...") or name in node or name in output:
                    raise SdJwtError("Disclosure overwrites an existing claim")
                child = f"{path}.{name}" if path else name
                paths.append(child)
                output[name] = walk(value, child)
            for key, value in node.items():
                if key not in ("_sd", "_sd_alg"):
                    output[key] = walk(value, f"{path}.{key}" if path else key)
            return output
        if isinstance(node, list):
            items: list[Any] = []
            for index, item in enumerate(node):
                if isinstance(item, dict) and set(item) == {"..."}:
                    found = take(item["..."])
                    if found is None:
                        continue
                    if len(found) != 2:
                        raise SdJwtError("Array disclosure must not name a claim")
                    child = f"{path}[{index}]"
                    paths.append(child)
                    items.append(walk(found[1], child))
                else:
                    items.append(walk(item, f"{path}[{index}]"))
            return items
        return node

    claims = walk(payload, "")
    if len(used) != len(by_digest):
        raise SdJwtError("A disclosure is not covered by the issuer's signature")
    return Reconstruction(claims, paths)
