"""JsonWebSignature2020 sign and verify over the RDFC-1.0 canonical form.

The detached JWS covers sha256(canon(proof options)) || sha256(canon(document)), the
Linked Data Proofs construction. tests/test_opencred_live.py checks this against a real
OpenCred-signed credential.
"""

from __future__ import annotations

import copy
import hashlib
from typing import Any

from pyld import jsonld

from ..crypto.encoding import b64u_decode, b64u_encode, json_b64u
from ..crypto.jose import sign_es256, verify_signature
from ..ies import jsonld_documents


class CanonicalisationError(ValueError):
    """The document references a context that is not one of the known IES contexts."""


def _loader(url: str, _options: dict[str, Any]) -> dict[str, Any]:
    # Never fetch contexts remotely: a verifier input must not choose what we download.
    document = jsonld_documents().get(url)
    if document is None:
        raise CanonicalisationError(f"Unknown JSON-LD context: {url}")
    return {"contentType": "application/ld+json", "contextUrl": None, "documentUrl": url, "document": document}


def _canonical_hash(document: dict[str, Any]) -> bytes:
    canon = jsonld.normalize(
        document,
        {"algorithm": "URDNA2015", "format": "application/n-quads", "documentLoader": _loader},
    )
    return hashlib.sha256(canon.encode("utf-8")).digest()


def _signing_payload(credential: dict[str, Any]) -> tuple[bytes, dict[str, Any]]:
    document = copy.deepcopy(credential)
    proof = document.pop("proof")
    options = {k: v for k, v in proof.items() if k != "jws"}
    options["@context"] = document["@context"]
    return _canonical_hash(options) + _canonical_hash(document), proof


def verify_jws2020(credential: dict[str, Any], jwk: dict[str, Any]) -> bool:
    payload, proof = _signing_payload(credential)
    header, separator, signature = proof["jws"].partition("..")
    if not separator:
        return False
    return verify_signature(jwk, header.encode("ascii") + b"." + payload, b64u_decode(signature))


def sign_jws2020(credential: dict[str, Any], proof: dict[str, Any], private_key: Any) -> str:
    payload, _ = _signing_payload({**credential, "proof": proof})
    header = json_b64u({"alg": "ES256", "b64": False, "crit": ["b64"]})
    signature = sign_es256(private_key, header.encode("ascii") + b"." + payload)
    return f"{header}..{b64u_encode(signature)}"
