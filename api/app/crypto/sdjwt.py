"""SD-JWT issuance (RFC 9901) with field-level disclosure and revocation.

Why this is here rather than in OpenCred: in the image probed on 2026-11-05, OpenCred's
`selectiveDisclosureClaims` only conceals top-level claims and silently ignores nested
paths, and its sd-jwt-vc output omits credentialStatus. The Passport needs "sanctioned
load only", and it must stay revocable. See docs/DECISIONS.md, D-05.

The payload layout otherwise follows OpenCred: top-level customerProfile/customerDetails
with iss, vct, iat, nbf, exp, sub.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any

from .encoding import b64u_encode, json_b64u, sha256_b64u
from .keys import IssuerKey

SD_ALG = "sha-256"
VCT = "ElectricityCredential"
TYP = "vc+sd-jwt"


@dataclass
class _Builder:
    disclosures: list[str]

    def _encode(self, disclosure: list[Any]) -> str:
        encoded = json_b64u([b64u_encode(os.urandom(16)), *disclosure])
        self.disclosures.append(encoded)
        return sha256_b64u(encoded)

    def conceal_keys(self, obj: dict[str, Any], keep: tuple[str, ...] = ()) -> dict[str, Any]:
        """Replace every key except `keep` with a digest in `_sd`."""
        visible = {k: v for k, v in obj.items() if k in keep}
        digests = sorted(self._encode([k, v]) for k, v in obj.items() if k not in keep)
        return {**visible, "_sd": digests} if digests else visible

    def conceal_element(self, value: Any) -> dict[str, str]:
        return {"...": self._encode([value])}


def _conceal_resource(builder: _Builder, resource: dict[str, Any]) -> dict[str, str]:
    """A resource is hidden whole; once shown, each attribute is still chosen separately."""
    inner = dict(resource)
    attributes = inner.pop("attributes", None)
    inner = builder.conceal_keys(inner, keep=("id", "type"))
    if attributes is not None:
        inner["attributes"] = builder.conceal_keys(attributes)
    return builder.conceal_element(inner)


def conceal_subject(subject: dict[str, Any]) -> tuple[dict[str, Any], list[str]]:
    """Return the concealed customerProfile/customerDetails claims and their disclosures."""
    builder = _Builder([])
    profile = dict(subject["customerProfile"])
    resources = profile.pop("energyResources")
    consumption = profile.pop("consumptionProfiles", [])
    concealed_profile = builder.conceal_keys(profile)
    concealed_profile["energyResources"] = [_conceal_resource(builder, r) for r in resources]
    concealed_profile["consumptionProfiles"] = [builder.conceal_keys(c) for c in consumption]
    claims: dict[str, Any] = {"customerProfile": concealed_profile}
    if "customerDetails" in subject:
        claims["customerDetails"] = builder.conceal_keys(subject["customerDetails"])
    return claims, builder.disclosures


def issue_sd_jwt(
    key: IssuerKey,
    *,
    credential_id: str,
    subject: dict[str, Any],
    iat: int,
    nbf: int,
    exp: int,
    credential_status: dict[str, Any],
    holder_jwk: dict[str, Any] | None,
) -> str:
    claims, disclosures = conceal_subject(subject)
    payload: dict[str, Any] = {
        "iss": key.did,
        "vct": VCT,
        "jti": credential_id,
        "iat": iat,
        "nbf": nbf,
        "exp": exp,
        "credentialStatus": credential_status,
        "_sd_alg": SD_ALG,
        **claims,
    }
    if "id" in subject:
        payload["sub"] = subject["id"]
    if holder_jwk:
        payload["cnf"] = {"jwk": holder_jwk}
    return "~".join([key.sign_jwt({"typ": TYP}, payload), *disclosures]) + "~"
