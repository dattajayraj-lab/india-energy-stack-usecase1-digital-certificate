"""Stateless Passport verification.

This module must never import the database, the adapter or any issuer service: "anyone
can verify without calling the DISCOM" is a product promise, and
tests/test_verifier_isolation.py enforces it. Everything the verifier needs comes from
public sources: the issuer's did.json, the DeDi registry and the credential itself.

Check order follows IES "Verify a credential you received".
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import Any, Literal, Protocol

from ..crypto.did import DidError, did_web_domain, did_web_url, holder_jwk, is_wallet_did
from ..crypto.encoding import b64u_encode
from ..crypto.jose import JoseError, decode_compact, expected_alg, verify_compact, verify_signature
from ..ies import partial_subject_validator, schema_errors, subject_validator
from . import sdjwt
from .fetch import FetchError, SafeFetcher
from .jsonld import CanonicalisationError, verify_jws2020

Status = Literal["pass", "fail", "warn", "skip"]
ALLOWED_SD_TYP = {"vc+sd-jwt", "dc+sd-jwt"}
MAX_KB_AGE_SECONDS = 7 * 24 * 3600
CLOCK_SKEW_SECONDS = 60
SUBJECT_CLAIMS = ("customerDetails", "customerProfile")


class Cache(Protocol):
    async def get(self, key: str) -> Any: ...

    async def set(self, key: str, value: Any, ex: int | None = None) -> Any: ...


@dataclass
class Check:
    id: str
    status: Status
    detail: str


@dataclass
class VerificationResult:
    valid: bool = False
    format: str = "unknown"
    issuer: str | None = None
    credential_id: str | None = None
    valid_until: str | None = None
    checks: list[Check] = field(default_factory=list)
    disclosed: dict[str, Any] = field(default_factory=dict)
    disclosed_paths: list[str] = field(default_factory=list)

    def add(self, check_id: str, status: Status, detail: str) -> None:
        self.checks.append(Check(check_id, status, detail))

    def finish(self) -> VerificationResult:
        self.valid = bool(self.checks) and all(c.status != "fail" for c in self.checks)
        return self

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _iso(epoch: int | None) -> str | None:
    return None if epoch is None else time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(epoch))


def _epoch(value: str | None) -> int | None:
    return int(datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()) if value else None


def plaintext_claims(payload: dict[str, Any]) -> list[str]:
    """Name any consumer field the issuer left outside `_sd`.

    OpenCred silently ignores nested disclosure paths, so an "SD-JWT" can reach a verifier
    with every field in the clear. This check makes that a failure, not a quiet leak.
    """
    leaked: list[str] = []
    details = payload.get("customerDetails") or {}
    leaked += [f"customerDetails.{k}" for k in details if k != "_sd"]
    profile = payload.get("customerProfile") or {}
    structural = ("_sd", "energyResources", "consumptionProfiles")
    leaked += [f"customerProfile.{k}" for k in profile if k not in structural]
    for item in profile.get("energyResources") or []:
        if not (isinstance(item, dict) and set(item) == {"..."}):
            leaked.append("customerProfile.energyResources[]")
    for item in profile.get("consumptionProfiles") or []:
        if isinstance(item, dict):
            leaked += [f"customerProfile.consumptionProfiles[].{k}" for k in item if k != "_sd"]
    return leaked


class Verifier:
    def __init__(
        self,
        fetcher: SafeFetcher,
        cache: Cache | None = None,
        allow_http_did: bool = False,
        dedi_base_url: str = "https://api.dedi.global",
    ) -> None:
        self._fetcher = fetcher
        self._cache = cache
        self._allow_http_did = allow_http_did
        self._dedi_base_url = dedi_base_url.rstrip("/")

    async def verify(
        self,
        presented: str | dict[str, Any],
        expected_nonce: str | None = None,
        expected_audience: str | None = None,
    ) -> VerificationResult:
        result = VerificationResult()
        if isinstance(presented, str):
            presented = presented.strip()
            if presented.startswith("{"):
                try:
                    presented = json.loads(presented)
                except ValueError:
                    result.add("format", "fail", "The input is not valid JSON.")
                    return result.finish()
        if isinstance(presented, dict):
            proof = presented.get("proof")
            if isinstance(proof, dict) and "jws" in proof:
                await self._verify_jws2020(presented, result)
            elif isinstance(proof, dict) and "jwt" in proof:
                await self._verify_vc_jwt(proof["jwt"], result)
            else:
                result.add("format", "fail", "Unrecognised credential proof.")
        elif "~" in presented:
            await self._verify_sd_jwt(presented, result, expected_nonce, expected_audience)
        elif presented.count(".") == 2:
            await self._verify_vc_jwt(presented, result)
        else:
            result.add("format", "fail", "Not a recognised Passport format.")
        return result.finish()

    # -- shared steps ------------------------------------------------------------------

    async def _resolve_key(
        self, issuer: Any, kid: str | None, result: VerificationResult
    ) -> dict[str, Any] | None:
        """Resolve the issuer DID and find a key it allows to issue credentials."""
        if not isinstance(issuer, str) or not issuer.startswith("did:web:"):
            result.add("issuer_did", "fail", "The issuer is not a did:web.")
            return None
        try:
            document = await self._did_document(issuer)
        except (DidError, FetchError, ValueError) as exc:
            result.add("issuer_did", "fail", f"Issuer DID could not be resolved: {exc}")
            return None
        if document.get("id") != issuer:
            result.add("issuer_did", "fail", "The DID document does not belong to this issuer.")
            return None
        if kid and kid.split("#")[0] != issuer:
            result.add("issuer_did", "fail", "The signing key is not under the issuer's DID.")
            return None
        allowed = {r if isinstance(r, str) else r.get("id") for r in document.get("assertionMethod", [])}
        for method in document.get("verificationMethod", []):
            if method.get("id") in allowed and (kid is None or method.get("id") == kid):
                result.add("issuer_did", "pass", f"Resolved {issuer}.")
                return method.get("publicKeyJwk")
        result.add("issuer_did", "fail", "No matching assertion key in the issuer's DID document.")
        return None

    async def _did_document(self, did: str) -> dict[str, Any]:
        cache_key = f"did:{did}"
        if self._cache:
            cached = await self._cache.get(cache_key)
            if cached:
                return json.loads(cached)
        response = await self._fetcher.get(did_web_url(did, allow_http=self._allow_http_did))
        if response.status != 200:
            raise FetchError(f"DID document returned HTTP {response.status}")
        document = json.loads(response.text)
        if self._cache:
            await self._cache.set(cache_key, json.dumps(document), ex=3600)
        return document

    async def _check_directory(self, issuer: str, result: VerificationResult) -> None:
        """Architecture: the verifier looks the issuer up in the DeDi directory."""
        namespace = did_web_domain(issuer)
        try:
            response = await self._fetcher.get(f"{self._dedi_base_url}/dedi/lookup/{namespace}")
        except FetchError as exc:
            result.add("issuer_directory", "warn", f"DeDi directory unreachable: {exc}")
            return
        if response.status == 200:
            result.add("issuer_directory", "pass", f"{namespace} is listed in DeDi.")
        else:
            result.add("issuer_directory", "fail", f"{namespace} is not listed in the DeDi directory.")

    async def _check_revocation(self, status: dict[str, Any] | None, result: VerificationResult) -> None:
        """Record existence signals revocation: 404 is valid, 200 is revoked. Fail closed."""
        if not status:
            result.add("revocation", "warn", "This credential carries no revocation status.")
            return
        url = status.get("id")
        if not isinstance(url, str):
            result.add("revocation", "fail", "Malformed credentialStatus.")
            return
        cache_key = f"status:{url.rsplit('/', 1)[-1]}"
        if self._cache and await self._cache.get(cache_key) in (b"ok", "ok"):
            result.add("revocation", "pass", "Not revoked.")
            return
        try:
            response = await self._fetcher.get(url)
        except FetchError as exc:
            result.add("revocation", "fail", f"Revocation status unavailable, so do not rely on this: {exc}")
            return
        if response.status == 404:
            if self._cache:
                await self._cache.set(cache_key, "ok", ex=300)
            result.add("revocation", "pass", "Not revoked.")
        elif response.status == 200:
            result.add("revocation", "fail", "This Passport has been revoked by the issuer.")
        else:
            result.add("revocation", "fail", f"Revocation registry returned HTTP {response.status}.")

    @staticmethod
    def _check_window(nbf: int | None, exp: int | None, result: VerificationResult) -> None:
        now = time.time()
        if nbf is not None and now + CLOCK_SKEW_SECONDS < nbf:
            result.add("validity", "fail", "This Passport is not valid yet.")
        elif exp is not None and now - CLOCK_SKEW_SECONDS > exp:
            result.add("validity", "fail", f"This Passport expired on {_iso(exp)}.")
        else:
            result.add("validity", "pass", f"Valid until {_iso(exp)}." if exp else "No expiry set.")

    # -- SD-JWT ------------------------------------------------------------------------

    async def _verify_sd_jwt(
        self,
        token: str,
        result: VerificationResult,
        expected_nonce: str | None,
        expected_audience: str | None,
    ) -> None:
        result.format = "sd-jwt-vc"
        try:
            parsed = sdjwt.parse(token)
            header, payload, signing_input, signature = decode_compact(parsed.issuer_jwt)
        except (sdjwt.SdJwtError, JoseError, ValueError):
            result.add("format", "fail", "The SD-JWT is malformed.")
            return
        if header.get("typ") not in ALLOWED_SD_TYP or payload.get("vct") != "ElectricityCredential":
            result.add("format", "fail", "This is not an ElectricityCredential SD-JWT.")
            return
        result.add("format", "pass", "SD-JWT VC, ElectricityCredential.")
        result.issuer = payload.get("iss")
        result.credential_id = payload.get("jti")
        result.valid_until = _iso(payload.get("exp"))

        jwk = await self._resolve_key(payload.get("iss"), header.get("kid"), result)
        if jwk is None:
            return
        if header.get("alg") != expected_alg(jwk) or not verify_signature(jwk, signing_input, signature):
            result.add("signature", "fail", "The issuer's seal is broken: this credential has been altered.")
            return
        result.add("signature", "pass", "The issuer's seal is intact.")
        await self._check_directory(payload["iss"], result)

        try:
            rebuilt = sdjwt.reconstruct(payload, parsed.disclosures)
        except sdjwt.SdJwtError as exc:
            result.add("disclosures", "fail", f"Disclosed fields do not match the seal: {exc}")
            return
        leaked = plaintext_claims(payload)
        if leaked:
            result.add("disclosures", "fail", f"Fields exposed outside selective disclosure: {leaked[:5]}")
        else:
            result.add("disclosures", "pass", f"{len(parsed.disclosures)} item(s) disclosed, all under the seal.")
        subject = {k: rebuilt.claims[k] for k in SUBJECT_CLAIMS if k in rebuilt.claims}
        if "sub" in rebuilt.claims:
            subject["id"] = rebuilt.claims["sub"]
        result.disclosed = subject
        result.disclosed_paths = sorted(rebuilt.paths)

        errors = schema_errors(partial_subject_validator(), subject)
        if errors:
            result.add("schema", "fail", f"Disclosed fields break ElectricityCredential v1.2: {errors[:3]}")
        else:
            result.add("schema", "pass", "Disclosed fields conform to ElectricityCredential v1.2.")

        await self._check_revocation(payload.get("credentialStatus"), result)
        self._check_window(payload.get("nbf"), payload.get("exp"), result)
        self._check_holder(payload, parsed, result, expected_nonce, expected_audience)

    @staticmethod
    def _check_holder(
        payload: dict[str, Any],
        parsed: sdjwt.ParsedSdJwt,
        result: VerificationResult,
        expected_nonce: str | None,
        expected_audience: str | None,
    ) -> None:
        holder = (payload.get("cnf") or {}).get("jwk")
        if holder is None and is_wallet_did(payload.get("sub")):
            try:
                holder = holder_jwk(payload["sub"])
            except DidError:
                result.add("holder_binding", "fail", "The holder DID cannot be decoded.")
                return
        if holder is None:
            result.add("holder_binding", "warn", "Bearer Passport: the presenter's control of it is not proven.")
            return
        if parsed.key_binding_jwt is None:
            result.add("holder_binding", "fail", "The holder's proof is missing, so this may be a stolen copy.")
            return
        try:
            header, claims = verify_compact(parsed.key_binding_jwt, holder)
        except JoseError:
            result.add("holder_binding", "fail", "The holder's proof does not match this Passport.")
            return
        digest = hashlib.sha256(parsed.sd_hash_input.encode("ascii")).digest()
        if header.get("typ") != "kb+jwt" or claims.get("sd_hash") != b64u_encode(digest):
            result.add("holder_binding", "fail", "The holder's proof does not cover these fields.")
            return
        now = time.time()
        issued = claims.get("iat", 0)
        if issued > now + CLOCK_SKEW_SECONDS or now - issued > MAX_KB_AGE_SECONDS:
            result.add("holder_binding", "fail", "The holder's proof is out of date.")
        elif expected_nonce and claims.get("nonce") != expected_nonce:
            result.add("holder_binding", "fail", "The holder's proof is for a different challenge (possible replay).")
        elif expected_audience and claims.get("aud") != expected_audience:
            result.add("holder_binding", "fail", "The holder's proof was made for a different verifier.")
        elif expected_nonce:
            result.add("holder_binding", "pass", "The presenter proved control of the wallet for this challenge.")
        else:
            result.add("holder_binding", "warn", "Holder proof is valid but not tied to a fresh challenge.")

    # -- full credentials --------------------------------------------------------------

    async def _verify_jws2020(self, credential: dict[str, Any], result: VerificationResult) -> None:
        result.format = "jws-2020"
        if "ElectricityCredential" not in (credential.get("type") or []):
            result.add("format", "fail", "This is not an ElectricityCredential.")
            return
        result.add("format", "pass", "W3C VC 2.0, JsonWebSignature2020, ElectricityCredential.")
        issuer = credential.get("issuer")
        issuer = issuer.get("id") if isinstance(issuer, dict) else issuer
        result.issuer = issuer
        result.credential_id = credential.get("id")
        result.valid_until = credential.get("validUntil")
        proof = credential["proof"]
        jwk = await self._resolve_key(issuer, proof.get("verificationMethod"), result)
        if jwk is None:
            return
        try:
            sound = verify_jws2020(credential, jwk)
        except Exception as exc:  # noqa: BLE001 - pyld raises its own broad error types
            detail = str(exc) if isinstance(exc, CanonicalisationError) else type(exc).__name__
            result.add("signature", "fail", f"The credential could not be canonicalised: {detail}")
            return
        if not sound:
            result.add("signature", "fail", "The issuer's seal is broken: this credential has been altered.")
            return
        result.add("signature", "pass", "The issuer's seal is intact.")
        await self._finish_full(credential, issuer, result)

    async def _verify_vc_jwt(self, token: str, result: VerificationResult) -> None:
        result.format = "vc-jwt"
        try:
            header, payload, _, _ = decode_compact(token)
        except JoseError:
            result.add("format", "fail", "The JWT is malformed.")
            return
        credential = payload.get("vc", payload)
        if "ElectricityCredential" not in (credential.get("type") or []):
            result.add("format", "fail", "This is not an ElectricityCredential.")
            return
        result.add("format", "pass", "W3C VC 2.0 as JWT, ElectricityCredential.")
        issuer = credential.get("issuer") or payload.get("iss")
        issuer = issuer.get("id") if isinstance(issuer, dict) else issuer
        result.issuer = issuer
        result.credential_id = credential.get("id") or payload.get("jti")
        result.valid_until = credential.get("validUntil")
        jwk = await self._resolve_key(issuer, header.get("kid"), result)
        if jwk is None:
            return
        try:
            verify_compact(token, jwk)
        except JoseError:
            result.add("signature", "fail", "The issuer's seal is broken: this credential has been altered.")
            return
        result.add("signature", "pass", "The issuer's seal is intact.")
        await self._finish_full(credential, issuer, result)

    async def _finish_full(self, credential: dict[str, Any], issuer: str, result: VerificationResult) -> None:
        await self._check_directory(issuer, result)
        subject = credential.get("credentialSubject") or {}
        result.disclosed = subject
        errors = schema_errors(subject_validator(), subject)
        if errors:
            result.add("schema", "fail", f"The credential breaks ElectricityCredential v1.2: {errors[:3]}")
        else:
            result.add("schema", "pass", "Conforms to ElectricityCredential v1.2.")
        await self._check_revocation(credential.get("credentialStatus"), result)
        self._check_window(_epoch(credential.get("validFrom")), _epoch(credential.get("validUntil")), result)
        if is_wallet_did(subject.get("id")):
            result.add("holder_binding", "warn", "Full credential: challenge the holder's wallet separately.")
        else:
            result.add("holder_binding", "skip", "Bound through the delivery channel, such as DigiLocker.")
