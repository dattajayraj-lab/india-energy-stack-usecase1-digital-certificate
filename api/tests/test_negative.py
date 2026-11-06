"""Attacks and failure paths from the plan's negative-test list, and a few it did not name."""

from __future__ import annotations

import ast
import base64
import json
import time
from pathlib import Path

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric import ec

from app.crypto.encoding import json_b64u
from app.crypto.jose import sign_compact
from app.crypto.keys import IssuerKey, get_issuer_key
from app.crypto.sdjwt import issue_sd_jwt
from app.verifier.core import Verifier
from app.verifier.fetch import FetchError, SafeFetcher
from tests.conftest import LAKSHMI, Wallet, check, issue_to_wallet, login_consumer, login_staff, verify


def resign_payload(token: str, change) -> str:
    """Alter the signed payload and keep the original signature."""
    head, payload, signature = token.split("~")[0].split(".")
    data = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
    change(data)
    rest = token.split("~", 1)[1]
    return f"{head}.{json_b64u(data)}.{signature}~{rest}"


async def test_tampered_payload_breaks_the_seal(client):
    wallet = Wallet()
    issued, _ = await issue_to_wallet(client, LAKSHMI, wallet)
    forged = resign_payload(issued["credential"], lambda p: p.update(exp=p["exp"] + 10**8))
    result = await verify(client, forged)
    assert not result["valid"] and check(result, "signature") == "fail"


async def test_forged_disclosure_is_rejected(client):
    """Claiming 80 kW instead of 8 kW: the digest will not be under the issuer's seal."""
    wallet = Wallet()
    issued, _ = await issue_to_wallet(client, LAKSHMI, wallet)
    forged = json_b64u(["salt", "sanctionedLoad", {"value": 80, "unit": "kW"}])
    head, *rest = issued["credential"].split("~")
    result = await verify(client, "~".join([head, forged, *rest]))
    assert not result["valid"] and check(result, "disclosures") == "fail"


async def test_wrong_issuer_key_fails(client):
    """A forger signs with their own key but claims the DISCOM's DID."""
    forger = IssuerKey(ec.generate_private_key(ec.SECP256R1()), get_issuer_key().did)
    token = issue_sd_jwt(
        forger,
        credential_id="urn:uuid:00000000-0000-4000-8000-000000000000",
        subject={"customerProfile": {"customerNumber": "1", "energyResources": []}},
        iat=int(time.time()),
        nbf=int(time.time()),
        exp=int(time.time()) + 1000,
        credential_status={"id": "http://localhost:8000/mock-dedi/dedi/lookup/x/vc-revocation-registry/y"},
        holder_jwk=None,
    )
    result = await verify(client, token)
    assert not result["valid"] and check(result, "signature") == "fail"


async def test_alg_none_is_rejected(client):
    wallet = Wallet()
    issued, _ = await issue_to_wallet(client, LAKSHMI, wallet)
    head, payload, _ = issued["credential"].split("~")[0].split(".")
    header = json.loads(base64.urlsafe_b64decode(head + "=" * (-len(head) % 4)))
    forged = f"{json_b64u({**header, 'alg': 'none'})}.{payload}.~"
    assert not (await verify(client, forged))["valid"]


async def test_stolen_credential_cannot_be_presented_without_the_wallet_key(client):
    wallet = Wallet()
    issued, _ = await issue_to_wallet(client, LAKSHMI, wallet)
    without_proof = await verify(client, issued["credential"])
    assert not without_proof["valid"] and check(without_proof, "holder_binding") == "fail"
    thief = Wallet()
    stolen = thief.present(issued["credential"])
    result = await verify(client, stolen)
    assert not result["valid"] and check(result, "holder_binding") == "fail"


async def test_replayed_presentation_fails_a_fresh_challenge(client):
    wallet = Wallet()
    issued, _ = await issue_to_wallet(client, LAKSHMI, wallet)
    replay = wallet.present(issued["credential"], nonce="old-nonce")
    result = await verify(client, replay, expected_nonce="new-nonce")
    assert not result["valid"] and check(result, "holder_binding") == "fail"


async def test_presentation_for_another_verifier_is_rejected(client):
    wallet = Wallet()
    issued, _ = await issue_to_wallet(client, LAKSHMI, wallet)
    captured = wallet.present(issued["credential"], audience="other-bank")
    result = await verify(client, captured, expected_audience="this-bank")
    assert not result["valid"] and check(result, "holder_binding") == "fail"


async def test_disclosure_added_after_key_binding_is_caught(client):
    wallet = Wallet()
    issued, _ = await issue_to_wallet(client, LAKSHMI, wallet)
    presentation = wallet.present(issued["credential"], keep=lambda d: d[1] == "fullName")
    extra = issued["credential"].split("~")[2]
    head, *rest = presentation.split("~")
    result = await verify(client, "~".join([head, extra, *rest]))
    assert not result["valid"]


async def test_expired_credential_fails(client):
    key = get_issuer_key()
    past = int(time.time()) - 86400
    token = issue_sd_jwt(
        key,
        credential_id="urn:uuid:00000000-0000-4000-8000-000000000001",
        subject={"customerProfile": {"customerNumber": "1", "energyResources": []}},
        iat=past - 10,
        nbf=past - 10,
        exp=past,
        credential_status={"id": "http://localhost:8000/mock-dedi/dedi/lookup/x/vc-revocation-registry/y"},
        holder_jwk=None,
    )
    result = await verify(client, token)
    assert not result["valid"] and check(result, "validity") == "fail"


async def test_plaintext_leak_in_a_signed_token_is_flagged(client):
    """What OpenCred produces for nested paths: a valid seal with every field in the clear."""
    key = get_issuer_key()
    now = int(time.time())
    payload = {
        "iss": key.did,
        "vct": "ElectricityCredential",
        "nbf": now,
        "exp": now + 1000,
        "customerDetails": {"fullName": "Leaked Name"},
        "customerProfile": {"customerNumber": "1", "energyResources": []},
    }
    token = key.sign_jwt({"typ": "vc+sd-jwt"}, payload) + "~"
    result = await verify(client, token)
    assert not result["valid"] and check(result, "disclosures") == "fail"


async def test_expired_share_link_is_gone(client):
    from app.cache import get_redis
    from app.crypto.sealed import token_hash

    wallet = Wallet()
    issued, headers = await issue_to_wallet(client, LAKSHMI, wallet)
    presentation = wallet.present(issued["credential"], keep=lambda d: d[1] == "fullName")
    created = await client.post(
        f"/api/v1/passports/{issued['passport']['id']}/share",
        json={
            "presentation": presentation,
            "disclosed_fields": ["customerDetails.fullName"],
            "ttl_seconds": 60,
            "consent": True,
        },
        headers=headers,
    )
    assert created.status_code == 201, created.text
    token = created.json()["token"]
    await get_redis().delete(f"share:{token_hash(token)}")  # what Redis TTL expiry does
    assert (await client.post("/api/v1/shares/open", json={"token": token})).status_code == 410


async def test_extra_fields_in_a_share_are_rejected(client):
    wallet = Wallet()
    issued, headers = await issue_to_wallet(client, LAKSHMI, wallet)
    response = await client.post(
        f"/api/v1/passports/{issued['passport']['id']}/share",
        json={
            "presentation": wallet.present(issued["credential"]),  # discloses everything
            "disclosed_fields": ["customerDetails.fullName"],  # but the consumer ticked one field
            "ttl_seconds": 600,
            "consent": True,
        },
        headers=headers,
    )
    assert response.status_code == 422


async def test_share_needs_consent(client):
    wallet = Wallet()
    issued, headers = await issue_to_wallet(client, LAKSHMI, wallet)
    response = await client.post(
        f"/api/v1/passports/{issued['passport']['id']}/share",
        json={"presentation": "x~", "disclosed_fields": [], "ttl_seconds": 600, "consent": False},
        headers=headers,
    )
    assert response.status_code == 422


async def test_consumer_cannot_read_or_share_another_consumers_passport(client):
    wallet = Wallet()
    issued, _ = await issue_to_wallet(client, LAKSHMI, wallet)
    other = await login_consumer(client, "1100000003")
    url = f"/api/v1/passports/{issued['passport']['id']}"
    assert (await client.get(url, headers=other)).status_code == 404
    response = await client.post(
        f"{url}/share",
        json={"presentation": "x~", "disclosed_fields": [], "ttl_seconds": 600, "consent": True},
        headers=other,
    )
    assert response.status_code == 404


async def test_role_boundaries(client):
    wallet = Wallet()
    issued, consumer = await issue_to_wallet(client, LAKSHMI, wallet)
    revoke = f"/api/v1/passports/{issued['passport']['id']}/revoke"
    body = {"reason": "request"}
    assert (await client.post(revoke, json=body)).status_code == 401
    assert (await client.post(revoke, json=body, headers=consumer)).status_code == 403
    assert (await client.post(revoke, json=body, headers=await login_staff(client, "operator"))).status_code == 403
    auditor = await login_staff(client, "auditor")
    assert (await client.post(revoke, json=body, headers=auditor)).status_code == 403
    assert (await client.get("/api/v1/admin/audit", headers=auditor)).status_code == 200
    operator = await login_staff(client, "operator")
    assert (await client.get("/api/v1/admin/audit", headers=operator)).status_code == 403
    assert (await client.get("/api/v1/admin/dashboard", headers=consumer)).status_code == 403


async def test_holder_binding_needs_proof_of_control(client):
    """IES: copying a DID from an unauthenticated request makes holder binding worthless."""
    victim_wallet, attacker = Wallet(), Wallet()
    headers = await login_consumer(client, LAKSHMI)
    nonce = (await client.post("/api/v1/passports/nonce", headers=headers)).json()
    response = await client.post(
        "/api/v1/passports/issue",
        json={
            "holder_did": victim_wallet.did,
            "holder_proof": attacker.nonce_proof(nonce["nonce"], nonce["audience"]),
            "consent": True,
        },
        headers=headers,
    )
    assert response.status_code == 401


async def test_nonce_is_single_use_and_tied_to_the_consumer(client):
    wallet = Wallet()
    await issue_to_wallet(client, LAKSHMI, wallet)
    first = await login_consumer(client, LAKSHMI)
    nonce = (await client.post("/api/v1/passports/nonce", headers=first)).json()
    proof = wallet.nonce_proof(nonce["nonce"], nonce["audience"])
    other = await login_consumer(client, "1100000003")
    body = {"holder_did": wallet.did, "holder_proof": proof, "consent": True}
    assert (await client.post("/api/v1/passports/issue", json=body, headers=other)).status_code == 401
    assert (await client.post("/api/v1/passports/issue", json=body, headers=other)).status_code == 401


async def test_otp_lockout_and_no_account_enumeration(client):
    known = await client.post("/api/v1/auth/otp/request", json={"consumer_no": LAKSHMI})
    unknown = await client.post("/api/v1/auth/otp/request", json={"consumer_no": "9999999999"})
    assert known.status_code == unknown.status_code == 200
    assert set(known.json()) - {"dev_otp"} == set(unknown.json()) - {"dev_otp"}
    code = known.json()["dev_otp"]
    wrong = "000000" if code != "000000" else "111111"
    for _ in range(5):
        response = await client.post("/api/v1/auth/otp/verify", json={"consumer_no": LAKSHMI, "otp": wrong})
        assert response.status_code == 401
    # After five wrong attempts even the right code no longer works.
    response = await client.post("/api/v1/auth/otp/verify", json={"consumer_no": LAKSHMI, "otp": code})
    assert response.status_code == 401


async def test_otp_requests_are_rate_limited(client):
    statuses = [
        (await client.post("/api/v1/auth/otp/request", json={"consumer_no": LAKSHMI})).status_code for _ in range(6)
    ]
    assert statuses[-1] == 429


async def test_failed_revocation_keeps_the_passport_active(client, monkeypatch):
    from app.engine.base import EngineError, get_engine_instance

    wallet = Wallet()
    issued, _ = await issue_to_wallet(client, LAKSHMI, wallet)
    engine = get_engine_instance()

    async def fail(*_args):
        raise EngineError("down")

    monkeypatch.setattr(engine, "revoke", fail)
    admin = await login_staff(client)
    response = await client.post(
        f"/api/v1/passports/{issued['passport']['id']}/revoke", json={"reason": "request"}, headers=admin
    )
    assert response.status_code == 502
    passport = (await client.get(f"/api/v1/passports/{issued['passport']['id']}", headers=admin)).json()
    assert passport["status"] == "active"


async def test_revocation_outage_fails_closed(client):
    """If nobody can say it is not revoked, the verifier must not pass it."""
    wallet = Wallet()
    issued, _ = await issue_to_wallet(client, LAKSHMI, wallet)

    def outage(request: httpx.Request) -> httpx.Response:
        if "vc-revocation-registry" in request.url.path:
            raise httpx.ConnectError("down")
        return httpx.Response(200, json=get_issuer_key().did_document())

    http = httpx.AsyncClient(transport=httpx.MockTransport(outage))
    verifier = Verifier(SafeFetcher(http, allow_loopback=True), allow_http_did=True,
                        dedi_base_url="http://localhost:8000/mock-dedi")
    result = await verifier.verify(wallet.present(issued["credential"]))
    assert not result.valid
    assert next(c for c in result.checks if c.id == "revocation").status == "fail"


@pytest.mark.parametrize(
    "url",
    [
        "http://example.com/x",
        "https://127.0.0.1/x",
        "https://169.254.169.254/latest/meta-data",
        "https://10.0.0.1/x",
        "file:///etc/passwd",
    ],
)
async def test_verifier_refuses_ssrf_targets(url):
    async with httpx.AsyncClient() as http:
        with pytest.raises(FetchError):
            await SafeFetcher(http).get(url)


async def test_hostile_did_cannot_reach_internal_addresses(client):
    key = ec.generate_private_key(ec.SECP256R1())
    token = sign_compact(
        key,
        {"alg": "ES256", "typ": "vc+sd-jwt", "kid": "did:web:169.254.169.254#key-0"},
        {"iss": "did:web:169.254.169.254", "vct": "ElectricityCredential"},
    )
    result = await verify(client, token + "~")
    assert not result["valid"] and check(result, "issuer_did") == "fail"


def test_verifier_has_no_dependency_on_issuer_state():
    """The promise 'verify without calling the DISCOM', enforced at the import level."""
    forbidden = {"db", "models", "cache", "services", "routers", "engine", "security", "config"}
    for path in Path("app/verifier").glob("*.py"):
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if isinstance(node, ast.ImportFrom) and node.level >= 2:
                root = (node.module or "").split(".")[0]
                assert root not in forbidden, f"{path} imports {root}"
                names = {alias.name for alias in node.names}
                assert not (names & forbidden), f"{path} imports {names & forbidden}"
            if isinstance(node, ast.ImportFrom | ast.Import):
                module = getattr(node, "module", None) or ""
                assert not module.startswith(("sqlalchemy", "ies_adapter")), f"{path} imports {module}"
