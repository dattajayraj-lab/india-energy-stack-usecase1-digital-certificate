"""End-to-end flows: issue, share, verify, revoke, re-issue."""

from __future__ import annotations

import hashlib
import hmac
import json

from sqlalchemy import select

from app.config import get_settings
from app.crypto.encoding import b64u_decode, sha256_b64u
from app.db import get_sessionmaker
from app.models import AuditLog, ConsentRecord, ConsumerRef, Passport
from tests.conftest import (
    ARJUN,
    FARIDA,
    LAKSHMI,
    MEENA,
    ROHAN,
    Wallet,
    check,
    decode,
    issue_to_wallet,
    login_consumer,
    login_staff,
    verify,
)


def sanctioned_load_only(disclosure: list) -> bool:
    return len(disclosure) == 3 and disclosure[1] == "sanctionedLoad"


async def test_full_disclosure_passes_every_check(client):
    wallet = Wallet()
    issued, _ = await issue_to_wallet(client, LAKSHMI, wallet)
    presentation = wallet.present(issued["credential"], nonce="abc", audience="bank")
    result = await verify(client, presentation, expected_nonce="abc", expected_audience="bank")
    assert result["valid"], result["checks"]
    assert {c["status"] for c in result["checks"]} == {"pass"}
    assert result["disclosed"]["customerDetails"]["fullName"] == "Lakshmi Naidu"
    assert issued["passport"]["binding"] == "wallet"


async def test_lender_sees_sanctioned_load_and_nothing_else(client):
    """The use-case promise: 'Sanctioned load for a lender. Nothing more.'"""
    wallet = Wallet()
    issued, _ = await issue_to_wallet(client, LAKSHMI, wallet)
    presentation = wallet.present(issued["credential"], keep=sanctioned_load_only)
    result = await verify(client, presentation)
    assert result["valid"], result["checks"]
    assert "Lakshmi" not in json.dumps(result["disclosed"])
    assert "customerNumber" not in json.dumps(result["disclosed"])
    assert result["disclosed"]["customerProfile"]["consumptionProfiles"][0]["sanctionedLoad"]["value"] == 8
    assert result["disclosed"]["customerProfile"]["energyResources"] == []


async def test_signed_payload_has_no_personal_data_in_the_clear(client):
    wallet = Wallet()
    issued, _ = await issue_to_wallet(client, LAKSHMI, wallet)
    text = b64u_decode(issued["credential"].split("~")[0].split(".")[1]).decode()
    for secret in ("Lakshmi", "Dwaraka", "530016", LAKSHMI, "NM-10001", "LT2A"):
        assert secret not in text


async def test_marketplace_can_get_solar_capacity_only(client):
    wallet = Wallet()
    issued, _ = await issue_to_wallet(client, LAKSHMI, wallet)

    disclosures = issued["credential"].split("~")[1:-1]
    [solar] = [d for d in map(decode, disclosures) if len(d) == 2 and d[1].get("type") == "SOLAR_PV"]
    solar_attributes = set(solar[1]["attributes"]["_sd"])
    wanted = {
        json.dumps(d)
        for raw, d in zip(disclosures, map(decode, disclosures), strict=True)
        if d == solar or (sha256_b64u(raw) in solar_attributes and d[1] == "maxExport")
    }

    result = await verify(client, wallet.present(issued["credential"], keep=lambda d: json.dumps(d) in wanted))
    assert result["valid"], result["checks"]
    [resource] = result["disclosed"]["customerProfile"]["energyResources"]
    assert resource["type"] == "SOLAR_PV"
    assert resource["attributes"] == {"maxExport": {"value": 5, "unit": "kW"}}


async def test_revocation_reaches_verifiers_immediately(client):
    wallet = Wallet()
    issued, _ = await issue_to_wallet(client, LAKSHMI, wallet)
    presentation = wallet.present(issued["credential"])
    assert (await verify(client, presentation))["valid"]  # warms the status cache
    admin = await login_staff(client)
    response = await client.post(
        f"/api/v1/passports/{issued['passport']['id']}/revoke", json={"reason": "request"}, headers=admin
    )
    assert response.status_code == 200, response.text
    result = await verify(client, presentation)
    assert not result["valid"]
    assert check(result, "revocation") == "fail"


async def test_source_change_revokes_then_consumer_collects_new_version(client):
    wallet = Wallet()
    issued, headers = await issue_to_wallet(client, LAKSHMI, wallet)
    body = json.dumps({"event_id": "evt-1", "consumer_no": LAKSHMI, "event": "meter_swap"}).encode()
    signature = hmac.new(get_settings().webhook_secret.encode(), body, hashlib.sha256).hexdigest()
    post = {"content": body, "headers": {"x-adapter-signature": signature}}
    response = await client.post("/api/v1/webhooks/source-change", **post)
    assert response.json()["action"] == "revoked_pending_reissue"
    assert (await client.post("/api/v1/webhooks/source-change", **post)).json()["action"] == "duplicate_event"

    old = wallet.present(issued["credential"])
    assert check(await verify(client, old), "revocation") == "fail"
    mine = (await client.get("/api/v1/passports/mine", headers=headers)).json()
    assert mine[0]["reissue_pending"] is True

    fresh, _ = await issue_to_wallet(client, LAKSHMI, wallet)
    assert fresh["passport"]["version"] == 2
    assert (await verify(client, wallet.present(fresh["credential"])))["valid"]
    mine = (await client.get("/api/v1/passports/mine", headers=headers)).json()
    assert not any(p["reissue_pending"] for p in mine)


async def test_webhook_rejects_a_bad_signature(client):
    response = await client.post(
        "/api/v1/webhooks/source-change",
        json={"event_id": "e", "consumer_no": LAKSHMI, "event": "meter_swap"},
        headers={"x-adapter-signature": "0" * 64},
    )
    assert response.status_code == 401


async def test_only_one_active_passport_per_connection(client):
    wallet = Wallet()
    await issue_to_wallet(client, MEENA, wallet)
    headers = await login_consumer(client, MEENA)
    nonce = (await client.post("/api/v1/passports/nonce", headers=headers)).json()
    response = await client.post(
        "/api/v1/passports/issue",
        json={
            "holder_did": wallet.did,
            "holder_proof": wallet.nonce_proof(nonce["nonce"], nonce["audience"]),
            "consent": True,
        },
        headers=headers,
    )
    assert response.status_code == 409


async def test_blocker_stops_issuance_and_warning_does_not(client):
    admin = await login_staff(client)
    blocked = await client.post(
        "/api/v1/passports/issue", json={"consumer_no": ARJUN, "consent": True}, headers=admin
    )
    assert blocked.status_code == 409
    codes = {f["code"] for f in blocked.json()["detail"]["flags"]}
    assert codes == {"MISSING_SANCTIONED_LOAD", "DUPLICATE_METER"}
    preview = (await client.get(f"/api/v1/admin/consumers/{FARIDA}/preview", headers=admin)).json()
    assert preview["issuable"] is True
    assert [f["code"] for f in preview["flags"]] == ["UNVERIFIED_ASSET"]
    allowed = await client.post(
        "/api/v1/passports/issue", json={"consumer_no": FARIDA, "consent": True}, headers=admin
    )
    assert allowed.status_code == 201


async def test_staff_issue_is_a_bearer_passport_and_can_be_claimed_by_a_wallet(client):
    admin = await login_staff(client)
    issued = (
        await client.post("/api/v1/passports/issue", json={"consumer_no": ROHAN, "consent": True}, headers=admin)
    ).json()
    assert issued["passport"]["binding"] == "discom-did"
    result = await verify(client, issued["credential"])
    assert result["valid"]
    assert check(result, "holder_binding") == "warn"

    wallet = Wallet()
    headers = await login_consumer(client, ROHAN)
    nonce = (await client.post("/api/v1/passports/nonce", headers=headers)).json()
    response = await client.post(
        f"/api/v1/passports/{issued['passport']['id']}/reissue",
        json={"holder_did": wallet.did, "holder_proof": wallet.nonce_proof(nonce["nonce"], nonce["audience"])},
        headers=headers,
    )
    assert response.status_code == 201, response.text
    claimed = response.json()
    assert claimed["passport"]["binding"] == "wallet" and claimed["passport"]["version"] == 2
    assert check(await verify(client, issued["credential"]), "revocation") == "fail"


async def test_share_link_round_trip_and_history(client):
    wallet = Wallet()
    issued, headers = await issue_to_wallet(client, LAKSHMI, wallet)
    presentation = wallet.present(issued["credential"], keep=sanctioned_load_only)
    paths = ["customerProfile.consumptionProfiles[0].sanctionedLoad"]
    created = await client.post(
        f"/api/v1/passports/{issued['passport']['id']}/share",
        json={
            "presentation": presentation,
            "disclosed_fields": paths,
            "ttl_seconds": 600,
            "verifier_hint": "Example Bank",
            "consent": True,
        },
        headers=headers,
    )
    assert created.status_code == 201, created.text
    share = created.json()
    assert "#share=" in share["url"]

    opened = await client.post("/api/v1/shares/open", json={"token": share["token"]})
    assert opened.json()["presentation"] == presentation
    history = (await client.get(f"/api/v1/passports/{issued['passport']['id']}/shares", headers=headers)).json()
    assert history[0]["used_count"] == 1 and history[0]["disclosed_fields"] == paths

    assert (await client.delete(f"/api/v1/shares/{share['share']['id']}", headers=headers)).status_code == 204
    assert (await client.post("/api/v1/shares/open", json={"token": share["token"]})).status_code == 410


async def test_redis_holds_no_readable_presentation(client):
    from app.cache import get_redis

    wallet = Wallet()
    issued, headers = await issue_to_wallet(client, LAKSHMI, wallet)
    presentation = wallet.present(issued["credential"])
    paths = (await verify(client, presentation))["disclosed_paths"]
    created = await client.post(
        f"/api/v1/passports/{issued['passport']['id']}/share",
        json={"presentation": presentation, "disclosed_fields": paths, "ttl_seconds": 600, "consent": True},
        headers=headers,
    )
    assert created.status_code == 201, created.text
    redis = get_redis()
    for key in await redis.keys("*"):
        if (await redis.type(key)) == b"string":
            value = await redis.get(key)
            assert b"Lakshmi" not in value and presentation[:40].encode() not in value
            assert created.json()["token"].encode() not in key


async def test_database_never_holds_the_credential_or_personal_data(client):
    wallet = Wallet()
    issued, _ = await issue_to_wallet(client, LAKSHMI, wallet)
    async with get_sessionmaker()() as session:
        passport = await session.scalar(select(Passport))
        ref = await session.scalar(select(ConsumerRef))
    row = json.dumps({c.name: str(getattr(passport, c.name)) for c in Passport.__table__.columns})
    assert issued["credential"][:60] not in row and "Lakshmi" not in row
    assert ref.mobile_hash and "9000000001" not in ref.mobile_hash


async def test_consent_and_audit_are_recorded(client):
    wallet = Wallet()
    await issue_to_wallet(client, LAKSHMI, wallet)
    async with get_sessionmaker()() as session:
        consent = (await session.scalars(select(ConsentRecord))).all()
        audit = (await session.scalars(select(AuditLog))).all()
    assert [c.purpose for c in consent] == ["issue"]
    assert audit[0].action == "passport.issue" and audit[0].actor == f"consumer:{LAKSHMI}"


async def test_dashboard_counts(client):
    wallet = Wallet()
    issued, _ = await issue_to_wallet(client, LAKSHMI, wallet)
    await verify(client, wallet.present(issued["credential"]))
    await verify(client, "garbage")
    admin = await login_staff(client)
    data = (await client.get("/api/v1/admin/dashboard", headers=admin)).json()
    assert (data["issued"], data["active"], data["verified_pass"], data["verified_fail"]) == (1, 1, 1, 1)
    assert len(data["by_day"]) == 14 and data["by_day"][-1]["issued"] == 1
