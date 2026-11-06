"""OpenCred client. The first group uses a stub; `opencred`-marked tests hit a real container.

Run the live group with OPENCRED_TEST_URL and OPENCRED_TEST_KEY_FILE set, see docs/RUNBOOK.md.
"""

from __future__ import annotations

import json
import os
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
import pytest
from cryptography.hazmat.primitives import serialization
from ies_adapter import MockFileSource, build_subject

from app.config import get_settings
from app.crypto.keys import IssuerKey, get_issuer_key
from app.engine.base import EngineError, IssueRequest, revocation_hash
from app.engine.local import LocalEngine
from app.engine.opencred import OpenCredEngine
from app.ies import prune_for_jsonld, schema_errors, subject_validator
from app.verifier.jsonld import verify_jws2020

SUBJECT_DOMAIN = "ies.discom.example"


def subject() -> dict:
    source = MockFileSource()
    mapped = build_subject(source.fetch("1100000002"), SUBJECT_DOMAIN, meter_owners=source.meter_owners)
    assert schema_errors(subject_validator(), mapped.subject) == []
    return {"id": f"did:web:{SUBJECT_DOMAIN}:consumers:1100000002", **mapped.subject}


def request(proof_format: str) -> IssueRequest:
    now = datetime.now(UTC).replace(microsecond=0)
    body = prune_for_jsonld(subject())[0] if proof_format == "jws-2020" else subject()
    return IssueRequest(f"urn:uuid:{uuid.uuid4()}", body, now, now + timedelta(days=30), proof_format)


def test_fields_undefined_in_the_ies_context_are_reported():
    """Remove from this set as IES adds the terms; the test will say when that happens."""
    _, dropped = prune_for_jsonld(subject())
    names = {path.rsplit(".", 1)[-1] for path in dropped}
    assert {"serialNumber", "inspection", "dcArrayCapacity"} <= names


def stub_engine(handler) -> OpenCredEngine:
    settings = get_settings().model_copy(update={"opencred_url": "http://opencred", "opencred_api_key": "k"})
    return OpenCredEngine(settings, LocalEngine(settings, get_issuer_key()), httpx.MockTransport(handler))


async def test_jws2020_goes_to_opencred_with_the_documented_body():
    seen = {}

    def handler(http_request: httpx.Request) -> httpx.Response:
        seen.update(json.loads(http_request.content))
        seen["auth"] = http_request.headers["authorization"]
        return httpx.Response(200, json={"credential": {"id": "urn:uuid:11111111-1111-4111-8111-111111111111"}})

    issued = await stub_engine(handler).issue(request("jws-2020"))
    assert seen["schemaId"] == "ies/electricity-credential/v1.2"
    assert seen["proofFormat"] == "jws-2020" and seen["auth"] == "Bearer k"
    assert "revocationRegistryUrl" not in seen  # rejected by OpenCred with jws-2020, see D-06
    assert issued.credential_id == "urn:uuid:11111111-1111-4111-8111-111111111111"


async def test_sd_jwt_never_goes_to_opencred():
    def handler(_: httpx.Request) -> httpx.Response:
        raise AssertionError("sd-jwt-vc must be signed in-process")

    issued = await stub_engine(handler).issue(request("sd-jwt-vc"))
    assert isinstance(issued.credential, str) and issued.has_status


async def test_errors_never_echo_opencred_messages():
    def handler(_: httpx.Request) -> httpx.Response:
        body = {"error": {"code": "CRYPTO_ERROR", "message": "field fullName=Rohan Iyer rejected"}}
        return httpx.Response(500, json=body)

    with pytest.raises(EngineError) as caught:
        await stub_engine(handler).issue(request("jws-2020"))
    assert "Rohan" not in str(caught.value) and "CRYPTO_ERROR" in str(caught.value)


async def test_unreachable_opencred_is_an_engine_error():
    def handler(_: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused")

    with pytest.raises(EngineError):
        await stub_engine(handler).revoke("abc", "request")


def test_revocation_hash_matches_the_value_opencred_stamped():
    """Captured from the real image on 2026-11-05."""
    expected = "2a8e74b555ab9cf71c440e2d9113fe230a6be0484ce00990a51870de16902245"
    assert revocation_hash("urn:uuid:4ce40362-2690-4f5e-bd7a-c4c519b332e7") == expected


live = pytest.mark.skipif(not os.environ.get("OPENCRED_TEST_URL"), reason="OPENCRED_TEST_URL is not set")


def live_engine() -> tuple[OpenCredEngine, IssuerKey]:
    pem = Path(os.environ["OPENCRED_TEST_KEY_FILE"]).read_bytes()
    key = IssuerKey(serialization.load_pem_private_key(pem, None), f"did:web:{SUBJECT_DOMAIN}")
    settings = get_settings().model_copy(
        update={
            "issuer_domain": SUBJECT_DOMAIN,
            "opencred_url": os.environ["OPENCRED_TEST_URL"],
            "opencred_api_key": os.environ.get("OPENCRED_TEST_API_KEY", "probe-key"),
        }
    )
    return OpenCredEngine(settings, LocalEngine(settings, key)), key


@live
@pytest.mark.opencred
async def test_live_mapped_passport_is_signed_by_opencred_and_our_verifier_accepts_it():
    engine, key = live_engine()
    issued = await engine.issue(request("jws-2020"))
    assert verify_jws2020(issued.credential, key.public_jwk())
    tampered = json.loads(json.dumps(issued.credential))
    tampered["credentialSubject"]["customerProfile"]["customerNumber"] = "0"
    assert not verify_jws2020(tampered, key.public_jwk())


@live
@pytest.mark.opencred
async def test_live_pdf_rendering():
    engine, _ = live_engine()
    issued = await engine.issue(request("jws-2020"))
    pdf = await engine.render_pdf(issued.credential, "Consumer Energy Passport")
    assert pdf.startswith(b"%PDF")
