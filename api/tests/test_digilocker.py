"""DigiLocker Pull URI for NYCER, shapes from the IES implementation guide."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re

from app.config import get_settings
from tests.conftest import ARJUN, LAKSHMI, Wallet, check, issue_to_wallet, verify

URL = "/digilocker/pulluri"


def pull_xml(consumer_no=LAKSHMI, mobile="9000000001", name="Lakshmi Naidu", doc="NYCER") -> bytes:
    return f"""<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<PullURIRequest ver="3.0" ts="2026-11-05T10:30:00+05:30" txn="TXN-1" orgId="discom">
  <DocDetails><DocType>{doc}</DocType><DigiLockerId>dl-7a3f</DigiLockerId>
  <UDF1>{consumer_no}</UDF1><UDF2>{mobile}</UDF2><FullName>{name}</FullName></DocDetails>
</PullURIRequest>""".encode()


def signed(body: bytes) -> dict:
    digest = hmac.new(get_settings().digilocker_api_key.encode(), body, hashlib.sha256).digest()
    headers = {"x-digilocker-hmac": base64.b64encode(digest).decode(), "content-type": "application/xml"}
    return {"content": body, "headers": headers}


def tag(xml: str, name: str) -> str:
    return re.search(rf"<{name}[^>]*>(.*?)</{name}>", xml, re.S).group(1)


def credential_from(xml: str) -> dict:
    return json.loads(base64.b64decode(tag(xml, "VcContent")))


async def test_pull_returns_a_verifiable_nycer_credential(client):
    xml = (await client.post(URL, **signed(pull_xml()))).text
    assert 'Status="1"' in xml and 'txn="TXN-1"' in xml
    assert tag(xml, "URI") == f"{get_settings().digilocker_org_id}-NYCER-{LAKSHMI}"
    assert tag(xml, "IssuedTo") == "Lakshmi Naidu"
    assert tag(xml, "VcType") == "application/ld+json"
    assert xml.index("</VcContent>") < xml.index("<VcType>"), "NeGD requires VcType right after VcContent"
    assert base64.b64decode(tag(xml, "DocContent")).startswith(b"%PDF")

    credential = credential_from(xml)
    profile = credential["credentialSubject"]["customerProfile"]
    assert profile["idRef"] == {"issuedBy": "did:web:digilocker.gov.in", "subjectId": "digilocker.gov.in:dl-7a3f"}
    contexts = credential["@context"]
    inline = next(i for i, c in enumerate(contexts) if c.endswith("context.inline.jsonld"))
    main = next(i for i, c in enumerate(contexts) if c.endswith("v1.2/context.jsonld"))
    assert inline < main, "DigiLocker needs the inline context first"
    result = await verify(client, credential)
    assert result["format"] == "jws-2020" and result["valid"], result["checks"]
    assert check(result, "revocation") == "warn"  # D-06


async def test_nycer_keeps_capacity_and_omits_only_unsignable_fields(client):
    credential = credential_from((await client.post(URL, **signed(pull_xml()))).text)
    resources = credential["credentialSubject"]["customerProfile"]["energyResources"]
    solar = next(r for r in resources if r["type"] == "SOLAR_PV")
    assert solar["attributes"]["maxExport"] == {"value": 5, "unit": "kW"}
    assert "inspection" not in solar["attributes"]  # D-07


async def test_tampered_jws2020_credential_fails(client):
    credential = credential_from((await client.post(URL, **signed(pull_xml()))).text)
    profile = credential["credentialSubject"]["customerProfile"]
    profile["consumptionProfiles"][0]["sanctionedLoad"]["value"] = 80
    result = await verify(client, credential)
    assert not result["valid"] and check(result, "signature") == "fail"


async def test_bad_hmac_is_rejected_before_parsing(client):
    response = await client.post(URL, content=pull_xml(), headers={"x-digilocker-hmac": "bad"})
    assert response.status_code == 401


async def test_wrong_mobile_and_unknown_consumer_look_identical(client):
    wrong_mobile = await client.post(URL, **signed(pull_xml(mobile="9999999999")))
    unknown = await client.post(URL, **signed(pull_xml(consumer_no="9999999999")))
    assert 'Status="0"' in wrong_mobile.text
    assert tag(wrong_mobile.text, "ResponseStatus") == tag(unknown.text, "ResponseStatus")


async def test_name_mismatch_is_refused(client):
    response = await client.post(URL, **signed(pull_xml(name="Somebody Else")))
    assert 'Status="0"' in response.text


async def test_xxe_payload_is_refused(client):
    body = b"""<?xml version="1.0"?><!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/passwd">]>
    <PullURIRequest ts="t" txn="t" orgId="o"><DocDetails><UDF1>&e;</UDF1></DocDetails></PullURIRequest>"""
    response = await client.post(URL, **signed(body))
    assert 'Status="0"' in response.text


async def test_refresh_supersedes_the_previous_document(client):
    first = await client.post(URL, **signed(pull_xml()))
    assert 'Status="1"' in first.text
    second = await client.post(URL, **signed(pull_xml()))
    assert 'Status="1"' in second.text
    assert tag(first.text, "VcContent") != tag(second.text, "VcContent")


async def test_refresh_replaces_a_wallet_passport(client):
    wallet = Wallet()
    issued, _ = await issue_to_wallet(client, LAKSHMI, wallet)
    assert 'Status="1"' in (await client.post(URL, **signed(pull_xml()))).text
    assert check(await verify(client, wallet.present(issued["credential"])), "revocation") == "fail"


async def test_blocked_record_is_refused(client):
    body = pull_xml(consumer_no=ARJUN, mobile="9000000004", name="Arjun Rao")
    response = await client.post(URL, **signed(body))
    assert 'Status="0"' in response.text
