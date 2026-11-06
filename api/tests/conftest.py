"""Test harness: a real app, a real SQLite file and fake Redis, with no network.

The verifier's outbound client is routed back into the app, so did.json and DeDi lookups
exercise the real routes end to end.
"""

from __future__ import annotations

import base64
import json
import os
import tempfile
import time
from pathlib import Path

_TMP = Path(tempfile.mkdtemp(prefix="cep-tests-"))
os.environ.update(
    CEP_ENVIRONMENT="test",
    CEP_DATABASE_URL=f"sqlite+aiosqlite:///{(_TMP / 'test.db').as_posix()}",
    CEP_REDIS_URL="memory://",
    CEP_KEY_PATH=str(_TMP / "issuer-key.pem"),
)

import httpx  # noqa: E402
import pytest  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402

from app.cache import get_redis  # noqa: E402
from app.crypto.encoding import b64u_encode, json_b64u  # noqa: E402
from app.crypto.jose import sign_compact  # noqa: E402
from app.db import get_engine  # noqa: E402
from app.main import app, seed  # noqa: E402
from app.models import Base  # noqa: E402
from app.verifier import sdjwt as sd  # noqa: E402

ADMIN_PASSWORD = "ChangeMe-Dev-Only-1"
LAKSHMI = "1100000001"  # solar + inverter + generation meter, all inspected
ROHAN = "1100000002"  # solar, battery (conditional inspection), EV charger
MEENA = "1100000003"  # meter only
ARJUN = "1100000004"  # blocker: no sanctioned load, duplicate meter
FARIDA = "1100000005"  # warning: solar with no inspection record


class Wallet:
    """A test double for the browser wallet: an ES256 key behind a did:jwk."""

    def __init__(self) -> None:
        self.key = ec.generate_private_key(ec.SECP256R1())
        numbers = self.key.public_key().public_numbers()
        self.jwk = {
            "kty": "EC",
            "crv": "P-256",
            "x": b64u_encode(numbers.x.to_bytes(32, "big")),
            "y": b64u_encode(numbers.y.to_bytes(32, "big")),
        }
        self.did = f"did:jwk:{json_b64u(self.jwk)}"

    def nonce_proof(self, nonce: str, audience: str) -> str:
        return sign_compact(self.key, {"alg": "ES256"}, {"nonce": nonce, "aud": audience, "iat": int(time.time())})

    def present(
        self, token: str, keep: str | None = "all", nonce: str = "n-1", audience: str = "bank.example"
    ) -> str:
        """Build a presentation, keeping disclosures chosen by `keep` (a predicate or 'all')."""
        parsed = sd.parse(token)
        chosen = parsed.disclosures if keep == "all" else [d for d in parsed.disclosures if keep(decode(d))]
        body = "~".join([parsed.issuer_jwt, *chosen]) + "~"
        import hashlib

        sd_hash = b64u_encode(hashlib.sha256(body.encode("ascii")).digest())
        claims = {"iat": int(time.time()), "aud": audience, "nonce": nonce, "sd_hash": sd_hash}
        return body + sign_compact(self.key, {"alg": "ES256", "typ": "kb+jwt"}, claims)


def decode(disclosure: str) -> list:
    return json.loads(base64.urlsafe_b64decode(disclosure + "=" * (-len(disclosure) % 4)))


@pytest.fixture
async def client():
    engine = get_engine()
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.drop_all)
        await connection.run_sync(Base.metadata.create_all)
    await get_redis().flushall()
    await seed()
    transport = httpx.ASGITransport(app=app)
    app.state.http = httpx.AsyncClient(transport=transport, base_url="http://localhost:8000")
    async with httpx.AsyncClient(transport=transport, base_url="http://localhost:8000") as test_client:
        yield test_client


async def login_consumer(client: httpx.AsyncClient, consumer_no: str) -> dict[str, str]:
    response = await client.post("/api/v1/auth/otp/request", json={"consumer_no": consumer_no})
    code = response.json()["dev_otp"]
    response = await client.post("/api/v1/auth/otp/verify", json={"consumer_no": consumer_no, "otp": code})
    assert response.status_code == 200, response.text
    return {"Authorization": f"Bearer {response.json()['access_token']}"}


async def login_staff(client: httpx.AsyncClient, username: str = "admin") -> dict[str, str]:
    response = await client.post(
        "/api/v1/auth/admin/login", json={"username": username, "password": ADMIN_PASSWORD}
    )
    assert response.status_code == 200, response.text
    return {"Authorization": f"Bearer {response.json()['access_token']}"}


async def issue_to_wallet(client: httpx.AsyncClient, consumer_no: str, wallet: Wallet) -> tuple[dict, dict]:
    headers = await login_consumer(client, consumer_no)
    nonce = (await client.post("/api/v1/passports/nonce", headers=headers)).json()
    body = {
        "holder_did": wallet.did,
        "holder_proof": wallet.nonce_proof(nonce["nonce"], nonce["audience"]),
        "consent": True,
    }
    response = await client.post("/api/v1/passports/issue", json=body, headers=headers)
    assert response.status_code == 201, response.text
    return response.json(), headers


async def verify(client: httpx.AsyncClient, credential, **extra) -> dict:
    response = await client.post("/api/v1/verify", json={"credential": credential, **extra})
    assert response.status_code == 200, response.text
    return response.json()


def check(result: dict, check_id: str) -> str:
    return next((c["status"] for c in result["checks"] if c["id"] == check_id), "absent")
