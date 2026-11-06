"""Standalone verifier, for a bank or marketplace to run on its own infrastructure.

No database, no adapter, no DISCOM credentials: `uvicorn app.verifier_app:app`.
It needs only public internet access to did.json and DeDi.
"""

from __future__ import annotations

import os
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

import httpx
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from .verifier.core import Verifier
from .verifier.fetch import SafeFetcher

DEDI_BASE_URL = os.environ.get("VERIFIER_DEDI_BASE_URL", "https://api.dedi.global")
ALLOW_LOOPBACK = os.environ.get("VERIFIER_ALLOW_LOOPBACK") == "1"
ALLOWED_ORIGINS = [o for o in os.environ.get("VERIFIER_ALLOWED_ORIGINS", "").split(",") if o]


class VerifyRequest(BaseModel):
    credential: str | dict[str, Any]
    expected_nonce: str | None = Field(None, max_length=256)
    expected_audience: str | None = Field(None, max_length=256)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    if not hasattr(app.state, "http"):
        app.state.http = httpx.AsyncClient()
    yield
    await app.state.http.aclose()


app = FastAPI(title="Consumer Energy Passport Verifier", version="1.0.0", lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=ALLOWED_ORIGINS, allow_methods=["POST"], allow_headers=["*"])


@app.post("/verify")
async def verify(body: VerifyRequest, request: Request) -> dict[str, Any]:
    verifier = Verifier(
        SafeFetcher(request.app.state.http, allow_loopback=ALLOW_LOOPBACK),
        allow_http_did=ALLOW_LOOPBACK,
        dedi_base_url=DEDI_BASE_URL,
    )
    result = await verifier.verify(body.credential, body.expected_nonce, body.expected_audience)
    return result.to_dict()
