"""DISCOM issuer API."""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

import httpx
from fastapi import APIRouter, FastAPI
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import select

from .config import get_settings
from .crypto.keys import get_issuer_key
from .db import write_transaction
from .models import AdminUser
from .routers import admin, auth, passports, system, verify
from .security import hash_password
from .services.adapter import seed_field_mapping

SEED_USERS = (("admin", "admin"), ("operator", "operator"), ("auditor", "auditor"))


async def seed() -> None:
    settings = get_settings()
    async with write_transaction() as session:
        await seed_field_mapping(session)
        if await session.scalar(select(AdminUser.id).limit(1)) is None:
            hashed = hash_password(settings.seed_admin_password)
            session.add_all(AdminUser(username=u, password_hash=hashed, role=r) for u, r in SEED_USERS)
            await session.commit()


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    get_issuer_key()  # fail at startup, not on the first issue, if the key is missing
    await seed()
    if not hasattr(app.state, "http"):
        app.state.http = httpx.AsyncClient()
    yield
    await app.state.http.aclose()


def create_app() -> FastAPI:
    settings = get_settings()
    app = FastAPI(
        title="Consumer Energy Passport API",
        version="1.0.0",
        description="DISCOM issuer for the IES Consumer Energy Passport (ElectricityCredential v1.2).",
        lifespan=lifespan,
    )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=[settings.web_base_url],
        allow_methods=["GET", "POST", "DELETE"],
        allow_headers=["Authorization", "Content-Type"],
    )

    v1 = APIRouter(prefix="/api/v1")
    for module_router in (auth.router, passports.router, verify.router, admin.router, system.webhook_router):
        v1.include_router(module_router)
    app.include_router(v1)
    app.include_router(system.public_router)
    if not settings.is_prod:
        app.include_router(system.mock_dedi_router)

    @app.get("/health", tags=["identity"])
    async def health() -> dict[str, str]:
        return {"status": "ok", "issuer": settings.issuer_did}

    return app


app = create_app()
