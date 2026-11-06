"""Application settings. Everything environment-specific comes from CEP_* variables."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

DEV_SECRET = "dev-only-secret-change-me-0123456789abcdef"  # noqa: S105 - rejected outside dev/test
DEV_ADMIN_PASSWORD = "ChangeMe-Dev-Only-1"  # noqa: S105 - rejected outside dev/test


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="CEP_", env_file=".env", extra="ignore")

    environment: Literal["dev", "test", "prod"] = "dev"
    database_url: str = "sqlite+aiosqlite:///./cep.db"
    redis_url: str = "memory://"

    # Identity. The domain is the did:web method-specific id, so a port is %3A-encoded.
    issuer_domain: str = "localhost%3A8000"
    issuer_name: str = "Example Andhra Distribution Company Limited"
    discom_id: str = "EXAMPLE-DISCOM"
    public_base_url: str = "http://localhost:8000"
    web_base_url: str = "http://localhost:3000"
    key_path: Path = Path(".secrets/issuer-key.pem")

    # Sessions and shared secrets
    jwt_secret: str = DEV_SECRET
    pii_pepper: str = DEV_SECRET
    webhook_secret: str = DEV_SECRET
    consumer_session_minutes: int = 15
    admin_session_minutes: int = 30
    seed_admin_password: str = DEV_ADMIN_PASSWORD

    # Credential policy
    credential_validity_days: int = 365
    share_max_seconds: int = 7 * 24 * 3600

    # OpenCred. When unset, jws-2020 credentials are signed in-process.
    opencred_url: str | None = None
    opencred_api_key: str | None = None

    # DeDi. Defaults to the dev mock mounted by this API.
    dedi_base_url: str = "http://localhost:8000/mock-dedi"
    dedi_namespace: str = "ies.discom.example"

    # DigiLocker Pull URI
    digilocker_api_key: str = DEV_SECRET
    digilocker_org_id: str = "in.example.discom"

    @property
    def issuer_did(self) -> str:
        return f"did:web:{self.issuer_domain}"

    @property
    def is_prod(self) -> bool:
        return self.environment == "prod"

    @model_validator(mode="after")
    def _reject_dev_defaults_in_prod(self) -> Settings:
        if self.is_prod:
            for name in ("jwt_secret", "pii_pepper", "webhook_secret", "digilocker_api_key"):
                if getattr(self, name) == DEV_SECRET:
                    raise ValueError(f"CEP_{name.upper()} must be set in production")
            if self.seed_admin_password == DEV_ADMIN_PASSWORD:
                raise ValueError("CEP_SEED_ADMIN_PASSWORD must be set in production")
            if self.redis_url.startswith("memory://"):
                raise ValueError("CEP_REDIS_URL must point at a real Redis in production")
            if "mock-dedi" in self.dedi_base_url:
                raise ValueError("CEP_DEDI_BASE_URL must point at DeDi in production")
        return self


@lru_cache
def get_settings() -> Settings:
    return Settings()
