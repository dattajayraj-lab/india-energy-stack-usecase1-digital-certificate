"""Sessions, RBAC, rate limiting and privacy helpers."""

from __future__ import annotations

import hashlib
import hmac
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import timedelta

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from .cache import get_redis
from .config import get_settings
from .models import utcnow

ALGORITHM = "HS256"
ROLES = ("admin", "operator", "auditor")

_bearer = HTTPBearer(auto_error=False)
_hasher = PasswordHasher()


@dataclass(frozen=True)
class Principal:
    subject: str
    role: str  # consumer / admin / operator / auditor

    @property
    def actor(self) -> str:
        return f"{self.role}:{self.subject}"


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(stored: str, password: str) -> bool:
    try:
        return _hasher.verify(stored, password)
    except (VerificationError, InvalidHashError):
        return False


def create_session(subject: str, role: str, minutes: int) -> str:
    now = utcnow()
    claims = {"sub": subject, "role": role, "iat": now, "exp": now + timedelta(minutes=minutes)}
    return jwt.encode(claims, get_settings().jwt_secret, algorithm=ALGORITHM)


def pii_hash(value: str) -> str:
    """Peppered hash, so a leaked table cannot be reversed by enumerating mobile numbers."""
    return hmac.new(get_settings().pii_pepper.encode(), value.encode(), hashlib.sha256).hexdigest()


def mask_ip(ip: str | None) -> str | None:
    """Keep enough for abuse analysis without storing a full personal identifier."""
    if not ip:
        return None
    if "." in ip:
        return ".".join(ip.split(".")[:3] + ["0"])
    return ":".join(ip.split(":")[:3]) + "::"


async def current_principal(
    credentials: HTTPAuthorizationCredentials | None = Depends(_bearer),
) -> Principal:
    if credentials is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Sign in to continue.")
    try:
        claims = jwt.decode(credentials.credentials, get_settings().jwt_secret, algorithms=[ALGORITHM])
    except jwt.PyJWTError as exc:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Your session has expired.") from exc
    return Principal(claims["sub"], claims["role"])


def require_roles(*roles: str) -> Callable[[Principal], Awaitable[Principal]]:
    async def check(principal: Principal = Depends(current_principal)) -> Principal:
        if principal.role not in roles:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "Your role does not allow this.")
        return principal

    return check


def rate_limit(route: str, limit: int, window_seconds: int = 60) -> Callable[[Request], Awaitable[None]]:
    async def check(request: Request) -> None:
        who = request.client.host if request.client else "unknown"
        key = f"rl:{who}:{route}"
        client = get_redis()
        count = await client.incr(key)
        if count == 1:
            await client.expire(key, window_seconds)
        if count > limit:
            raise HTTPException(
                status.HTTP_429_TOO_MANY_REQUESTS,
                "Too many requests. Try again in a minute.",
                headers={"Retry-After": str(window_seconds)},
            )

    return check
