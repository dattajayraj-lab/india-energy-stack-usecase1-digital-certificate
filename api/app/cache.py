"""Redis access. `memory://` selects an in-process fake for local runs without Docker.

Key plan (values are hashes, ids, ciphertext or public documents, never raw personal data):
    did:{did}            resolved issuer DID documents      1 hour
    status:{hash}        "not revoked" result               5 minutes, cleared on revoke
    otp:{mobile_hash}    OTP hash and attempt count         5 minutes
    nonce:{nonce}        holder proof challenge             5 minutes, single use
    rl:{who}:{route}     rate-limit counter                 1 minute window
    share:{token_hash}   sealed presentation                share expiry
    webhook:{event_id}   idempotency marker                 1 day
"""

from __future__ import annotations

from functools import lru_cache

import redis.asyncio as redis

from .config import get_settings


@lru_cache
def get_redis() -> redis.Redis:
    url = get_settings().redis_url
    if url.startswith("memory://"):
        import fakeredis

        return fakeredis.FakeAsyncRedis()
    return redis.from_url(url)
