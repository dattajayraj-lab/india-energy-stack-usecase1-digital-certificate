"""Hosted verification. Same stateless core a bank can run itself (app/verifier_app.py).

The only DISCOM-side addition is the optional audit row, which holds no credential content.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request

from ..api_models import VerifyIn, VerifyOut
from ..cache import get_redis
from ..config import get_settings
from ..db import write_transaction
from ..models import VerificationLog
from ..security import rate_limit
from ..verifier.core import VerificationResult, Verifier
from ..verifier.fetch import SafeFetcher

router = APIRouter(tags=["verify"])


def build_verifier(request: Request) -> Verifier:
    settings = get_settings()
    return Verifier(
        SafeFetcher(request.app.state.http, allow_loopback=not settings.is_prod),
        cache=get_redis(),
        allow_http_did=not settings.is_prod,
        dedi_base_url=settings.dedi_base_url,
    )


async def _log(result: VerificationResult, verifier_did: str | None) -> None:
    failed = [c.id for c in result.checks if c.status == "fail"]
    async with write_transaction() as session:
        session.add(
            VerificationLog(
                credential_id=result.credential_id,
                verifier_did=verifier_did,
                result="pass" if result.valid else "fail",
                failed_checks=failed,
            )
        )
        await session.commit()


@router.post("/verify", response_model=VerifyOut, dependencies=[Depends(rate_limit("verify", 120))])
async def verify(body: VerifyIn, verifier: Verifier = Depends(build_verifier)) -> VerificationResult:
    # Runs outside any database transaction: the checks make network calls.
    result = await verifier.verify(body.credential, body.expected_nonce, body.expected_audience)
    await _log(result, body.verifier_did)
    return result
