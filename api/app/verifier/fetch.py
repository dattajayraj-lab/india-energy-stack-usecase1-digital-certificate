"""Outbound fetching for the verifier, hardened against SSRF.

A credential tells the verifier which URLs to fetch (its DID host and its status URL), and
credentials arrive from strangers. So: HTTPS only, no redirects, no private addresses, and
a size cap. `allow_loopback` exists for local development only.
"""

from __future__ import annotations

import asyncio
import ipaddress
import socket
from dataclasses import dataclass
from urllib.parse import urlsplit

import httpx

MAX_BYTES = 256 * 1024
TIMEOUT_SECONDS = 5.0


class FetchError(RuntimeError):
    """The URL was refused or could not be read."""


@dataclass
class FetchResponse:
    status: int
    text: str


async def _assert_public(host: str) -> None:
    loop = asyncio.get_running_loop()
    try:
        infos = await loop.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise FetchError(f"Cannot resolve {host}") from exc
    for info in infos:
        if not ipaddress.ip_address(info[4][0]).is_global:
            raise FetchError(f"Refusing non-public address for {host}")


class SafeFetcher:
    def __init__(self, client: httpx.AsyncClient, allow_loopback: bool = False) -> None:
        self._client = client
        self._allow_loopback = allow_loopback

    async def get(self, url: str) -> FetchResponse:
        parts = urlsplit(url)
        if not parts.hostname:
            raise FetchError("URL has no host")
        if not (self._allow_loopback and parts.hostname in {"localhost", "127.0.0.1"}):
            if parts.scheme != "https":
                raise FetchError("Only HTTPS URLs are fetched")
            await _assert_public(parts.hostname)
        try:
            response = await self._client.get(url, follow_redirects=False, timeout=TIMEOUT_SECONDS)
        except httpx.HTTPError as exc:
            raise FetchError(f"Could not reach {parts.hostname}") from exc
        if len(response.content) > MAX_BYTES:
            raise FetchError("Response too large")
        return FetchResponse(response.status_code, response.text)
