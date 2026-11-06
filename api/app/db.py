"""Database access.

SQLite in WAL mode allows one writer, so writes pass through a single in-process lock
(the plan's "single worker"); run the API with one uvicorn worker. Reads run concurrently.
Commits are explicit in the services, so a response is only sent after data is durable.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from functools import lru_cache

from sqlalchemy import event
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker, create_async_engine

from .config import get_settings

_write_lock = asyncio.Lock()


@lru_cache
def get_engine() -> AsyncEngine:
    engine = create_async_engine(get_settings().database_url)

    if engine.dialect.name == "sqlite":

        @event.listens_for(engine.sync_engine, "connect")
        def _sqlite_pragmas(connection, _record) -> None:  # type: ignore[no-untyped-def]
            cursor = connection.cursor()
            cursor.execute("PRAGMA journal_mode=WAL")
            cursor.execute("PRAGMA busy_timeout=5000")
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.close()

    return engine


@lru_cache
def get_sessionmaker() -> async_sessionmaker[AsyncSession]:
    return async_sessionmaker(get_engine(), expire_on_commit=False)


async def read_session() -> AsyncIterator[AsyncSession]:
    async with get_sessionmaker()() as session:
        yield session


@asynccontextmanager
async def write_transaction() -> AsyncIterator[AsyncSession]:
    async with _write_lock, get_sessionmaker()() as session:
        yield session


async def write_session() -> AsyncIterator[AsyncSession]:
    async with write_transaction() as session:
        yield session
