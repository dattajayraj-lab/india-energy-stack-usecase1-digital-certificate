"""Alembic migrations, run with the sync driver against the configured database."""

from __future__ import annotations

from sqlalchemy import create_engine, pool

from alembic import context
from app.config import get_settings
from app.models import Base

url = get_settings().database_url.replace("+aiosqlite", "")


def run() -> None:
    engine = create_engine(url, poolclass=pool.NullPool)
    with engine.connect() as connection:
        context.configure(connection=connection, target_metadata=Base.metadata, render_as_batch=True)
        with context.begin_transaction():
            context.run_migrations()


run()
