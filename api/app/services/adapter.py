"""Glue between the API and the adapter package."""

from __future__ import annotations

from functools import lru_cache

from ies_adapter import DEFAULT_FIELD_MAPPING, FieldMapping, MappingResult, MockFileSource, SourceSystem, build_subject
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..config import get_settings
from ..models import FieldMappingRow


@lru_cache
def get_source() -> SourceSystem:
    """Swap this for the DISCOM's real CIS/MDMS client. Nothing else reads source data."""
    return MockFileSource()


async def seed_field_mapping(session: AsyncSession) -> None:
    if await session.scalar(select(FieldMappingRow.id).limit(1)):
        return
    session.add_all(
        FieldMappingRow(
            ies_field=m.ies_field,
            source_system=m.source_system,
            source_column=m.source_column,
            transform_rule=m.transform_rule,
        )
        for m in DEFAULT_FIELD_MAPPING
    )
    await session.commit()


async def load_mapping(session: AsyncSession) -> list[FieldMapping]:
    rows = (await session.scalars(select(FieldMappingRow))).all()
    return [FieldMapping(r.ies_field, r.source_system, r.source_column, r.transform_rule) for r in rows]


async def map_consumer(session: AsyncSession, consumer_no: str) -> MappingResult | None:
    source = get_source()
    record = source.fetch(consumer_no)
    if record is None:
        return None
    # did:web asset ids use the same percent-encoded domain as the issuer DID.
    return build_subject(record, get_settings().issuer_domain, await load_mapping(session), source.meter_owners)
