"""IES adapter: DISCOM source systems -> ElectricityCredential v1.2."""

from .mapping import (
    DEFAULT_FIELD_MAPPING,
    FieldMapping,
    MappingResult,
    QualityFlag,
    asset_did,
    build_subject,
)
from .sources import MockFileSource, SourceRecord, SourceSystem

__all__ = [
    "DEFAULT_FIELD_MAPPING",
    "FieldMapping",
    "MappingResult",
    "MockFileSource",
    "QualityFlag",
    "SourceRecord",
    "SourceSystem",
    "asset_did",
    "build_subject",
]
