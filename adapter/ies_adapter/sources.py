"""Read-only access to DISCOM source systems.

The adapter never writes back: CIS, billing, MDMS and inspection records stay exactly
where they are. A real deployment implements `SourceSystem` over the DISCOM's API or
nightly extract; `MockFileSource` reads CSV extracts shaped like one.
"""

from __future__ import annotations

import csv
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol

MOCK_DIR = Path(__file__).parent / "mock_data"


@dataclass(frozen=True)
class SourceRecord:
    """Everything the source systems hold for one consumer, in their own field names."""

    cis: dict[str, str]
    meters: list[dict[str, str]] = field(default_factory=list)
    assets: list[dict[str, str]] = field(default_factory=list)


class SourceSystem(Protocol):
    def fetch(self, consumer_no: str) -> SourceRecord | None: ...

    def search(self, query: str, limit: int = 20) -> list[dict[str, str]]: ...

    def meter_owners(self, meter_slno: str) -> list[str]: ...


class MockFileSource:
    """CSV-backed stand-in for a nightly CIS/MDMS/inspection extract."""

    def __init__(self, directory: Path = MOCK_DIR) -> None:
        self._cis = self._load(directory / "cis_consumers.csv")
        self._meters = self._load(directory / "mdms_meters.csv")
        self._assets = self._load(directory / "inspection_assets.csv")

    @staticmethod
    def _load(path: Path) -> list[dict[str, str]]:
        with path.open(newline="", encoding="utf-8") as handle:
            return list(csv.DictReader(handle))

    def fetch(self, consumer_no: str) -> SourceRecord | None:
        cis = next((row for row in self._cis if row["CA_NUMBER"] == consumer_no), None)
        if cis is None:
            return None
        return SourceRecord(
            cis=dict(cis),
            meters=[dict(m) for m in self._meters if m["CA_NUMBER"] == consumer_no],
            assets=[dict(a) for a in self._assets if a["CA_NUMBER"] == consumer_no],
        )

    def search(self, query: str, limit: int = 20) -> list[dict[str, str]]:
        needle = query.strip().lower()
        hits = [
            row
            for row in self._cis
            if not needle
            or needle in row["CA_NUMBER"].lower()
            or needle in row["CUST_NAME"].lower()
            or needle in row["SERVICE_CONN_NO"].lower()
        ]
        return hits[:limit]

    def meter_owners(self, meter_slno: str) -> list[str]:
        return sorted({m["CA_NUMBER"] for m in self._meters if m["MET_SLNO"] == meter_slno})
