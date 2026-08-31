"""Mock CISA KEV (Known Exploited Vulnerabilities) connector."""

from __future__ import annotations

import json
from pathlib import Path

from agentsec.models.cve import KEVEntry

_DATA_DIR = Path(__file__).resolve().parents[4] / "data" / "mock"


class MockKEVConnector:
    """Mock connector that loads KEV data from JSON fixtures."""

    def __init__(self) -> None:
        self._kev_entries = self._load_kev()

    def _load_kev(self) -> dict[str, KEVEntry]:
        path = _DATA_DIR / "kev_catalog.json"
        with open(path) as f:
            data = json.load(f)
        return {
            item["cve_id"]: KEVEntry.model_validate(item)
            for item in data
        }

    async def is_in_kev(self, cve_id: str) -> bool:
        return cve_id.upper() in self._kev_entries

    async def get_kev_entry(self, cve_id: str) -> KEVEntry | None:
        return self._kev_entries.get(cve_id.upper())

    async def get_all_kev(self) -> list[KEVEntry]:
        return list(self._kev_entries.values())
