"""Mock NVD (National Vulnerability Database) connector."""

from __future__ import annotations

import json
from pathlib import Path

from agentsec.models.cve import CVEDetail

_DATA_DIR = Path(__file__).resolve().parents[4] / "data" / "mock"


class MockNVDConnector:
    """Mock connector that loads CVE data from JSON fixtures."""

    def __init__(self) -> None:
        self._cves = self._load_cves()

    def _load_cves(self) -> dict[str, CVEDetail]:
        path = _DATA_DIR / "cves.json"
        with open(path) as f:
            data = json.load(f)
        return {
            item["cve_id"]: CVEDetail.model_validate(item)
            for item in data
        }

    async def lookup_cve(self, cve_id: str) -> CVEDetail | None:
        return self._cves.get(cve_id.upper())

    async def search_cves(self, keyword: str, limit: int = 10) -> list[CVEDetail]:
        keyword_lower = keyword.lower()
        results = [
            cve for cve in self._cves.values()
            if keyword_lower in cve.description.lower()
            or keyword_lower in cve.cve_id.lower()
            or any(keyword_lower in p.lower() for p in cve.affected_products)
        ]
        return results[:limit]
