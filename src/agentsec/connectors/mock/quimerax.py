"""Mock QuimeraX CTI connector."""

from __future__ import annotations

import json
from pathlib import Path

from agentsec.models.threat_intel import IOC, IOCType, LeakedCredential, QuimeraXAlert

_DATA_DIR = Path(__file__).resolve().parents[4] / "data" / "mock"


class MockQuimeraXConnector:
    """Mock connector that loads QuimeraX CTI data from JSON fixtures."""

    def __init__(self) -> None:
        self._data = self._load_data()

    def _load_data(self) -> dict:
        path = _DATA_DIR / "quimerax_iocs.json"
        with open(path) as f:
            return json.load(f)

    async def search_iocs(
        self, query: str, ioc_type: str | None = None, limit: int = 20
    ) -> list[IOC]:
        iocs = [IOC.model_validate(item) for item in self._data.get("iocs", [])]
        query_lower = query.lower()
        results = [
            ioc for ioc in iocs
            if query_lower in ioc.value.lower()
            or query_lower in ioc.description.lower()
            or any(query_lower in tag.lower() for tag in ioc.tags)
        ]
        if ioc_type:
            results = [ioc for ioc in results if ioc.type.value == ioc_type.lower()]
        return results[:limit]

    async def get_alerts(self, limit: int = 20) -> list[QuimeraXAlert]:
        alerts_data = self._data.get("alerts", [])
        alerts = [QuimeraXAlert.model_validate(item) for item in alerts_data]
        return alerts[:limit]

    async def get_leaked_credentials(
        self, domain: str, limit: int = 20
    ) -> list[LeakedCredential]:
        creds_data = self._data.get("leaked_credentials", [])
        creds = [LeakedCredential.model_validate(item) for item in creds_data]
        domain_lower = domain.lower()
        results = [c for c in creds if domain_lower in c.email.lower()]
        return results[:limit]
