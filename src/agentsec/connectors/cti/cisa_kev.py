"""Real CISA KEV (Known Exploited Vulnerabilities) connector."""

from __future__ import annotations

import logging
from datetime import date

import httpx

from agentsec.models.cve import KEVEntry

logger = logging.getLogger(__name__)

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


class RealKEVConnector:
    """Connector for CISA Known Exploited Vulnerabilities catalog.
    
    Downloads and caches the full KEV catalog (public JSON, no auth needed).
    """

    def __init__(self) -> None:
        self._client = httpx.AsyncClient(timeout=30.0)
        self._cache: dict[str, KEVEntry] | None = None

    async def _ensure_loaded(self) -> dict[str, KEVEntry]:
        """Download and cache KEV catalog if not already loaded."""
        if self._cache is not None:
            return self._cache

        try:
            response = await self._client.get(KEV_URL)
            response.raise_for_status()
            data = response.json()

            self._cache = {}
            for vuln in data.get("vulnerabilities", []):
                cve_id = vuln.get("cveID", "")
                if not cve_id:
                    continue
                self._cache[cve_id] = KEVEntry(
                    cve_id=cve_id,
                    vendor=vuln.get("vendorProject", ""),
                    product=vuln.get("product", ""),
                    vulnerability_name=vuln.get("vulnerabilityName", ""),
                    date_added=vuln.get("dateAdded"),
                    due_date=vuln.get("dueDate"),
                    known_ransomware_use=vuln.get("knownRansomwareCampaignUse", "Unknown") == "Known",
                    notes=vuln.get("notes", ""),
                )
            logger.info("KEV catalog loaded: %d entries", len(self._cache))
        except httpx.HTTPError as e:
            logger.error("Failed to load KEV catalog: %s", e)
            self._cache = {}

        return self._cache

    async def is_in_kev(self, cve_id: str) -> bool:
        catalog = await self._ensure_loaded()
        return cve_id.upper() in catalog

    async def get_kev_entry(self, cve_id: str) -> KEVEntry | None:
        catalog = await self._ensure_loaded()
        return catalog.get(cve_id.upper())

    async def get_all_kev(self) -> list[KEVEntry]:
        catalog = await self._ensure_loaded()
        return list(catalog.values())

    async def close(self) -> None:
        await self._client.aclose()
