"""Real EPSS (Exploit Prediction Scoring System) connector."""

from __future__ import annotations

import logging

import httpx

from agentsec.models.cve import EPSSScore

logger = logging.getLogger(__name__)

EPSS_BASE = "https://api.first.org/data/v1/epss"


class RealEPSSConnector:
    """Connector for FIRST EPSS API.
    
    Public API, no authentication required.
    """

    def __init__(self) -> None:
        self._client = httpx.AsyncClient(timeout=30.0)

    async def get_epss_score(self, cve_id: str) -> EPSSScore | None:
        """Get EPSS score for a single CVE."""
        try:
            response = await self._client.get(
                EPSS_BASE, params={"cve": cve_id.upper()}
            )
            response.raise_for_status()
            data = response.json()

            entries = data.get("data", [])
            if not entries:
                return None

            entry = entries[0]
            return EPSSScore(
                cve_id=entry.get("cve", cve_id),
                score=float(entry.get("epss", 0)),
                percentile=float(entry.get("percentile", 0)),
            )
        except (httpx.HTTPError, ValueError) as e:
            logger.error("EPSS API error for %s: %s", cve_id, e)
            return None

    async def get_epss_scores(self, cve_ids: list[str]) -> list[EPSSScore]:
        """Get EPSS scores for multiple CVEs in one request."""
        if not cve_ids:
            return []

        try:
            cve_param = ",".join(c.upper() for c in cve_ids)
            response = await self._client.get(
                EPSS_BASE, params={"cve": cve_param}
            )
            response.raise_for_status()
            data = response.json()

            return [
                EPSSScore(
                    cve_id=entry.get("cve", ""),
                    score=float(entry.get("epss", 0)),
                    percentile=float(entry.get("percentile", 0)),
                )
                for entry in data.get("data", [])
            ]
        except (httpx.HTTPError, ValueError) as e:
            logger.error("EPSS API batch error: %s", e)
            return []

    async def close(self) -> None:
        await self._client.aclose()
