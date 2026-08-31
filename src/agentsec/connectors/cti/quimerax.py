"""Real QuimeraX CTI platform connector.

Abstract connector with configurable endpoints.
The actual API documentation is customer-only, so endpoints
are placeholder and should be adjusted when real docs are available.
"""

from __future__ import annotations

import logging

import httpx

from agentsec.models.threat_intel import IOC, LeakedCredential, QuimeraXAlert

logger = logging.getLogger(__name__)


class RealQuimeraXConnector:
    """Connector for QuimeraX CTI platform.
    
    Endpoints are configurable since the API documentation is not public.
    Adjust the endpoint paths when the actual documentation becomes available.
    """

    # Placeholder endpoint paths — update these with real API paths
    ENDPOINTS = {
        "iocs": "/api/v1/iocs",
        "alerts": "/api/v1/alerts",
        "credentials": "/api/v1/credentials",
        "assets": "/api/v1/assets",
    }

    def __init__(self, base_url: str, api_key: str) -> None:
        self._base_url = base_url.rstrip("/")
        self._client = httpx.AsyncClient(
            timeout=30.0,
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
        )

    def _url(self, endpoint_key: str) -> str:
        return f"{self._base_url}{self.ENDPOINTS[endpoint_key]}"

    async def search_iocs(
        self, query: str, ioc_type: str | None = None, limit: int = 20
    ) -> list[IOC]:
        """Search IOCs on QuimeraX."""
        try:
            params: dict[str, str] = {"q": query, "limit": str(limit)}
            if ioc_type:
                params["type"] = ioc_type

            response = await self._client.get(self._url("iocs"), params=params)
            response.raise_for_status()
            data = response.json()

            return [IOC.model_validate(item) for item in data.get("results", [])]
        except httpx.HTTPError as e:
            logger.error("QuimeraX IOC search error: %s", e)
            return []

    async def get_alerts(self, limit: int = 20) -> list[QuimeraXAlert]:
        """Fetch recent alerts from QuimeraX."""
        try:
            response = await self._client.get(
                self._url("alerts"), params={"limit": str(limit)}
            )
            response.raise_for_status()
            data = response.json()

            return [
                QuimeraXAlert.model_validate(item)
                for item in data.get("results", [])
            ]
        except httpx.HTTPError as e:
            logger.error("QuimeraX alerts error: %s", e)
            return []

    async def get_leaked_credentials(
        self, domain: str, limit: int = 20
    ) -> list[LeakedCredential]:
        """Search for leaked credentials by domain."""
        try:
            response = await self._client.get(
                self._url("credentials"),
                params={"domain": domain, "limit": str(limit)},
            )
            response.raise_for_status()
            data = response.json()

            return [
                LeakedCredential.model_validate(item)
                for item in data.get("results", [])
            ]
        except httpx.HTTPError as e:
            logger.error("QuimeraX credentials error: %s", e)
            return []

    async def close(self) -> None:
        await self._client.aclose()
