"""Real Microsoft Defender connector using Graph Security API."""

from __future__ import annotations

import logging

import httpx

from agentsec.connectors.microsoft.auth import MSAuthProvider
from agentsec.models.alert import Alert, Incident

logger = logging.getLogger(__name__)

GRAPH_BASE = "https://graph.microsoft.com/v1.0"
DEFENDER_BASE = "https://api.security.microsoft.com"


class RealDefenderConnector:
    """Connector for Microsoft Defender using Graph Security API.
    
    Uses /security/alerts_v2 and /security/incidents endpoints.
    Note: Advanced Hunting requires Defender for Endpoint P2 license.
    """

    def __init__(
        self, tenant_id: str, client_id: str, client_secret: str
    ) -> None:
        self._auth = MSAuthProvider(tenant_id, client_id, client_secret)
        self._client = httpx.AsyncClient(timeout=30.0)

    async def _graph_headers(self) -> dict[str, str]:
        token = self._auth.get_graph_token()
        return {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}

    async def _defender_headers(self) -> dict[str, str]:
        token = self._auth.get_defender_token()
        return {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}

    async def get_alerts(
        self, severity: str | None = None, status: str | None = None, limit: int = 20
    ) -> list[Alert]:
        """Fetch alerts from Microsoft Graph Security API."""
        headers = await self._graph_headers()
        url = f"{GRAPH_BASE}/security/alerts_v2"
        params: dict[str, str] = {"$top": str(limit)}

        filters: list[str] = []
        if severity:
            filters.append(f"severity eq '{severity}'")
        if status:
            filters.append(f"status eq '{status}'")
        if filters:
            params["$filter"] = " and ".join(filters)

        response = await self._client.get(url, headers=headers, params=params)
        response.raise_for_status()
        data = response.json()

        alerts = []
        for item in data.get("value", []):
            alerts.append(Alert(
                id=item.get("id", ""),
                title=item.get("title", ""),
                severity=item.get("severity", "medium").lower(),
                status=item.get("status", "new").lower(),
                description=item.get("description", ""),
                category=item.get("category", ""),
                source=item.get("serviceSource", "Microsoft Defender"),
                assigned_to=item.get("assignedTo"),
                created_at=item.get("createdDateTime"),
                updated_at=item.get("lastUpdateDateTime"),
            ))
        return alerts

    async def get_incidents(
        self, status: str | None = None, limit: int = 20
    ) -> list[Incident]:
        """Fetch incidents from Microsoft Graph Security API."""
        headers = await self._graph_headers()
        url = f"{GRAPH_BASE}/security/incidents"
        params: dict[str, str] = {"$top": str(limit)}

        if status:
            params["$filter"] = f"status eq '{status}'"

        response = await self._client.get(url, headers=headers, params=params)
        response.raise_for_status()
        data = response.json()

        incidents = []
        for item in data.get("value", []):
            incidents.append(Incident(
                id=item.get("id", ""),
                title=item.get("displayName", ""),
                severity=item.get("severity", "medium").lower(),
                status=item.get("status", "active").lower(),
                description=item.get("description", ""),
                classification=item.get("classification"),
                determination=item.get("determination"),
                assigned_to=item.get("assignedTo"),
                created_at=item.get("createdDateTime"),
                updated_at=item.get("lastUpdateDateTime"),
            ))
        return incidents

    async def get_vulnerabilities(self, limit: int = 50) -> list[dict]:
        """Fetch vulnerabilities from Defender TVM API."""
        headers = await self._defender_headers()
        url = f"{DEFENDER_BASE}/api/vulnerabilities"
        params = {"$top": str(limit)}

        response = await self._client.get(url, headers=headers, params=params)
        response.raise_for_status()
        data = response.json()
        return data.get("value", [])

    async def close(self) -> None:
        await self._client.aclose()
