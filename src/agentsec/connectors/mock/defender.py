"""Mock Microsoft Defender connector for development."""

from __future__ import annotations

import json
from pathlib import Path

from agentsec.models.alert import Alert, Incident, Severity

_DATA_DIR = Path(__file__).resolve().parents[4] / "data" / "mock"


class MockDefenderConnector:
    """Mock connector that loads alerts and incidents from JSON fixtures."""

    def __init__(self) -> None:
        self._alerts = self._load_alerts()
        self._incidents = self._load_incidents()

    def _load_alerts(self) -> list[Alert]:
        path = _DATA_DIR / "alerts.json"
        with open(path) as f:
            data = json.load(f)
        return [Alert.model_validate(item) for item in data]

    def _load_incidents(self) -> list[Incident]:
        path = _DATA_DIR / "incidents.json"
        with open(path) as f:
            data = json.load(f)
        incidents = []
        for item in data:
            # Map alert_ids to actual Alert objects
            alert_ids = item.pop("alert_ids", [])
            matched_alerts = [a for a in self._alerts if a.id in alert_ids]
            item["alerts"] = [a.model_dump() for a in matched_alerts]
            incidents.append(Incident.model_validate(item))
        return incidents

    async def get_alerts(
        self, severity: str | None = None, status: str | None = None, limit: int = 20
    ) -> list[Alert]:
        results = self._alerts
        if severity:
            results = [a for a in results if a.severity.value == severity.lower()]
        if status:
            results = [a for a in results if a.status.value.lower() == status.lower()]
        return results[:limit]

    async def get_incidents(
        self, status: str | None = None, limit: int = 20
    ) -> list[Incident]:
        results = self._incidents
        if status:
            results = [i for i in results if i.status.value.lower() == status.lower()]
        return results[:limit]

    async def get_vulnerabilities(self, limit: int = 50) -> list[dict]:
        """Return mock vulnerability data from Defender TVM."""
        # Simplified mock - in real connector this would call the Defender TVM API
        return [
            {
                "id": "CVE-2024-3400",
                "name": "PAN-OS Command Injection",
                "severity": "Critical",
                "exposed_machines": 3,
                "published_on": "2024-04-12",
            },
            {
                "id": "CVE-2024-21762",
                "name": "FortiOS Out-of-Bounds Write",
                "severity": "Critical",
                "exposed_machines": 5,
                "published_on": "2024-02-09",
            },
            {
                "id": "CVE-2024-6387",
                "name": "OpenSSH regreSSHion",
                "severity": "High",
                "exposed_machines": 12,
                "published_on": "2024-07-01",
            },
        ][:limit]
