"""Protocol definitions for all connector interfaces.

Uses typing.Protocol for structural subtyping — connectors don't need
to inherit from these classes, they just need to implement the methods.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from agentsec.models.alert import Alert, Incident
from agentsec.models.cve import CVEDetail, EPSSScore, KEVEntry
from agentsec.models.threat_intel import IOC, LeakedCredential, QuimeraXAlert


@runtime_checkable
class DefenderConnector(Protocol):
    """Interface for Microsoft Defender operations."""

    async def get_alerts(
        self, severity: str | None = None, status: str | None = None, limit: int = 20
    ) -> list[Alert]: ...

    async def get_incidents(
        self, status: str | None = None, limit: int = 20
    ) -> list[Incident]: ...

    async def get_vulnerabilities(self, limit: int = 50) -> list[dict]: ...


@runtime_checkable
class CVEConnector(Protocol):
    """Interface for CVE data lookups (NVD)."""

    async def lookup_cve(self, cve_id: str) -> CVEDetail | None: ...

    async def search_cves(self, keyword: str, limit: int = 10) -> list[CVEDetail]: ...


@runtime_checkable
class KEVConnector(Protocol):
    """Interface for CISA Known Exploited Vulnerabilities catalog."""

    async def is_in_kev(self, cve_id: str) -> bool: ...

    async def get_kev_entry(self, cve_id: str) -> KEVEntry | None: ...

    async def get_all_kev(self) -> list[KEVEntry]: ...


@runtime_checkable
class EPSSConnector(Protocol):
    """Interface for EPSS exploit prediction scores."""

    async def get_epss_score(self, cve_id: str) -> EPSSScore | None: ...

    async def get_epss_scores(self, cve_ids: list[str]) -> list[EPSSScore]: ...


@runtime_checkable
class CTIConnector(Protocol):
    """Interface for Cyber Threat Intelligence platforms (QuimeraX, etc.)."""

    async def search_iocs(
        self, query: str, ioc_type: str | None = None, limit: int = 20
    ) -> list[IOC]: ...

    async def get_alerts(self, limit: int = 20) -> list[QuimeraXAlert]: ...

    async def get_leaked_credentials(
        self, domain: str, limit: int = 20
    ) -> list[LeakedCredential]: ...
