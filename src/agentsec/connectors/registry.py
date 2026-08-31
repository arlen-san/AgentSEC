"""Connector registry — manages and provides access to all connectors."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from agentsec.connectors.base import (
    CTIConnector,
    CVEConnector,
    DefenderConnector,
    EPSSConnector,
    KEVConnector,
)


@dataclass
class ConnectorRegistry:
    """Central registry for all security connectors.
    
    Provides type-safe access to connectors by their role.
    """

    defender: DefenderConnector | None = None
    cve: CVEConnector | None = None
    kev: KEVConnector | None = None
    epss: EPSSConnector | None = None
    cti: CTIConnector | None = None
    
    _extras: dict[str, Any] = field(default_factory=dict)

    def register_extra(self, name: str, connector: Any) -> None:
        """Register an additional connector by name."""
        self._extras[name] = connector

    def get_extra(self, name: str) -> Any | None:
        """Get an extra connector by name."""
        return self._extras.get(name)

    def status_report(self) -> dict[str, str]:
        """Return a dict of connector statuses for display."""
        connectors = {
            "Defender": self.defender,
            "NVD (CVE)": self.cve,
            "CISA KEV": self.kev,
            "EPSS": self.epss,
            "QuimeraX (CTI)": self.cti,
        }
        return {
            name: type(conn).__name__ if conn else "Não configurado"
            for name, conn in connectors.items()
        }


def create_registry(use_mock: bool = True) -> ConnectorRegistry:
    """Factory function to create a ConnectorRegistry with mock or real connectors.
    
    Args:
        use_mock: If True, use mock connectors. If False, use real API connectors.
    
    Returns:
        A fully configured ConnectorRegistry.
    """
    registry = ConnectorRegistry()

    if use_mock:
        from agentsec.connectors.mock.cisa_kev import MockKEVConnector
        from agentsec.connectors.mock.defender import MockDefenderConnector
        from agentsec.connectors.mock.epss import MockEPSSConnector
        from agentsec.connectors.mock.nvd import MockNVDConnector
        from agentsec.connectors.mock.quimerax import MockQuimeraXConnector

        registry.defender = MockDefenderConnector()
        registry.cve = MockNVDConnector()
        registry.kev = MockKEVConnector()
        registry.epss = MockEPSSConnector()
        registry.cti = MockQuimeraXConnector()
    else:
        # Real connectors — imported only when needed
        # These require proper API keys configured in settings
        from agentsec.config.settings import settings
        from agentsec.connectors.cti.cisa_kev import RealKEVConnector
        from agentsec.connectors.cti.epss import RealEPSSConnector
        from agentsec.connectors.cti.nvd import RealNVDConnector
        from agentsec.connectors.cti.quimerax import RealQuimeraXConnector
        from agentsec.connectors.microsoft.defender import RealDefenderConnector

        registry.defender = RealDefenderConnector(
            tenant_id=settings.defender_tenant_id,
            client_id=settings.defender_client_id,
            client_secret=settings.defender_client_secret,
        )
        registry.cve = RealNVDConnector(api_key=settings.nvd_api_key)
        registry.kev = RealKEVConnector()
        registry.epss = RealEPSSConnector()
        registry.cti = RealQuimeraXConnector(
            base_url=settings.quimerax_base_url,
            api_key=settings.quimerax_api_key,
        )

    return registry
