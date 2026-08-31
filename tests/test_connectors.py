import pytest
from agentsec.models.alert import Severity
from agentsec.models.threat_intel import IOCType

@pytest.mark.asyncio
async def test_mock_defender_connector(mock_registry):
    alerts = await mock_registry.defender.get_alerts()
    assert len(alerts) > 0
    
    # Test filtering
    critical_alerts = await mock_registry.defender.get_alerts(severity=Severity.CRITICAL.value)
    assert len(critical_alerts) > 0
    assert all(a.severity == Severity.CRITICAL for a in critical_alerts)
    
    incidents = await mock_registry.defender.get_incidents()
    assert len(incidents) > 0

@pytest.mark.asyncio
async def test_mock_nvd_connector(mock_registry):
    # CVE-2024-3400 is in our mock data
    cve = await mock_registry.cve.lookup_cve("CVE-2024-3400")
    assert cve is not None
    assert cve.cve_id == "CVE-2024-3400"
    assert cve.cvss_score == 10.0

@pytest.mark.asyncio
async def test_mock_kev_connector(mock_registry):
    assert await mock_registry.kev.is_in_kev("CVE-2024-3400") is True
    assert await mock_registry.kev.is_in_kev("CVE-9999-9999") is False

@pytest.mark.asyncio
async def test_mock_epss_connector(mock_registry):
    score = await mock_registry.epss.get_epss_score("CVE-2024-3400")
    assert score is not None
    assert score.score > 0.0

@pytest.mark.asyncio
async def test_mock_quimerax_connector(mock_registry):
    iocs = await mock_registry.cti.search_iocs(query="185.220.101.45")
    assert len(iocs) > 0
    assert iocs[0].type == IOCType.IP
