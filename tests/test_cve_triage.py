import pytest
from agentsec.workflows.cve_triage import CVETriageWorkflow
from agentsec.models.cve import TriagePriority

@pytest.mark.asyncio
async def test_cve_triage_critical(mock_registry):
    workflow = CVETriageWorkflow(mock_registry)
    # CVE-2024-3400 is in KEV and has high CVSS/EPSS
    triaged = await workflow.triage_single("CVE-2024-3400")
    
    assert triaged is not None
    assert triaged.cve.cve_id == "CVE-2024-3400"
    assert triaged.is_in_kev is True
    assert triaged.priority == TriagePriority.CRITICAL

@pytest.mark.asyncio
async def test_cve_triage_not_found(mock_registry):
    workflow = CVETriageWorkflow(mock_registry)
    triaged = await workflow.triage_single("CVE-9999-9999")
    assert triaged is None

@pytest.mark.asyncio
async def test_cve_triage_batch(mock_registry):
    workflow = CVETriageWorkflow(mock_registry)
    results = await workflow.triage_batch(["CVE-2024-3400", "CVE-2024-21762"])
    
    assert len(results) == 2
    assert results[0].priority == TriagePriority.CRITICAL
