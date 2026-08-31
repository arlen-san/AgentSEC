"""Tool functions exposed to the Gemini agent via function calling."""

import json
from agentsec.connectors.registry import ConnectorRegistry
from agentsec.workflows.cve_triage import CVETriageWorkflow
from agentsec.workflows.report import ReportGenerator

# Helper to serialize pydantic models safely
def _serialize(data):
    if hasattr(data, "model_dump"):
        return data.model_dump()
    if isinstance(data, list):
        return [_serialize(item) for item in data]
    return str(data)

async def search_alerts(registry: ConnectorRegistry, severity: str = "", status: str = "", limit: int = 10) -> str:
    """Busca alertas de segurança do Microsoft Defender."""
    alerts = await registry.defender.get_alerts()
    # Mocking filtering for simplicity
    results = [_serialize(a) for a in alerts][:limit]
    return json.dumps({"alerts": results}, ensure_ascii=False, indent=2)

async def get_incidents(registry: ConnectorRegistry, status: str = "", limit: int = 10) -> str:
    """Busca incidentes de segurança do Microsoft Defender."""
    incidents = await registry.defender.get_incidents()
    results = [_serialize(i) for i in incidents][:limit]
    return json.dumps({"incidents": results}, ensure_ascii=False, indent=2)

async def get_defender_vulnerabilities(registry: ConnectorRegistry, limit: int = 10) -> str:
    """Obtém as vulnerabilidades reportadas no ambiente via Defender TVM."""
    vulns = await registry.defender.get_vulnerabilities()
    results = [_serialize(v) for v in vulns][:limit]
    return json.dumps({"vulnerabilities": results}, ensure_ascii=False, indent=2)

async def lookup_cve(registry: ConnectorRegistry, cve_id: str) -> str:
    """Busca detalhes de uma CVE no NVD."""
    cve = await registry.cve.lookup_cve(cve_id)
    if not cve:
        return json.dumps({"error": "CVE não encontrada."})
    return json.dumps({"cve": _serialize(cve)}, ensure_ascii=False, indent=2)

async def triage_cve(registry: ConnectorRegistry, cve_id: str) -> str:
    """Faz a triagem inteligente de uma única CVE calculando o score composto."""
    workflow = CVETriageWorkflow(registry)
    result = await workflow.triage_single(cve_id)
    return json.dumps({"triage": _serialize(result)}, ensure_ascii=False, indent=2)

async def triage_cves(registry: ConnectorRegistry, cve_ids: list[str]) -> str:
    """Faz a triagem em lote de múltiplas CVEs."""
    workflow = CVETriageWorkflow(registry)
    results = await workflow.triage_batch(cve_ids)
    return json.dumps({"triages": _serialize(results)}, ensure_ascii=False, indent=2)

async def search_iocs(registry: ConnectorRegistry, query: str, ioc_type: str = "") -> str:
    """Busca por Indicadores de Comprometimento (IOCs) no QuimeraX."""
    iocs = await registry.cti.search_iocs(query)
    results = [_serialize(i) for i in iocs]
    return json.dumps({"iocs": results}, ensure_ascii=False, indent=2)

async def get_leaked_credentials(registry: ConnectorRegistry, domain: str) -> str:
    """Verifica credenciais vazadas para um domínio específico."""
    creds = await registry.cti.get_leaked_credentials(domain)
    results = [_serialize(c) for c in creds]
    return json.dumps({"leaked_credentials": results}, ensure_ascii=False, indent=2)

async def generate_summary(registry: ConnectorRegistry, topic: str) -> str:
    """Gera um resumo executivo para um tópico específico ('alerts', 'threat_intel')."""
    generator = ReportGenerator(registry)
    if topic == "alerts":
        res = await generator.generate_alert_summary()
    elif topic == "threat_intel":
        res = await generator.generate_threat_intel_summary()
    else:
        res = "Tópico desconhecido. Use 'alerts' ou 'threat_intel'."
    return json.dumps({"summary": res}, ensure_ascii=False, indent=2)
