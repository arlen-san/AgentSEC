from collections import Counter
from agentsec.connectors.registry import ConnectorRegistry
from agentsec.workflows.cve_triage import CVETriageWorkflow

class ReportGenerator:
    def __init__(self, registry: ConnectorRegistry):
        self.registry = registry
        self.cve_triage = CVETriageWorkflow(registry)

    async def generate_alert_summary(self) -> str:
        """Gera um resumo dos alertas do Defender em PT-BR."""
        alerts = await self.registry.defender.get_alerts()
        if not alerts:
            return "Nenhum alerta encontrado no Microsoft Defender."

        counts = Counter(getattr(a, "severity", "UNKNOWN") for a in alerts)
        
        lines = ["### Resumo de Alertas - Microsoft Defender\n"]
        lines.append(f"**Total de Alertas:** {len(alerts)}\n")
        lines.append("**Distribuição por Severidade:**")
        for sev, count in counts.items():
            # Formatting cleanly
            lines.append(f"- {str(sev).replace('Severity.', '')}: {count}")
            
        lines.append("\n**Top Alertas Recentes:**")
        for alert in alerts[:5]:
            title = getattr(alert, "title", "Sem título")
            sev = str(getattr(alert, "severity", "INFO")).replace('Severity.', '')
            lines.append(f"- [{sev}] {title}")
            
        return "\n".join(lines)

    async def generate_cve_dashboard(self, cve_ids: list[str]) -> str:
        """Gera um dashboard para as CVEs fornecidas."""
        if not cve_ids:
            return "Nenhuma CVE fornecida para triagem."

        triaged = await self.cve_triage.triage_batch(cve_ids)
        
        lines = ["### Dashboard de Triagem de CVEs\n"]
        lines.append("| CVE | Score Composto | Prioridade | KEV | EPSS | CVSS |")
        lines.append("|---|---|---|---|---|---|")
        
        for t in triaged:
            kev_str = "Sim" if t.in_kev else "Não"
            prio = str(t.priority).replace('TriagePriority.', '')
            lines.append(f"| {t.cve_id} | {t.composite_score:.2f} | {prio} | {kev_str} | {t.epss_score:.2f} | {t.base_score:.2f} |")
            
        lines.append("\n**Recomendações:**")
        for t in triaged:
            lines.append(f"- **{t.cve_id}**: {t.recommendation}")
            
        return "\n".join(lines)

    async def generate_threat_intel_summary(self) -> str:
        """Gera um resumo de ameaças via QuimeraX."""
        alerts = await self.registry.cti.get_alerts()
        
        if not alerts:
            return "Nenhuma inteligência de ameaça recente encontrada no QuimeraX."
            
        lines = ["### Resumo de Threat Intel (QuimeraX)\n"]
        lines.append(f"**Alertas Recentes:** {len(alerts)}\n")
        
        for alert in alerts[:5]:
            title = getattr(alert, "title", "Alerta")
            desc = getattr(alert, "description", "")
            lines.append(f"- **{title}**: {desc}")
            
        return "\n".join(lines)
