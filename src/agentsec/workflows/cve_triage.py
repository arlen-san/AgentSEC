"""CVE triage workflow combining NVD, CISA KEV, and EPSS."""

from __future__ import annotations

import asyncio

from agentsec.connectors.registry import ConnectorRegistry
from agentsec.models.cve import TriagedCVE, TriagePriority


class CVETriageWorkflow:
    """Orchestrates CVE triage combining multiple threat intelligence sources."""

    def __init__(self, registry: ConnectorRegistry):
        self.registry = registry

    async def triage_single(self, cve_id: str) -> TriagedCVE | None:
        if not self.registry.cve:
            return None

        cve = await self.registry.cve.lookup_cve(cve_id)
        if cve is None:
            return None

        kev_task = self.registry.kev.get_kev_entry(cve_id) if self.registry.kev else None
        epss_task = self.registry.epss.get_epss_score(cve_id) if self.registry.epss else None

        tasks = []
        if kev_task:
            tasks.append(kev_task)
        if epss_task:
            tasks.append(epss_task)

        kev_entry = None
        epss_score = None

        if tasks:
            results = await asyncio.gather(*tasks, return_exceptions=True)
            idx = 0
            if kev_task:
                res = results[idx]
                idx += 1
                if not isinstance(res, Exception):
                    kev_entry = res
            if epss_task:
                res = results[idx]
                idx += 1
                if not isinstance(res, Exception):
                    epss_score = res

        cvss = cve.cvss_score or 0.0
        epss_val = epss_score.score if epss_score else 0.0
        in_kev = kev_entry is not None

        kev_bonus = 10.0 if in_kev else 0.0
        composite_score = (cvss * 0.4) + (epss_val * 10.0 * 0.4) + (kev_bonus * 0.2)
        composite_score = round(min(composite_score, 10.0), 2)

        if in_kev:
            priority = TriagePriority.CRITICAL
            recommendation = (
                "CRÍTICO: Vulnerabilidade explorada ativamente (CISA KEV). "
                "Aplique o patch imediatamente ou isole o ativo."
            )
            composite_score = 10.0
        elif epss_val >= 0.6 and cvss >= 7.0:
            priority = TriagePriority.HIGH
            recommendation = (
                "ALTO: Alta probabilidade de exploração e impacto severo. "
                "Priorize a correção no próximo ciclo."
            )
        elif epss_val >= 0.3 and cvss >= 4.0:
            priority = TriagePriority.MEDIUM
            recommendation = (
                "MÉDIO: Risco moderado. Monitore ou aplique mitigação quando possível."
            )
        elif cvss >= 4.0:
            priority = TriagePriority.LOW
            recommendation = (
                "BAIXO: Impacto identificado, mas a probabilidade de exploração é menor. "
                "Atualize conforme a janela de manutenção."
            )
        else:
            priority = TriagePriority.INFO
            recommendation = "INFORMATIVO: Risco mínimo. Nenhuma ação imediata é necessária."

        return TriagedCVE(
            cve=cve,
            epss=epss_score,
            kev_entry=kev_entry,
            composite_score=composite_score,
            priority=priority,
            recommendation=recommendation,
        )

    async def triage_batch(self, cve_ids: list[str]) -> list[TriagedCVE]:
        tasks = [self.triage_single(cve_id) for cve_id in cve_ids]
        results = await asyncio.gather(*tasks)
        valid_results = [r for r in results if r is not None]
        return sorted(valid_results, key=lambda x: x.composite_score, reverse=True)
