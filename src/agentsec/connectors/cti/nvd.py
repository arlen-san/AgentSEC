"""Real NVD (National Vulnerability Database) connector."""

from __future__ import annotations

import logging

import httpx

from agentsec.models.cve import CVEDetail

logger = logging.getLogger(__name__)

NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"


class RealNVDConnector:
    """Connector for NIST NVD API 2.0.
    
    Rate limits: Without API key: 5 requests/30s. With key: 50 requests/30s.
    """

    def __init__(self, api_key: str = "") -> None:
        self._api_key = api_key
        self._client = httpx.AsyncClient(timeout=30.0)

    def _headers(self) -> dict[str, str]:
        headers: dict[str, str] = {}
        if self._api_key:
            headers["apiKey"] = self._api_key
        return headers

    async def lookup_cve(self, cve_id: str) -> CVEDetail | None:
        """Look up a specific CVE by ID."""
        try:
            response = await self._client.get(
                NVD_BASE,
                params={"cveId": cve_id.upper()},
                headers=self._headers(),
            )
            response.raise_for_status()
            data = response.json()

            vulnerabilities = data.get("vulnerabilities", [])
            if not vulnerabilities:
                return None

            return self._parse_cve(vulnerabilities[0]["cve"])
        except httpx.HTTPError as e:
            logger.error("NVD API error for %s: %s", cve_id, e)
            return None

    async def search_cves(self, keyword: str, limit: int = 10) -> list[CVEDetail]:
        """Search CVEs by keyword."""
        try:
            response = await self._client.get(
                NVD_BASE,
                params={"keywordSearch": keyword, "resultsPerPage": str(limit)},
                headers=self._headers(),
            )
            response.raise_for_status()
            data = response.json()

            return [
                self._parse_cve(item["cve"])
                for item in data.get("vulnerabilities", [])
            ]
        except httpx.HTTPError as e:
            logger.error("NVD API search error: %s", e)
            return []

    @staticmethod
    def _parse_cve(cve_data: dict) -> CVEDetail:
        """Parse NVD API response into CVEDetail model."""
        cve_id = cve_data.get("id", "")
        descriptions = cve_data.get("descriptions", [])
        description = next(
            (d["value"] for d in descriptions if d.get("lang") == "en"), ""
        )

        # Extract CVSS score (prefer v3.1, fall back to v4.0, then v2.0)
        cvss_score = None
        cvss_vector = None
        cvss_version = None
        metrics = cve_data.get("metrics", {})

        for version_key, version_label in [
            ("cvssMetricV31", "3.1"),
            ("cvssMetricV40", "4.0"),
            ("cvssMetricV2", "2.0"),
        ]:
            if version_key in metrics and metrics[version_key]:
                metric = metrics[version_key][0]
                cvss_data = metric.get("cvssData", {})
                cvss_score = cvss_data.get("baseScore")
                cvss_vector = cvss_data.get("vectorString")
                cvss_version = version_label
                break

        # Extract CWE
        cwe_id = None
        weaknesses = cve_data.get("weaknesses", [])
        if weaknesses:
            cwe_desc = weaknesses[0].get("description", [])
            if cwe_desc:
                cwe_id = cwe_desc[0].get("value")

        # Extract affected products (CPE)
        affected_products = []
        configurations = cve_data.get("configurations", [])
        for config in configurations:
            for node in config.get("nodes", []):
                for match in node.get("cpeMatch", []):
                    if match.get("vulnerable"):
                        affected_products.append(match.get("criteria", ""))

        # Extract references
        references = [
            ref.get("url", "") for ref in cve_data.get("references", [])
        ]

        return CVEDetail(
            cve_id=cve_id,
            description=description,
            cvss_score=cvss_score,
            cvss_vector=cvss_vector,
            cvss_version=cvss_version,
            cwe_id=cwe_id,
            published_date=cve_data.get("published"),
            modified_date=cve_data.get("lastModified"),
            affected_products=affected_products[:10],
            references=references[:5],
        )

    async def close(self) -> None:
        await self._client.aclose()
