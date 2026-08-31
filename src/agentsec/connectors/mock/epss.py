"""Mock EPSS (Exploit Prediction Scoring System) connector."""

from __future__ import annotations

import json
from pathlib import Path

from agentsec.models.cve import EPSSScore

_DATA_DIR = Path(__file__).resolve().parents[4] / "data" / "mock"


class MockEPSSConnector:
    """Mock connector that loads EPSS scores from JSON fixtures."""

    def __init__(self) -> None:
        self._scores = self._load_scores()

    def _load_scores(self) -> dict[str, EPSSScore]:
        path = _DATA_DIR / "epss_scores.json"
        with open(path) as f:
            data = json.load(f)
        return {
            item["cve_id"]: EPSSScore.model_validate(item)
            for item in data
        }

    async def get_epss_score(self, cve_id: str) -> EPSSScore | None:
        return self._scores.get(cve_id.upper())

    async def get_epss_scores(self, cve_ids: list[str]) -> list[EPSSScore]:
        results = []
        for cve_id in cve_ids:
            score = self._scores.get(cve_id.upper())
            if score:
                results.append(score)
        return results
