"""Data models for CVE triage (NVD, CISA KEV, EPSS)."""

from __future__ import annotations

from datetime import date, datetime
from enum import StrEnum

from pydantic import BaseModel, Field


class TriagePriority(StrEnum):
    """CVE triage priority levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class CVEDetail(BaseModel):
    """CVE details from NVD (National Vulnerability Database)."""
    cve_id: str = Field(..., pattern=r"^CVE-\d{4}-\d{4,}$")
    description: str = ""
    cvss_score: float | None = Field(None, ge=0.0, le=10.0)
    cvss_vector: str | None = None
    cvss_version: str | None = None  # "3.1", "4.0"
    cwe_id: str | None = None
    published_date: datetime | None = None
    modified_date: datetime | None = None
    affected_products: list[str] = Field(default_factory=list)
    references: list[str] = Field(default_factory=list)
    
    @property
    def cvss_severity(self) -> str:
        """Return human-readable CVSS severity label."""
        if self.cvss_score is None:
            return "N/A"
        if self.cvss_score >= 9.0:
            return "Critical"
        if self.cvss_score >= 7.0:
            return "High"
        if self.cvss_score >= 4.0:
            return "Medium"
        if self.cvss_score > 0.0:
            return "Low"
        return "None"


class EPSSScore(BaseModel):
    """EPSS (Exploit Prediction Scoring System) data from FIRST.org."""
    cve_id: str
    score: float = Field(..., ge=0.0, le=1.0, description="Probability of exploitation in 30 days")
    percentile: float = Field(..., ge=0.0, le=1.0, description="Percentile rank among all CVEs")
    
    @property
    def score_percent(self) -> str:
        """Return score as percentage string."""
        return f"{self.score * 100:.1f}%"


class KEVEntry(BaseModel):
    """Entry from CISA Known Exploited Vulnerabilities catalog."""
    cve_id: str
    vendor: str = ""
    product: str = ""
    vulnerability_name: str = ""
    date_added: date | None = None
    due_date: date | None = None
    known_ransomware_use: bool = False
    notes: str = ""
    
    @property
    def is_overdue(self) -> bool:
        """Check if remediation due date has passed."""
        if self.due_date is None:
            return False
        return date.today() > self.due_date


class TriagedCVE(BaseModel):
    """Result of CVE triage combining CVSS + KEV + EPSS."""
    cve: CVEDetail
    epss: EPSSScore | None = None
    kev_entry: KEVEntry | None = None
    composite_score: float = Field(0.0, ge=0.0, le=10.0)
    priority: TriagePriority = TriagePriority.INFO
    recommendation: str = ""
    
    @property
    def is_in_kev(self) -> bool:
        """Whether this CVE is in the CISA KEV catalog."""
        return self.kev_entry is not None

    @property
    def in_kev(self) -> bool:
        """Alias for is_in_kev."""
        return self.is_in_kev

    @property
    def cve_id(self) -> str:
        """CVE ID helper."""
        return self.cve.cve_id

    @property
    def base_score(self) -> float:
        """Base CVSS score helper."""
        return self.cve.cvss_score or 0.0

    @property
    def epss_score(self) -> float:
        """EPSS score helper."""
        return self.epss.score if self.epss else 0.0
    
    @property
    def summary(self) -> str:
        """Return a comprehensive one-line summary."""
        parts = [f"[{self.priority.value.upper()}] {self.cve.cve_id}"]
        if self.cve.cvss_score is not None:
            parts.append(f"CVSS:{self.cve.cvss_score}")
        if self.epss:
            parts.append(f"EPSS:{self.epss.score_percent}")
        if self.is_in_kev:
            parts.append("⚠️ KEV")
        return " | ".join(parts)
