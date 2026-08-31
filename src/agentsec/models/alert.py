"""Data models for security alerts and incidents."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, Field


class Severity(StrEnum):
    """Alert/incident severity levels."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"
    INFORMATIONAL = "informational"


class AlertStatus(StrEnum):
    """Alert status values."""
    NEW = "new"
    IN_PROGRESS = "inProgress"
    RESOLVED = "resolved"
    CLOSED = "closed"
    UNKNOWN = "unknown"


class IncidentStatus(StrEnum):
    """Incident status values."""
    ACTIVE = "active"
    RESOLVED = "resolved"
    REDIRECTED = "redirected"
    UNKNOWN = "unknown"


class Alert(BaseModel):
    """Represents a security alert from Microsoft Defender."""
    id: str
    title: str
    severity: Severity = Severity.MEDIUM
    status: AlertStatus = AlertStatus.NEW
    description: str = ""
    category: str = ""
    source: str = "Microsoft Defender"
    assigned_to: str | None = None
    created_at: datetime = Field(default_factory=datetime.now)
    updated_at: datetime | None = None
    
    def short_summary(self) -> str:
        """Return a one-line summary of the alert."""
        return f"[{self.severity.value.upper()}] {self.title} ({self.status.value})"


class Incident(BaseModel):
    """Represents a security incident aggregating multiple alerts."""
    id: str
    title: str
    severity: Severity = Severity.MEDIUM
    status: IncidentStatus = IncidentStatus.ACTIVE
    description: str = ""
    classification: str | None = None
    determination: str | None = None
    alerts: list[Alert] = Field(default_factory=list)
    assigned_to: str | None = None
    created_at: datetime = Field(default_factory=datetime.now)
    updated_at: datetime | None = None
    
    @property
    def alert_count(self) -> int:
        return len(self.alerts)
    
    def short_summary(self) -> str:
        """Return a one-line summary of the incident."""
        return f"[{self.severity.value.upper()}] {self.title} - {self.alert_count} alert(s) ({self.status.value})"
