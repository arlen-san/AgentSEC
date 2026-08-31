"""Data models for Cyber Threat Intelligence (QuimeraX and other CTI sources)."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, Field


class IOCType(StrEnum):
    """Indicator of Compromise types."""
    IP = "ip"
    DOMAIN = "domain"
    URL = "url"
    HASH_MD5 = "hash_md5"
    HASH_SHA1 = "hash_sha1"
    HASH_SHA256 = "hash_sha256"
    EMAIL = "email"


class IOC(BaseModel):
    """Indicator of Compromise from a CTI platform."""
    type: IOCType
    value: str
    risk_score: float = Field(0.0, ge=0.0, le=100.0, description="Risk score 0-100")
    source: str = "QuimeraX"
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    tags: list[str] = Field(default_factory=list)
    description: str = ""
    
    @property
    def risk_level(self) -> str:
        """Human-readable risk level."""
        if self.risk_score >= 80:
            return "Critical"
        if self.risk_score >= 60:
            return "High"
        if self.risk_score >= 40:
            return "Medium"
        if self.risk_score >= 20:
            return "Low"
        return "Info"


class LeakedCredential(BaseModel):
    """Leaked credential detected by CTI platform."""
    email: str
    source: str = ""
    date_detected: datetime | None = None
    password_exposed: bool = False
    breach_name: str | None = None


class QuimeraXAlert(BaseModel):
    """Alert from QuimeraX CTI platform."""
    id: str
    title: str
    severity: str = "medium"
    category: str = ""
    description: str = ""
    iocs: list[IOC] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=datetime.now)
