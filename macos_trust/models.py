"""Data models for macOS trust scanner."""

from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field, ConfigDict


class Risk(str, Enum):
    """Risk level enumeration with ordering support."""
    
    HIGH = "HIGH"
    MED = "MED"
    LOW = "LOW"
    INFO = "INFO"
    
    def __lt__(self, other: object) -> bool:
        """Compare risk levels: HIGH > MED > LOW > INFO."""
        if not isinstance(other, Risk):
            return NotImplemented
        order = {Risk.HIGH: 0, Risk.MED: 1, Risk.LOW: 2, Risk.INFO: 3}
        return order[self] > order[other]  # Reversed for HIGH > MED ordering
    
    def __le__(self, other: object) -> bool:
        if not isinstance(other, Risk):
            return NotImplemented
        return self < other or self == other
    
    def __gt__(self, other: object) -> bool:
        if not isinstance(other, Risk):
            return NotImplemented
        return not self <= other
    
    def __ge__(self, other: object) -> bool:
        if not isinstance(other, Risk):
            return NotImplemented
        return not self < other
    
    @classmethod
    def from_bool(cls, is_high_risk: bool) -> "Risk":
        """Convert boolean to risk level (True=HIGH, False=LOW)."""
        return cls.HIGH if is_high_risk else cls.LOW
    
    @classmethod
    def from_score(cls, score: float, high_threshold: float = 7.0, med_threshold: float = 4.0) -> "Risk":
        """Convert numeric score to risk level."""
        if score >= high_threshold:
            return cls.HIGH
        elif score >= med_threshold:
            return cls.MED
        elif score > 0:
            return cls.LOW
        return cls.INFO


class Finding(BaseModel):
    """Individual security finding."""
    
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "id": "app_001",
                "category": "app",
                "risk": "HIGH",
                "title": "Unsigned application with elevated privileges",
                "details": "Application is not code signed and has accessibility permissions",
                "path": "/Applications/SuspiciousApp.app",
                "evidence": {"signature": "none", "permissions": "accessibility"},
                "recommendation": "Review application source and remove accessibility permissions"
            }
        }
    )
    
    id: str = Field(description="Unique identifier for this finding")
    category: str = Field(description="Finding category: 'app' or 'persistence'")
    risk: Risk = Field(description="Risk level of the finding")
    title: str = Field(description="Brief title describing the finding")
    details: str = Field(description="Detailed description of the finding")
    path: str | None = Field(default=None, description="File system path related to the finding")
    evidence: dict[str, str] = Field(
        default_factory=dict,
        description="Key-value pairs of supporting evidence"
    )
    recommendation: str = Field(description="Recommended action to address the finding")
    
    def model_dump_json(self, **kwargs: Any) -> str:
        """Serialize to JSON with sorted keys for stability."""
        kwargs.setdefault("sort_keys", True)
        return super().model_dump_json(**kwargs)


class HostInfo(BaseModel):
    """Host system information."""
    
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "os_version": "14.2.1",
                "build": "23C71",
                "arch": "arm64",
                "hostname": "macbook-pro.local"
            }
        }
    )
    
    os_version: str = Field(description="macOS version (e.g., '14.2.1')")
    build: str = Field(description="macOS build number (e.g., '23C71')")
    arch: str = Field(description="System architecture (e.g., 'arm64', 'x86_64')")
    hostname: str = Field(description="System hostname")


class ScanReport(BaseModel):
    """Complete scan report with findings."""
    
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "schema_version": "0.1",
                "host": {
                    "os_version": "14.2.1",
                    "build": "23C71",
                    "arch": "arm64",
                    "hostname": "macbook-pro.local"
                },
                "timestamp": "2026-02-05T10:30:00Z",
                "findings": []
            }
        }
    )
    
    schema_version: str = Field(
        default="0.1",
        description="Schema version for compatibility tracking"
    )
    host: HostInfo = Field(description="Information about the scanned host")
    timestamp: str = Field(description="Scan timestamp in ISO-8601 format")
    findings: list[Finding] = Field(
        default_factory=list,
        description="List of security findings"
    )
    
    @classmethod
    def create(cls, host: HostInfo, findings: list[Finding] | None = None) -> "ScanReport":
        """Create a new scan report with current timestamp."""
        return cls(
            host=host,
            timestamp=datetime.utcnow().isoformat() + "Z",
            findings=findings or []
        )
    
    def sorted_findings(self) -> list[Finding]:
        """Return findings sorted by risk level (highest first), then by title."""
        return sorted(self.findings, key=lambda f: (f.risk, f.title))
    
    def model_dump_json(self, **kwargs: Any) -> str:
        """Serialize to JSON with sorted keys for stability."""
        kwargs.setdefault("sort_keys", True)
        return super().model_dump_json(**kwargs)
    
    def get_findings_by_category(self, category: str) -> list[Finding]:
        """Get all findings for a specific category."""
        return [f for f in self.findings if f.category == category]
    
    def get_findings_by_risk(self, min_risk: Risk = Risk.LOW) -> list[Finding]:
        """Get all findings at or above the specified risk level."""
        return [f for f in self.findings if f.risk <= min_risk]  # <= because HIGH < MED in our ordering
    
    def summary(self) -> dict[str, int]:
        """Get summary counts of findings by risk level."""
        summary = {risk.value: 0 for risk in Risk}
        for finding in self.findings:
            summary[finding.risk.value] += 1
        return summary
