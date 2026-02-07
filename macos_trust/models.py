"""Data models for macOS trust scanner."""

from dataclasses import dataclass, field, asdict
from datetime import datetime, UTC
from enum import Enum
from typing import Any
import json


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


@dataclass
class Finding:
    """Individual security finding."""
    
    id: str
    category: str
    risk: Risk
    title: str
    details: str
    recommendation: str
    path: str | None = None
    evidence: dict[str, str] = field(default_factory=dict)
    
    def model_dump(self) -> dict[str, Any]:
        """Return finding as dictionary (pydantic compatibility)."""
        data = asdict(self)
        data['risk'] = self.risk.value
        return data
    
    def model_dump_json(self, **kwargs: Any) -> str:
        """Serialize to JSON with sorted keys for stability."""
        return json.dumps(self.model_dump(), sort_keys=True)


@dataclass
class HostInfo:
    """Host system information."""
    
    os_version: str
    build: str
    arch: str
    hostname: str
    
    def model_dump(self) -> dict[str, Any]:
        """Return host info as dictionary (pydantic compatibility)."""
        return asdict(self)


@dataclass
class ScanReport:
    """Complete scan report with findings."""
    
    host: HostInfo
    timestamp: str
    findings: list[Finding] = field(default_factory=list)
    schema_version: str = "0.1"
    
    @classmethod
    def create(cls, host: HostInfo, findings: list[Finding] | None = None) -> "ScanReport":
        """Create a new scan report with current timestamp."""
        return cls(
            host=host,
            timestamp=datetime.now(UTC).isoformat().replace("+00:00", "Z"),
            findings=findings or []
        )
    
    def model_dump(self) -> dict[str, Any]:
        """Return report as dictionary (pydantic compatibility)."""
        return {
            "schema_version": self.schema_version,
            "host": self.host.model_dump(),
            "timestamp": self.timestamp,
            "findings": [f.model_dump() for f in self.findings]
        }
    
    def model_dump_json(self, **kwargs: Any) -> str:
        """Serialize to JSON with sorted keys for stability."""
        return json.dumps(self.model_dump(), sort_keys=True, indent=2)
    
    def sorted_findings(self) -> list[Finding]:
        """Return findings sorted by risk level (highest first), then by title."""
        return sorted(self.findings, key=lambda f: (f.risk, f.title))
    
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
