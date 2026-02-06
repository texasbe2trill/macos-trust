"""Baseline management for tracking known findings over time."""

import json
from pathlib import Path
from datetime import datetime, UTC

from macos_trust.models import Finding, ScanReport


class Baseline:
    """Manages baseline findings for diff mode."""
    
    def __init__(self, baseline_path: Path | str):
        """Initialize baseline with path to storage file."""
        self.path = Path(baseline_path).expanduser()
        self.findings: dict[str, dict] = {}  # finding_id -> {risk, title, path, timestamp}
    
    def load(self) -> bool:
        """
        Load baseline from file.
        
        Returns:
            True if baseline was loaded, False if file doesn't exist
        """
        if not self.path.exists():
            return False
        
        try:
            with open(self.path, 'r') as f:
                data = json.load(f)
            
            self.findings = data.get('findings', {})
            return True
        except Exception:
            # If baseline is corrupted, treat as if it doesn't exist
            return False
    
    def save(self, report: ScanReport) -> None:
        """
        Save report findings as new baseline.
        
        Args:
            report: Scan report to save as baseline
        """
        # Create baseline directory if needed
        self.path.parent.mkdir(parents=True, exist_ok=True)
        
        # Convert findings to baseline format
        baseline_data = {
            'created_at': datetime.now(UTC).isoformat(),
            'host': report.host.model_dump(),
            'findings': {
                finding.id: {
                    'risk': finding.risk.value,
                    'title': finding.title,
                    'path': finding.path,
                    'category': finding.category,
                    'timestamp': report.timestamp
                }
                for finding in report.findings
            }
        }
        
        # Write to file
        with open(self.path, 'w') as f:
            json.dump(baseline_data, f, indent=2, sort_keys=True)
        
        self.findings = baseline_data['findings']
    
    def filter_new_findings(self, findings: list[Finding]) -> list[Finding]:
        """
        Filter findings to only those not in baseline or that have changed.
        
        Args:
            findings: Current scan findings
        
        Returns:
            List of new or changed findings
        """
        if not self.findings:
            # No baseline, all findings are new
            return findings
        
        new_or_changed = []
        
        for finding in findings:
            if finding.id not in self.findings:
                # Brand new finding
                new_or_changed.append(finding)
            else:
                # Check if risk level changed
                baseline_risk = self.findings[finding.id].get('risk')
                if baseline_risk != finding.risk.value:
                    # Risk level changed
                    new_or_changed.append(finding)
        
        return new_or_changed
    
    def is_in_baseline(self, finding_id: str) -> bool:
        """Check if a finding ID exists in the baseline."""
        return finding_id in self.findings
    
    def get_baseline_count(self) -> int:
        """Get number of findings in baseline."""
        return len(self.findings)
