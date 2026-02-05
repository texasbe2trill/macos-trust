"""SARIF (Static Analysis Results Interchange Format) output renderer."""

import json
from pathlib import Path

from macos_trust.models import ScanReport, Risk, Finding


def _risk_to_sarif_level(risk: Risk) -> str:
    """
    Convert Risk enum to SARIF level.
    
    SARIF levels: "error", "warning", "note", "none"
    Mapping: HIGH -> error, MED -> warning, LOW/INFO -> note
    """
    mapping = {
        Risk.HIGH: "error",
        Risk.MED: "warning",
        Risk.LOW: "note",
        Risk.INFO: "note",
    }
    return mapping[risk]


def _sanitize_rule_name(rule_id: str) -> str:
    """
    Convert a rule ID to a safe rule name.
    
    SARIF rule names should be short, alphanumeric identifiers.
    Example: "app:unsigned:elevated" -> "app-unsigned-elevated"
    """
    return rule_id.replace(":", "-").replace("_", "-")


def _dedupe_rules(findings: list[Finding]) -> dict[str, Finding]:
    """
    Deduplicate findings by ID to create unique SARIF rules.
    
    Returns a dict mapping rule_id -> representative Finding.
    """
    rules_map = {}
    for finding in findings:
        if finding.id not in rules_map:
            rules_map[finding.id] = finding
    return rules_map


def render_sarif(report: ScanReport) -> dict:
    """
    Render a ScanReport as a SARIF 2.1.0 document.
    
    Args:
        report: ScanReport to convert to SARIF format
    
    Returns:
        SARIF document as a dictionary (ready for JSON serialization)
    """
    # Get package version from pyproject.toml or default
    version = "0.1.0"
    
    # Deduplicate rules
    rules_map = _dedupe_rules(report.findings)
    
    # Build SARIF rules from unique findings
    rules = []
    for rule_id, finding in rules_map.items():
        rule = {
            "id": rule_id,
            "name": _sanitize_rule_name(rule_id),
            "shortDescription": {
                "text": finding.title
            },
            "fullDescription": {
                "text": finding.details
            },
            "help": {
                "text": finding.recommendation
            }
        }
        rules.append(rule)
    
    # Build SARIF results from all findings
    results = []
    for finding in report.findings:
        # Combine title + details for message
        message_text = f"{finding.title}: {finding.details}"
        
        # Build result object
        result = {
            "ruleId": finding.id,
            "level": _risk_to_sarif_level(finding.risk),
            "message": {
                "text": message_text
            },
            "properties": {
                "category": finding.category,
                "risk": finding.risk.value,
                "evidence": {k: str(v) for k, v in finding.evidence.items()}
            }
        }
        
        # Add location if path exists
        if finding.path:
            result["locations"] = [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": finding.path
                        }
                    }
                }
            ]
        
        results.append(result)
    
    # Build complete SARIF document
    sarif = {
        "$schema": "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0-rtm.5.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "macos-trust",
                        "informationUri": "https://github.com/texasbe2trill/macos-trust",
                        "version": version,
                        "rules": rules
                    }
                },
                "results": results
            }
        ]
    }
    
    return sarif


def write_sarif(path: str, report: ScanReport) -> None:
    """
    Write a ScanReport to a SARIF file.
    
    Args:
        path: Output file path
        report: ScanReport to write
    
    Raises:
        OSError: If file cannot be written
    """
    sarif_doc = render_sarif(report)
    sarif_json = json.dumps(sarif_doc, indent=2, sort_keys=True)
    
    # Write to file
    output_path = Path(path)
    output_path.write_text(sarif_json)
