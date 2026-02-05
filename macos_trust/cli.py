"""Command-line interface for macOS trust scanner."""

import sys
import platform
from pathlib import Path
from typing import Optional

import typer

from macos_trust.engine import run_scan
from macos_trust.output.render import render_human, render_json
from macos_trust.models import Risk
from macos_trust.vendors import KNOWN_VENDORS


def scan(
    json: bool = typer.Option(
        False,
        "--json",
        help="Output results in JSON format"
    ),
    out: Optional[Path] = typer.Option(
        None,
        "--out",
        help="Write output to file instead of stdout"
    ),
    min_risk: Optional[str] = typer.Option(
        None,
        "--min-risk",
        help="Filter findings by minimum risk level (INFO, LOW, MED, HIGH)"
    ),
    exclude_vendor: Optional[list[str]] = typer.Option(
        None,
        "--exclude-vendor",
        help="Exclude findings from specific vendors by team ID (e.g., UBF8T346G9 for Microsoft). Can be specified multiple times."
    ),
    verbose: bool = typer.Option(
        False,
        "--verbose",
        "-v",
        help="Show all findings including INFO level (default: only MED and HIGH)"
    ),
    group_by_vendor: bool = typer.Option(
        False,
        "--group-by-vendor",
        help="Group findings by vendor/developer in output"
    )
) -> None:
    """
    Scan the system for security and trust issues.
    
    By default, outputs a human-readable report to stdout showing MED and HIGH risk findings.
    Use --json for machine-readable JSON output.
    Use --out to write results to a file.
    Use --min-risk to filter by severity (e.g., --min-risk HIGH shows only HIGH).
    Use --exclude-vendor to hide findings from known vendors (e.g., --exclude-vendor UBF8T346G9).
    Use --verbose to see all findings including INFO level.
    Use --group-by-vendor to organize output by developer/vendor.
    
    Examples:
        macos-trust                                    # Show MED and HIGH findings
        macos-trust --verbose                          # Show all findings including INFO
        macos-trust --min-risk HIGH                    # Show only HIGH risk
        macos-trust --exclude-vendor UBF8T346G9        # Exclude Microsoft findings
        macos-trust --group-by-vendor                  # Group by vendor
        macos-trust --json --out report.json           # Save JSON report
    """
    # Check if running on macOS
    if platform.system() != "Darwin":
        print("Error: This tool only works on macOS", file=sys.stderr)
        sys.exit(2)
    
    # Parse min_risk option
    min_risk_level = None
    if min_risk:
        try:
            min_risk_level = Risk[min_risk.upper()]
        except KeyError:
            print(f"Error: Invalid risk level '{min_risk}'. Must be one of: INFO, LOW, MED, HIGH", file=sys.stderr)
            sys.exit(2)
    elif not verbose:
        # Default: show only MED and above
        min_risk_level = Risk.MED
    
    # Run the scan
    try:
        report = run_scan()
    except Exception as e:
        print(f"Scan failed: {e}", file=sys.stderr)
        sys.exit(3)
    
    # Apply filters to findings
    filtered_findings = report.findings
    
    # Filter by minimum risk level
    if min_risk_level:
        filtered_findings = [f for f in filtered_findings if f.risk >= min_risk_level]
    
    # Filter by excluded vendors
    if exclude_vendor:
        exclude_set = set(exclude_vendor)
        filtered_findings = [
            f for f in filtered_findings
            if f.evidence.get("codesign_team_id", "") not in exclude_set
            and f.evidence.get("spctl_team_id", "") not in exclude_set
        ]
    
    # Create filtered report
    from macos_trust.models import ScanReport
    filtered_report = ScanReport(
        host=report.host,
        findings=filtered_findings,
        timestamp=report.timestamp
    )
    
    # Render output based on format
    try:
        if json:
            output = render_json(filtered_report)
        else:
            output = render_human(filtered_report, group_by_vendor=group_by_vendor)
    except Exception as e:
        print(f"Rendering failed: {e}", file=sys.stderr)
        sys.exit(3)
    
    # Write output to file or stdout
    try:
        if out:
            # Ensure parent directory exists for better error message
            if not out.parent.exists():
                print(f"Error: Directory does not exist: {out.parent}", file=sys.stderr)
                sys.exit(2)
            out.write_text(output)
            print(f"✓ Report written to {out}", file=sys.stderr)
        else:
            # Print to stdout
            print(output)
    except Exception as e:
        print(f"Output failed: {e}", file=sys.stderr)
        sys.exit(3)
    
    # Success
    sys.exit(0)


def main() -> None:
    """Entry point for the CLI."""
    typer.run(scan)


if __name__ == "__main__":
    main()
