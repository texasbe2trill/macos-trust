"""Command-line interface for macOS trust scanner."""

import sys
import platform
from pathlib import Path
from typing import Optional

import typer

from macos_trust import __version__
from macos_trust.engine import run_scan
from macos_trust.output.render import render_human, render_json
from macos_trust.output.sarif import write_sarif
from macos_trust.output.html import generate_html_report
from macos_trust.models import Risk
from macos_trust.vendors import KNOWN_VENDORS
from macos_trust.config import Config, load_config, save_example_config
from macos_trust.baseline import Baseline


def version_callback(value: bool):
    """Print version and exit."""
    if value:
        print(f"macos-trust version {__version__}")
        raise typer.Exit()


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
    sarif: Optional[Path] = typer.Option(
        None,
        "--sarif",
        help="Write SARIF 2.1.0 format output to specified file"
    ),
    html: Optional[Path] = typer.Option(
        None,
        "--html",
        help="Write interactive HTML report to specified file"
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
    ),
    config_file: Optional[Path] = typer.Option(
        None,
        "--config",
        help="Path to configuration file (default: ~/.macos-trust.yaml)"
    ),
    save_baseline: bool = typer.Option(
        False,
        "--save-baseline",
        help="Save current scan results as baseline for future diff mode"
    ),
    baseline_file: Optional[Path] = typer.Option(
        None,
        "--baseline-file",
        help="Path to baseline file (default: from config or ~/.macos-trust/baseline.json)"
    ),
    diff_mode: bool = typer.Option(
        False,
        "--diff",
        help="Show only new or changed findings since baseline (default if baseline exists)"
    ),
    show_all: bool = typer.Option(
        False,
        "--show-all",
        help="Show all findings, not just diff (overrides diff mode)"
    ),
    trust_vendor: Optional[list[str]] = typer.Option(
        None,
        "--trust-vendor",
        help="Add vendor Team ID to trusted list for this scan. Can be specified multiple times."
    ),
    generate_config: Optional[Path] = typer.Option(
        None,
        "--generate-config",
        help="Generate example configuration file at specified path and exit"
    ),
    fast: bool = typer.Option(
        False,
        "--fast",
        help="Enable parallel processing for faster scans (uses more CPU)"
    ),
    version: Optional[bool] = typer.Option(
        None,
        "--version",
        callback=version_callback,
        is_eager=True,
        help="Show version and exit"
    )
) -> None:
    """
    Scan the system for security and trust issues.
    
    By default, outputs a human-readable report to stdout showing MED and HIGH risk findings.
    Use --json for machine-readable JSON output.
    Use --html to generate an interactive HTML report with charts.
    Use --sarif to write SARIF 2.1.0 format for CI/CD integration.
    Use --out to write results to a file.
    Use --min-risk to filter by severity (e.g., --min-risk HIGH shows only HIGH).
    Use --exclude-vendor to hide findings from known vendors (e.g., --exclude-vendor UBF8T346G9).
    Use --verbose to see all findings including INFO level.
    Use --group-by-vendor to organize output by developer/vendor.
    Use --config to specify configuration file.
    Use --save-baseline to save current results as baseline.
    Use --diff to show only new/changed findings since baseline.
    Use --trust-vendor to temporarily trust additional vendors.
    Use --generate-config to create example config file.
    
    Examples:
        macos-trust                                    # Show MED and HIGH findings
        macos-trust --verbose                          # Show all findings including INFO
        macos-trust --min-risk HIGH                    # Show only HIGH risk
        macos-trust --exclude-vendor UBF8T346G9        # Exclude Microsoft findings
        macos-trust --group-by-vendor                  # Group by vendor
        macos-trust --json --out report.json           # Save JSON report
        macos-trust --html security-report.html        # Generate interactive HTML report
        macos-trust --sarif findings.sarif             # Save SARIF report for CI/CD
        macos-trust --save-baseline                    # Save baseline
        macos-trust --diff                             # Show only new findings
        macos-trust --config custom.yaml               # Use custom config
        macos-trust --trust-vendor H7H8Q7M5CK          # Trust Postman for this scan
        macos-trust --generate-config ~/.macos-trust.yaml  # Create example config
    """
    # Check if generating config
    if generate_config:
        try:
            save_example_config(generate_config)
            print(f"✓ Example configuration saved to {generate_config}", file=sys.stderr)
            sys.exit(0)
        except Exception as e:
            print(f"Error generating config: {e}", file=sys.stderr)
            sys.exit(2)
    
    # Check if running on macOS
    if platform.system() != "Darwin":
        print("Error: This tool only works on macOS", file=sys.stderr)
        sys.exit(2)
    
    # Load configuration
    try:
        config = load_config(config_file)
    except Exception as e:
        print(f"Error loading configuration: {e}", file=sys.stderr)
        print("Continuing with default settings...", file=sys.stderr)
        config = Config()
    
    # Apply CLI overrides to config
    if trust_vendor:
        config.trusted_vendors.extend(trust_vendor)
    
    if exclude_vendor:
        config.exclude_vendors.extend(exclude_vendor)
    
    # Parse min_risk option (CLI overrides config)
    min_risk_level = None
    if min_risk:
        try:
            min_risk_level = Risk[min_risk.upper()]
        except KeyError:
            print(f"Error: Invalid risk level '{min_risk}'. Must be one of: INFO, LOW, MED, HIGH", file=sys.stderr)
            sys.exit(2)
    elif not verbose:
        # Try config, otherwise default to MED
        try:
            min_risk_level = Risk[config.min_risk.upper()]
        except (KeyError, AttributeError):
            min_risk_level = Risk.MED
    
    # Determine baseline file path
    baseline_path = baseline_file if baseline_file else Path(config.baseline_file).expanduser()
    
    # Initialize baseline
    baseline = Baseline(baseline_path)
    baseline_exists = baseline.load()
    
    # Determine if we should use diff mode
    use_diff_mode = (diff_mode or baseline_exists) and not show_all
    
    # Run the scan
    try:
        report = run_scan(config, parallel=fast)
    except Exception as e:
        print(f"Scan failed: {e}", file=sys.stderr)
        sys.exit(3)
    
    # Save baseline if requested
    if save_baseline:
        try:
            baseline.save(report)
            print(f"✓ Baseline saved to {baseline_path} ({len(report.findings)} findings)", file=sys.stderr)
            if not json and not sarif:
                # Don't exit if also generating output
                sys.exit(0)
        except Exception as e:
            print(f"Error saving baseline: {e}", file=sys.stderr)
            sys.exit(3)
    
    # Apply filters to findings
    filtered_findings = report.findings
    
    # Apply diff mode if enabled
    if use_diff_mode and baseline_exists:
        filtered_findings = baseline.filter_new_findings(filtered_findings)
        if not json:
            baseline_count = baseline.get_baseline_count()
            new_count = len(filtered_findings)
            print(f"ℹ️  Diff mode: Showing {new_count} new/changed findings (baseline has {baseline_count})", file=sys.stderr)
    
    # Filter by minimum risk level
    if min_risk_level:
        filtered_findings = [f for f in filtered_findings if f.risk >= min_risk_level]
    
    # Filter by excluded vendors
    if config.exclude_vendors:
        exclude_set = set(config.exclude_vendors)
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
    
    # Write SARIF output if requested
    if sarif:
        try:
            # Ensure parent directory exists
            if not sarif.parent.exists():
                print(f"Error: Directory does not exist: {sarif.parent}", file=sys.stderr)
                sys.exit(2)
            write_sarif(str(sarif), filtered_report)
            print(f"✓ SARIF report written to {sarif}", file=sys.stderr)
        except Exception as e:
            print(f"SARIF output failed: {e}", file=sys.stderr)
            sys.exit(3)
    
    # Write HTML output if requested
    if html:
        try:
            # Ensure parent directory exists
            if not html.parent.exists():
                print(f"Error: Directory does not exist: {html.parent}", file=sys.stderr)
                sys.exit(2)
            
            # Convert report to dict format for HTML generator
            findings_dict = [f.model_dump() for f in filtered_report.findings]
            metadata_dict = {
                "hostname": filtered_report.host.hostname,
                "os_version": filtered_report.host.os_version,
                "arch": filtered_report.host.arch,
                "timestamp": filtered_report.timestamp,
                "tool_version": __version__
            }
            
            generate_html_report(findings_dict, metadata_dict, html)
            print(f"✓ HTML report written to {html}", file=sys.stderr)
        except Exception as e:
            print(f"HTML output failed: {e}", file=sys.stderr)
            import traceback
            traceback.print_exc()
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
            # Print to stdout (unless only SARIF was requested)
            if not sarif or json:
                print(output)
            elif sarif and not out:
                # SARIF only, still show human output to stdout
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
