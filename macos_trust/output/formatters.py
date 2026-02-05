"""Output formatting for scan results."""

import json
from typing import List, Dict, Any
from datetime import datetime
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text


SCHEMA_VERSION = "1.0.0"


def format_json(results: List[Dict[str, Any]], metadata: Dict[str, Any]) -> str:
    """
    Format scan results as JSON with versioned schema.
    
    Args:
        results: List of scan results
        metadata: Scan metadata (timestamp, version, etc.)
    
    Returns:
        JSON string
    """
    output = {
        "schema_version": SCHEMA_VERSION,
        "metadata": metadata,
        "results": results
    }
    
    return json.dumps(output, indent=2, sort_keys=True)


def format_human(results: List[Dict[str, Any]], metadata: Dict[str, Any]) -> None:
    """
    Format scan results in human-readable format using Rich.
    
    Args:
        results: List of scan results
        metadata: Scan metadata
    """
    console = Console()
    
    # Header
    console.print()
    console.print(Panel.fit(
        "[bold cyan]macOS Trust Scanner[/bold cyan]",
        subtitle=f"v{metadata.get('tool_version', 'unknown')}"
    ))
    console.print()
    
    # Metadata
    console.print(f"[dim]Scan date:[/dim] {metadata.get('timestamp', 'unknown')}")
    console.print(f"[dim]macOS version:[/dim] {metadata.get('macos_version', 'unknown')}")
    console.print(f"[dim]Items scanned:[/dim] {len(results)}")
    console.print()
    
    # Summary statistics
    signed_count = sum(1 for r in results if r.get("codesign", {}).get("signed", False))
    valid_count = sum(1 for r in results if r.get("codesign", {}).get("valid", False))
    accepted_count = sum(1 for r in results if r.get("spctl", {}).get("accepted", False))
    quarantined_count = sum(1 for r in results if r.get("quarantine", {}).get("quarantined", False))
    
    summary_table = Table(show_header=True, header_style="bold magenta")
    summary_table.add_column("Check", style="cyan")
    summary_table.add_column("Count", justify="right", style="green")
    
    summary_table.add_row("Signed", str(signed_count))
    summary_table.add_row("Valid Signature", str(valid_count))
    summary_table.add_row("Gatekeeper Accepted", str(accepted_count))
    summary_table.add_row("Quarantined", str(quarantined_count))
    
    console.print(Panel(summary_table, title="[bold]Summary[/bold]"))
    console.print()
    
    # Detailed results table
    table = Table(show_header=True, header_style="bold magenta", show_lines=True)
    table.add_column("Name", style="cyan", no_wrap=False, max_width=40)
    table.add_column("Type", style="dim")
    table.add_column("Signed", justify="center")
    table.add_column("Valid", justify="center")
    table.add_column("Gatekeeper", justify="center")
    table.add_column("Quarantine", justify="center")
    
    for result in results:
        item = result.get("item", {})
        name = item.get("name", "unknown")
        item_type = item.get("type", "unknown")
        
        codesign = result.get("codesign", {})
        spctl = result.get("spctl", {})
        quarantine = result.get("quarantine", {})
        
        # Format status indicators
        signed = "✓" if codesign.get("signed") else "✗"
        valid = "✓" if codesign.get("valid") else "✗"
        accepted = "✓" if spctl.get("accepted") else "✗"
        quarantined = "✓" if quarantine.get("quarantined") else "✗"
        
        # Color code based on status
        signed_style = "green" if codesign.get("signed") else "red"
        valid_style = "green" if codesign.get("valid") else "red"
        accepted_style = "green" if spctl.get("accepted") else "yellow"
        quarantined_style = "yellow" if quarantine.get("quarantined") else "green"
        
        table.add_row(
            name,
            item_type,
            f"[{signed_style}]{signed}[/{signed_style}]",
            f"[{valid_style}]{valid}[/{valid_style}]",
            f"[{accepted_style}]{accepted}[/{accepted_style}]",
            f"[{quarantined_style}]{quarantined}[/{quarantined_style}]"
        )
    
    console.print(table)
    console.print()
    
    # Show items with issues
    issues = []
    for result in results:
        item = result.get("item", {})
        name = item.get("name", "unknown")
        
        item_issues = []
        
        if not result.get("codesign", {}).get("signed"):
            item_issues.append("Not signed")
        elif not result.get("codesign", {}).get("valid"):
            item_issues.append("Invalid signature")
        
        if not result.get("spctl", {}).get("accepted"):
            item_issues.append("Not accepted by Gatekeeper")
        
        if result.get("quarantine", {}).get("quarantined"):
            item_issues.append("Quarantined")
        
        if item_issues:
            issues.append((name, item_issues))
    
    if issues:
        console.print("[bold yellow]Items with Issues:[/bold yellow]")
        for name, item_issues in issues:
            console.print(f"  [cyan]{name}[/cyan]:")
            for issue in item_issues:
                console.print(f"    • {issue}")
        console.print()


def save_json(results: List[Dict[str, Any]], metadata: Dict[str, Any], output_file: str) -> None:
    """
    Save scan results to a JSON file.
    
    Args:
        results: List of scan results
        metadata: Scan metadata
        output_file: Path to output file
    """
    with open(output_file, 'w') as f:
        f.write(format_json(results, metadata))
