"""Output rendering for scan reports."""

import json
from io import StringIO
from collections import defaultdict

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich import box

from macos_trust.models import ScanReport, Risk
from macos_trust.vendors import get_vendor_name, is_known_vendor


def render_human(report: ScanReport, group_by_vendor: bool = False) -> str:
    """
    Render scan report in human-readable format using Rich.
    
    Args:
        report: ScanReport to render
        group_by_vendor: If True, group findings by vendor
    
    Returns:
        Formatted string suitable for terminal display
    """
    # Use Console with file=StringIO to capture output with colors
    output_buffer = StringIO()
    console = Console(file=output_buffer, width=120, force_terminal=True)
    
    # Header with panel
    console.print()
    header_text = Text()
    header_text.append("🔍 macOS Trust Scanner", style="bold cyan")
    console.print(Panel(header_text, border_style="cyan", box=box.ROUNDED))
    
    # Host information in a styled box
    host_info = Table.grid(padding=(0, 2))
    host_info.add_column(style="bold cyan", justify="right")
    host_info.add_column(style="white")
    
    host_info.add_row("Host:", f"[bold]{report.host.hostname}[/bold]")
    host_info.add_row("OS Version:", f"{report.host.os_version} [dim](Build {report.host.build})[/dim]")
    host_info.add_row("Architecture:", report.host.arch)
    host_info.add_row("Scan Time:", f"[dim]{report.timestamp}[/dim]")
    
    console.print(Panel(host_info, border_style="blue", box=box.ROUNDED, padding=(0, 1)))
    console.print()
    
    # Summary counts with styled panel
    summary = report.summary()
    summary_text = Text()
    
    # Add risk counts with colors and emojis
    if summary['HIGH'] > 0:
        summary_text.append(f"🔴 {summary['HIGH']} HIGH  ", style="bold red")
    else:
        summary_text.append(f"🔴 {summary['HIGH']} HIGH  ", style="dim")
    
    if summary['MED'] > 0:
        summary_text.append(f"🟡 {summary['MED']} MED  ", style="bold yellow")
    else:
        summary_text.append(f"🟡 {summary['MED']} MED  ", style="dim")
    
    if summary['LOW'] > 0:
        summary_text.append(f"🟢 {summary['LOW']} LOW  ", style="bold blue")
    else:
        summary_text.append(f"🟢 {summary['LOW']} LOW  ", style="dim")
        
    summary_text.append(f"ℹ️  {summary['INFO']} INFO", style="dim" if summary['INFO'] == 0 else "bold")
    
    console.print(Panel(summary_text, title="[bold]Summary[/bold]", border_style="yellow", box=box.ROUNDED))
    console.print()
    
    # Get sorted findings
    sorted_findings = report.sorted_findings()
    
    if not sorted_findings:
        success_text = Text()
        success_text.append("✓ No security findings detected", style="bold green")
        console.print(Panel(success_text, border_style="green", box=box.ROUNDED))
        console.print()
        return output_buffer.getvalue()
    
    # Group by vendor if requested
    if group_by_vendor:
        _render_grouped_findings(console, sorted_findings)
    else:
        _render_flat_findings(console, sorted_findings)
    
    # Detailed findings for HIGH and MED only
    high_med_findings = [f for f in sorted_findings if f.risk in (Risk.HIGH, Risk.MED)]
    
    if high_med_findings:
        console.print(Panel(
            "[bold]Detailed Analysis[/bold]",
            border_style="magenta",
            box=box.ROUNDED,
            padding=(0, 1)
        ))
        console.print()
        
        for idx, finding in enumerate(high_med_findings, 1):
            # Finding header with colored panel
            header_text = Text()
            
            # Add risk badge with proper styling
            if finding.risk == Risk.HIGH:
                header_text.append("🔴 HIGH", style="bold red")
            elif finding.risk == Risk.MED:
                header_text.append("🟡 MED", style="bold yellow")
            elif finding.risk == Risk.LOW:
                header_text.append("🟢 LOW", style="bold blue")
            else:
                header_text.append("ℹ️  INFO", style="dim")
            
            header_text.append(" ")
            header_text.append(finding.title, style="bold white")
            
            border_color = "red" if finding.risk == Risk.HIGH else "yellow"
            
            # Build content
            content_lines = []
            content_lines.append(f"[dim]ID:[/dim] [cyan]{finding.id}[/cyan]")
            content_lines.append("")
            content_lines.append(f"[white]{finding.details}[/white]")
            content_lines.append("")
            
            # Path
            if finding.path:
                content_lines.append(f"[bold cyan]Path:[/bold cyan] [dim]{finding.path}[/dim]")
                content_lines.append("")
            
            # Evidence
            if finding.evidence:
                content_lines.append("[bold cyan]Evidence:[/bold cyan]")
                for key, value in sorted(finding.evidence.items()):
                    # Truncate long values
                    value_display = value
                    if len(value_display) > 80:
                        value_display = value_display[:77] + "..."
                    content_lines.append(f"  [yellow]•[/yellow] [cyan]{key}:[/cyan] {value_display}")
                content_lines.append("")
            
            # Recommendation
            content_lines.append(f"[bold cyan]Recommendation:[/bold cyan] [white]{finding.recommendation}[/white]")
            
            console.print(Panel(
                "\n".join(content_lines),
                title=header_text,
                border_style=border_color,
                box=box.ROUNDED,
                padding=(1, 2)
            ))
            
            if idx < len(high_med_findings):
                console.print()
    
    return output_buffer.getvalue()


def _render_flat_findings(console: Console, findings: list) -> None:
    """Render findings in a flat table format."""
    console.print(f"[bold white]Findings[/bold white] [dim]({len(findings)} total)[/dim]")
    console.print()
    
    table = Table(
        show_header=True,
        header_style="bold cyan",
        box=box.ROUNDED,
        border_style="blue",
        row_styles=["", "dim"],
        expand=False
    )
    table.add_column("Risk", style="bold", no_wrap=True)
    table.add_column("Category", style="cyan", no_wrap=True)
    table.add_column("Title", max_width=50, overflow="fold")
    table.add_column("Path", max_width=60, style="dim", overflow="ellipsis")
    
    for finding in findings:
        # Style risk level with colors and icons
        risk_text = _style_risk_badge(finding.risk)
        
        # Truncate path intelligently - show last part
        path_display = finding.path or "N/A"
        if len(path_display) > 60:
            # Show beginning and end of path
            path_display = "..." + path_display[-57:]
        
        # Style title based on risk
        title_style = ""
        if finding.risk == Risk.HIGH:
            title_style = "bold"
        
        table.add_row(
            risk_text,
            finding.category,
            Text(finding.title, style=title_style),
            path_display
        )
    
    console.print(table)
    console.print()


def _render_grouped_findings(console: Console, findings: list) -> None:
    """Render findings grouped by vendor."""
    # Group findings by vendor
    vendor_groups = defaultdict(list)
    
    for finding in findings:
        # Try to extract team_id from evidence
        team_id = (
            finding.evidence.get("codesign_team_id") or 
            finding.evidence.get("spctl_team_id") or 
            ""
        )
        
        if team_id and is_known_vendor(team_id):
            vendor_name = get_vendor_name(team_id)
            vendor_groups[f"{vendor_name} ({team_id})"].append(finding)
        else:
            vendor_groups["Unknown / Other"].append(finding)
    
    # Display grouped findings
    console.print(f"[bold white]Findings by Vendor[/bold white] [dim]({len(findings)} total)[/dim]")
    console.print()
    
    for vendor, vendor_findings in sorted(vendor_groups.items()):
        # Vendor header
        vendor_text = Text()
        vendor_text.append(f"📦 {vendor}", style="bold cyan")
        vendor_text.append(f" - {len(vendor_findings)} finding(s)", style="dim")
        
        console.print(Panel(vendor_text, border_style="cyan", box=box.SIMPLE))
        
        # Findings table for this vendor
        table = Table(
            show_header=True,
            header_style="bold",
            box=box.SIMPLE,
            show_edge=False,
            pad_edge=False
        )
        table.add_column("Risk", style="bold", width=10, no_wrap=True)
        table.add_column("Category", width=12, no_wrap=True)
        table.add_column("Title", width=40)
        table.add_column("Path", width=48, style="dim")
        
        for finding in vendor_findings:
            risk_text = _style_risk_badge(finding.risk)
            path_display = finding.path or "N/A"
            
            title_style = ""
            if finding.risk == Risk.HIGH:
                title_style = "bold"
            
            table.add_row(
                risk_text,
                finding.category,
                Text(finding.title, style=title_style),
                path_display
            )
        
        console.print(table)
        console.print()


def render_json(report: ScanReport) -> str:
    """
    Render scan report as JSON.
    
    Args:
        report: ScanReport to render
    
    Returns:
        JSON string with sorted keys and indentation
    """
    # Convert report to dict
    report_dict = report.model_dump()
    
    # Serialize with sorted keys for deterministic output
    return json.dumps(report_dict, sort_keys=True, indent=2)


def _style_risk_badge(risk: Risk) -> str:
    """
    Apply Rich styling to risk level with icon.
    
    Args:
        risk: Risk level to style
    
    Returns:
        Styled risk string with icon for Rich console
    """
    if risk == Risk.HIGH:
        return "[bold red]🔴 HIGH[/bold red]"
    elif risk == Risk.MED:
        return "[bold yellow]🟡 MED[/bold yellow]"
    elif risk == Risk.LOW:
        return "[bold blue]🟢 LOW[/bold blue]"
    else:  # INFO
        return "[dim]ℹ️  INFO[/dim]"
