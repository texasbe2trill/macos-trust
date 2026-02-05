"""Main scan engine orchestrating the security assessment."""

from datetime import datetime

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn, TimeRemainingColumn

from macos_trust.models import ScanReport, Finding
from macos_trust.util.host import get_host_info
from macos_trust.scanners.apps import scan_applications
from macos_trust.scanners.launchd import scan_launchd
from macos_trust.collectors.codesign import codesign_verify
from macos_trust.collectors.spctl import spctl_assess
from macos_trust.collectors.quarantine import get_quarantine
from macos_trust.rules import analyze_app, analyze_launchd


def run_scan() -> ScanReport:
    """
    Execute a complete security scan of the macOS system.
    
    Returns:
        ScanReport containing host information and security findings
    
    Raises:
        RuntimeError: If critical system information cannot be retrieved
        
    Example:
        >>> report = run_scan()
        >>> print(f"Found {len(report.findings)} issues")
    """
    # Collect host information
    host = get_host_info()
    
    # Collect all findings
    all_findings: list[Finding] = []
    
    # Scan applications
    app_findings = _scan_and_analyze_apps()
    all_findings.extend(app_findings)
    
    # Scan launch agents/daemons
    launchd_findings = _scan_and_analyze_launchd()
    all_findings.extend(launchd_findings)
    
    # Sort findings by risk level (highest first), then by title
    sorted_findings = sorted(all_findings, key=lambda f: (f.risk, f.title))
    
    # Create report with current timestamp
    report = ScanReport(
        schema_version="0.1",
        host=host,
        timestamp=datetime.utcnow().isoformat() + "Z",
        findings=sorted_findings
    )
    
    return report


def _scan_and_analyze_apps() -> list[Finding]:
    """
    Scan all applications and generate findings.
    
    Returns:
        List of findings from application analysis
    """
    findings: list[Finding] = []
    console = Console(stderr=True)
    
    # Get all applications
    try:
        with Progress(
            SpinnerColumn(),
            TextColumn("[bold blue]Discovering applications..."),
            console=console,
            transient=False
        ) as progress:
            progress.add_task("scan", total=None)
            apps = scan_applications()
        console.print("[green]✓[/green] Found [bold]{} applications[/bold]".format(len(apps)))
    except Exception:
        # If we can't scan apps at all, return empty list
        # Individual app failures are handled below
        return findings
    
    if not apps:
        return findings
    
    # Analyze applications with progress bar
    with Progress(
        SpinnerColumn(),
        TextColumn("[bold cyan]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        TimeRemainingColumn(),
        console=console,
        transient=False
    ) as progress:
        task = progress.add_task(f"Analyzing applications...", total=len(apps))
        
        for app in apps:
            app_name = app.get('name', 'Unknown')
            progress.update(task, description=f"Analyzing [cyan]{app_name}[/cyan]...")
            
            try:
                app_findings = _analyze_single_app(app)
                findings.extend(app_findings)
            except Exception:
                # Skip this app if analysis fails completely
                # This ensures one bad app doesn't stop the entire scan
                pass
            
            progress.advance(task)
    
    console.print("[green]✓[/green] Application analysis complete\n")
    return findings


def _analyze_single_app(app: dict) -> list[Finding]:
    """
    Analyze a single application with all collectors.
    
    Args:
        app: Application record from scan_applications()
    
    Returns:
        List of findings for this application
    """
    # Only run collectors if we have an executable path
    exec_path = app.get("exec_path", "")
    
    if not exec_path:
        # No executable to analyze
        return []
    
    # Run collectors (each returns a dict, never throws)
    codesign_result = None
    spctl_result = None
    quarantine_result = None
    
    try:
        codesign_result = codesign_verify(exec_path)
    except Exception:
        # Collector failed, but we continue with other collectors
        pass
    
    try:
        spctl_result = spctl_assess(exec_path)
    except Exception:
        pass
    
    try:
        quarantine_result = get_quarantine(exec_path)
    except Exception:
        pass
    
    # Apply rules to generate findings
    try:
        findings = analyze_app(
            app=app,
            codesign_result=codesign_result,
            spctl_result=spctl_result,
            quarantine_result=quarantine_result
        )
        return findings
    except Exception:
        # Rule analysis failed
        return []


def _scan_and_analyze_launchd() -> list[Finding]:
    """
    Scan all launch agents/daemons and generate findings.
    
    Returns:
        List of findings from launchd analysis
    """
    findings: list[Finding] = []
    console = Console(stderr=True)
    
    # Get all launch items
    try:
        with Progress(
            SpinnerColumn(),
            TextColumn("[bold blue]Discovering launch agents/daemons..."),
            console=console,
            transient=False
        ) as progress:
            progress.add_task("scan", total=None)
            launchd_items = scan_launchd()
        console.print("[green]✓[/green] Found [bold]{} launch items[/bold]".format(len(launchd_items)))
    except Exception:
        # If we can't scan launchd at all, return empty list
        return findings
    
    if not launchd_items:
        return findings
    
    # Analyze launch items with progress bar
    with Progress(
        SpinnerColumn(),
        TextColumn("[bold cyan]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        TimeRemainingColumn(),
        console=console,
        transient=False
    ) as progress:
        task = progress.add_task(f"Analyzing launch items...", total=len(launchd_items))
        
        for item in launchd_items:
            label = item.get('label', 'Unknown')
            progress.update(task, description=f"Analyzing [cyan]{label}[/cyan]...")
            
            try:
                item_findings = _analyze_single_launchd(item)
                findings.extend(item_findings)
            except Exception:
                # Skip this item if analysis fails completely
                pass
            
            progress.advance(task)
    
    console.print("[green]✓[/green] LaunchD analysis complete\n")
    return findings


def _analyze_single_launchd(item: dict) -> list[Finding]:
    """
    Analyze a single launch agent/daemon with all collectors.
    
    Args:
        item: Launch item record from scan_launchd()
    
    Returns:
        List of findings for this launch item
    """
    # Only run collectors if we have a program path and it exists
    program = item.get("program", "")
    
    if not program:
        # No program to analyze, but still run rules (e.g., for user-writable path check)
        try:
            findings = analyze_launchd(
                launchd_item=item,
                codesign_result=None,
                spctl_result=None,
                quarantine_result=None
            )
            return findings
        except Exception:
            return []
    
    # Check if program path exists before running collectors
    from pathlib import Path
    program_path = Path(program)
    
    if not program_path.exists():
        # Program doesn't exist, still run rules for detection
        try:
            findings = analyze_launchd(
                launchd_item=item,
                codesign_result=None,
                spctl_result=None,
                quarantine_result=None
            )
            return findings
        except Exception:
            return []
    
    # Run collectors (each returns a dict, never throws)
    codesign_result = None
    spctl_result = None
    quarantine_result = None
    
    try:
        codesign_result = codesign_verify(program)
    except Exception:
        pass
    
    try:
        spctl_result = spctl_assess(program)
    except Exception:
        pass
    
    try:
        quarantine_result = get_quarantine(program)
    except Exception:
        pass
    
    # Apply rules to generate findings
    try:
        findings = analyze_launchd(
            launchd_item=item,
            codesign_result=codesign_result,
            spctl_result=spctl_result,
            quarantine_result=quarantine_result
        )
        return findings
    except Exception:
        return []
