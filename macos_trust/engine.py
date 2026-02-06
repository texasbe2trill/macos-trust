"""Main scan engine orchestrating the security assessment."""

import re
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

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
from macos_trust.config import Config


def run_scan(config: Config | None = None, parallel: bool = False) -> ScanReport:
    """
    Execute a complete security scan of the macOS system.
    
    Args:
        config: Configuration for scan behavior and filtering
        parallel: Enable parallel processing for faster scans (may use more CPU)
    
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
    app_findings = _scan_and_analyze_apps(config, parallel=parallel)
    all_findings.extend(app_findings)
    
    # Scan launch agents/daemons
    launchd_findings = _scan_and_analyze_launchd(config, parallel=parallel)
    all_findings.extend(launchd_findings)
    
    # Apply config-based filtering
    if config:
        all_findings = _apply_config_filters(all_findings, config)
    
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


def _apply_config_filters(findings: list[Finding], config: Config) -> list[Finding]:
    """Apply configuration-based filtering to findings."""
    filtered = []
    
    for finding in findings:
        # Check ignore_findings list
        if finding.id in config.ignore_findings:
            continue
        
        # Check ignore_patterns (regex)
        if any(re.match(pattern, finding.id) for pattern in config.ignore_patterns):
            continue
        
        filtered.append(finding)
    
    return filtered


def _scan_and_analyze_apps(config: Config | None = None, parallel: bool = False) -> list[Finding]:
    """
    Scan all applications and generate findings.
    
    Args:
        config: Configuration for scan behavior
        parallel: Enable parallel processing for faster scans
    
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
    if parallel:
        findings = _analyze_apps_parallel(apps, config, console)
    else:
        findings = _analyze_apps_sequential(apps, config, console)
    
    console.print("[green]✓[/green] Application analysis complete\n")
    return findings


def _analyze_apps_sequential(apps: list[dict], config: Config | None, console: Console) -> list[Finding]:
    """Analyze apps sequentially (original behavior)."""
    findings: list[Finding] = []
    
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
                app_findings = _analyze_single_app(app, config)
                findings.extend(app_findings)
            except Exception:
                # Skip this app if analysis fails completely
                # This ensures one bad app doesn't stop the entire scan
                pass
            
            progress.advance(task)
    
    return findings


def _analyze_apps_parallel(apps: list[dict], config: Config | None, console: Console) -> list[Finding]:
    """Analyze apps in parallel using thread pool."""
    findings: list[Finding] = []
    max_workers = min(8, len(apps))  # Limit to 8 concurrent threads
    completed = 0
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[bold cyan]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        TimeRemainingColumn(),
        console=console,
        transient=False
    ) as progress:
        task = progress.add_task(f"Analyzing {len(apps)} applications...", total=len(apps))
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Submit all tasks
            future_to_app = {
                executor.submit(_analyze_single_app, app, config): app 
                for app in apps
            }
            
            # Process results as they complete
            for future in as_completed(future_to_app):
                app = future_to_app[future]
                app_name = app.get('name', 'Unknown')
                completed += 1
                
                # Update description to show last completed app
                progress.update(task, description=f"Analyzed [cyan]{app_name}[/cyan] ({completed}/{len(apps)})...")
                
                try:
                    app_findings = future.result()
                    findings.extend(app_findings)
                except Exception:
                    # Skip this app if analysis fails
                    pass
                
                progress.advance(task)
    
    return findings


def _analyze_single_app(app: dict, config: Config | None = None) -> list[Finding]:
    """
    Analyze a single application with all collectors.
    
    Args:
        app: Application record from scan_applications()
        config: Configuration for scan behavior
    
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
            quarantine_result=quarantine_result,
            config=config
        )
        return findings
    except Exception:
        # Rule analysis failed
        return []


def _scan_and_analyze_launchd(config: Config | None = None, parallel: bool = False) -> list[Finding]:
    """
    Scan all launch agents/daemons and generate findings.
    
    Args:
        config: Configuration for scan behavior
        parallel: Enable parallel processing for faster scans
    
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
    if parallel:
        findings = _analyze_launchd_parallel(launchd_items, config, console)
    else:
        findings = _analyze_launchd_sequential(launchd_items, config, console)
    
    console.print("[green]✓[/green] LaunchD analysis complete\n")
    return findings


def _analyze_launchd_sequential(items: list[dict], config: Config | None, console: Console) -> list[Finding]:
    """Analyze launch items sequentially."""
    findings: list[Finding] = []
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[bold cyan]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        TimeRemainingColumn(),
        console=console,
        transient=False
    ) as progress:
        task = progress.add_task(f"Analyzing launch items...", total=len(items))
        
        for item in items:
            label = item.get('label', 'Unknown')
            progress.update(task, description=f"Analyzing [cyan]{label}[/cyan]...")
            
            try:
                item_findings = _analyze_single_launchd(item, config)
                findings.extend(item_findings)
            except Exception:
                # Skip this item if analysis fails completely
                pass
            
            progress.advance(task)
    
    return findings


def _analyze_launchd_parallel(items: list[dict], config: Config | None, console: Console) -> list[Finding]:
    """Analyze launch items in parallel using thread pool."""
    findings: list[Finding] = []
    max_workers = min(8, len(items))
    completed = 0
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[bold cyan]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        TimeRemainingColumn(),
        console=console,
        transient=False
    ) as progress:
        task = progress.add_task(f"Analyzing {len(items)} launch items...", total=len(items))
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_item = {
                executor.submit(_analyze_single_launchd, item, config): item
                for item in items
            }
            
            for future in as_completed(future_to_item):
                item = future_to_item[future]
                label = item.get('label', 'Unknown')
                completed += 1
                
                # Update description to show last completed item
                progress.update(task, description=f"Analyzed [cyan]{label}[/cyan] ({completed}/{len(items)})...")
                
                try:
                    item_findings = future.result()
                    findings.extend(item_findings)
                except Exception:
                    pass
                
                progress.advance(task)
    
    return findings


def _analyze_single_launchd(item: dict, config: Config | None = None) -> list[Finding]:
    """
    Analyze a single launch agent/daemon with all collectors.
    
    Args:
        item: Launch item record from scan_launchd()
        config: Configuration for scan behavior
    
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
                quarantine_result=None,
                config=config
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
                quarantine_result=None,
                config=config
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
            quarantine_result=quarantine_result,
            config=config
        )
        return findings
    except Exception:
        return []
