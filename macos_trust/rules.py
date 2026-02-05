"""Security rules for generating findings from collected data."""

from macos_trust.models import Finding, Risk
from macos_trust.vendors import (
    is_known_vendor,
    get_vendor_name,
    is_system_helper_path,
    is_user_writable_path as is_user_writable_location
)


def analyze_app(
    app: dict,
    codesign_result: dict | None = None,
    spctl_result: dict | None = None,
    quarantine_result: dict | None = None
) -> list[Finding]:
    """
    Analyze an application and generate security findings.
    
    Args:
        app: Application record from scanners.apps.scan_applications()
        codesign_result: Result from collectors.codesign.codesign_verify()
        spctl_result: Result from collectors.spctl.spctl_assess()
        quarantine_result: Result from collectors.quarantine.get_quarantine()
    
    Returns:
        List of Finding objects for security issues detected
    """
    findings = []
    
    # Generate base ID for this app
    app_id_base = app.get("bundle_id") or app.get("name", "unknown")
    path = app.get("exec_path") or app.get("app_path", "")
    
    # Extract context for risk assessment
    team_id = codesign_result.get("team_id", "") if codesign_result else ""
    is_signed = codesign_result and codesign_result.get("status") == "ok"
    known_vendor = is_known_vendor(team_id) if team_id else False
    
    # Rule 1: Invalid code signature
    if codesign_result and codesign_result.get("status") == "fail":
        # Adjust risk based on context
        risk = Risk.HIGH
        if known_vendor:
            risk = Risk.MED  # Known vendor but invalid signature - concerning but less critical
        
        finding = _create_codesign_fail_finding(
            app=app,
            codesign_result=codesign_result,
            finding_id=f"app:{app_id_base}:codesign_fail",
            risk=risk,
            team_id=team_id
        )
        findings.append(finding)
    
    # Rule 2: Gatekeeper rejected
    if spctl_result and spctl_result.get("status") == "rejected":
        # Context-aware risk assessment
        risk = Risk.HIGH
        
        # Downgrade if signed by known vendor (common for helpers/utilities)
        if is_signed and known_vendor:
            risk = Risk.MED
        
        finding = _create_spctl_rejected_finding(
            app=app,
            spctl_result=spctl_result,
            finding_id=f"app:{app_id_base}:spctl_rejected",
            risk=risk,
            team_id=team_id
        )
        findings.append(finding)
    
    # Rule 3: Quarantined but not auto-run -> LOW
    if quarantine_result and quarantine_result.get("is_quarantined") == "true":
        finding = _create_quarantined_app_finding(
            app=app,
            quarantine_result=quarantine_result,
            finding_id=f"app:{app_id_base}:quarantined"
        )
        findings.append(finding)
    
    # Rule 4: Fully verified by known vendor -> INFO
    if is_signed and known_vendor and codesign_result and spctl_result and spctl_result.get("status") == "accepted":
        finding = _create_verified_app_finding(
            app=app,
            codesign_result=codesign_result,
            spctl_result=spctl_result,
            finding_id=f"app:{app_id_base}:verified",
            team_id=team_id
        )
        findings.append(finding)
    
    return findings


def analyze_launchd(
    launchd_item: dict,
    codesign_result: dict | None = None,
    spctl_result: dict | None = None,
    quarantine_result: dict | None = None
) -> list[Finding]:
    """
    Analyze a launch agent/daemon and generate security findings.
    
    Args:
        launchd_item: Launch item record from scanners.launchd.scan_launchd()
        codesign_result: Result from collectors.codesign.codesign_verify()
        spctl_result: Result from collectors.spctl.spctl_assess()
        quarantine_result: Result from collectors.quarantine.get_quarantine()
    
    Returns:
        List of Finding objects for security issues detected
    """
    findings = []
    
    # Generate base ID for this persistence item
    scope = launchd_item.get("scope", "unknown")
    label = launchd_item.get("label", "unknown")
    persistence_id_base = f"persistence:{scope}:{label}"
    program = launchd_item.get("program", "")
    plist_path = launchd_item.get("plist_path", "")
    
    # Extract context for risk assessment
    team_id = codesign_result.get("team_id", "") if codesign_result else ""
    is_signed = codesign_result and codesign_result.get("status") == "ok"
    known_vendor = is_known_vendor(team_id) if team_id else False
    is_helper = is_system_helper_path(program)
    
    # Rule 1: Invalid code signature
    if codesign_result and codesign_result.get("status") == "fail":
        # Context-aware risk
        risk = Risk.HIGH
        if known_vendor:
            risk = Risk.MED
        
        finding = _create_codesign_fail_finding(
            app=launchd_item,
            codesign_result=codesign_result,
            finding_id=f"{persistence_id_base}:codesign_fail",
            category="persistence",
            risk=risk,
            team_id=team_id
        )
        findings.append(finding)
    
    # Rule 2: Gatekeeper rejected
    if spctl_result and spctl_result.get("status") == "rejected":
        # Context-aware risk assessment
        risk = Risk.HIGH
        
        # System helpers from known vendors commonly fail spctl -> MED
        if is_signed and known_vendor and is_helper:
            risk = Risk.MED
        # Signed by known vendor but not a helper -> still MED (better than unknown)
        elif is_signed and known_vendor:
            risk = Risk.MED
        
        finding = _create_spctl_rejected_finding(
            app=launchd_item,
            spctl_result=spctl_result,
            finding_id=f"{persistence_id_base}:spctl_rejected",
            category="persistence",
            risk=risk,
            team_id=team_id
        )
        findings.append(finding)
    
    # Rule 3: Daemon with user-writable path -> HIGH
    if scope == "daemon" and is_user_writable_location(program):
        finding = _create_user_writable_daemon_finding(
            launchd_item=launchd_item,
            finding_id=f"{persistence_id_base}:user_writable"
        )
        findings.append(finding)
    
    # Rule 4: Quarantined + RunAtLoad -> MED
    run_at_load = launchd_item.get("run_at_load", False)
    
    if quarantine_result and quarantine_result.get("is_quarantined") == "true":
        if run_at_load:
            finding = _create_quarantined_persistence_finding(
                launchd_item=launchd_item,
                quarantine_result=quarantine_result,
                finding_id=f"{persistence_id_base}:quarantined",
                run_at_load=True
            )
            findings.append(finding)
        else:
            # Quarantined but not auto-run -> LOW
            finding = _create_quarantined_persistence_finding(
                launchd_item=launchd_item,
                quarantine_result=quarantine_result,
                finding_id=f"{persistence_id_base}:quarantined_only",
                run_at_load=False
            )
            findings.append(finding)
    
    return findings


def _create_codesign_fail_finding(
    app: dict,
    codesign_result: dict,
    finding_id: str,
    category: str = "app",
    risk: Risk = Risk.HIGH,
    team_id: str = ""
) -> Finding:
    """Create a finding for failed code signature verification."""
    path = app.get("exec_path") or app.get("app_path") or app.get("plist_path", "")
    name = app.get("name") or app.get("label", "Unknown")
    
    # Build vendor-aware recommendation
    recommendation = "Verify the source of this item. Remove if untrusted. Re-download from official sources if legitimate."
    if team_id and is_known_vendor(team_id):
        vendor_name = get_vendor_name(team_id)
        recommendation = (
            f"This item is signed by {vendor_name} (Team ID: {team_id}), but the signature is invalid. "
            f"This could indicate corruption or tampering. Reinstall from official {vendor_name} sources."
        )
    
    return Finding(
        id=finding_id,
        category=category,
        risk=risk,
        title=f"Invalid code signature: {name}",
        details=(
            f"Code signature verification failed for {name}. "
            "This could indicate tampering, corruption, or an unsigned binary."
        ),
        path=path,
        evidence={
            "codesign_status": codesign_result.get("status", ""),
            "codesign_team_id": team_id,
            "codesign_raw": codesign_result.get("raw", "")[:200],
        },
        recommendation=recommendation
    )


def _create_spctl_rejected_finding(
    app: dict,
    spctl_result: dict,
    finding_id: str,
    category: str = "app",
    risk: Risk = Risk.HIGH,
    team_id: str = ""
) -> Finding:
    """Create a finding for Gatekeeper rejection."""
    path = app.get("exec_path") or app.get("app_path") or app.get("plist_path", "")
    name = app.get("name") or app.get("label", "Unknown")
    
    # Build vendor-aware recommendation
    recommendation = (
        "Do not run this item unless you explicitly trust the source. "
        "Verify authenticity and consider obtaining from App Store or notarized sources."
    )
    
    if team_id and is_known_vendor(team_id):
        vendor_name = get_vendor_name(team_id)
        is_helper = is_system_helper_path(path)
        
        if is_helper:
            recommendation = (
                f"This is a {vendor_name} system helper (Team ID: {team_id}). "
                f"Helper utilities commonly fail Gatekeeper checks but may be safe if part of a verified {vendor_name} installation. "
                f"Verify the main {vendor_name} application is properly installed and up to date."
            )
        else:
            recommendation = (
                f"This item is signed by {vendor_name} (Team ID: {team_id}) but rejected by Gatekeeper. "
                f"This may be a helper utility or older version. Verify with official {vendor_name} documentation."
            )
    
    return Finding(
        id=finding_id,
        category=category,
        risk=risk,
        title=f"Gatekeeper blocked: {name}",
        details=(
            f"macOS Gatekeeper has rejected {name}. "
            "This item does not meet Apple's security requirements for execution."
        ),
        path=path,
        evidence={
            "spctl_status": spctl_result.get("status", ""),
            "spctl_source": spctl_result.get("source", ""),
            "spctl_team_id": team_id,
            "spctl_raw": spctl_result.get("raw", "")[:200],
        },
        recommendation=recommendation
    )


def _create_user_writable_daemon_finding(
    launchd_item: dict,
    finding_id: str
) -> Finding:
    """Create a finding for system daemon with user-writable program path."""
    program = launchd_item.get("program", "")
    label = launchd_item.get("label", "Unknown")
    plist_path = launchd_item.get("plist_path", "")
    
    return Finding(
        id=finding_id,
        category="persistence",
        risk=Risk.HIGH,
        title=f"System daemon uses user-writable path: {label}",
        details=(
            f"System daemon '{label}' executes a program from a user-writable location ({program}). "
            "This is a privilege escalation risk, as the daemon runs with elevated privileges "
            "but its binary could be modified by unprivileged users."
        ),
        path=plist_path,
        evidence={
            "scope": "daemon",
            "program": program,
            "label": label,
        },
        recommendation=(
            "Move the program to a system-protected location (e.g., /usr/local/bin) with appropriate "
            "permissions, or remove this launch daemon if it's not needed."
        )
    )


def _create_quarantined_persistence_finding(
    launchd_item: dict,
    quarantine_result: dict,
    finding_id: str,
    run_at_load: bool = True
) -> Finding:
    """Create a finding for quarantined persistence item."""
    label = launchd_item.get("label", "Unknown")
    program = launchd_item.get("program", "")
    plist_path = launchd_item.get("plist_path", "")
    scope = launchd_item.get("scope", "unknown")
    
    if run_at_load:
        risk = Risk.MED
        title = f"Quarantined persistence item (auto-run): {label}"
        details = (
            f"Launch {scope} '{label}' has the quarantine attribute set and is configured to run at load. "
            "Quarantined items are typically downloads that haven't been explicitly approved by the user."
        )
        recommendation = (
            "Review this persistence item. If legitimate, remove the quarantine attribute. "
            "If untrusted, remove the launch agent/daemon entirely."
        )
    else:
        risk = Risk.LOW
        title = f"Quarantined persistence item: {label}"
        details = (
            f"Launch {scope} '{label}' has the quarantine attribute set but is not configured for auto-start. "
            "This is typically from a downloaded item that hasn't been user-approved yet."
        )
        recommendation = (
            "Review this item. Quarantine attributes on persistence items without RunAtLoad are lower risk "
            "since they don't auto-execute. Remove the quarantine if legitimate or delete if unwanted."
        )
    
    return Finding(
        id=finding_id,
        category="persistence",
        risk=risk,
        title=title,
        details=details,
        path=plist_path,
        evidence={
            "scope": scope,
            "program": program,
            "label": label,
            "quarantine_value": quarantine_result.get("value", "")[:100],
            "run_at_load": str(run_at_load).lower(),
        },
        recommendation=recommendation
    )


def _create_quarantined_app_finding(
    app: dict,
    quarantine_result: dict,
    finding_id: str
) -> Finding:
    """Create a finding for quarantined application."""
    name = app.get("name", "Unknown")
    path = app.get("exec_path") or app.get("app_path", "")
    
    return Finding(
        id=finding_id,
        category="app",
        risk=Risk.LOW,
        title=f"Quarantined application: {name}",
        details=(
            f"Application '{name}' has the quarantine attribute set. This typically indicates "
            "it was downloaded and hasn't been explicitly approved for execution yet."
        ),
        path=path,
        evidence={
            "quarantine_value": quarantine_result.get("value", "")[:100],
        },
        recommendation=(
            "Review this application. If it's legitimate software you downloaded, "
            "you can remove the quarantine attribute by running it or using: xattr -d com.apple.quarantine"
        )
    )


def _create_verified_app_finding(
    app: dict,
    codesign_result: dict,
    spctl_result: dict,
    finding_id: str,
    team_id: str
) -> Finding:
    """Create an informational finding for fully verified application."""
    name = app.get("name", "Unknown")
    path = app.get("exec_path") or app.get("app_path", "")
    vendor_name = get_vendor_name(team_id) if team_id else "Unknown"
    
    return Finding(
        id=finding_id,
        category="app",
        risk=Risk.INFO,
        title=f"Verified application: {name}",
        details=(
            f"Application '{name}' is properly signed by {vendor_name} and passes all "
            "macOS security requirements including Gatekeeper."
        ),
        path=path,
        evidence={
            "codesign_status": "ok",
            "spctl_status": "accepted",
            "team_id": team_id,
            "vendor": vendor_name,
        },
        recommendation=(
            "This application is fully verified and trusted. No action needed."
        )
    )
