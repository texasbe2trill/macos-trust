"""Security rules for generating findings from collected data."""

from macos_trust.models import Finding, Risk
from macos_trust.vendors import (
    is_known_vendor,
    get_vendor_name,
    is_system_helper_path,
    is_user_writable_path as is_user_writable_location
)
from macos_trust.context import (
    AppContext,
    parse_quarantine_source,
    is_homebrew_quarantine,
    should_trust_by_age
)
from macos_trust.config import Config


def analyze_app(
    app: dict,
    codesign_result: dict | None = None,
    spctl_result: dict | None = None,
    quarantine_result: dict | None = None,
    entitlements_result: dict | None = None,
    config: Config | None = None
) -> list[Finding]:
    """
    Analyze an application and generate security findings.
    
    Args:
        app: Application record from scanners.apps.scan_applications()
        codesign_result: Result from collectors.codesign.codesign_verify()
        spctl_result: Result from collectors.spctl.spctl_assess()
        quarantine_result: Result from collectors.quarantine.get_quarantine()
        entitlements_result: Result from collectors.entitlements.get_entitlements()
        config: Configuration for trust and risk adjustments
    
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
    
    # Check if vendor is in config's trusted list
    if config and team_id and team_id in config.trusted_vendors:
        known_vendor = True
    
    # Get enriched context
    app_context = AppContext(path) if path else None
    
    # Rule 1: Invalid code signature
    if codesign_result and codesign_result.get("status") == "fail":
        # Adjust risk based on context
        risk = Risk.HIGH
        if known_vendor:
            risk = Risk.MED  # Known vendor but invalid signature - concerning but less critical
        
        # Further adjust based on app context
        if app_context:
            # App Store apps with invalid signatures are still concerning (MED)
            if app_context.is_app_store:
                risk = Risk.MED
            # Old apps that have been stable might have expired certs
            elif config and config.trust_old_apps and app_context.age_days >= config.old_app_days:
                risk = Risk.LOW
        
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
        
        # App Store apps shouldn't be rejected, but if they are, still MED
        if app_context and app_context.is_app_store:
            risk = Risk.MED
        
        finding = _create_spctl_rejected_finding(
            app=app,
            spctl_result=spctl_result,
            finding_id=f"app:{app_id_base}:spctl_rejected",
            risk=risk,
            team_id=team_id
        )
        findings.append(finding)
    
    # Rule 3: Quarantined but not auto-run -> LOW (context-aware)
    if quarantine_result and quarantine_result.get("is_quarantined") == "true":
        risk = Risk.LOW
        quarantine_value = quarantine_result.get("value", "")
        
        # Check quarantine source
        if config and config.trust_homebrew_cask and is_homebrew_quarantine(quarantine_value):
            # Skip quarantine findings for Homebrew Cask if configured
            pass
        else:
            finding = _create_quarantined_app_finding(
                app=app,
                quarantine_result=quarantine_result,
                finding_id=f"app:{app_id_base}:quarantined",
                quarantine_source=parse_quarantine_source(quarantine_value)
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
    
    # Rule 5: High-risk entitlements -> MED (or HIGH if unsigned/untrusted)
    if entitlements_result and entitlements_result.get("status") == "ok":
        high_risk_ents = entitlements_result.get("high_risk", [])
        if high_risk_ents:
            # Adjust risk based on signature and vendor trust
            risk = Risk.HIGH
            if is_signed and known_vendor:
                risk = Risk.MED  # Known vendor with high-risk entitlements - still concerning but less critical
            elif is_signed:
                risk = Risk.MED  # At least it's signed
            
            finding = _create_high_risk_entitlements_finding(
                app=app,
                entitlements_result=entitlements_result,
                finding_id=f"app:{app_id_base}:high_risk_entitlements",
                risk=risk,
                team_id=team_id
            )
            findings.append(finding)
    
    # Rule 6: Sensitive entitlements -> INFO (for awareness)
    if entitlements_result and entitlements_result.get("status") == "ok":
        sensitive_ents = entitlements_result.get("sensitive", [])
        # Only report if there are sensitive entitlements and they're not all high-risk
        # (high-risk already reported above)
        high_risk_ents = entitlements_result.get("high_risk", [])
        non_high_risk_sensitive = [e for e in sensitive_ents if e not in high_risk_ents]
        
        if non_high_risk_sensitive and len(non_high_risk_sensitive) >= 3:
            # Only report if app has 3+ non-high-risk sensitive entitlements
            finding = _create_sensitive_entitlements_finding(
                app=app,
                entitlements_result=entitlements_result,
                finding_id=f"app:{app_id_base}:sensitive_entitlements",
                team_id=team_id
            )
            findings.append(finding)
    
    return findings


def analyze_launchd(
    launchd_item: dict,
    codesign_result: dict | None = None,
    spctl_result: dict | None = None,
    quarantine_result: dict | None = None,
    config: Config | None = None
) -> list[Finding]:
    """
    Analyze a launch agent/daemon and generate security findings.
    
    Args:
        launchd_item: Launch item record from scanners.launchd.scan_launchd()
        codesign_result: Result from collectors.codesign.codesign_verify()
        spctl_result: Result from collectors.spctl.spctl_assess()
        quarantine_result: Result from collectors.quarantine.get_quarantine()
        config: Configuration for trust and risk adjustments
    
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
    
    # Check if vendor is in config's trusted list
    if config and team_id and team_id in config.trusted_vendors:
        known_vendor = True
    
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
        quarantine_value = quarantine_result.get("value", "")
        
        # Check if Homebrew source and config trusts it
        if config and config.trust_homebrew_cask and is_homebrew_quarantine(quarantine_value):
            # Skip quarantine finding for Homebrew items if configured
            pass
        else:
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
    finding_id: str,
    quarantine_source: str | None = None
) -> Finding:
    """Create a finding for quarantined application."""
    name = app.get("name", "Unknown")
    path = app.get("exec_path") or app.get("app_path", "")
    
    # Enhance recommendation with source info
    recommendation = (
        "Review this application. If it's legitimate software you downloaded, "
        "you can remove the quarantine attribute by running it or using: xattr -d com.apple.quarantine"
    )
    
    if quarantine_source:
        recommendation = (
            f"This app was downloaded via {quarantine_source}. "
            "If it's legitimate software you intentionally downloaded, "
            "you can remove the quarantine attribute by running it or using: xattr -d com.apple.quarantine"
        )
    
    evidence = {
        "quarantine_value": quarantine_result.get("value", "")[:100],
    }
    
    if quarantine_source:
        evidence["quarantine_source"] = quarantine_source
    
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
        evidence=evidence,
        recommendation=recommendation
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


def analyze_kext(kext: dict, config: Config | None = None) -> list[Finding]:
    """
    Analyze a kernel extension or system extension.
    
    Args:
        kext: Kernel extension record from scanners.kext.scan_kexts()
        config: Configuration for trust and risk adjustments
    
    Returns:
        List of Finding objects for security issues detected
    """
    findings = []
    
    name = kext.get("name", "Unknown")
    bundle_id = kext.get("bundle_id", name)
    path = kext.get("path", "")
    kext_type = kext.get("type", "kext")
    location = kext.get("location", "library")
    loaded = kext.get("loaded", False)
    codesign_result = kext.get("codesign", {})
    
    # Skip system KEXTs in /System/Library/Extensions - these are Apple's and expected
    if location == "system":
        return findings
    
    # Extract team ID from codesign
    team_id = codesign_result.get("team_id", "")
    known_vendor = is_known_vendor(team_id) if team_id else False
    
    # Check if vendor is trusted via config
    config_trusted_vendor = False
    if config and team_id:
        config_trusted_vendor = team_id in config.trusted_vendors
    
    # Base finding ID
    finding_id_base = f"kext:{bundle_id}"
    
    # Check code signature
    codesign_status = codesign_result.get("status", "unknown")
    
    # Only flag actual security issues:
    # 1. Unsigned KEXTs (HIGH risk - kernel access without verification)
    # 2. Invalid signatures (HIGH - tampering or corruption)
    # Everything else is noise - properly signed third-party KEXTs are generally fine
    
    if codesign_status == "unsigned":
        # Unsigned KEXT is HIGH risk (kernel-level access)
        findings.append(_create_unsigned_kext_finding(
            kext, finding_id_base, known_vendor, config_trusted_vendor
        ))
    elif codesign_status == "invalid":
        # Invalid signature is HIGH risk
        findings.append(_create_invalid_kext_finding(
            kext, finding_id_base, known_vendor, config_trusted_vendor
        ))
    # Skip third-party and legacy KEXT findings - they're just noise
    # Users have intentionally installed these, and they're properly signed
    
    return findings


def _create_unsigned_kext_finding(
    kext: dict,
    finding_id_base: str,
    known_vendor: bool,
    config_trusted_vendor: bool
) -> Finding:
    """Create finding for unsigned kernel extension."""
    name = kext.get("name", "Unknown")
    path = kext.get("path", "")
    kext_type = kext.get("type", "kext")
    loaded = kext.get("loaded", False)
    
    type_label = "System Extension" if kext_type == "systemextension" else "Kernel Extension"
    loaded_status = "loaded" if loaded else "not loaded"
    
    return Finding(
        id=f"{finding_id_base}:unsigned",
        category="kext",
        risk=Risk.HIGH,
        title=f"Unsigned {type_label}: {name}",
        details=(
            f"{type_label} '{name}' is not signed with a valid code signature. "
            f"This extension is currently {loaded_status}. "
            f"Unsigned kernel extensions have full system access and pose significant security risks."
        ),
        path=path,
        evidence={
            "codesign_status": "unsigned",
            "type": kext_type,
            "loaded": loaded,
        },
        recommendation=(
            f"Verify the source of this {type_label.lower()}. Unsigned kernel-level code "
            "is a major security risk. Only install kernel extensions from verified sources. "
            "Consider removing if not essential."
        )
    )


def _create_invalid_kext_finding(
    kext: dict,
    finding_id_base: str,
    known_vendor: bool,
    config_trusted_vendor: bool
) -> Finding:
    """Create finding for kernel extension with invalid signature."""
    name = kext.get("name", "Unknown")
    path = kext.get("path", "")
    kext_type = kext.get("type", "kext")
    loaded = kext.get("loaded", False)
    codesign_result = kext.get("codesign", {})
    
    type_label = "System Extension" if kext_type == "systemextension" else "Kernel Extension"
    
    return Finding(
        id=f"{finding_id_base}:invalid_signature",
        category="kext",
        risk=Risk.HIGH,
        title=f"Invalid signature: {name}",
        details=(
            f"{type_label} '{name}' has an invalid code signature. "
            "This could indicate tampering or corruption."
        ),
        path=path,
        evidence={
            "codesign_status": "invalid",
            "codesign_message": codesign_result.get("message", ""),
            "type": kext_type,
            "loaded": loaded,
        },
        recommendation=(
            "This kernel extension's signature is invalid. This is a serious security concern. "
            "Reinstall the parent application or driver, or remove if no longer needed."
        )
    )


def _create_thirdparty_kext_finding(
    kext: dict,
    finding_id_base: str,
    risk: Risk,
    known_vendor: bool,
    config_trusted_vendor: bool
) -> Finding:
    """Create finding for third-party kernel extension."""
    name = kext.get("name", "Unknown")
    path = kext.get("path", "")
    kext_type = kext.get("type", "kext")
    loaded = kext.get("loaded", False)
    codesign_result = kext.get("codesign", {})
    team_id = codesign_result.get("team_id", "")
    
    type_label = "System Extension" if kext_type == "systemextension" else "Kernel Extension"
    vendor_info = get_vendor_name(team_id) if team_id and known_vendor else f"Team ID: {team_id}" if team_id else "Unknown vendor"
    
    return Finding(
        id=f"{finding_id_base}:thirdparty",
        category="kext",
        risk=risk,
        title=f"Third-party {type_label}: {name}",
        details=(
            f"{type_label} '{name}' from {vendor_info} is installed. "
            f"This extension is {'currently loaded' if loaded else 'not currently loaded'}. "
            "Third-party kernel extensions have deep system access."
        ),
        path=path,
        evidence={
            "codesign_status": codesign_result.get("status", "unknown"),
            "team_id": team_id,
            "vendor": vendor_info,
            "type": kext_type,
            "loaded": loaded,
        },
        recommendation=(
            f"Review whether this {type_label.lower()} is necessary. "
            "Kernel extensions from third parties have full system privileges. "
            "Ensure it comes from a trusted source and is actively maintained."
        )
    )


def _create_high_risk_entitlements_finding(
    app: dict,
    entitlements_result: dict,
    finding_id: str,
    risk: Risk = Risk.HIGH,
    team_id: str = ""
) -> Finding:
    """Create a finding for high-risk entitlements."""
    path = app.get("exec_path") or app.get("app_path", "")
    name = app.get("name", "Unknown")
    high_risk_ents = entitlements_result.get("high_risk", [])
    sensitive_ents = entitlements_result.get("sensitive", [])
    
    # Build vendor-aware recommendation
    recommendation = (
        "Review whether this application needs these high-risk entitlements. "
        "These permissions can be exploited for code injection, sandbox escape, or system compromise. "
        "Remove if the application is untrusted or no longer needed."
    )
    
    if team_id and is_known_vendor(team_id):
        vendor_name = get_vendor_name(team_id)
        recommendation = (
            f"This application is from {vendor_name} (Team ID: {team_id}) and has high-risk entitlements. "
            "While known vendors may legitimately need these permissions, verify the application is up to date "
            f"and obtained from official {vendor_name} sources."
        )
    
    high_risk_list = ", ".join(high_risk_ents)
    
    return Finding(
        id=finding_id,
        category="app",
        risk=risk,
        title=f"High-risk entitlements: {name}",
        details=(
            f"{name} has high-risk code signing entitlements: {high_risk_list}. "
            "These permissions can be exploited to bypass security controls, inject code, or escape sandboxing."
        ),
        path=path,
        evidence={
            "high_risk_entitlements": high_risk_list,
            "sensitive_entitlements": ", ".join(sensitive_ents),
            "entitlements_count": str(entitlements_result.get("count", 0)),
            "codesign_team_id": team_id,
        },
        recommendation=recommendation
    )


def _create_sensitive_entitlements_finding(
    app: dict,
    entitlements_result: dict,
    finding_id: str,
    team_id: str = ""
) -> Finding:
    """Create an INFO finding for sensitive entitlements (awareness)."""
    path = app.get("exec_path") or app.get("app_path", "")
    name = app.get("name", "Unknown")
    sensitive_ents = entitlements_result.get("sensitive", [])
    high_risk_ents = entitlements_result.get("high_risk", [])
    
    # Filter out high-risk from sensitive list (already reported)
    non_high_risk_sensitive = [e for e in sensitive_ents if e not in high_risk_ents]
    
    sensitive_list = ", ".join(non_high_risk_sensitive)
    
    # Build vendor-aware recommendation
    recommendation = (
        "Review whether this application needs these sensitive permissions. "
        "Ensure the application is from a trusted source and you understand why it needs these capabilities."
    )
    
    if team_id and is_known_vendor(team_id):
        vendor_name = get_vendor_name(team_id)
        recommendation = (
            f"This application from {vendor_name} (Team ID: {team_id}) has sensitive permissions. "
            "This is informational - many legitimate applications need camera, microphone, or contact access. "
            f"Verify you obtained this from official {vendor_name} sources."
        )
    
    return Finding(
        id=finding_id,
        category="app",
        risk=Risk.INFO,
        title=f"Sensitive permissions: {name}",
        details=(
            f"{name} has requested sensitive system permissions: {sensitive_list}. "
            "While many legitimate applications need these permissions, you should verify they're necessary."
        ),
        path=path,
        evidence={
            "sensitive_entitlements": sensitive_list,
            "entitlements_count": str(entitlements_result.get("count", 0)),
            "codesign_team_id": team_id,
        },
        recommendation=recommendation
    )


def _create_legacy_kext_finding(
    kext: dict,
    finding_id_base: str,
    known_vendor: bool,
    config_trusted_vendor: bool
) -> Finding:
    """Create info finding for loaded legacy KEXT."""
    name = kext.get("name", "Unknown")
    path = kext.get("path", "")
    codesign_result = kext.get("codesign", {})
    team_id = codesign_result.get("team_id", "")
    vendor_info = get_vendor_name(team_id) if team_id and known_vendor else f"Team ID: {team_id}" if team_id else "Unknown vendor"
    
    return Finding(
        id=f"{finding_id_base}:legacy",
        category="kext",
        risk=Risk.INFO,
        title=f"Legacy KEXT loaded: {name}",
        details=(
            f"Legacy kernel extension '{name}' from {vendor_info} is currently loaded. "
            "Apple has deprecated kernel extensions in favor of System Extensions. "
            "This KEXT may stop working in future macOS versions."
        ),
        path=path,
        evidence={
            "codesign_status": codesign_result.get("status", "unknown"),
            "team_id": team_id,
            "vendor": vendor_info,
            "type": "kext",
            "loaded": True,
        },
        recommendation=(
            "Check if the vendor provides a System Extension version. "
            "Legacy KEXTs are deprecated and may not be supported in future macOS releases."
        )
    )


# Suspicious browser extension permissions
SUSPICIOUS_PERMISSIONS = {
    "tabs": "Access browser tabs",
    "history": "Access browsing history",
    "cookies": "Access cookies",
    "webRequest": "Intercept web requests",
    "webRequestBlocking": "Block/modify web requests",
    "proxy": "Control proxy settings",
    "debugger": "Attach debugger to pages",
    "management": "Manage other extensions",
    "nativeMessaging": "Communicate with native apps",
    "privacy": "Modify privacy settings",
    "clipboardRead": "Read clipboard",
    "clipboardWrite": "Write to clipboard",
    "downloads": "Manage downloads",
    "geolocation": "Access location",
    "notifications": "Show notifications",
}

# High-risk permissions that are especially concerning
HIGH_RISK_PERMISSIONS = {
    "webRequestBlocking",  # Can intercept and modify all web traffic
    "debugger",  # Can inject code into pages
    "proxy",  # Can route all traffic through attacker
    "management",  # Can disable security extensions
    "nativeMessaging",  # Can execute native code
    "privacy",  # Can weaken security settings
}


def analyze_browser_extension(
    extension: dict,
    config: Config | None = None
) -> list[Finding]:
    """
    Analyze a browser extension and generate security findings.
    
    Args:
        extension: Extension record from scanners.browser.scan_browser_extensions()
        config: Configuration for trust and risk adjustments
    
    Returns:
        List of Finding objects for security issues detected
    """
    findings = []
    
    # Generate base ID for this extension
    browser = extension.get("browser", "unknown")
    ext_id = extension.get("id", "unknown")
    ext_id_base = f"browser_ext:{browser}:{ext_id}"
    
    permissions = extension.get("permissions", [])
    host_permissions = extension.get("host_permissions", [])
    
    # Identify suspicious permissions
    suspicious_perms = _identify_suspicious_extension_permissions(permissions)
    high_risk_perms = _identify_high_risk_extension_permissions(permissions)
    
    # Rule 1: High-risk permissions -> HIGH
    if high_risk_perms:
        finding = _create_high_risk_extension_finding(
            extension=extension,
            finding_id=f"{ext_id_base}:high_risk_permissions",
            high_risk_perms=high_risk_perms,
            all_perms=permissions
        )
        findings.append(finding)
    
    # Rule 2: Broad host access -> MED
    if _has_broad_host_access(host_permissions):
        finding = _create_broad_access_extension_finding(
            extension=extension,
            finding_id=f"{ext_id_base}:broad_access",
            host_permissions=host_permissions
        )
        findings.append(finding)
    
    # Rule 3: Multiple suspicious permissions -> MED
    if len(suspicious_perms) >= 3:  # 3+ suspicious perms is concerning
        finding = _create_suspicious_extension_finding(
            extension=extension,
            finding_id=f"{ext_id_base}:suspicious_permissions",
            suspicious_perms=suspicious_perms
        )
        findings.append(finding)
    
    # Rule 4: Basic extension info -> INFO (for awareness)
    if permissions or host_permissions:
        finding = _create_extension_info_finding(
            extension=extension,
            finding_id=f"{ext_id_base}:info",
            permissions=permissions,
            host_permissions=host_permissions
        )
        findings.append(finding)
    
    return findings


def _identify_suspicious_extension_permissions(permissions: List[str]) -> List[str]:
    """Identify suspicious permissions from extension's permission list."""
    suspicious = []
    for perm in permissions:
        if perm in SUSPICIOUS_PERMISSIONS:
            suspicious.append(SUSPICIOUS_PERMISSIONS[perm])
    return suspicious


def _identify_high_risk_extension_permissions(permissions: List[str]) -> List[str]:
    """Identify high-risk permissions from extension's permission list."""
    high_risk = []
    for perm in permissions:
        if perm in HIGH_RISK_PERMISSIONS:
            if perm in SUSPICIOUS_PERMISSIONS:
                high_risk.append(SUSPICIOUS_PERMISSIONS[perm])
            else:
                high_risk.append(perm)
    return high_risk


def _has_broad_host_access(host_permissions: List[str]) -> bool:
    """Check if extension has overly broad host access."""
    broad_patterns = [
        "<all_urls>",
        "*://*/*",
        "http://*/*",
        "https://*/*",
    ]
    
    for host in host_permissions:
        if host in broad_patterns:
            return True
        # Check for wildcards in domain
        if host.count("*") >= 2:  # Multiple wildcards like *://*.example.com/*
            return True
    
    return False


def _create_high_risk_extension_finding(
    extension: dict,
    finding_id: str,
    high_risk_perms: List[str],
    all_perms: List[str]
) -> Finding:
    """Create a finding for high-risk browser extension permissions."""
    name = extension.get("name", "Unknown")
    browser = extension.get("browser", "unknown").capitalize()
    path = extension.get("manifest_path", "")
    
    perms_list = ", ".join(high_risk_perms)
    
    return Finding(
        id=finding_id,
        category="browser_extension",
        risk=Risk.HIGH,
        title=f"High-risk {browser} extension: {name}",
        details=(
            f"{browser} extension '{name}' has high-risk permissions: {perms_list}. "
            "These permissions can be exploited to intercept web traffic, inject malicious code, "
            "or compromise your browsing security."
        ),
        path=path,
        evidence={
            "browser": browser.lower(),
            "extension_name": name,
            "high_risk_permissions": perms_list,
            "all_permissions": ", ".join(all_perms),
            "extension_id": extension.get("id", ""),
        },
        recommendation=(
            "Review whether this extension is necessary and from a trusted source. "
            "Extensions with these permissions can intercept and modify all web traffic, "
            "inject code into pages, or weaken security settings. "
            "Remove if untrusted or no longer needed."
        )
    )


def _create_broad_access_extension_finding(
    extension: dict,
    finding_id: str,
    host_permissions: List[str]
) -> Finding:
    """Create a finding for browser extension with broad host access."""
    name = extension.get("name", "Unknown")
    browser = extension.get("browser", "unknown").capitalize()
    path = extension.get("manifest_path", "")
    
    hosts_list = ", ".join(host_permissions[:5])  # First 5 hosts
    if len(host_permissions) > 5:
        hosts_list += f", ... ({len(host_permissions)} total)"
    
    return Finding(
        id=finding_id,
        category="browser_extension",
        risk=Risk.MED,
        title=f"Broad access {browser} extension: {name}",
        details=(
            f"{browser} extension '{name}' has access to all websites or very broad URL patterns. "
            "This extension can read and modify content on any page you visit."
        ),
        path=path,
        evidence={
            "browser": browser.lower(),
            "extension_name": name,
            "host_permissions": hosts_list,
            "extension_id": extension.get("id", ""),
        },
        recommendation=(
            "Verify this extension is from a trusted source and review its privacy policy. "
            "Extensions with broad host access can read passwords, credit card info, and "
            "personal data from any website you visit."
        )
    )


def _create_suspicious_extension_finding(
    extension: dict,
    finding_id: str,
    suspicious_perms: List[str]
) -> Finding:
    """Create a finding for browser extension with multiple suspicious permissions."""
    name = extension.get("name", "Unknown")
    browser = extension.get("browser", "unknown").capitalize()
    path = extension.get("manifest_path", "")
    
    perms_list = ", ".join(suspicious_perms)
    
    return Finding(
        id=finding_id,
        category="browser_extension",
        risk=Risk.MED,
        title=f"Suspicious {browser} extension: {name}",
        details=(
            f"{browser} extension '{name}' requests multiple sensitive permissions: {perms_list}. "
            "The combination of these permissions could be used for tracking, data collection, or malicious activity."
        ),
        path=path,
        evidence={
            "browser": browser.lower(),
            "extension_name": name,
            "suspicious_permissions": perms_list,
            "extension_id": extension.get("id", ""),
        },
        recommendation=(
            "Review whether this extension needs all these permissions. "
            "Consider alternatives with fewer permissions or remove if not essential."
        )
    )


def _create_extension_info_finding(
    extension: dict,
    finding_id: str,
    permissions: List[str],
    host_permissions: List[str]
) -> Finding:
    """Create an INFO finding for browser extension (awareness)."""
    name = extension.get("name", "Unknown")
    browser = extension.get("browser", "unknown").capitalize()
    path = extension.get("manifest_path", "")
    version = extension.get("version", "unknown")
    
    perm_count = len(permissions) + len(host_permissions)
    
    return Finding(
        id=finding_id,
        category="browser_extension",
        risk=Risk.INFO,
        title=f"{browser} extension: {name}",
        details=(
            f"{browser} extension '{name}' (v{version}) is installed with {perm_count} permissions. "
            "Browser extensions can access sensitive data and modify web pages."
        ),
        path=path,
        evidence={
            "browser": browser.lower(),
            "extension_name": name,
            "version": version,
            "permissions": ", ".join(permissions) if permissions else "None",
            "host_permissions": ", ".join(host_permissions[:3]) if host_permissions else "None",
            "extension_id": extension.get("id", ""),
        },
        recommendation=(
            "Periodically review installed browser extensions and remove those no longer needed. "
            "Only install extensions from trusted sources."
        )
    )

