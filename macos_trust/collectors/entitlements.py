"""Entitlements extraction for macOS applications and binaries."""

import plistlib
import re
from typing import Dict, Any, List

from macos_trust.util.shell import run


# Sensitive entitlements that warrant security review
SENSITIVE_ENTITLEMENTS = {
    "com.apple.security.device.camera": "Camera Access",
    "com.apple.security.device.microphone": "Microphone Access",
    "com.apple.security.device.usb": "USB Device Access",
    "com.apple.security.device.bluetooth": "Bluetooth Access",
    "com.apple.security.device.audio-input": "Audio Input Access",
    "com.apple.security.personal-information.addressbook": "Contacts Access",
    "com.apple.security.personal-information.calendars": "Calendar Access",
    "com.apple.security.personal-information.location": "Location Access",
    "com.apple.security.personal-information.photos-library": "Photos Library Access",
    "com.apple.security.automation.apple-events": "Apple Events Automation",
    "com.apple.security.full-disk-access": "Full Disk Access",
    "com.apple.security.network.client": "Network Client",
    "com.apple.security.network.server": "Network Server",
    "com.apple.security.files.user-selected.read-write": "User-Selected Files Access",
    "com.apple.security.files.downloads.read-write": "Downloads Folder Access",
    "com.apple.security.temporary-exception.files.absolute-path.read-write": "Absolute Path File Access",
    "com.apple.security.cs.allow-jit": "JIT Code Execution",
    "com.apple.security.cs.allow-unsigned-executable-memory": "Unsigned Executable Memory",
    "com.apple.security.cs.allow-dyld-environment-variables": "DYLD Environment Variables",
    "com.apple.security.cs.disable-library-validation": "Disabled Library Validation",
    "com.apple.security.get-task-allow": "Task Inspection (Debug)",
    "com.apple.private.security.no-sandbox": "No Sandbox",
    "com.apple.rootless.install": "System Integrity Protection Bypass",
    "com.apple.private.tcc.allow": "TCC Bypass",
}

# High-risk entitlements that are especially concerning
HIGH_RISK_ENTITLEMENTS = {
    "com.apple.security.get-task-allow",  # Debug in production
    "com.apple.security.cs.allow-unsigned-executable-memory",  # Code injection vector
    "com.apple.security.cs.allow-dyld-environment-variables",  # Library injection
    "com.apple.security.cs.disable-library-validation",  # Unsigned library loading
    "com.apple.private.security.no-sandbox",  # Sandbox escape
    "com.apple.rootless.install",  # SIP bypass
    "com.apple.private.tcc.allow",  # Privacy bypass
}


def get_entitlements(path: str) -> Dict[str, Any]:
    """
    Extract code signature entitlements from an application or binary.
    
    Args:
        path: File system path to the application or binary
    
    Returns:
        Dictionary with keys:
        - status: "ok" (entitlements found), "none" (no entitlements), or "error"
        - entitlements: Dictionary of all entitlements (empty if none)
        - sensitive: List of sensitive entitlements detected
        - high_risk: List of high-risk entitlements detected
        - count: Total number of entitlements
        - raw: Brief raw output for debugging
    
    Example:
        >>> result = get_entitlements("/Applications/Zoom.app")
        >>> result['status']
        'ok'
        >>> result['sensitive']
        ['Camera Access', 'Microphone Access']
    """
    try:
        # Extract entitlements using codesign
        # --entitlements :- outputs to stdout in XML plist format
        result = run(
            ["/usr/bin/codesign", "-d", "--entitlements", ":-", path],
            timeout=10
        )
    except (TimeoutError, FileNotFoundError) as e:
        return {
            "status": "error",
            "entitlements": {},
            "sensitive": [],
            "high_risk": [],
            "count": 0,
            "raw": f"error: {str(e)[:100]}"
        }
    
    # Check if command failed
    if result.code != 0:
        # Non-zero could mean no entitlements or actual error
        error_msg = result.err.lower()
        if "no such file" in error_msg or "not found" in error_msg:
            return {
                "status": "error",
                "entitlements": {},
                "sensitive": [],
                "high_risk": [],
                "count": 0,
                "raw": f"error: {result.err[:100]}"
            }
        else:
            # Probably just no entitlements
            return {
                "status": "none",
                "entitlements": {},
                "sensitive": [],
                "high_risk": [],
                "count": 0,
                "raw": "no entitlements"
            }
    
    # Parse the plist output
    try:
        # The output is XML plist format
        if not result.out or result.out.strip() == "":
            return {
                "status": "none",
                "entitlements": {},
                "sensitive": [],
                "high_risk": [],
                "count": 0,
                "raw": "no entitlements"
            }
        
        # Parse the plist
        entitlements_dict = plistlib.loads(result.out.encode('utf-8'))
        
        # Analyze entitlements
        sensitive = _identify_sensitive_entitlements(entitlements_dict)
        high_risk = _identify_high_risk_entitlements(entitlements_dict)
        
        return {
            "status": "ok",
            "entitlements": entitlements_dict,
            "sensitive": sensitive,
            "high_risk": high_risk,
            "count": len(entitlements_dict),
            "raw": f"{len(entitlements_dict)} entitlements found"
        }
        
    except Exception as e:
        # Parsing error
        return {
            "status": "error",
            "entitlements": {},
            "sensitive": [],
            "high_risk": [],
            "count": 0,
            "raw": f"parse error: {str(e)[:100]}"
        }


def _identify_sensitive_entitlements(entitlements: Dict[str, Any]) -> List[str]:
    """
    Identify sensitive entitlements from the entitlements dictionary.
    
    Args:
        entitlements: Dictionary of entitlements from plist
    
    Returns:
        List of human-readable names for sensitive entitlements found
    """
    sensitive = []
    
    for key, value in entitlements.items():
        # Only include if the entitlement is enabled (value is True or truthy)
        if key in SENSITIVE_ENTITLEMENTS:
            # For boolean entitlements, check if True
            if isinstance(value, bool) and value:
                sensitive.append(SENSITIVE_ENTITLEMENTS[key])
            # For non-boolean entitlements, include if present
            elif not isinstance(value, bool) and value:
                sensitive.append(SENSITIVE_ENTITLEMENTS[key])
    
    return sorted(sensitive)


def _identify_high_risk_entitlements(entitlements: Dict[str, Any]) -> List[str]:
    """
    Identify high-risk entitlements from the entitlements dictionary.
    
    Args:
        entitlements: Dictionary of entitlements from plist
    
    Returns:
        List of human-readable names for high-risk entitlements found
    """
    high_risk = []
    
    for key, value in entitlements.items():
        if key in HIGH_RISK_ENTITLEMENTS:
            # For boolean entitlements, check if True
            if isinstance(value, bool) and value:
                if key in SENSITIVE_ENTITLEMENTS:
                    high_risk.append(SENSITIVE_ENTITLEMENTS[key])
                else:
                    high_risk.append(key)
            # For non-boolean entitlements, include if present
            elif not isinstance(value, bool) and value:
                if key in SENSITIVE_ENTITLEMENTS:
                    high_risk.append(SENSITIVE_ENTITLEMENTS[key])
                else:
                    high_risk.append(key)
    
    return sorted(high_risk)


def format_entitlements_list(entitlements: List[str]) -> str:
    """
    Format a list of entitlements into a human-readable string.
    
    Args:
        entitlements: List of entitlement names
    
    Returns:
        Formatted string (comma-separated)
    """
    if not entitlements:
        return "None"
    
    return ", ".join(entitlements)
