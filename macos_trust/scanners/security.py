"""Scanners for analyzing files with macOS security tools."""

from pathlib import Path
from typing import Dict, Any, Optional
from macos_trust.util import run_macos_binary


def scan_codesign(file_path: str) -> Dict[str, Any]:
    """
    Scan a file using codesign to check signature validity.
    
    Args:
        file_path: Path to the file to scan
    
    Returns:
        Dictionary with codesign results
    """
    result = {
        "signed": False,
        "valid": False,
        "details": None,
        "error": None
    }
    
    # Check if signed with: codesign -dv <path>
    check_result = run_macos_binary(
        "/usr/bin/codesign",
        ["-dv", file_path]
    )
    
    if check_result.success or "code object is not signed" not in check_result.stderr:
        # File is signed if codesign -dv doesn't say it's not signed
        if "code object is not signed" not in check_result.stderr.lower():
            result["signed"] = True
            result["details"] = check_result.stderr.strip()
    
    # Verify signature with: codesign -v <path>
    if result["signed"]:
        verify_result = run_macos_binary(
            "/usr/bin/codesign",
            ["-v", file_path]
        )
        
        if verify_result.success:
            result["valid"] = True
        else:
            result["error"] = verify_result.stderr.strip() or verify_result.error
    
    return result


def scan_spctl(file_path: str) -> Dict[str, Any]:
    """
    Scan a file using spctl to check Gatekeeper status.
    
    Args:
        file_path: Path to the file to scan
    
    Returns:
        Dictionary with spctl results
    """
    result = {
        "accepted": False,
        "details": None,
        "error": None
    }
    
    # Check with: spctl -a -v <path>
    check_result = run_macos_binary(
        "/usr/sbin/spctl",
        ["-a", "-v", file_path]
    )
    
    if check_result.success:
        result["accepted"] = True
        result["details"] = check_result.stderr.strip()  # spctl outputs to stderr
    else:
        result["details"] = check_result.stderr.strip()
        result["error"] = check_result.error
    
    return result


def scan_quarantine(file_path: str) -> Dict[str, Any]:
    """
    Check quarantine attributes using xattr.
    
    Args:
        file_path: Path to the file to scan
    
    Returns:
        Dictionary with quarantine status
    """
    result = {
        "quarantined": False,
        "attributes": [],
        "error": None
    }
    
    # List all extended attributes
    list_result = run_macos_binary(
        "/usr/bin/xattr",
        ["-l", file_path]
    )
    
    if list_result.success:
        # Parse attributes
        attrs = []
        for line in list_result.stdout.strip().split('\n'):
            line = line.strip()
            if line:
                attrs.append(line)
        
        result["attributes"] = attrs
        
        # Check specifically for quarantine
        if any("com.apple.quarantine" in attr for attr in attrs):
            result["quarantined"] = True
    elif "No such xattr" in list_result.stderr or not list_result.stderr:
        # No attributes is not an error
        result["attributes"] = []
    else:
        result["error"] = list_result.error or list_result.stderr.strip()
    
    return result


def scan_item(item: Dict[str, Any]) -> Dict[str, Any]:
    """
    Perform all scans on an item.
    
    Args:
        item: Item dictionary from collectors
    
    Returns:
        Complete scan results for the item
    """
    file_path = item["path"]
    
    scan_result = {
        "item": item,
        "codesign": None,
        "spctl": None,
        "quarantine": None,
        "error": None
    }
    
    # Verify file exists
    if not Path(file_path).exists():
        scan_result["error"] = "File not found"
        return scan_result
    
    # Run each scanner, continue even if one fails
    try:
        scan_result["codesign"] = scan_codesign(file_path)
    except Exception as e:
        scan_result["codesign"] = {"error": str(e)}
    
    try:
        scan_result["spctl"] = scan_spctl(file_path)
    except Exception as e:
        scan_result["spctl"] = {"error": str(e)}
    
    try:
        scan_result["quarantine"] = scan_quarantine(file_path)
    except Exception as e:
        scan_result["quarantine"] = {"error": str(e)}
    
    return scan_result
