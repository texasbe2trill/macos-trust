"""Quarantine attribute checking for macOS files."""

from macos_trust.util.shell import run


def get_quarantine(path: str) -> dict[str, str]:
    """
    Check if a file has the macOS quarantine extended attribute.
    
    The quarantine attribute (com.apple.quarantine) is set by macOS on files
    downloaded from the internet, indicating they should be subject to Gatekeeper
    checks before execution.
    
    Args:
        path: File system path to check for quarantine attribute
    
    Returns:
        Dictionary with keys:
        - is_quarantined: "true" (has attribute), "false" (no attribute), or "unknown" (error)
        - value: Raw quarantine attribute value if present, empty string otherwise
    
    Example:
        >>> result = get_quarantine("/tmp/downloaded_app.app")
        >>> result['is_quarantined']
        'true'
        >>> result['value']
        '0083;65a1b2c3;Safari;...'
    """
    try:
        result = run(
            ["/usr/bin/xattr", "-p", "com.apple.quarantine", path],
            timeout=5
        )
    except (TimeoutError, FileNotFoundError) as e:
        return {
            "is_quarantined": "unknown",
            "value": f"error: {str(e)[:80]}"
        }
    
    # Exit code 0: Attribute exists (quarantined)
    if result.code == 0:
        return {
            "is_quarantined": "true",
            "value": result.out
        }
    
    # Exit code 1: Attribute does not exist (not quarantined)
    # This is the normal case for files that don't have the attribute
    if result.code == 1:
        # Check if this is actually "no such xattr" vs a real error
        if _is_missing_attribute_error(result.err):
            return {
                "is_quarantined": "false",
                "value": ""
            }
    
    # Other exit codes or ambiguous errors
    # Check stderr for common error patterns
    if _is_access_error(result.err):
        return {
            "is_quarantined": "unknown",
            "value": f"access error: {result.err[:80]}"
        }
    
    if _is_file_not_found_error(result.err):
        return {
            "is_quarantined": "unknown",
            "value": f"file not found: {result.err[:80]}"
        }
    
    # Default: treat as not quarantined unless error is unusual
    # This handles cases where the attribute simply doesn't exist
    return {
        "is_quarantined": "false",
        "value": ""
    }


def _is_missing_attribute_error(stderr: str) -> bool:
    """
    Check if stderr indicates the attribute doesn't exist (normal case).
    
    Args:
        stderr: Error output from xattr command
    
    Returns:
        True if this is a "no such attribute" error
    """
    if not stderr:
        return True
    
    stderr_lower = stderr.lower()
    
    # Common messages when attribute doesn't exist
    return any(phrase in stderr_lower for phrase in [
        "no such xattr",
        "no such attribute",
        "attribute not found",
        # xattr sometimes just returns empty stderr with exit 1
    ])


def _is_access_error(stderr: str) -> bool:
    """
    Check if stderr indicates a permission/access error.
    
    Args:
        stderr: Error output from xattr command
    
    Returns:
        True if this is an access/permission error
    """
    if not stderr:
        return False
    
    stderr_lower = stderr.lower()
    
    return any(phrase in stderr_lower for phrase in [
        "permission denied",
        "operation not permitted",
        "access denied",
    ])


def _is_file_not_found_error(stderr: str) -> bool:
    """
    Check if stderr indicates the file doesn't exist.
    
    Args:
        stderr: Error output from xattr command
    
    Returns:
        True if this is a "file not found" error
    """
    if not stderr:
        return False
    
    stderr_lower = stderr.lower()
    
    return any(phrase in stderr_lower for phrase in [
        "no such file",
        "not found",
        "does not exist",
    ])
