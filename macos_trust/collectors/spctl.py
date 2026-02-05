"""Gatekeeper assessment for macOS applications."""

import re

from macos_trust.util.shell import run


def spctl_assess(path: str) -> dict[str, str]:
    """
    Assess application using macOS Gatekeeper (spctl).
    
    Args:
        path: File system path to the application or binary to assess
    
    Returns:
        Dictionary with keys:
        - status: "accepted" (passes Gatekeeper), "rejected" (blocked), or "unknown" (error)
        - source: Description of the trust source (e.g., "Notarized Developer ID")
        - raw: Brief raw output for debugging
    
    Example:
        >>> result = spctl_assess("/Applications/Safari.app")
        >>> result['status']
        'accepted'
        >>> result['source']
        'Apple System'
    """
    try:
        result = run(
            ["/usr/sbin/spctl", "-a", "-vv", "--type", "execute", path],
            timeout=10
        )
    except (TimeoutError, FileNotFoundError) as e:
        return {
            "status": "unknown",
            "source": "",
            "raw": f"spctl error: {str(e)[:100]}"
        }
    
    # Combine stdout and stderr (spctl outputs to both)
    output = result.out + "\n" + result.err
    
    # Parse status
    status = _parse_status(output, result.code)
    
    # Extract source information
    source = _extract_source(output)
    
    # Create brief raw summary
    raw = _create_raw_summary(output, result.code)
    
    return {
        "status": status,
        "source": source,
        "raw": raw
    }


def _parse_status(output: str, exit_code: int) -> str:
    """
    Determine assessment status from spctl output.
    
    Args:
        output: Combined stdout/stderr from spctl
        exit_code: Process exit code
    
    Returns:
        Status string: "accepted", "rejected", or "unknown"
    """
    output_lower = output.lower()
    
    # Look for explicit status strings
    if "accepted" in output_lower:
        return "accepted"
    elif "rejected" in output_lower:
        return "rejected"
    
    # Fall back to exit code interpretation
    # spctl typically returns 0 for accepted, 3 for rejected
    if exit_code == 0:
        return "accepted"
    elif exit_code == 3:
        return "rejected"
    
    return "unknown"


def _extract_source(output: str) -> str:
    """
    Extract trust source from spctl output.
    
    Args:
        output: Combined stdout/stderr from spctl
    
    Returns:
        Source description or empty string
    """
    # Look for source=... in output
    # Examples:
    # source=Notarized Developer ID
    # source=Apple System
    # source=Developer ID
    match = re.search(r"source=(.+?)(?:\n|$)", output)
    if match:
        return match.group(1).strip()
    
    # Alternative pattern: origin=...
    match = re.search(r"origin=(.+?)(?:\n|$)", output)
    if match:
        return match.group(1).strip()
    
    return ""


def _create_raw_summary(output: str, exit_code: int) -> str:
    """
    Create a brief summary of spctl output.
    
    Args:
        output: Combined stdout/stderr from spctl
        exit_code: Process exit code
    
    Returns:
        Brief string summarizing the output (max ~150 chars)
    """
    if output:
        # Take first meaningful line
        lines = [line.strip() for line in output.split("\n") if line.strip()]
        if lines:
            raw = lines[0]
            # Truncate if too long
            if len(raw) > 150:
                raw = raw[:147] + "..."
            return raw
    
    # Fallback to exit code
    return f"exit code: {exit_code}"
