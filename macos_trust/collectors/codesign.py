"""Code signature verification for macOS applications."""

import re

from macos_trust.util.shell import run


def codesign_verify(path: str) -> dict[str, str]:
    """
    Verify code signature and extract signing information.
    
    Args:
        path: File system path to the application or binary to verify
    
    Returns:
        Dictionary with keys:
        - status: "ok" (valid signature), "fail" (invalid), or "unknown" (error)
        - team_id: Apple Team ID or empty string
        - authorities: Pipe-separated list of certificate authorities
        - raw: Brief raw output for debugging
    
    Example:
        >>> result = codesign_verify("/Applications/Safari.app")
        >>> result['status']
        'ok'
        >>> result['team_id']
        'ABCD1234EF'
    """
    # Step 1: Verify the signature
    try:
        verify_result = run(
            ["/usr/bin/codesign", "--verify", "--deep", "--strict", "--verbose=2", path],
            timeout=10
        )
    except (TimeoutError, FileNotFoundError) as e:
        return {
            "status": "unknown",
            "team_id": "",
            "authorities": "",
            "raw": f"verify error: {str(e)[:100]}"
        }
    
    # Determine initial status from verification result
    if verify_result.code == 0:
        status = "ok"
    elif verify_result.code in (1, 2, 3):
        # Common codesign failure codes
        status = "fail"
    else:
        status = "unknown"
    
    # Step 2: Get detailed signature information
    # Note: codesign -dv outputs to stderr, not stdout
    try:
        detail_result = run(
            ["/usr/bin/codesign", "-dv", "--verbose=4", path],
            timeout=10
        )
    except (TimeoutError, FileNotFoundError) as e:
        return {
            "status": status,
            "team_id": "",
            "authorities": "",
            "raw": f"detail error: {str(e)[:100]}"
        }
    
    # Parse the detailed output (usually in stderr)
    # Combine stdout and stderr since codesign uses both
    detail_output = detail_result.err + "\n" + detail_result.out
    
    # Extract Team ID
    team_id = _extract_team_id(detail_output)
    
    # Extract certificate authorities
    authorities = _extract_authorities(detail_output)
    
    # Create a brief raw output summary
    raw = _create_raw_summary(verify_result, detail_result)
    
    return {
        "status": status,
        "team_id": team_id,
        "authorities": authorities,
        "raw": raw
    }


def _extract_team_id(output: str) -> str:
    """
    Extract Team ID from codesign output.
    
    Args:
        output: Combined stdout/stderr from codesign -dv
    
    Returns:
        Team ID string or empty string if not found
    """
    # Look for TeamIdentifier=ABCD1234EF
    match = re.search(r"TeamIdentifier=([A-Z0-9]+)", output)
    if match:
        return match.group(1)
    
    # Alternative format: TeamIdentifier: ABCD1234EF
    match = re.search(r"TeamIdentifier:\s*([A-Z0-9]+)", output)
    if match:
        return match.group(1)
    
    return ""


def _extract_authorities(output: str) -> str:
    """
    Extract certificate authorities from codesign output.
    
    Args:
        output: Combined stdout/stderr from codesign -dv
    
    Returns:
        Pipe-separated string of authorities or empty string
    """
    # Look for Authority=... lines
    authorities = re.findall(r"Authority=(.+)", output)
    
    if not authorities:
        # Try alternative format
        authorities = re.findall(r"Authority:\s*(.+)", output)
    
    if authorities:
        # Clean up each authority and join with " | "
        cleaned = [auth.strip() for auth in authorities]
        return " | ".join(cleaned)
    
    return ""


def _create_raw_summary(verify_result, detail_result) -> str:
    """
    Create a brief summary of raw codesign output.
    
    Args:
        verify_result: Result from --verify command
        detail_result: Result from -dv command
    
    Returns:
        Brief string summarizing the raw output (max ~200 chars)
    """
    parts = []
    
    # Add verification status
    if verify_result.err:
        parts.append(f"verify: {verify_result.err[:80]}")
    elif verify_result.out:
        parts.append(f"verify: {verify_result.out[:80]}")
    else:
        parts.append(f"verify: code {verify_result.code}")
    
    # Add a snippet from detail if there's an error
    if detail_result.code != 0:
        if detail_result.err:
            parts.append(f"detail: {detail_result.err[:80]}")
    
    raw = " | ".join(parts)
    
    # Truncate to reasonable length
    if len(raw) > 200:
        raw = raw[:197] + "..."
    
    return raw
