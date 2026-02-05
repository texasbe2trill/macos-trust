"""Host system information collection."""

import platform
import socket
import re

from macos_trust.models import HostInfo
from macos_trust.util.shell import run


def get_host_info() -> HostInfo:
    """
    Collect macOS host system information.
    
    Returns:
        HostInfo with OS version, build, architecture, and hostname
    
    Raises:
        RuntimeError: If critical system information cannot be retrieved
    
    Example:
        >>> info = get_host_info()
        >>> print(f"{info.os_version} ({info.build}) on {info.arch}")
    """
    # Get architecture from Python's platform module
    arch = platform.machine()
    
    # Get hostname from socket
    hostname = socket.gethostname()
    
    # Get macOS version and build from sw_vers
    os_version, build = _get_macos_version()
    
    return HostInfo(
        os_version=os_version,
        build=build,
        arch=arch,
        hostname=hostname
    )


def _get_macos_version() -> tuple[str, str]:
    """
    Retrieve macOS version and build number from sw_vers.
    
    Returns:
        Tuple of (version, build) strings
    
    Raises:
        RuntimeError: If sw_vers fails or output cannot be parsed
    """
    try:
        result = run(["/usr/bin/sw_vers"], timeout=5)
        
        if not result.success:
            raise RuntimeError(
                f"sw_vers failed with exit code {result.code}: {result.err}"
            )
        
        # Parse output like:
        # ProductName:        macOS
        # ProductVersion:     14.2.1
        # BuildVersion:       23C71
        
        version_match = re.search(r"ProductVersion:\s*(.+)", result.out)
        build_match = re.search(r"BuildVersion:\s*(.+)", result.out)
        
        if not version_match or not build_match:
            raise RuntimeError(
                f"Could not parse sw_vers output: {result.out}"
            )
        
        os_version = version_match.group(1).strip()
        build = build_match.group(1).strip()
        
        return os_version, build
    
    except TimeoutError as e:
        raise RuntimeError(f"sw_vers timed out: {e}") from e
    except FileNotFoundError as e:
        raise RuntimeError(
            "sw_vers not found at /usr/bin/sw_vers. Are you running on macOS?"
        ) from e
    except Exception as e:
        raise RuntimeError(f"Failed to get macOS version: {e}") from e
