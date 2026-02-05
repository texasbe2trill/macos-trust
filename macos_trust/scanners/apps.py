"""Application scanner for macOS."""

import os
import plistlib
from pathlib import Path


def scan_applications() -> list[dict]:
    """
    Enumerate macOS applications from standard locations.
    
    Scans /Applications and ~/Applications for .app bundles and extracts
    metadata from their Info.plist files.
    
    Returns:
        List of dictionaries with keys:
        - app_path: Full path to the .app bundle
        - exec_path: Full path to main executable (empty string if not found)
        - bundle_id: CFBundleIdentifier from Info.plist (empty string if not found)
        - name: Application name (derived from .app bundle name)
    
    Example:
        >>> apps = scan_applications()
        >>> [app for app in apps if 'Safari' in app['name']]
        [{'app_path': '/Applications/Safari.app', 'exec_path': '...', ...}]
    """
    apps = []
    
    # Locations to scan for applications
    scan_paths = [
        Path("/Applications"),
        Path.home() / "Applications"
    ]
    
    for scan_path in scan_paths:
        if not scan_path.exists():
            continue
        
        try:
            # Find all .app directories in this location
            for item in scan_path.iterdir():
                if item.is_dir() and item.suffix == ".app":
                    app_info = _process_app_bundle(item)
                    if app_info:
                        apps.append(app_info)
        except (OSError, PermissionError):
            # Skip directories we can't read
            continue
    
    return apps


def _process_app_bundle(app_path: Path) -> dict | None:
    """
    Process a single .app bundle to extract metadata.
    
    Args:
        app_path: Path to the .app bundle
    
    Returns:
        Dictionary with app metadata, or None if processing fails critically
    """
    # Extract app name from bundle name
    app_name = app_path.stem  # e.g., "Safari.app" -> "Safari"
    
    # Initialize result with known values
    result = {
        "app_path": str(app_path),
        "exec_path": "",
        "bundle_id": "",
        "name": app_name
    }
    
    # Try to read Info.plist
    info_plist_path = app_path / "Contents" / "Info.plist"
    
    if not info_plist_path.exists():
        # No Info.plist - return minimal info
        return result
    
    try:
        with open(info_plist_path, "rb") as f:
            plist_data = plistlib.load(f)
    except (OSError, plistlib.InvalidFileException, PermissionError, Exception):
        # Can't read or parse plist (including XML parsing errors) - return minimal info
        return result
    
    # Extract bundle identifier
    bundle_id = plist_data.get("CFBundleIdentifier", "")
    if bundle_id:
        result["bundle_id"] = bundle_id
    
    # Extract executable name and resolve path
    executable_name = plist_data.get("CFBundleExecutable", "")
    
    if executable_name:
        # Standard location: <App>.app/Contents/MacOS/<CFBundleExecutable>
        exec_path = app_path / "Contents" / "MacOS" / executable_name
        
        # Check if executable exists
        if exec_path.exists():
            result["exec_path"] = str(exec_path)
        # If it doesn't exist, exec_path remains empty string
    
    # Use CFBundleName or CFBundleDisplayName if available for better name
    display_name = plist_data.get("CFBundleDisplayName") or plist_data.get("CFBundleName")
    if display_name:
        result["name"] = display_name
    
    return result
