"""Launch agents and daemons scanner for macOS."""

import plistlib
from pathlib import Path


def scan_launchd() -> list[dict]:
    """
    Enumerate macOS launch agents and daemons.
    
    Scans standard launchd locations for .plist files and extracts metadata
    about persistent and scheduled tasks.
    
    Returns:
        List of dictionaries with keys:
        - scope: "user" (user agents), "system" (system agents), or "daemon" (system daemons)
        - plist_path: Full path to the .plist file
        - label: Label from plist or filename as fallback
        - program: Executable path from Program or ProgramArguments[0]
        - run_at_load: Boolean indicating if item runs at load (default False)
    
    Example:
        >>> items = scan_launchd()
        >>> [item for item in items if item['run_at_load']]
        [{'scope': 'user', 'plist_path': '...', 'label': 'com.example.agent', ...}]
    """
    items = []
    
    # Define scan locations with their scope
    scan_locations = [
        (Path.home() / "Library" / "LaunchAgents", "user"),
        (Path("/Library/LaunchAgents"), "system"),
        (Path("/Library/LaunchDaemons"), "daemon"),
    ]
    
    for scan_path, scope in scan_locations:
        if not scan_path.exists():
            continue
        
        try:
            # Find all .plist files in this location
            for plist_file in scan_path.iterdir():
                if plist_file.is_file() and plist_file.suffix == ".plist":
                    item_info = _process_launchd_plist(plist_file, scope)
                    if item_info:
                        items.append(item_info)
        except (OSError, PermissionError):
            # Skip directories we can't read
            continue
    
    return items


def _process_launchd_plist(plist_path: Path, scope: str) -> dict | None:
    """
    Process a single launchd plist file to extract metadata.
    
    Args:
        plist_path: Path to the .plist file
        scope: Scope type ("user", "system", or "daemon")
    
    Returns:
        Dictionary with launchd item metadata, or None if processing fails critically
    """
    # Initialize result with known values
    result = {
        "scope": scope,
        "plist_path": str(plist_path),
        "label": plist_path.stem,  # Fallback: use filename without extension
        "program": "",
        "run_at_load": False
    }
    
    # Try to read and parse the plist
    try:
        with open(plist_path, "rb") as f:
            plist_data = plistlib.load(f)
    except (OSError, plistlib.InvalidFileException, PermissionError):
        # Can't read or parse plist - return minimal info
        return result
    
    # Extract Label (use plist value if present, otherwise keep filename fallback)
    label = plist_data.get("Label")
    if label:
        result["label"] = label
    
    # Extract Program or ProgramArguments[0]
    program = plist_data.get("Program")
    if program:
        result["program"] = program
    else:
        # Try ProgramArguments array
        program_args = plist_data.get("ProgramArguments")
        if program_args and isinstance(program_args, list) and len(program_args) > 0:
            result["program"] = program_args[0]
    
    # Extract RunAtLoad (default to False if not present)
    run_at_load = plist_data.get("RunAtLoad", False)
    # Ensure it's a boolean
    if isinstance(run_at_load, bool):
        result["run_at_load"] = run_at_load
    else:
        # Handle non-boolean values (convert truthy/falsy)
        result["run_at_load"] = bool(run_at_load)
    
    return result
