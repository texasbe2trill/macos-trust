"""Collectors for discovering files to scan."""

from pathlib import Path
from typing import List, Dict, Any
import os


def collect_applications() -> List[Dict[str, Any]]:
    """
    Collect all .app bundles from standard macOS application directories.
    
    Returns:
        List of dictionaries with app metadata
    """
    apps = []
    search_paths = [
        "/Applications",
        "/System/Applications",
        Path.home() / "Applications"
    ]
    
    for search_path in search_paths:
        path = Path(search_path)
        if not path.exists():
            continue
        
        try:
            for item in path.iterdir():
                if item.suffix == ".app" and item.is_dir():
                    apps.append({
                        "path": str(item),
                        "name": item.stem,
                        "location": str(search_path),
                        "type": "application"
                    })
        except PermissionError:
            # Skip directories we can't read (read-only requirement)
            continue
        except Exception:
            # Continue on any other errors (per-item failure handling)
            continue
    
    # Sort for deterministic output
    apps.sort(key=lambda x: x["path"])
    return apps


def collect_launchd_plists() -> List[Dict[str, Any]]:
    """
    Collect LaunchDaemons and LaunchAgents plist files.
    
    Returns:
        List of dictionaries with plist metadata
    """
    plists = []
    search_paths = [
        "/Library/LaunchDaemons",
        "/Library/LaunchAgents",
        "/System/Library/LaunchDaemons",
        "/System/Library/LaunchAgents",
        Path.home() / "Library" / "LaunchAgents"
    ]
    
    for search_path in search_paths:
        path = Path(search_path)
        if not path.exists():
            continue
        
        try:
            for item in path.iterdir():
                if item.suffix == ".plist" and item.is_file():
                    plists.append({
                        "path": str(item),
                        "name": item.name,
                        "location": str(search_path),
                        "type": "launchd_plist"
                    })
        except PermissionError:
            # Skip directories we can't read
            continue
        except Exception:
            # Continue on any other errors
            continue
    
    # Sort for deterministic output
    plists.sort(key=lambda x: x["path"])
    return plists


def collect_all_items() -> List[Dict[str, Any]]:
    """
    Collect all items (applications and plists).
    
    Returns:
        Combined list of all items to scan
    """
    items = []
    items.extend(collect_applications())
    items.extend(collect_launchd_plists())
    return items
