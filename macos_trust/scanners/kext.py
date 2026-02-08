"""Kernel extension and system extension scanner."""

from pathlib import Path
from typing import List, Dict, Any

from macos_trust.util.shell import run
from macos_trust.collectors.codesign import codesign_verify


def scan_kexts() -> List[Dict[str, Any]]:
    """
    Scan for kernel extensions and system extensions.
    
    Returns:
        List of dictionaries with kext information
    """
    kexts = []
    
    # Scan for legacy KEXTs in common locations
    kext_paths = [
        Path("/Library/Extensions"),
        Path("/System/Library/Extensions"),
    ]
    
    for kext_dir in kext_paths:
        if not kext_dir.exists():
            continue
        
        try:
            for kext_path in kext_dir.glob("*.kext"):
                kext_info = _analyze_kext(kext_path)
                if kext_info:
                    kexts.append(kext_info)
        except (PermissionError, OSError):
            # Skip directories we can't access
            continue
    
    # Scan for modern System Extensions
    sysext_path = Path("/Library/SystemExtensions")
    if sysext_path.exists():
        try:
            for sysext in sysext_path.rglob("*.systemextension"):
                sysext_info = _analyze_system_extension(sysext)
                if sysext_info:
                    kexts.append(sysext_info)
        except (PermissionError, OSError):
            pass
    
    # Get list of loaded kernel extensions
    loaded_kexts = _get_loaded_kexts()
    
    # Mark which kexts are currently loaded
    for kext in kexts:
        bundle_id = kext.get("bundle_id", "")
        kext["loaded"] = bundle_id in loaded_kexts
    
    return kexts


def _analyze_kext(kext_path: Path) -> Dict[str, Any] | None:
    """
    Analyze a single kernel extension.
    
    Args:
        kext_path: Path to the .kext bundle
    
    Returns:
        Dictionary with kext information or None if analysis failed
    """
    try:
        kext_info: Dict[str, Any] = {
            "path": str(kext_path),
            "name": kext_path.name,
            "type": "kext",
            "location": "system" if "/System/" in str(kext_path) else "library",
        }
        
        # Try to read Info.plist for bundle identifier
        info_plist = kext_path / "Contents" / "Info.plist"
        if info_plist.exists():
            # Use plutil to read plist
            result = run(["plutil", "-extract", "CFBundleIdentifier", "raw", str(info_plist)])
            if result.success and result.out:
                kext_info["bundle_id"] = result.out.strip()
            
            # Get version
            result = run(["plutil", "-extract", "CFBundleVersion", "raw", str(info_plist)])
            if result.success and result.out:
                kext_info["version"] = result.out.strip()
        
        # Check code signature
        codesign_result = codesign_verify(str(kext_path))
        kext_info["codesign"] = codesign_result
        
        return kext_info
    
    except Exception:
        return None


def _analyze_system_extension(sysext_path: Path) -> Dict[str, Any] | None:
    """
    Analyze a modern system extension.
    
    Args:
        sysext_path: Path to the .systemextension bundle
    
    Returns:
        Dictionary with system extension information or None if analysis failed
    """
    try:
        sysext_info: Dict[str, Any] = {
            "path": str(sysext_path),
            "name": sysext_path.name,
            "type": "systemextension",
            "location": "library",
        }
        
        # Try to read Info.plist
        info_plist = sysext_path / "Contents" / "Info.plist"
        if info_plist.exists():
            # Get bundle identifier
            result = run(["plutil", "-extract", "CFBundleIdentifier", "raw", str(info_plist)])
            if result.success and result.out:
                sysext_info["bundle_id"] = result.out.strip()
            
            # Get version
            result = run(["plutil", "-extract", "CFBundleVersion", "raw", str(info_plist)])
            if result.success and result.out:
                sysext_info["version"] = result.out.strip()
        
        # Check code signature
        codesign_result = codesign_verify(str(sysext_path))
        sysext_info["codesign"] = codesign_result
        
        return sysext_info
    
    except Exception:
        return None


def _get_loaded_kexts() -> set[str]:
    """
    Get set of currently loaded kernel extension bundle IDs.
    
    Returns:
        Set of bundle identifiers for loaded KEXTs
    """
    loaded = set()
    
    result = run(["kextstat", "-l"])
    if not result.success:
        return loaded
    
    # Parse kextstat output
    # Format: Index Refs Address Size Wired Name (Version) UUID <Linked Against>
    for line in result.out.splitlines()[1:]:  # Skip header
        parts = line.split()
        if len(parts) >= 6:
            # Bundle ID is in format: com.apple.driver.ExampleDriver (1.0.0)
            name_version = " ".join(parts[5:])
            # Extract just the bundle ID (before the version in parentheses)
            if "(" in name_version:
                bundle_id = name_version.split("(")[0].strip()
                loaded.add(bundle_id)
    
    return loaded
