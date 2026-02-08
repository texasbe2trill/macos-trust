"""Browser extension scanner for Chrome, Firefox, and Safari."""

import json
import plistlib
from pathlib import Path
from typing import List, Dict, Any


def scan_browser_extensions() -> List[Dict[str, Any]]:
    """
    Scan for browser extensions installed in Chrome, Firefox, and Safari.
    
    Returns:
        List of dictionaries with extension information including:
        - browser: Browser name ("chrome", "firefox", "safari")
        - name: Extension name
        - id: Extension ID
        - version: Extension version
        - manifest_path: Path to manifest file
        - permissions: List of permissions requested
        - optional_permissions: List of optional permissions
        - host_permissions: List of host permissions (URLs extension can access)
    """
    extensions = []
    
    # Scan Chrome extensions
    extensions.extend(_scan_chrome_extensions())
    
    # Scan Firefox extensions
    extensions.extend(_scan_firefox_extensions())
    
    # Scan Safari extensions
    extensions.extend(_scan_safari_extensions())
    
    return extensions


def _scan_chrome_extensions() -> List[Dict[str, Any]]:
    """Scan for Chrome browser extensions."""
    extensions = []
    home = Path.home()
    
    # Chrome stores extensions in profile directories
    chrome_profiles = [
        home / "Library/Application Support/Google/Chrome/Default/Extensions",
        home / "Library/Application Support/Google/Chrome/Profile 1/Extensions",
        home / "Library/Application Support/Google/Chrome/Profile 2/Extensions",
    ]
    
    for profile_path in chrome_profiles:
        if not profile_path.exists():
            continue
        
        try:
            # Each subdirectory is an extension ID
            for ext_id_dir in profile_path.iterdir():
                if not ext_id_dir.is_dir() or ext_id_dir.name.startswith("."):
                    continue
                
                # Extensions may have multiple versions
                for version_dir in ext_id_dir.iterdir():
                    if not version_dir.is_dir():
                        continue
                    
                    manifest_path = version_dir / "manifest.json"
                    if manifest_path.exists():
                        ext_info = _parse_chrome_manifest(manifest_path, ext_id_dir.name)
                        if ext_info:
                            extensions.append(ext_info)
                        break  # Only process the first (usually latest) version
                    
        except (OSError, PermissionError):
            continue
    
    return extensions


def _scan_firefox_extensions() -> List[Dict[str, Any]]:
    """Scan for Firefox browser extensions."""
    extensions = []
    home = Path.home()
    
    # Firefox stores extensions differently
    firefox_profile_root = home / "Library/Application Support/Firefox/Profiles"
    
    if not firefox_profile_root.exists():
        return extensions
    
    try:
        # Find profile directories (they have random names like abcd1234.default)
        for profile_dir in firefox_profile_root.iterdir():
            if not profile_dir.is_dir():
                continue
            
            extensions_dir = profile_dir / "extensions"
            if not extensions_dir.exists():
                continue
            
            # Extensions can be XPI files or directories
            for item in extensions_dir.iterdir():
                if item.is_dir():
                    manifest_path = item / "manifest.json"
                    if manifest_path.exists():
                        ext_info = _parse_firefox_manifest(manifest_path, item.name)
                        if ext_info:
                            extensions.append(ext_info)
                elif item.suffix == ".xpi":
                    # XPI files are ZIP archives - could extract and parse but skip for now
                    pass
                    
    except (OSError, PermissionError):
        pass
    
    return extensions


def _scan_safari_extensions() -> List[Dict[str, Any]]:
    """Scan for Safari browser extensions.
    
    Modern Safari extensions are App Extensions (.appex) bundled within host applications.
    They are located in /Applications/*.app/Contents/PlugIns/*.appex.
    
    Safari supports two types of extensions:
    - com.apple.Safari.extension: Legacy Safari App Extensions (native)
    - com.apple.Safari.web-extension: Safari Web Extensions (WebExtensions API)
    """
    extensions = []
    apps_dir = Path("/Applications")
    
    if not apps_dir.exists():
        return extensions
    
    # Valid Safari extension point identifiers
    safari_extension_types = {
        "com.apple.Safari.extension",
        "com.apple.Safari.web-extension"
    }
    
    try:
        # Scan all applications for Safari extensions
        for app_bundle in apps_dir.iterdir():
            if not app_bundle.is_dir() or not app_bundle.suffix == ".app":
                continue
            
            # Look for app extensions in PlugIns directory
            plugins_dir = app_bundle / "Contents" / "PlugIns"
            if not plugins_dir.exists():
                continue
            
            try:
                for appex_bundle in plugins_dir.iterdir():
                    if not appex_bundle.is_dir() or not appex_bundle.suffix == ".appex":
                        continue
                    
                    info_plist = appex_bundle / "Contents" / "Info.plist"
                    if not info_plist.exists():
                        continue
                    
                    # Check if this is a Safari extension
                    try:
                        with open(info_plist, 'rb') as f:
                            plist_data = plistlib.load(f)
                        
                        # Check if this is any type of Safari extension
                        ns_extension = plist_data.get("NSExtension", {})
                        extension_point = ns_extension.get("NSExtensionPointIdentifier", "")
                        
                        if extension_point in safari_extension_types:
                            ext_info = _parse_safari_extension(
                                info_plist, 
                                appex_bundle.name, 
                                app_bundle.name,
                                is_web_extension=(extension_point == "com.apple.Safari.web-extension")
                            )
                            if ext_info:
                                extensions.append(ext_info)
                    except (plistlib.InvalidFileException, OSError, KeyError):
                        continue
            except (OSError, PermissionError):
                continue
    except (OSError, PermissionError):
        pass
    
    return extensions


def _parse_chrome_manifest(manifest_path: Path, ext_id: str) -> Dict[str, Any] | None:
    """Parse a Chrome extension manifest.json file."""
    try:
        with open(manifest_path, 'r', encoding='utf-8') as f:
            manifest = json.load(f)
        
        # Extract key information
        return {
            "browser": "chrome",
            "name": manifest.get("name", "Unknown"),
            "id": ext_id,
            "version": manifest.get("version", ""),
            "manifest_path": str(manifest_path),
            "permissions": manifest.get("permissions", []),
            "optional_permissions": manifest.get("optional_permissions", []),
            "host_permissions": manifest.get("host_permissions", []),
            "description": manifest.get("description", ""),
            "manifest_version": manifest.get("manifest_version", 2),
        }
    except (json.JSONDecodeError, OSError, UnicodeDecodeError):
        return None


def _parse_firefox_manifest(manifest_path: Path, ext_id: str) -> Dict[str, Any] | None:
    """Parse a Firefox extension manifest.json file."""
    try:
        with open(manifest_path, 'r', encoding='utf-8') as f:
            manifest = json.load(f)
        
        # Firefox uses WebExtensions API (similar to Chrome)
        permissions = manifest.get("permissions", [])
        
        # Firefox may store host permissions differently depending on manifest version
        host_permissions = manifest.get("host_permissions", [])
        
        # In manifest v2, host permissions might be in permissions
        if not host_permissions and permissions:
            host_permissions = [p for p in permissions if isinstance(p, str) and ('://' in p or p.startswith('<all_urls>'))]
        
        return {
            "browser": "firefox",
            "name": manifest.get("name", "Unknown"),
            "id": manifest.get("browser_specific_settings", {}).get("gecko", {}).get("id", ext_id),
            "version": manifest.get("version", ""),
            "manifest_path": str(manifest_path),
            "permissions": [p for p in permissions if isinstance(p, str) and not ('://' in p or p.startswith('<all_urls>'))],
            "optional_permissions": manifest.get("optional_permissions", []),
            "host_permissions": host_permissions,
            "description": manifest.get("description", ""),
            "manifest_version": manifest.get("manifest_version", 2),
        }
    except (json.JSONDecodeError, OSError, UnicodeDecodeError):
        return None


def _parse_safari_extension(info_plist_path: Path, ext_name: str, app_name: str, is_web_extension: bool = False) -> Dict[str, Any] | None:
    """Parse a Safari extension Info.plist file.
    
    Args:
        info_plist_path: Path to the extension's Info.plist
        ext_name: Name of the .appex bundle (e.g., "Extension.appex")
        app_name: Name of the parent app bundle (e.g., "AdGuard for Safari.app")
        is_web_extension: True if this is a Safari Web Extension (WebExtensions API)
    
    Returns:
        Dictionary with extension information or None if parsing fails
    """
    try:
        with open(info_plist_path, 'rb') as f:
            plist_data = plistlib.load(f)
        
        # Get basic extension info
        name = plist_data.get("CFBundleDisplayName") or plist_data.get("CFBundleName", ext_name)
        bundle_id = plist_data.get("CFBundleIdentifier", "")
        version = plist_data.get("CFBundleShortVersionString") or plist_data.get("CFBundleVersion", "")
        
        # Safari extensions store permissions/capabilities in NSExtension
        permissions = []
        host_permissions = []
        
        ns_extension = plist_data.get("NSExtension", {})
        
        if is_web_extension:
            # Safari Web Extensions use WebExtensions API (similar to Chrome/Firefox)
            # Check for manifest file which contains permissions
            permissions.append("webExtensionsAPI")
            
            # Try to find and parse the manifest.json if available
            # Note: This is embedded in the .appex bundle's Resources
            ext_dir = info_plist_path.parent.parent  # Go up from Contents/Info.plist to .appex
            resources_dir = ext_dir / "Contents" / "Resources"
            
            # Look for manifest.json or _locales (indicates web extension structure)
            if resources_dir.exists():
                manifest_json = resources_dir / "manifest.json"
                if manifest_json.exists():
                    try:
                        with open(manifest_json, 'r', encoding='utf-8') as mf:
                            manifest_data = json.load(mf)
                            permissions.extend(manifest_data.get("permissions", []))
                            host_permissions.extend(manifest_data.get("host_permissions", []))
                    except (json.JSONDecodeError, OSError, UnicodeDecodeError):
                        pass
        else:
            # Legacy Safari App Extensions
            # Extract content scripts and their URL patterns
            content_scripts = ns_extension.get("SFSafariContentScript", [])
            if isinstance(content_scripts, list):
                for script in content_scripts:
                    if isinstance(script, dict):
                        # Allowed patterns indicate which sites the extension can access
                        allowed_patterns = script.get("Allowed URL Patterns", [])
                        if allowed_patterns:
                            host_permissions.extend(allowed_patterns)
                        
                        # Script file indicates content injection capability
                        if script.get("Script"):
                            permissions.append(f"contentScript:{script['Script']}")
            
            # Web request permissions
            if ns_extension.get("SFSafariWebRequestPermissions"):
                permissions.append("webRequest")
            
            # Check for other common Safari extension capabilities
            extension_principal = ns_extension.get("NSExtensionPrincipalClass", "")
            if "SafariExtensionHandler" in extension_principal:
                permissions.append("safariExtensionHandler")
        
        extension_type = "web-extension" if is_web_extension else "app-extension"
        
        return {
            "browser": "safari",
            "name": name,
            "id": bundle_id,
            "version": version,
            "manifest_path": str(info_plist_path),
            "permissions": permissions,
            "optional_permissions": [],
            "host_permissions": host_permissions,
            "description": f"Safari {extension_type} from {app_name}",
            "manifest_version": 0,  # Safari doesn't use manifest versions in Info.plist
            "app_bundle": app_name,
            "extension_type": extension_type,
        }
    except (plistlib.InvalidFileException, OSError):
        return None
