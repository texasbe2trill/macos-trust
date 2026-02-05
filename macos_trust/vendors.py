"""Known vendor information and trust metadata."""

from typing import Dict

# Known legitimate vendors by Team ID
# These are used to provide context when assessing risk
KNOWN_VENDORS: Dict[str, str] = {
    # Major software companies
    "9BNSXJN65R": "Docker Inc",
    "UBF8T346G9": "Microsoft Corporation",
    "BJ4HAAB9B3": "Zoom Video Communications",
    "MXGJJ98X76": "Valve Corporation",  # Steam
    "EQHXZ8M8AV": "Google LLC",
    "6N38VWS5BX": "Mozilla Corporation",
    "43AQ936H96": "JetBrains s.r.o.",
    "4XRHD3P41Q": "Slack Technologies",
    "2E337YPCZY": "Dropbox Inc",
    "5E9KR5BC68": "Discord Inc",
    "MXCNVGBRW2": "Homebrew",
    
    # Apple
    "Apple": "Apple Inc",
    "0000000000": "Apple Inc",  # Sometimes used for system components
    
    # Open source / Development tools
    "PKV8ZPD836": "GPGTools GmbH",
    "PXPBC95EF8": "Oracle America Inc",
}

# System helper tool patterns that commonly fail spctl but are legitimate
SYSTEM_HELPER_PATTERNS = [
    "PrivilegedHelperTools",
    "XPCServices",
    "Frameworks/",
    ".framework/",
    "/Contents/Library/",
]

# User-writable locations that indicate higher risk
USER_WRITABLE_PATHS = [
    "/Users/",
    "/tmp/",
    "/var/tmp/",
    "/private/tmp/",
    "~/",
]


def is_known_vendor(team_id: str) -> bool:
    """Check if a Team ID belongs to a known vendor."""
    return team_id in KNOWN_VENDORS


def get_vendor_name(team_id: str) -> str:
    """Get vendor name for a Team ID, or return the ID if unknown."""
    return KNOWN_VENDORS.get(team_id, team_id)


def is_system_helper_path(path: str) -> bool:
    """Check if a path indicates a system helper/service."""
    if not path:
        return False
    return any(pattern in path for pattern in SYSTEM_HELPER_PATTERNS)


def is_user_writable_path(path: str) -> bool:
    """Check if a path is in a user-writable location."""
    if not path:
        return False
    path_lower = path.lower()
    return any(path_lower.startswith(prefix) for prefix in USER_WRITABLE_PATHS)
