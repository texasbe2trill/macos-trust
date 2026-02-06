"""Context enrichment for applications and findings."""

import os
import re
from pathlib import Path
from datetime import datetime, timedelta
from typing import Any

from macos_trust.util.shell import run


class AppContext:
    """Enriched context information about an application."""
    
    def __init__(self, app_path: str):
        """Initialize context for an app path."""
        self.app_path = app_path
        self.is_app_store = self._check_app_store()
        self.is_homebrew = self._check_homebrew()
        self.age_days = self._get_age_days()
        self.quarantine_source = None
    
    def _check_app_store(self) -> bool:
        """Check if app is from Mac App Store by looking for receipt."""
        if not self.app_path:
            return False
        
        # Extract app bundle path (may be given executable path)
        if self.app_path.endswith('.app'):
            app_bundle = self.app_path
        elif '.app/' in self.app_path:
            app_bundle = self.app_path.split('.app/')[0] + '.app'
        else:
            return False
        
        # Check for App Store receipt
        receipt_path = Path(app_bundle) / 'Contents' / '_MASReceipt' / 'receipt'
        return receipt_path.exists()
    
    def _check_homebrew(self) -> bool:
        """Check if app is managed by Homebrew."""
        if not self.app_path:
            return False
        
        # Homebrew cask apps are typically in /Applications
        # and have metadata linking them to Homebrew
        # We'll check if path appears in brew cask list
        # This is cached for performance
        if not hasattr(AppContext, '_homebrew_apps'):
            AppContext._homebrew_apps = self._get_homebrew_apps()
        
        # Check if this app is in the Homebrew list
        app_name = self._extract_app_name(self.app_path)
        return app_name in AppContext._homebrew_apps
    
    @staticmethod
    def _get_homebrew_apps() -> set[str]:
        """Get list of Homebrew-managed app names (cached)."""
        try:
            result = run(['/usr/local/bin/brew', 'list', '--cask'], timeout=10)
            if result.code == 0:
                # Extract app names from cask list
                return set(result.out.strip().split('\n'))
        except (FileNotFoundError, TimeoutError):
            # Homebrew not installed or brew command not found
            # Try alternate location for Apple Silicon
            try:
                result = run(['/opt/homebrew/bin/brew', 'list', '--cask'], timeout=10)
                if result.code == 0:
                    return set(result.out.strip().split('\n'))
            except (FileNotFoundError, TimeoutError):
                pass
        
        return set()
    
    @staticmethod
    def _extract_app_name(app_path: str) -> str:
        """Extract app name from path."""
        if '.app' in app_path:
            # Extract "AppName" from "/Applications/AppName.app/..."
            app_with_ext = app_path.split('/')[-1] if app_path.endswith('.app') else app_path.split('.app/')[0].split('/')[-1] + '.app'
            return app_with_ext.replace('.app', '').lower()
        return ''
    
    def _get_age_days(self) -> int:
        """Get age of app in days based on modification time."""
        if not self.app_path:
            return 0
        
        try:
            stat = os.stat(self.app_path)
            mtime = datetime.fromtimestamp(stat.st_mtime)
            age = datetime.now() - mtime
            return age.days
        except (OSError, ValueError):
            return 0
    
    def set_quarantine_source(self, quarantine_value: str) -> None:
        """
        Parse and set quarantine source from quarantine attribute value.
        
        Format: "flags;timestamp;app_name;UUID"
        Example: "0181;697f95d3;Homebrew\\x20Cask;082DC06F-877D-4038-9E75-6FAFE46B30B8"
        """
        if not quarantine_value:
            return
        
        parts = quarantine_value.split(';')
        if len(parts) >= 3:
            # Third field is the source application
            source = parts[2].replace('\\x20', ' ')  # Unescape spaces
            self.quarantine_source = source


def parse_quarantine_source(quarantine_value: str) -> str | None:
    """
    Extract the source application from a quarantine attribute value.
    
    Args:
        quarantine_value: Raw quarantine attribute value
    
    Returns:
        Source application name or None if not parseable
    
    Example:
        >>> parse_quarantine_source("0181;697f95d3;Homebrew\\x20Cask;UUID")
        "Homebrew Cask"
    """
    if not quarantine_value:
        return None
    
    parts = quarantine_value.split(';')
    if len(parts) >= 3:
        source = parts[2].replace('\\x20', ' ')  # Unescape spaces
        return source
    
    return None


def is_homebrew_quarantine(quarantine_value: str) -> bool:
    """Check if quarantine source is Homebrew Cask."""
    source = parse_quarantine_source(quarantine_value)
    return source is not None and 'homebrew' in source.lower()


def is_browser_quarantine(quarantine_value: str) -> bool:
    """Check if quarantine source is a web browser."""
    source = parse_quarantine_source(quarantine_value)
    if not source:
        return False
    
    source_lower = source.lower()
    browsers = ['safari', 'chrome', 'firefox', 'edge', 'brave', 'opera']
    return any(browser in source_lower for browser in browsers)


def get_codesign_timestamp(codesign_result: dict | None) -> datetime | None:
    """
    Extract signing timestamp from codesign result.
    
    This requires parsing codesign -dvvv output which includes:
    Timestamp=Jan 15, 2024 at 10:30:00 AM
    
    Args:
        codesign_result: Result from codesign_verify
    
    Returns:
        Signing timestamp or None if not available
    """
    # TODO: Implement timestamp extraction from codesign -dvvv
    # For now, return None (feature for future enhancement)
    return None


def should_trust_by_age(app_path: str, threshold_days: int = 30) -> bool:
    """
    Check if app is old enough to be considered stable.
    
    Args:
        app_path: Path to application
        threshold_days: Minimum age in days to consider stable
    
    Returns:
        True if app is older than threshold
    """
    try:
        stat = os.stat(app_path)
        mtime = datetime.fromtimestamp(stat.st_mtime)
        age = datetime.now() - mtime
        return age.days >= threshold_days
    except (OSError, ValueError):
        return False
