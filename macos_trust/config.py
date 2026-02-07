"""Configuration file management for macos-trust."""

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

try:
    import yaml
    HAS_YAML = True
except ImportError:
    HAS_YAML = False


@dataclass
class Config:
    """Configuration for macos-trust scanner."""
    
    # Risk filtering
    min_risk: str = "MED"
    
    # Vendor filtering
    exclude_vendors: list[str] = field(default_factory=list)
    trusted_vendors: list[str] = field(default_factory=list)
    
    # Finding suppression
    ignore_findings: list[str] = field(default_factory=list)
    ignore_patterns: list[str] = field(default_factory=list)
    
    # Baseline mode
    baseline_file: str = "~/.macos-trust/baseline.json"
    
    # Source trust settings
    trust_homebrew_cask: bool = False
    trust_app_store: bool = True
    trust_old_apps: bool = False
    old_app_days: int = 30
    
    def __post_init__(self) -> None:
        """Validate configuration after initialization."""
        # Validate ignore_patterns are valid regex
        for pattern in self.ignore_patterns:
            try:
                re.compile(pattern)
            except re.error as e:
                raise ValueError(f"Invalid regex pattern '{pattern}': {e}")


def load_config(config_path: Path | str | None = None) -> Config:
    """
    Load configuration from file.
    
    Args:
        config_path: Path to config file. If None, checks default locations:
            1. ~/.macos-trust.yaml
            2. ~/.macos-trust.yml
            3. ~/.config/macos-trust/config.yaml
            4. ~/.config/macos-trust/config.yml
    
    Returns:
        Config object with loaded settings (or defaults if no config found)
    """
    # If explicit path provided, validate it exists first
    if config_path:
        path = Path(config_path).expanduser()
        if not path.exists():
            raise FileNotFoundError(f"Config file not found: {path}")
        if not HAS_YAML:
            raise RuntimeError("PyYAML is required to load config files. Install with: pip install pyyaml")
        config_file = path
    else:
        # No explicit path provided
        if not HAS_YAML:
            # If PyYAML not installed, return default config
            return Config()
        
        # Check default locations
        default_paths = [
            Path.home() / ".macos-trust.yaml",
            Path.home() / ".macos-trust.yml",
            Path.home() / ".config" / "macos-trust" / "config.yaml",
            Path.home() / ".config" / "macos-trust" / "config.yml",
        ]
        
        config_file = None
        for path in default_paths:
            if path.exists():
                config_file = path
                break
        
        if not config_file:
            # No config file found, use defaults
            return Config()
    
    # Load and parse config
    try:
        with open(config_file, 'r') as f:
            data = yaml.safe_load(f) or {}  # type: ignore[possibly-unbound]
        return Config(**data)
    except Exception as e:
        raise ValueError(f"Failed to load config from {config_file}: {e}")


def save_example_config(output_path: Path | str) -> None:
    """
    Save an example configuration file with all options documented.
    
    Args:
        output_path: Where to save the example config
    """
    if not HAS_YAML:
        raise RuntimeError("PyYAML is required to generate config files. Install with: pip install pyyaml")
    
    example = """# macos-trust configuration file
# Place at ~/.macos-trust.yaml or ~/.config/macos-trust/config.yaml

# Minimum risk level to report (INFO, LOW, MED, HIGH)
min_risk: MED

# Vendor filtering
exclude_vendors:
  - UBF8T346G9  # Microsoft Corporation
  - 9BNSXJN65R  # Docker Inc
  # - BJ4HAAB9B3  # Zoom Video Communications

# Additional trusted vendors (downgrades their findings from HIGH to MED)
trusted_vendors:
  - H7H8Q7M5CK  # Postman
  - LH6JV2ZBQ7  # Rakuten Kobo

# Suppress specific findings by ID
ignore_findings:
  - app:org.gimp.gimp:quarantined
  - persistence:daemon:com.docker.vmnetd:spctl_rejected

# Suppress findings matching regex patterns
ignore_patterns:
  - ".*:quarantined$"  # Ignore all quarantine warnings
  # - "^persistence:user:.*"  # Ignore all user LaunchAgents

# Baseline file for diff mode (shows only new/changed findings)
baseline_file: ~/.macos-trust/baseline.json

# Trust settings for different sources
trust_homebrew_cask: true   # Trust Homebrew Cask installs (reduces quarantine warnings)
trust_app_store: true        # Trust Mac App Store apps
trust_old_apps: false        # Trust apps installed >30 days ago
old_app_days: 30             # Days to consider app "stable"
"""
    
    path = Path(output_path).expanduser()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(example)
