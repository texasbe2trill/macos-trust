# False Positive Reduction - Implementation Guide

This document explains all the features added in v0.2 to reduce false positives.

## Feature Overview

| Feature | Benefit | Configuration |
|---------|---------|---------------|
| Baseline & Diff Mode | Only see new findings | `--save-baseline`, `--diff` |
| Configuration File | Persistent settings | `~/.macos-trust.yaml` |
| Quarantine Intelligence | Context-aware quarantine | `trust_homebrew_cask: true` |
| App Store Detection | Auto-trust vetted apps | `trust_app_store: true` |
| Age-Based Trust | Trust stable apps | `trust_old_apps: true` |
| Homebrew Integration | Detect package manager | Automatic |
| Custom Vendor Trust | Trust your vendors | `trusted_vendors: [...]` |
| Finding Suppression | Bulk filtering | `ignore_patterns: [...]` |

## 1. Baseline & Diff Mode

### Problem
Running the same scan repeatedly shows the same 30+ findings you've already reviewed.

### Solution
Save current findings as a baseline. Future scans show only **new or changed** findings.

### Usage
```bash
# Initial scan - review everything
macos-trust --verbose --save-baseline

# Future scans automatically show only new findings
macos-trust

# Baseline is stored at ~/.macos-trust/baseline.json by default
# Customize location in config:
baseline_file: ~/Documents/security-baseline.json
```

### Advanced
```bash
# Force diff mode even without baseline
macos-trust --diff

# Override diff mode and show everything
macos-trust --show-all

# Use custom baseline file
macos-trust --baseline-file /path/to/baseline.json
```

## 2. Configuration File

### Problem
Passing `--exclude-vendor UBF8T346G9 --min-risk HIGH` on every scan is tedious.

### Solution
Create `~/.macos-trust.yaml` with persistent settings.

### Setup
```bash
# Generate example config
macos-trust --generate-config ~/.macos-trust.yaml

# Edit to your preferences
vim ~/.macos-trust.yaml
```

### Full Configuration Reference
```yaml
# ~/.macos-trust.yaml

# === Risk Filtering ===
min_risk: MED  # Options: INFO, LOW, MED, HIGH

# === Vendor Management ===
# Exclude findings from specific vendors
exclude_vendors:
  - UBF8T346G9  # Microsoft Corporation
  - 9BNSXJN65R  # Docker Inc
  - BJ4HAAB9B3  # Zoom Video Communications

# Trust additional vendors (downgrades HIGH → MED)
trusted_vendors:
  - H7H8Q7M5CK  # Postman
  - LH6JV2ZBQ7  # Rakuten Kobo
  - QED4VVPZWA  # Logitech

# === Finding Suppression ===
# Suppress specific findings by ID
ignore_findings:
  - app:org.gimp.gimp:quarantined
  - persistence:daemon:com.docker.vmnetd:spctl_rejected
  - app:com.kobo.desktop.Kobo:quarantined

# Suppress findings matching regex patterns
ignore_patterns:
  - ".*:quarantined$"           # All quarantine warnings
  - "^persistence:user:.*"      # All user LaunchAgents
  - "app:org\\.mozilla\\..*"   # All Mozilla apps

# === Baseline Settings ===
baseline_file: ~/.macos-trust/baseline.json

# === Trust Settings ===
trust_homebrew_cask: true   # Trust Homebrew Cask installs
trust_app_store: true        # Trust Mac App Store apps (default)
trust_old_apps: false        # Trust apps installed >30 days ago
old_app_days: 30             # Days threshold for "old" apps
```

### Configuration Locations
The tool checks these locations in order:
1. Path specified with `--config`
2. `~/.macos-trust.yaml`
3. `~/.macos-trust.yml`
4. `~/.config/macos-trust/config.yaml`
5. `~/.config/macos-trust/config.yml`

## 3. Quarantine Source Intelligence

### Problem
All quarantined files get LOW risk, even those from Homebrew (package manager) or App Store.

### Solution
Parse quarantine attributes to identify source and adjust risk accordingly.

### How It Works
macOS quarantine attributes include source information:
```
0181;697f95d3;Homebrew Cask;UUID
     ↑         ↑
     timestamp source app
```

### Configuration
```yaml
trust_homebrew_cask: true  # Suppress quarantine warnings for Homebrew installs
```

### Sources Detected
- **Homebrew Cask**: Package manager installs
- **Safari, Chrome, Firefox, etc**: Browser downloads
- **App Store**: Apple-vetted applications

## 4. App Store Detection

### Problem
Apps from Mac App Store get flagged despite being vetted by Apple.

### Solution
Detect `_MASReceipt/receipt` in app bundle to identify App Store apps.

### Configuration
```yaml
trust_app_store: true  # Default: true
```

### How It Works
- Checks for `/Applications/AppName.app/Contents/_MASReceipt/receipt`
- If present, downgrades risk levels for findings
- App Store apps are already notarized by Apple

## 5. Age-Based Trust

### Problem
Apps installed months ago with no issues still show HIGH risk warnings.

### Solution
Check file modification time - apps stable for 30+ days likely aren't malicious.

### Configuration
```yaml
trust_old_apps: true     # Enable age-based trust
old_app_days: 30         # Days to consider "stable"
```

### How It Works
- Checks `mtime` of application binary
- If age > threshold, reduces risk level
- Useful for legacy apps with expired certificates

## 6. Homebrew Integration

### Problem
Apps installed via `brew install --cask` get flagged as untrusted.

### Solution
Query `brew list --cask` to identify package-manager-installed apps.

### How It Works
- Automatically detects Homebrew installation
- Tries both `/usr/local/bin/brew` (Intel) and `/opt/homebrew/bin/brew` (Apple Silicon)
- Results are cached for performance

### Usage
Works automatically. Combined with `trust_homebrew_cask: true`:
- Suppresses quarantine warnings for Homebrew apps
- Provides context in recommendations

## 7. Custom Vendor Trust

### Problem
You trust vendors not in the default list (Postman, Kobo, etc).

### Solution
Add vendors to trusted list - downgrades their findings from HIGH to MED.

### Configuration
```yaml
trusted_vendors:
  - H7H8Q7M5CK  # Postman Team ID
  - LH6JV2ZBQ7  # Rakuten Kobo
  - QED4VVPZWA  # Logitech
```

### CLI Usage (temporary)
```bash
macos-trust --trust-vendor H7H8Q7M5CK --trust-vendor LH6JV2ZBQ7
```

### Finding Team IDs
Run scan with `--verbose` and check evidence:
```json
"evidence": {
  "codesign_team_id": "H7H8Q7M5CK",
  "vendor": "Postman"
}
```

## 8. Pattern-Based Suppression

### Problem
You have dozens of similar low-priority findings.

### Solution
Use regex patterns to suppress entire categories.

### Configuration
```yaml
ignore_patterns:
  - ".*:quarantined$"                 # All quarantine warnings
  - "^persistence:user:.*"            # All user LaunchAgents
  - "app:com\\.adobe\\..*"           # All Adobe apps
  - ".*:spctl_rejected$"              # All Gatekeeper rejections
```

### Finding ID Format
```
{category}:{identifier}:{issue}

Examples:
app:com.microsoft.VSCode:codesign_fail
persistence:daemon:com.docker.vmnetd:spctl_rejected
app:org.mozilla.firefox:quarantined
```

## Real-World Workflows

### Workflow 1: Initial Setup
```bash
# 1. Run verbose scan and save baseline
macos-trust --verbose --save-baseline --out initial-scan.json

# 2. Review findings in initial-scan.json

# 3. Create config based on your environment
macos-trust --generate-config ~/.macos-trust.yaml

# 4. Edit config to exclude trusted vendors, enable Homebrew trust, etc.
vim ~/.macos-trust.yaml

# 5. Future scans show only new findings with your filters applied
macos-trust
```

### Workflow 2: CI/CD Integration
```yaml
# .github/workflows/security-scan.yml
- name: Run security scan
  run: |
    macos-trust \
      --min-risk HIGH \
      --exclude-vendor UBF8T346G9 \
      --sarif security.sarif \
      --baseline-file baseline.json

- name: Upload to GitHub Security
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: security.sarif
```

### Workflow 3: Developer Workstation
```yaml
# ~/.macos-trust.yaml
min_risk: HIGH
exclude_vendors: [UBF8T346G9, 9BNSXJN65R]
trusted_vendors: [H7H8Q7M5CK, QED4VVPZWA]
trust_homebrew_cask: true
ignore_patterns: [".*:quarantined$"]
```

Then just run `macos-trust` periodically to check for new risks.

## Troubleshooting

### Baseline Not Working
```bash
# Check if baseline exists
ls -la ~/.macos-trust/baseline.json

# Verify baseline is loading
macos-trust --show-all  # Should show all findings
macos-trust             # Should show diff
```

### Config Not Loading
```bash
# Test config generation
macos-trust --generate-config /tmp/test.yaml

# Verify config loads
macos-trust --config /tmp/test.yaml --json | jq '.findings | length'
```

### Pattern Not Matching
Finding IDs are case-sensitive. Check exact ID:
```bash
macos-trust --json | jq '.findings[].id'
```

Then use exact match or proper regex:
```yaml
ignore_patterns:
  - "app:org\\.gimp\\.gimp:quarantined"  # Escape dots!
```

## Performance Considerations

- **Homebrew detection**: Cached after first call
- **App Store detection**: File check per app bundle
- **Age-based trust**: `stat()` call per executable
- **Baseline**: JSON parsing on startup

For large environments (100+ apps), expect ~2-3 seconds total scan time.

## Migration from v0.1

All v0.1 functionality remains unchanged. New features are opt-in:

1. **No config file?** Tool works exactly as before
2. **No baseline?** Tool shows all findings as before
3. **CLI flags?** Still work and override config settings

Your existing scripts and workflows continue working without changes.
