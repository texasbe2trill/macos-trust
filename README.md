# macos-trust

[![macOS](https://img.shields.io/badge/macOS-10.15+-blue.svg)](https://www.apple.com/macos/)
[![Python](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-59%20passed-success.svg)](tests/)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](CONTRIBUTING.md)

**Security audit tool for macOS applications and persistence mechanisms**

Instantly identify unsigned apps, Gatekeeper violations, and suspicious launch agents on your Mac. Smart risk scoring distinguishes between genuine security threats and legitimate helper tools from trusted vendors.

### 📊 See the Difference

**Before: Default scan showing all findings**  
Every issue flagged, including legitimate apps from trusted vendors.

![Raw Scan](docs/demo.gif)

**After: Same system with custom config — 1 potential threat identified**  
Filtered out 30 false positives using vendor trust lists and smart patterns.

![Filtered Scan](docs/demo2.gif)

**Track changes over time with baseline mode**  
Save your current state, then see only new or changed findings in future scans.

![Baseline Demo](docs/demo3.gif)

> **The power of configuration:** Transform noisy scans into actionable intelligence. See [Reducing False Positives](#reducing-false-positives) to learn how.

---

### Key Features

- **Context-aware risk assessment** – Known vendors get appropriate risk levels, not blanket HIGH warnings
- **Comprehensive scanning** – Apps, LaunchAgents, LaunchDaemons, kernel extensions (KEXTs), browser extensions (Chrome/Firefox/Safari), code signatures, Gatekeeper status, entitlements
- **Permission auditing** – Reveals sensitive entitlements (camera, microphone, full disk access) and high-risk permissions (code injection, sandbox escapes)
- **Browser extension analysis** – Identifies dangerous extension permissions across Chrome, Firefox, and Safari
- **Flexible filtering** – Focus on what matters with `--min-risk`, `--exclude-vendor`, vendor grouping
- **Beautiful terminal output** – Clear, color-coded findings with detailed analysis
- **JSON export** – Machine-readable output for automation and CI/CD
- **Privacy-first** – No network calls, no telemetry, read-only operations

### Why macos-trust?

Unlike generic security scanners, **macos-trust understands macOS**:

- **Context-aware** – Recognizes 15+ major vendors (Microsoft, Docker, Zoom) with vendor-specific risk assessment
- **Eliminate noise** – Baseline mode shows only changes, not 50 repeated findings every scan
- **Fast** – Parallel processing delivers results 2-3x faster than sequential scanning
- **Deep analysis** – Entitlements auditing reveals 24+ sensitive permissions and 7 high-risk capabilities per app
- **Browser security** – Audit browser extensions across Chrome, Firefox, and Safari (including modern Web Extensions and legacy App Extensions)
- **Zero false positives** – Proper config + baseline = only real threats surface
- **Privacy-first** – 100% local analysis, no network calls, no telemetry, read-only operations
- **Battle-tested** – 59 passing tests, can be used in production environments

---

## Installation

### Homebrew (Recommended)

```bash
# Add the tap and install
brew tap texasbe2trill/tap
brew install macos-trust

# Verify installation
macos-trust --version
```

### Using pipx

```bash
# Using pipx (isolated environment)
pipx install git+https://github.com/texasbe2trill/macos-trust.git
```

### From Source (Development)

```bash
# Clone and install for development
git clone https://github.com/texasbe2trill/macos-trust.git
cd macos-trust
pip install -e .

# Optional: Install with config file support
pip install -e ".[config]"  # Adds PyYAML for YAML configuration files
```

---

## Quick Start

```bash
# Basic scan (shows MED and HIGH findings by default)
macos-trust

# Critical issues only
macos-trust --min-risk HIGH

# Faster scans with parallel processing (2-3x speedup)
macos-trust --fast

# Save baseline, then future scans show only NEW findings
macos-trust --save-baseline
macos-trust  # Automatically shows only changes

# Generate and use a config file for persistent settings
macos-trust --generate-config ~/.macos-trust.yaml
macos-trust --config ~/.macos-trust.yaml
```

**Common workflows:**

```bash
# Hide findings from trusted vendors
macos-trust --exclude-vendor UBF8T346G9  # Microsoft
macos-trust --exclude-vendor 9BNSXJN65R  # Docker

# Organize by vendor for easier review
macos-trust --group-by-vendor

# Export to JSON for automation/CI/CD
macos-trust --json --out security-report.json

# Export to SARIF for GitHub Advanced Security
macos-trust --sarif findings.sarif

# See everything including INFO-level findings
macos-trust --verbose
```

![Example Output](docs/screenshot.png)

See [Command-Line Options](#command-line-options) for the complete reference.

---

## Security Analysis Features

### Entitlements Auditing

Reveals what apps are **allowed** to do by analyzing code signing entitlements:

**Sensitive Permissions Detected:**
- Camera & Microphone Access
- Full Disk Access
- Location, Contacts, Calendar, Photos
- Network Client/Server
- Bluetooth & USB Devices
- Apple Events Automation
- Downloads & User Files Access

**High-Risk Capabilities Flagged:**
- JIT Code Execution
- Unsigned Executable Memory (code injection vector)
- Disabled Library Validation (malware can load unsigned libraries)
- DYLD Environment Variables (library injection)
- Task Inspection/Debug (should not be in production apps)
- Sandbox Escapes & SIP Bypasses
- TCC (Privacy) Bypasses

Example findings:
```
🔴 HIGH | High-risk entitlements: Firefox
Evidence: Disabled Library Validation, Unsigned Executable Memory

🟡 MED | High-risk entitlements: Safari
Evidence: JIT Code Execution

ℹ️  INFO | Sensitive permissions: Microsoft Excel
Evidence: Camera Access, Microphone Access, Contacts Access, USB Device Access
```

### Browser Extension Analysis

Scans **Chrome, Firefox, and Safari** extensions for dangerous permissions:

**Safari Extension Detection:**
- ✅ **Modern Safari Web Extensions** - WebExtensions API format (Chrome/Firefox compatible)
- ✅ **Legacy Safari App Extensions** - Native Safari extension format
- ✅ **Automatic discovery** - Scans `/Applications/*/Contents/PlugIns/*.appex` bundles
- ✅ **Permission parsing** - Extracts permissions from both `manifest.json` (Web Extensions) and `Info.plist` (App Extensions)

**High-Risk Permissions:**
- `webRequestBlocking` - Can intercept and modify all web traffic
- `proxy` - Can route traffic through attacker-controlled server
- `debugger` - Can inject malicious code into pages
- `nativeMessaging` - Can execute native code on your system (bypass browser sandbox)
- `management` - Can disable security extensions
- `privacy` - Can weaken browser security settings
- `<all_urls>` - Access to all websites (combine with other permissions for tracking)

**Suspicious Patterns:**
- Broad host access patterns (`<all_urls>`, `*://*/*`)
- Combinations of tracking-capable permissions (tabs, history, cookies)
- Multiple data access permissions together

Example findings:
```
🔴 HIGH | High-risk Safari extension: Extension
Evidence: nativeMessaging, <all_urls>, scripting
Details: Can communicate with native apps and access all websites

🔴 HIGH | High-risk Chrome extension: Ad Blocker Pro
Evidence: webRequestBlocking, proxy
Details: Can intercept and modify all web traffic, route through proxy

🟡 MED | Broad access Firefox extension: AutoFill Plus
Evidence: <all_urls>, cookies, tabs
Details: Can read passwords and credit card info from any website

ℹ️  INFO | Safari extension: Bear's Safari Extension
Evidence: storage, activeTab, scripting
Details: Standard extension with 5 permissions
```

---

## Example Output

**Verbose mode with progress indicators:**

```
❯ macos-trust --verbose --fast
⠋ Discovering applications...
✓ Found 56 applications
  Analyzed Microsoft PowerPoint (56/56)... ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 100% 0:00:00
✓ Application analysis complete

⠋ Discovering launch agents/daemons...
✓ Found 23 launch items
  Analyzed com.microsoft.update.agent (23/23)... ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 100% 0:00:00
✓ LaunchD analysis complete

⠋ Discovering kernel extensions...
✓ Found 676 kernel/system extensions
  Analyzed AppleD1755PMU.kext (676/676)... ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 100% 0:00:00
✓ Kernel extension analysis complete

⠋ Discovering browser extensions...
✓ Found 4 browser extensions
  Analyzing Extension... ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 100% 0:00:00
✓ Browser extension analysis complete
```

**Standard scan output:**

```
🔍 macOS Trust Scanner
================================================================================

Host:         Mac-Studio
OS Version:   26.2 (Build 25C56)
Architecture: arm64
Scan Time:    2026-02-05T17:30:46Z

SUMMARY
--------------------------------------------------------------------------------
  🔴 7 HIGH    🟡 6 MED    🟢 0 LOW    ℹ️  0 INFO

FINDINGS (13 total)
--------------------------------------------------------------------------------
Risk      Category      Title                              Path
--------------------------------------------------------------------------------
🟡 MED    persistence   Gatekeeper blocked:                /Library/LaunchDaemons/
                        com.docker.vmnetd                  com.docker.vmnetd.plist

🟡 MED    persistence   Gatekeeper blocked:                /Library/LaunchDaemons/
                        com.microsoft.autoupdate.helper    com.microsoft...plist

🔴 HIGH   persistence   Invalid code signature:            ~/Library/LaunchAgents/
                        homebrew.mxcl.jupyterlab           homebrew...plist

DETAILED ANALYSIS
================================================================================

🟡 MED | Gatekeeper blocked: com.docker.vmnetd
--------------------------------------------------------------------------------
ID: persistence:daemon:com.docker.vmnetd:spctl_rejected

macOS Gatekeeper has rejected com.docker.vmnetd. This item does not meet
Apple's security requirements.

Path: /Library/LaunchDaemons/com.docker.vmnetd.plist

EVIDENCE
  • spctl_status: rejected
  • spctl_source: Developer ID: Docker Inc (9BNSXJN65R)
  • spctl_team_id: 9BNSXJN65R

RECOMMENDATION
  This is a Docker Inc system helper (Team ID: 9BNSXJN65R). Helper utilities
  commonly fail Gatekeeper checks but may be safe if part of a verified Docker
  Desktop installation. Verify your Docker Desktop installation is up to date.
```

**Grouped by vendor (`--group-by-vendor`):**

```
Findings by Vendor (13 total)
================================================================================

📦 Docker Inc (9BNSXJN65R) — 1 finding
--------------------------------------------------------------------------------
  🟡 MED  | Gatekeeper blocked: com.docker.vmnetd

📦 Microsoft Corporation (UBF8T346G9) — 2 findings
--------------------------------------------------------------------------------
  🟡 MED  | Gatekeeper blocked: com.microsoft.autoupdate.helper
  🟡 MED  | Gatekeeper blocked: com.microsoft.office.licensingV2.helper

📦 Zoom Video Communications (BJ4HAAB9B3) — 1 finding
--------------------------------------------------------------------------------
  🟡 MED  | Gatekeeper blocked: us.zoom.ZoomDaemon

📦 Unknown / Other — 9 findings
--------------------------------------------------------------------------------
  🔴 HIGH | Invalid code signature: homebrew.mxcl.jupyterlab
  🔴 HIGH | Gatekeeper blocked: org.gpgtools.macgpg2.fix
  🔴 HIGH | Invalid code signature: org.gpgtools.macgpg2.shutdown-gpg-agent
  ... 6 more findings
```

> **Smart recommendations:** Vendor-aware advice helps you quickly assess whether findings are genuine threats or expected behavior from legitimate software.

---

## Reducing False Positives

Version 0.3 introduces powerful features to minimize false positive fatigue:

### 1. **Baseline & Diff Mode** (Track Changes Over Time)
Stop seeing the same findings repeatedly. Save your current state as a baseline, then future scans only show **new or changed** findings.

```bash
# First scan: save as baseline
macos-trust --save-baseline

# Future scans automatically show only NEW findings
macos-trust

# To see everything again
macos-trust --show-all
```

**How it helps:** After initial review and acceptance of existing findings, you only see what's actually changed. Perfect for regular monitoring.

### 2. **Configuration File** (Set It and Forget It)
Stop passing the same CLI flags every time. Create `~/.macos-trust.yaml`:

```yaml
min_risk: HIGH                    # Only show critical issues
exclude_vendors:
  - UBF8T346G9                    # Microsoft
  - 9BNSXJN65R                    # Docker
trusted_vendors:
  - H7H8Q7M5CK                    # Postman (downgrades their findings)
trust_homebrew_cask: true         # Trust Homebrew Cask installs
ignore_patterns:
  - ".*:quarantined$"             # Suppress all quarantine warnings
```

**How it helps:** Persistent configuration means your preferences apply to every scan without repetition.

### 3. **Quarantine Source Intelligence** (Context Matters)
Not all quarantine warnings are equal. The tool now detects where files came from:

- **Homebrew Cask**: `trust_homebrew_cask: true` suppresses quarantine warnings for package manager installs
- **Mac App Store**: Automatically detected and trusted (Apple-vetted apps)
- **Safari/Chrome/etc**: Identified in evidence for informed decisions

**How it helps:** Apps from trusted sources like Homebrew or the App Store get appropriate risk levels.

### 4. **Age-Based Trust** (Stability Matters)
Apps installed 30+ days ago with no issues are likely safe:

```yaml
trust_old_apps: true
old_app_days: 30
```

**How it helps:** Long-running stable apps get reduced risk scores, focusing attention on recent changes.

### 5. **Custom Vendor Trust** (Your Environment, Your Rules)
Add vendors you trust beyond the default list:

```yaml
trusted_vendors:
  - H7H8Q7M5CK  # Postman
  - LH6JV2ZBQ7  # Kobo
```

Or use CLI for one-time trust:
```bash
macos-trust --trust-vendor H7H8Q7M5CK
```

**How it helps:** Downgrades findings from vendors you know and trust from HIGH → MED or suppresses them entirely.

### 6. **Pattern-Based Suppression** (Bulk Filtering)
Suppress entire categories of findings with regex:

```yaml
ignore_patterns:
  - ".*:quarantined$"              # All quarantine warnings
  - "^persistence:user:.*"         # All user LaunchAgents
  - "app:org\\.gimp\\..*"          # All GIMP-related findings
```

**How it helps:** One pattern can suppress dozens of similar low-priority findings.

### Real-World Example

**Before (v0.1):**
```bash
$ macos-trust
🔍 33 findings (7 HIGH, 6 MED, 5 LOW, 15 INFO)
# Same findings every scan, including legitimate apps
```

**After (v0.2 with config):**
```bash
$ macos-trust
🔍 2 findings (1 HIGH, 1 MED)
# Only new/changed findings from unknown sources
```

**Configuration used:**
```yaml
min_risk: MED
trust_homebrew_cask: true
trusted_vendors: [H7H8Q7M5CK, LH6JV2ZBQ7, QED4VVPZWA]
exclude_vendors: [UBF8T346G9, 9BNSXJN65R]
ignore_patterns: [".*:quarantined$"]
```

Plus baseline mode automatically filters out the 28 previously-reviewed findings.

---

## What Gets Checked

| Check | Description |
|-------|-------------|
| **Code Signatures** | Validates binary signatures using `codesign --verify` |
| **Gatekeeper Status** | Checks if apps pass macOS security requirements via `spctl` |
| **Quarantine Attributes** | Detects downloaded files that haven't been user-approved |
| **Launch Persistence** | Scans LaunchAgents and LaunchDaemons for auto-starting items |
| **Privilege Escalation** | Flags system daemons executing from user-writable locations |
| **Vendor Recognition** | Identifies helpers from trusted vendors (Docker, Microsoft, Zoom, etc.) |
| **Kernel Extensions** | Detects legacy KEXTs and modern System Extensions with kernel-level access |
| **Entitlements** | Audits 24+ sensitive permissions: camera, microphone, Full Disk Access, JIT execution, code injection vectors |
| **Browser Extensions** | Scans Chrome, Firefox, and Safari (modern .appex + legacy .safariextension) for dangerous permissions |

---

## Risk Scoring Logic

**Context-aware assessment** means the tool considers multiple factors:

- **HIGH Risk** – Unsigned binaries, unknown vendors, privilege escalation vectors
- **MED Risk** – Signed by known vendors but rejected by Gatekeeper (common for helper tools)
- **LOW Risk** – Minor issues with low security impact
- **INFO** – Informational findings for awareness

Helper utilities from Docker, Microsoft, Zoom, and other major vendors are automatically downgraded from HIGH to MED when they fail Gatekeeper checks, as this is expected behavior for many legitimate system helpers.

---

## Command-Line Options

```
Usage: macos-trust [OPTIONS]

Options:
  --json                    Output results in JSON format
  --out PATH               Write output to file instead of stdout
  --html PATH              Generate interactive HTML report with charts
  --sarif PATH             Write SARIF 2.1.0 format to file (for CI/CD)
  --min-risk LEVEL         Filter by minimum risk level (INFO, LOW, MED, HIGH)
  --exclude-vendor TEAM_ID Exclude findings from specific vendor (repeatable)
  --trust-vendor TEAM_ID   Trust additional vendor for this scan (repeatable)
  --verbose, -v            Show all findings including INFO level
  --group-by-vendor        Organize findings by vendor/developer
  --config PATH            Path to config file (default: ~/.macos-trust.yaml)
  --save-baseline          Save current scan as baseline
  --baseline-file PATH     Path to baseline file (default: ~/.macos-trust/baseline.json)
  --diff                   Show only new/changed findings since baseline
  --show-all               Show all findings (ignore baseline)
  --generate-config PATH   Generate example config file and exit
  --fast                   Enable parallel processing for faster scans (2-3x faster)
```
  --help                   Show this message and exit
```

**Examples:**

```bash
# Only show critical findings
macos-trust --min-risk HIGH

# Hide Microsoft and Docker findings
macos-trust --exclude-vendor UBF8T346G9 --exclude-vendor 9BNSXJN65R

# See everything organized by vendor
macos-trust --group-by-vendor --verbose

# Generate JSON report for CI/CD
macos-trust --json --min-risk HIGH --out report.json

# Generate SARIF output for GitHub Advanced Security / security tools
macos-trust --sarif findings.sarif

# Generate interactive HTML report with charts
macos-trust --html security-report.html

# HTML report with filtering
macos-trust --html report.html --min-risk HIGH --config ~/.macos-trust.yaml

# SARIF with filtered results and human output to stdout
macos-trust --min-risk MED --sarif security-report.sarif

# Baseline workflow
macos-trust --save-baseline              # First time: save baseline
macos-trust                              # Later: shows only new findings
macos-trust --show-all                   # Show everything regardless of baseline

# Use configuration file
macos-trust --config ~/.macos-trust.yaml

# Trust Postman temporarily (just for this scan)
macos-trust --trust-vendor H7H8Q7M5CK
```

### HTML Reports

Generate beautiful, interactive HTML reports with charts and visualizations. Perfect for sharing with stakeholders or embedding in documentation.

**[View Live Example Report →](https://texasbe2trill.github.io/macos-trust/example-report.html)**

Features:
- 📊 **Interactive charts** - Risk distribution, category breakdown, top vendors
- 🎨 **Color-coded findings** - Visual risk levels (HIGH = red, MED = yellow, etc.)
- 🔍 **Detailed analysis** - Full evidence and recommendations for each finding
- 📱 **Responsive design** - Works on desktop and mobile
- 🚀 **Self-contained** - Single HTML file with embedded CSS and Chart.js

```bash
# Generate HTML report
macos-trust --html security-report.html

# With custom filtering
macos-trust --html report.html --min-risk HIGH --config ~/.macos-trust.yaml

# Combined outputs (HTML for humans, JSON for automation)
macos-trust --html visual-report.html --json data.json
```

**Example output:**
- Summary cards showing 1 HIGH, 0 MED, 0 LOW, 0 INFO findings
- Doughnut chart for risk distribution
- Bar chart for category breakdown  
- Horizontal bar chart for top vendors
- Color-coded detailed findings with full evidence

---

### JSON Output

The `--json` flag produces machine-readable output for automation and CI/CD integration:

```json
{
  "scan_metadata": {
    "host": "Mac-Studio",
    "os_version": "26.2 (Build 25C56)",
    "architecture": "arm64",
    "scan_time": "2026-02-05T17:30:46Z"
  },
  "summary": {
    "total": 13,
    "by_risk": {
      "HIGH": 7,
      "MED": 6,
      "LOW": 0,
      "INFO": 0
    }
  },
  "findings": [
    {
      "id": "persistence:daemon:com.docker.vmnetd:spctl_rejected",
      "risk": "MED",
      "category": "persistence",
      "title": "Gatekeeper blocked: com.docker.vmnetd",
      "description": "macOS Gatekeeper has rejected com.docker.vmnetd. This item does not meet Apple's security requirements.",
      "path": "/Library/LaunchDaemons/com.docker.vmnetd.plist",
      "evidence": {
        "spctl_status": "rejected",
        "spctl_source": "Developer ID: Docker Inc (9BNSXJN65R)",
        "team_id": "9BNSXJN65R"
      },
      "recommendation": "This is a Docker Inc system helper (Team ID: 9BNSXJN65R). Helper utilities commonly fail Gatekeeper checks but may be safe if part of a verified Docker Desktop installation."
    },
    {
      "id": "app:org.example.myapp:unsigned",
      "risk": "HIGH",
      "category": "application",
      "title": "Unsigned application: MyApp",
      "description": "Application is not signed with a valid code signature.",
      "path": "/Applications/MyApp.app",
      "evidence": {
        "codesign_status": "unsigned",
        "bundle_id": "org.example.myapp"
      },
      "recommendation": "Verify the source of this application. Unsigned apps pose a security risk as their origin and integrity cannot be verified."
    }
  ]
}
```

**Typical workflow:**

```bash
# Generate JSON report
macos-trust --json --min-risk HIGH --out security-report.json

# Parse with jq
cat security-report.json | jq '.summary.by_risk'

# Filter for specific categories
cat security-report.json | jq '.findings[] | select(.category == "persistence")'

# Count findings by vendor
cat security-report.json | jq '[.findings[].evidence.team_id] | group_by(.) | map({vendor: .[0], count: length})'
```

---

### Configuration File

Create a configuration file at `~/.macos-trust.yaml` (or use `--config` to specify a different location).

**Quick setup:**

```bash
# Option 1: Generate from template
macos-trust --generate-config ~/.macos-trust.yaml

# Option 2: Copy example from repo
cp config.example.yaml ~/.macos-trust.yaml

# Edit the file to customize for your needs
nano ~/.macos-trust.yaml
```

**Configuration options** (see [`config.example.yaml`](config.example.yaml) for full documentation):

```yaml
# Minimum risk level to report (INFO, LOW, MED, HIGH)
min_risk: MED

# Vendor filtering
exclude_vendors:
  - UBF8T346G9  # Microsoft Corporation
  - 9BNSXJN65R  # Docker Inc

# Additional trusted vendors (downgrades their findings from HIGH to MED)
trusted_vendors:
  - H7H8Q7M5CK  # Postman
  - VEKTX9H2N7  # GitHub

# Suppress specific findings by ID
ignore_findings:
  - app:org.gimp.gimp:quarantined

# Suppress findings matching regex patterns
ignore_patterns:
  - ".*:quarantined$"      # Ignore all quarantine warnings
  - ".*:spctl_rejected$"   # Ignore helper tool rejections

# Trust settings
trust_homebrew_cask: true   # Trust Homebrew Cask downloads
trust_app_store: true        # Trust Mac App Store apps
trust_old_apps: true         # Trust apps installed >30 days ago
old_app_days: 30

# Baseline for diff mode
baseline_file: ~/.macos-trust/baseline.json
```

See [`config.example.yaml`](config.example.yaml) for a comprehensive example with common vendor Team IDs and detailed explanations.

### SARIF Output

SARIF (Static Analysis Results Interchange Format) is a standard format for static analysis tools. The `--sarif` option writes findings in SARIF 2.1.0 format, which is compatible with:

- **GitHub Advanced Security** (Code Scanning)
- **Azure DevOps** security pipelines
- **GitLab** security dashboards
- **VS Code** and other IDEs with SARIF support
- CI/CD security scanning tools

SARIF output includes:
- Tool metadata with version information
- Deduplicated rules for each unique finding type
- Results with risk-based severity levels (HIGH → error, MED → warning, LOW/INFO → note)
- File locations for each finding
- Full evidence and recommendation details

```bash
# Generate SARIF and upload to GitHub Advanced Security
macos-trust --sarif results.sarif
gh api repos/$REPO/code-scanning/sarifs -F sarif=@results.sarif -F commit_sha=$SHA
```

#### GitHub Actions Workflow Example

Here's an example workflow for running macos-trust and uploading results to GitHub Code Scanning. Add this to `.github/workflows/macos-security.yml`:

```yaml
name: macOS Security Scan

on:
  push:
    branches: [ main ]
  pull_request:
    branches: [ main ]
  schedule:
    # Run weekly on Mondays at 9 AM UTC
    - cron: '0 9 * * 1'

jobs:
  security-scan:
    name: Scan macOS Security
    runs-on: macos-latest
    permissions:
      # Required for uploading SARIF results
      security-events: write
      # Required for private repos
      contents: read
    
    steps:
      - name: Checkout repository
        uses: actions/checkout@v4
      
      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.12'
      
      - name: Install macos-trust
        run: |
          pip install git+https://github.com/texasbe2trill/macos-trust.git
      
      - name: Run security scan
        run: |
          macos-trust --sarif macos-security.sarif --min-risk MED
        continue-on-error: true
      
      - name: Upload SARIF to GitHub Security
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: macos-security.sarif
          category: macos-trust
        # Only upload if SARIF file was created
        if: always() && hashFiles('macos-security.sarif') != ''
      
      - name: Upload SARIF as artifact
        uses: actions/upload-artifact@v4
        with:
          name: sarif-results
          path: macos-security.sarif
        if: always()
```

**Notes:**
- Requires GitHub Advanced Security for private repositories
- Works on public repositories without additional licensing
- Results appear in the **Security** → **Code scanning** tab
- The `continue-on-error: true` ensures workflow continues even if findings are detected
- Adjust `--min-risk` to control severity threshold

---
## Architecture

The tool is organized into focused modules:

```
macos_trust/
├── models.py          # Data models (Finding, Risk, ScanReport)
├── vendors.py         # Known vendor whitelist and helper detection
├── collectors/        # Code signature, Gatekeeper, quarantine checks
├── scanners/          # Application and persistence scanning
├── rules.py           # Risk assessment and finding generation
├── engine.py          # Scan orchestration
├── output/            # Human and JSON output rendering
└── cli.py             # Command-line interface
```

**Design principles:**
- No shell injection risks (no `shell=True`)
- Defensive error handling (per-item failures don't stop scans)
- Local-only operations (no network requests)
- Read-only analysis (never modifies system state)

---

## Known Vendors

**macos-trust recognizes 15+ trusted vendors** and their helper utilities, providing context-aware risk assessment:

**Major Software Companies:**
- Microsoft Corporation
- Google LLC
- Apple Inc
- Oracle America Inc

**Developer Tools:**
- JetBrains s.r.o.
- Homebrew
- Docker Inc
- GPGTools GmbH

**Communication & Productivity:**
- Zoom Video Communications
- Slack Technologies
- Discord Inc
- Dropbox Inc

**Entertainment:**
- Valve Corporation (Steam)
- Mozilla Corporation

Findings from recognized vendors receive appropriate risk levels and context-specific recommendations. For example, helper utilities commonly fail Gatekeeper checks but are downgraded from HIGH to MED when signed by known vendors.

Add your own trusted vendors via [configuration file](#configuration-file) or `--trust-vendor` flag.

---

## Roadmap

**Completed (v0.3.0):**
- ✅ Context-aware risk assessment with vendor reputation
- ✅ CLI filtering by risk level and vendor
- ✅ Vendor-specific recommendations
- ✅ Grouped output by vendor/developer
- ✅ Progress indicators and verbose output mode
- ✅ JSON export for automation and CI/CD
- ✅ SARIF 2.1.0 output format for CI/CD integration
- ✅ Comprehensive test suite (48 tests, 100% passing)
- ✅ Security audit and automated vulnerability scanning
- ✅ GitHub Actions workflows for testing and security
- ✅ Full contribution guidelines and issue templates
- ✅ Security policy and vulnerability reporting
- ✅ **Baseline & diff mode** – Track changes over time, show only new findings
- ✅ **Configuration file support** – Persistent settings via YAML config
- ✅ **Custom vendor whitelist** – Add trusted vendors via config or CLI
- ✅ **Quarantine source intelligence** – Detect Homebrew Cask, App Store, Safari downloads
- ✅ **App Store detection** – Auto-trust Mac App Store apps
- ✅ **Age-based trust** – Reduce risk for apps stable >30 days
- ✅ **Homebrew integration** – Detect and optionally trust Homebrew Cask installs
- ✅ **Finding suppression** – Ignore specific findings or patterns via config
- ✅ **Parallel processing** – 2-3x faster scans with `--fast` flag
- ✅ **HTML report generation** – Interactive reports with charts and visualizations ([see example](https://texasbe2trill.github.io/macos-trust/example-report.html))
- ✅ **Kernel extension detection** – Scan for legacy KEXTs and modern System Extensions with kernel-level access
- ✅ **Entitlements analysis** – Deep permission auditing revealing what apps *can* do: camera, microphone, full disk access, code injection, sandbox escapes
- ✅ **Browser extension scanning** – Audit Chrome/Firefox/Safari extensions for dangerous permissions like webRequestBlocking, proxy control, and broad host access

**Planned (Next Features):**

🎯 **Medium Priority:**
- **Network endpoint detection in launch items** – Identify apps that phone home on startup. Privacy-focused analysis.
- **Signature timestamp validation** – Detect expired certificates still in use.

🔧 **Future Enhancements:**
- **Integration with macOS security frameworks** – Query Endpoint Security Framework, System Extensions.
- **Launch item scheduling analysis** – Detect persistence timing patterns (boot vs login vs interval).

---

## Troubleshooting

**Config file not loading / "No such file or directory"**
- Check file path: `ls -la ~/.macos-trust.yaml`
- Generate fresh config: `macos-trust --generate-config ~/.macos-trust.yaml`
- Verify YAML syntax: `python -c "import yaml; yaml.safe_load(open('~/.macos-trust.yaml'))"`

**"ModuleNotFoundError: No module named 'yaml'"**
- Cause: PyYAML not installed (optional dependency)
- Solution: `pip install PyYAML` or `pip install -e ".[config]"`

**Scans are slow / taking minutes**
- Enable parallel processing: `macos-trust --fast` (2-3x speedup)
- Reduce scope: `macos-trust --min-risk HIGH` (skip low-priority checks)

**Too many findings / overwhelming output**
- Save baseline: `macos-trust --save-baseline`
- Future scans show only changes: `macos-trust`
- Use config file to suppress known-good findings: See [Reducing False Positives](#reducing-false-positives)

**Need help?**
- Check [GitHub Issues](https://github.com/texasbe2trill/macos-trust/issues) for similar problems
- Open a [bug report](.github/ISSUE_TEMPLATE/bug_report.md) with scan output and environment details

---

## Requirements

- **macOS 10.15 or later** (tested on macOS 15+)
- **Python 3.11 or later**
- Dependencies: `typer`, `rich` (auto-installed)
- Optional: `PyYAML` for configuration file support

---

## Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for detailed guidelines.

### Ways to Contribute

- 🐛 **Report bugs** – Found an issue? [Open a bug report](.github/ISSUE_TEMPLATE/bug_report.md)
- ✨ **Request features** – Have an idea? [Submit a feature request](.github/ISSUE_TEMPLATE/feature_request.md)
- 📦 **Add vendors** – Know a vendor that should be recognized? [Request vendor addition](.github/ISSUE_TEMPLATE/vendor_addition.md)
- 💻 **Write code** – Submit a pull request with bug fixes or new features
- 📚 **Improve docs** – Help make documentation clearer and more comprehensive
- 🧪 **Write tests** – Expand test coverage for better reliability

### Quick Start for Contributors

```bash
# Fork and clone the repo
git clone https://github.com/YOUR_USERNAME/macos-trust.git
cd macos-trust

# Set up development environment
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
pip install pytest

# Run tests
python -m pytest tests/ -v

# Make your changes and submit a PR!
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for coding standards, commit message format, and PR process.

---

## Security Notice

This tool provides **security visibility**, not security decisions. Always review findings in the context of your threat model and environment. A finding doesn't automatically mean something is malicious—it means it warrants investigation.

---

## License

MIT License - see [LICENSE](LICENSE) file for details.

---

## Acknowledgments

Built for security practitioners who need fast, accurate macOS trust assessment without false positive fatigue.
