# macos-trust

[![macOS](https://img.shields.io/badge/macOS-10.15+-blue.svg)](https://www.apple.com/macos/)
[![Python](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-21%20passed-success.svg)](tests/)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](CONTRIBUTING.md)

**Security audit tool for macOS applications and persistence mechanisms**

Instantly identify unsigned apps, Gatekeeper violations, and suspicious launch agents on your Mac. Smart risk scoring distinguishes between genuine security threats and legitimate helper tools from trusted vendors.

### Key Features

- **Context-aware risk assessment** – Known vendors get appropriate risk levels, not blanket HIGH warnings
- **Comprehensive scanning** – Apps, LaunchAgents, LaunchDaemons, code signatures, Gatekeeper status
- **Flexible filtering** – Focus on what matters with `--min-risk`, `--exclude-vendor`, vendor grouping
- **Beautiful terminal output** – Clear, color-coded findings with detailed analysis
- **JSON export** – Machine-readable output for automation and CI/CD
- **Privacy-first** – No network calls, no telemetry, read-only operations

---

## Installation

```bash
# Using pipx (recommended)
pipx install git+https://github.com/texasbe2trill/macos-trust.git

# Or with pip for development
git clone https://github.com/texasbe2trill/macos-trust.git
cd macos-trust
pip install -e .
```

---

## Quick Start

```bash
# Scan your system (shows MED and HIGH findings by default)
macos-trust

# Focus on critical issues only
macos-trust --min-risk HIGH

# Hide findings from vendors you trust
macos-trust --exclude-vendor UBF8T346G9  # Microsoft
macos-trust --exclude-vendor 9BNSXJN65R  # Docker

# Organize findings by vendor
macos-trust --group-by-vendor

# Export to JSON for automation
macos-trust --json --out security-report.json

# Show all findings including informational
macos-trust --verbose
```

---

## Example Output

**Verbose mode with progress indicators:**

```
❯ macos-trust --verbose
⠋ Discovering applications...
✓ Found 56 applications
  Analyzing Sid Meier's Civilization VII... ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 100% 0:00:00
✓ Application analysis complete

⠋ Discovering launch agents/daemons...
✓ Found 23 launch items
  Analyzing com.microsoft.autoupdate.helper... ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 100% 0:00:00
✓ LaunchD analysis complete
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

## What Gets Checked

| Check | Description |
|-------|-------------|
| **Code Signatures** | Validates binary signatures using `codesign --verify` |
| **Gatekeeper Status** | Checks if apps pass macOS security requirements via `spctl` |
| **Quarantine Attributes** | Detects downloaded files that haven't been user-approved |
| **Launch Persistence** | Scans LaunchAgents and LaunchDaemons for auto-starting items |
| **Privilege Escalation** | Flags system daemons executing from user-writable locations |
| **Vendor Recognition** | Identifies helpers from trusted vendors (Docker, Microsoft, Zoom, etc.) |

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
  --min-risk LEVEL         Filter by minimum risk level (INFO, LOW, MED, HIGH)
  --exclude-vendor TEAM_ID Exclude findings from specific vendor (repeatable)
  --verbose, -v            Show all findings including INFO level
  --group-by-vendor        Organize findings by vendor/developer
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
```

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

The tool recognizes helpers and utilities from these vendors:

- Docker Inc
- Microsoft Corporation
- Apple Inc
- Zoom Video Communications
- Valve Corporation (Steam)
- Google LLC
- Mozilla Corporation
- JetBrains s.r.o.
- Slack Technologies
- Dropbox Inc
- Discord Inc
- GPGTools GmbH
- Oracle America Inc
- Homebrew

Findings from recognized vendors receive appropriate risk levels and context-specific recommendations.

---

## Roadmap

**Completed (v0.1):**
- ✅ Context-aware risk scoring with vendor reputation
- ✅ CLI filtering by risk level and vendor
- ✅ Vendor-specific recommendations
- ✅ Grouped output by vendor/developer
- ✅ Progress indicators and verbose output mode
- ✅ JSON export for automation and CI/CD
- ✅ Comprehensive test suite (21 tests, 100% passing)
- ✅ Security audit and automated vulnerability scanning
- ✅ GitHub Actions workflows for testing and security
- ✅ Full contribution guidelines and issue templates
- ✅ Security policy and vulnerability reporting

**Planned (Future releases):**
- Baseline & diff mode to track changes over time
- Configuration file support (`~/.macos-trust.yaml`)
- Performance improvements with parallel scanning
- SARIF output format for enhanced CI/CD integration
- Entitlements analysis for permission auditing
- Browser extension scanning
- Kernel extension detection
- Custom vendor whitelist management
- HTML report generation with charts
- Integration with macOS security frameworks

---

## Requirements

- **macOS 10.15 or later** (tested on macOS 15+)
- **Python 3.10 or later**
- Dependencies: `pydantic`, `typer`, `rich` (auto-installed)

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
