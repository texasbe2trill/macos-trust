# macos-trust v0.2.0 - SARIF Integration Release

**Release Date:** February 5, 2026  
**Status:** Stable

## What's New in v0.2.0

### SARIF 2.1.0 Output Support

macos-trust now supports **SARIF (Static Analysis Results Interchange Format)** output, enabling seamless integration with enterprise security platforms and CI/CD pipelines.

**Key Features:**
- ✅ Full SARIF 2.1.0 specification compliance
- ✅ Compatible with GitHub Advanced Security Code Scanning
- ✅ Works with Azure DevOps, GitLab, VS Code, and other SARIF-aware tools
- ✅ Automatic risk-to-severity mapping (HIGH → error, MED → warning, LOW/INFO → note)
- ✅ Deduplicated rules with complete metadata
- ✅ Full evidence and recommendation data in properties

### New CLI Option

```bash
# Generate SARIF output for CI/CD integration
macos-trust --sarif findings.sarif

# Combine with filtering
macos-trust --min-risk MED --sarif security-report.sarif

# Multiple output formats
macos-trust --json --out report.json --sarif findings.sarif
```

### GitHub Actions Integration

New workflow example in README showing how to:
- Run macos-trust on macOS runners
- Generate SARIF reports
- Upload to GitHub Code Scanning
- Schedule automated security scans

```yaml
- name: Run security scan
  run: macos-trust --sarif macos-security.sarif --min-risk MED

- name: Upload to GitHub Security
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: macos-security.sarif
    category: macos-trust
```

### Enhanced Testing

- Added 2 comprehensive SARIF tests
- Total test count: **23 tests** (100% passing)
- Full validation of SARIF structure, schema, and level mapping

---

## Installation

### Upgrade from v0.1.0

```bash
pip install --upgrade git+https://github.com/texasbe2trill/macos-trust.git@v0.2.0
```

### Fresh Installation

```bash
# Using pipx (recommended)
pipx install git+https://github.com/texasbe2trill/macos-trust.git@v0.2.0

# Using pip
pip install git+https://github.com/texasbe2trill/macos-trust.git@v0.2.0
```

---

## Usage Examples

### Basic SARIF Generation

```bash
# Generate SARIF report
macos-trust --sarif findings.sarif
```

### CI/CD Integration

```bash
# Filter to critical findings only
macos-trust --min-risk HIGH --sarif critical.sarif

# Upload to GitHub (using gh CLI)
gh api repos/$OWNER/$REPO/code-scanning/sarifs \
  -F sarif=@findings.sarif \
  -F commit_sha=$GITHUB_SHA
```

### Multiple Formats

```bash
# Human output to stdout + SARIF to file
macos-trust --sarif findings.sarif

# JSON + SARIF
macos-trust --json --out report.json --sarif findings.sarif
```

---

## SARIF Structure

The generated SARIF includes:

**Tool Metadata:**
- Name: `macos-trust`
- Version: `0.2.0`
- Information URI: `https://github.com/texasbe2trill/macos-trust`

**Rules:**
- One rule per unique finding type
- Short and full descriptions
- Actionable help text (recommendations)

**Results:**
- Risk-based severity levels
- File locations when available
- Complete evidence as properties
- Category and risk metadata

**Example SARIF:**
```json
{
  "$schema": "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0-rtm.5.json",
  "version": "2.1.0",
  "runs": [{
    "tool": {
      "driver": {
        "name": "macos-trust",
        "version": "0.2.0",
        "informationUri": "https://github.com/texasbe2trill/macos-trust",
        "rules": [...]
      }
    },
    "results": [...]
  }]
}
```

---

## What's Included from v0.1.0

All features from the initial release remain available:

- Context-aware risk assessment with vendor intelligence
- Application and LaunchAgent/Daemon scanning
- Code signature and Gatekeeper verification
- Beautiful terminal output with Rich
- JSON export
- Risk-level filtering (`--min-risk`)
- Vendor exclusion (`--exclude-vendor`)
- Vendor grouping (`--group-by-vendor`)
- Progress indicators
- 21 core tests + 2 new SARIF tests

---

## Breaking Changes

**None** - This is a backwards-compatible release. All v0.1.0 functionality remains unchanged.

---

## Platform Compatibility

### SARIF Output Works With:

- **GitHub Advanced Security** - Code Scanning alerts in Security tab
- **Azure DevOps** - Security pipeline integration
- **GitLab** - Security dashboards
- **VS Code** - Native SARIF viewer
- **SARIF Viewer** - Microsoft's desktop viewer
- **Any SARIF 2.1.0-compliant tool**

### System Requirements:

- macOS 10.15 (Catalina) or later
- Python 3.10 or later
- Tested on macOS 15 (Sequoia) with Apple Silicon and Intel

---

## Documentation Updates

- Added SARIF section to README
- GitHub Actions workflow example
- SARIF usage examples
- Platform compatibility guide
- Updated roadmap (SARIF moved from planned to completed)

---

## Bug Fixes

None - This release adds new functionality without fixing bugs.

---

## Known Issues

None at release time.

---

## Migration Guide

### From v0.1.0 to v0.2.0

No migration needed - all existing commands work identically. Simply start using `--sarif` when SARIF output is desired:

```bash
# Before (v0.1.0)
macos-trust --json --out report.json

# After (v0.2.0) - both work
macos-trust --json --out report.json           # Still works
macos-trust --sarif findings.sarif              # New option
macos-trust --json --out report.json --sarif findings.sarif  # Both
```

---

## Development

### Running Tests

```bash
python -m pytest tests/ -v
# 23 tests, all passing
```

### New Test Coverage

- `TestSARIFOutput.test_render_sarif_structure` - Complete SARIF validation
- `TestSARIFOutput.test_sarif_level_mapping` - Risk-to-level conversion

---

## Security

No security changes in this release. All v0.1.0 security guarantees remain:
- Read-only operations
- No network calls
- No telemetry
- User privileges only
- No command injection risks

---

## Acknowledgments

Thanks to the community for requesting SARIF support for better CI/CD integration!

---

## Links

- **Release:** https://github.com/texasbe2trill/macos-trust/releases/tag/v0.2.0
- **Repository:** https://github.com/texasbe2trill/macos-trust
- **Issues:** https://github.com/texasbe2trill/macos-trust/issues
- **Changelog:** https://github.com/texasbe2trill/macos-trust/blob/main/CHANGELOG.md
- **SARIF Specification:** https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html

---

**⭐ If you find this useful, please star the repository!**

### Quick Release Command

```bash
# Tag and push
git tag -a v0.2.0 -m "SARIF 2.1.0 output support"
git push origin v0.2.0

# Create GitHub release
gh release create v0.2.0 \
  --title "v0.2.0 - SARIF Integration" \
  --notes-file RELEASE_NOTES_v0.2.0.md
```
