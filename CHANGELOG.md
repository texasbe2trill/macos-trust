# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.4.0] - 2026-02-07

### Added
- **Interactive HTML reports** - Beautiful, self-contained HTML reports with Chart.js visualizations
  - Risk distribution doughnut chart showing HIGH/MED/LOW/INFO breakdown
  - Category breakdown bar chart for finding types
  - Top vendors horizontal bar chart for developer/vendor analysis
  - Animated header with pulsing gradient effect
  - Gradient accent bars on summary cards
  - Responsive 3-column layout with tablet/mobile breakpoints
  - Color-coded findings with gradient risk badges
  - Export with `--html PATH` flag
- **Enhanced example report** - Comprehensive showcase with all risk levels on GitHub Pages
  - 15 sanitized demo findings across all severity levels
  - Demonstrates full tool capabilities for new users
  - Fixed chart rendering with proper height containers

### Fixed
- Vendor chart double-counting bug (was incrementing counters twice)
- Chart.js rendering stability issues (added `maintainAspectRatio: false`)
- Chart label truncation with fixed height containers

## [0.3.0] - 2026-02-06

### Added
- **Configuration file support** - Persistent settings via YAML config files
  - Load from `~/.macos-trust.yaml` or custom path with `--config`
  - Generate example config with `--generate-config`
  - Includes `config.example.yaml` with comprehensive documentation
- **Baseline & diff mode** - Track findings over time and show only changes
  - Save baseline with `--save-baseline`
  - Automatic diff mode with `--diff` flag
  - Override with `--show-all` to force full scan results
  - Baseline stored in `~/.macos-trust/baseline.json` (configurable)
- **Context enrichment** - Smart risk assessment based on app source
  - Quarantine source intelligence (Homebrew vs browser downloads)
  - App Store detection via receipt validation
  - Homebrew Cask integration (`brew list --cask`)
  - Age-based trust for stable applications (30+ days)
- **Advanced filtering** - Reduce false positives dramatically
  - Trust Homebrew Cask downloads (`trust_homebrew_cask`)
  - Trust App Store apps automatically (`trust_app_store`)
  - Trust old/stable apps (`trust_old_apps`)
  - Suppress findings by exact ID (`ignore_findings`)
  - Suppress findings by regex pattern (`ignore_patterns`)
  - Custom trusted vendor list (`trusted_vendors`)
  - Temporary vendor trust via `--trust-vendor` flag
- **Parallel processing** - 2-3x faster scans on multi-core systems
  - Enable with `--fast` flag
  - Thread pool execution with up to 8 concurrent workers
  - Shows real-time progress with app names
- **New modules**
  - `macos_trust/config.py` - Configuration management with PyYAML support
  - `macos_trust/baseline.py` - Baseline tracking and diff functionality
  - `macos_trust/context.py` - Context enrichment (App Store, Homebrew, age detection)
- **Comprehensive test suite** - 24 new tests (47 total)
  - Config validation and loading
  - Baseline save/load/filter operations
  - Context enrichment (quarantine parsing, Homebrew detection, App Store)
  - Engine filtering with patterns
  - Rules integration with config
  - End-to-end workflow testing
  - Test coverage: 49% overall, 95% on new baseline module

### Changed
- **Enhanced CLI** - 7 new command-line options
  - `--config PATH` - Specify config file location
  - `--save-baseline` - Save current scan as baseline
  - `--baseline-file PATH` - Override baseline location
  - `--diff` - Show only new/changed findings
  - `--show-all` - Force full results (ignore baseline)
  - `--trust-vendor TEAM_ID` - Temporarily trust vendor
  - `--generate-config PATH` - Generate example config
  - `--fast` - Enable parallel processing
- **Risk assessment** - Context-aware scoring
  - Trusted vendors downgrade findings from HIGH to MED
  - Homebrew Cask apps no longer flagged as suspicious
  - Helper tools properly categorized (not false alarms)
  - Old/stable apps treated as lower risk
- **Progress indicators** - Improved visibility
  - Parallel mode shows app names and counts
  - Real-time updates: "Analyzed ChatGPT (23/49)..."
  - Clearer status messages
- **Engine architecture** - Extensible filtering system
  - Config parameter passed through scan pipeline
  - `_apply_config_filters()` for centralized filtering
  - Separate sequential and parallel analysis paths
- **Documentation** - Significantly expanded
  - "Reducing False Positives" section in README
  - Configuration examples with common vendor Team IDs
  - Usage examples for all new features
  - `config.example.yaml` with inline documentation
  - Updated command-line options reference

### Fixed
- Pylance type checking warnings resolved
- Deprecation warning for `datetime.utcnow()` (now uses `datetime.now(UTC)`)
- Progress bar display in parallel mode shows meaningful app names
- Baseline diff mode correctly detects changed risk levels

### Performance
- Parallel scanning reduces total scan time by 50-70%
- Config and baseline loading adds <0.2s overhead
- Homebrew detection cached for entire scan session
- Minimal impact on sequential scan performance

## [0.2.0] - 2026-02-05

### Added
- SARIF 2.1.0 output format support (`--sarif` option)
- GitHub Actions workflow example for Code Scanning integration
- Comprehensive SARIF tests validating structure and level mapping
- SARIF documentation in README with usage examples

### Changed
- Test suite expanded from 21 to 23 tests
- README updated with SARIF integration examples
- CHANGELOG updated to reflect SARIF feature

## [0.1.0] - 2026-02-05

### Added
- Initial release of macos-trust security scanner
- Application scanning with code signature verification
- LaunchAgent/Daemon scanning and analysis
- Gatekeeper (spctl) status checking
- Quarantine attribute detection
- Context-aware risk assessment with vendor intelligence
- Beautiful terminal output with Rich library
- JSON export functionality
- Progress indicators for long-running scans
- Filtering by risk level (`--min-risk`)
- Vendor grouping (`--group-by-vendor`)
- Vendor exclusion (`--exclude-vendor`)
- Comprehensive test suite with 21 tests
- Type hints throughout codebase
- Full documentation (README, CONTRIBUTING)
- Core scanning engine
- Security rules engine
- CLI interface
- Vendor database with major software companies
- MIT License

### Security
- Read-only operations, no system modifications
- No network calls or telemetry
- Runs with user privileges only

---

## Release Guidelines

### Version Numbers
- **Major (1.0.0):** Breaking changes, major new features
- **Minor (0.1.0):** New features, non-breaking changes
- **Patch (0.0.1):** Bug fixes, documentation updates

### Categories
- **Added:** New features
- **Changed:** Changes in existing functionality
- **Deprecated:** Soon-to-be removed features
- **Removed:** Removed features
- **Fixed:** Bug fixes
- **Security:** Security-related changes
