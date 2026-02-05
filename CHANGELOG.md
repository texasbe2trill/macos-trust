# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
