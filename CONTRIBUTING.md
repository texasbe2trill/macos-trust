# Contributing to macos-trust

Thank you for your interest in contributing to macos-trust! This document provides guidelines and information for contributors.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [How to Contribute](#how-to-contribute)
- [Coding Standards](#coding-standards)
- [Testing](#testing)
- [Pull Request Process](#pull-request-process)
- [Project Structure](#project-structure)
- [Adding New Features](#adding-new-features)

## Code of Conduct

This project follows a simple code of conduct:

- Be respectful and inclusive
- Focus on constructive feedback
- Help create a welcoming environment for all contributors
- Respect differing viewpoints and experiences

## Getting Started

### Prerequisites

- macOS 10.15 or later
- Python 3.10 or later
- Git

### Development Setup

1. **Fork and clone the repository**
   ```bash
   git clone https://github.com/YOUR_USERNAME/macos-trust.git
   cd macos-trust
   ```

2. **Create a virtual environment**
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   ```

3. **Install in development mode**
   ```bash
   pip install -e .
   pip install pytest  # For running tests
   ```

4. **Verify installation**
   ```bash
   macos-trust --help
   python -m pytest tests/ -v
   ```

## How to Contribute

### Reporting Bugs

Before creating a bug report, please check existing issues to avoid duplicates.

When filing a bug report, include:
- macOS version and build number
- Python version
- Full command you ran
- Expected vs actual behavior
- Complete error output (use `--verbose` flag)
- Relevant security scan results (sanitize any sensitive paths)

**Bug Report Template:**
```markdown
**Environment:**
- macOS Version: 
- Python Version: 
- macos-trust Version: 

**Command:**
```
macos-trust [your command]
```

**Expected Behavior:**
[What you expected to happen]

**Actual Behavior:**
[What actually happened]

**Error Output:**
```
[Paste error output here]
```
```

### Suggesting Enhancements

Enhancement suggestions are welcome! Consider:
- New security checks to add
- Additional vendor Team IDs
- Output format improvements
- Performance optimizations
- Documentation improvements

Open an issue with:
- Clear description of the enhancement
- Use cases and benefits
- Example of how it would work
- Any implementation ideas

### Contributing Code

1. **Create a branch**
   ```bash
   git checkout -b feature/your-feature-name
   # or
   git checkout -b fix/issue-description
   ```

2. **Make your changes**
   - Write clear, documented code
   - Follow existing code style
   - Add tests for new functionality
   - Update documentation as needed

3. **Test your changes**
   ```bash
   # Run all tests
   python -m pytest tests/ -v
   
   # Run specific test
   python -m pytest tests/test_macos_trust.py::TestClass::test_method -v
   
   # Run the tool
   macos-trust --verbose
   ```

4. **Commit your changes**
   ```bash
   git add .
   git commit -m "feat: add support for new security check"
   ```

5. **Push and create a Pull Request**
   ```bash
   git push origin feature/your-feature-name
   ```

## Coding Standards

### Python Style

- Follow [PEP 8](https://pep8.org/) style guide
- Use type hints for function signatures
- Use descriptive variable names
- Keep functions focused and small
- Maximum line length: 100 characters

**Example:**
```python
def analyze_app(
    app: dict,
    codesign_result: dict | None = None,
    spctl_result: dict | None = None
) -> list[Finding]:
    """
    Analyze an application and generate security findings.
    
    Args:
        app: Application record from scanners
        codesign_result: Result from codesign verification
        spctl_result: Result from spctl assessment
    
    Returns:
        List of Finding objects for security issues detected
    """
    findings = []
    # Implementation...
    return findings
```

### Documentation

- Use docstrings for all public functions and classes
- Include type information in docstrings
- Provide examples for complex functionality
- Keep README.md up to date

### Commit Messages

Use conventional commit format:

- `feat:` New feature
- `fix:` Bug fix
- `docs:` Documentation changes
- `test:` Adding or updating tests
- `refactor:` Code refactoring
- `perf:` Performance improvements
- `chore:` Maintenance tasks

**Examples:**
```
feat: add support for system extension scanning
fix: handle missing bundle identifier gracefully
docs: update README with new CLI options
test: add tests for quarantine attribute parsing
```

## Testing

### Running Tests

```bash
# Run all tests
python -m pytest tests/ -v

# Run with coverage (if pytest-cov installed)
python -m pytest tests/ --cov=macos_trust --cov-report=html

# Run specific test file
python -m pytest tests/test_macos_trust.py -v
```

### Writing Tests

- Place tests in `tests/` directory
- Use descriptive test names
- Test both success and failure cases
- Mock external dependencies when appropriate
- Ensure tests are idempotent

**Test Template:**
```python
class TestNewFeature(unittest.TestCase):
    """Test new feature functionality."""
    
    def test_feature_success_case(self):
        """Test feature with valid input."""
        result = new_feature("valid_input")
        self.assertEqual(result, expected_value)
    
    def test_feature_edge_case(self):
        """Test feature with edge case input."""
        result = new_feature(None)
        self.assertIsNone(result)
```

## Pull Request Process

1. **Before submitting:**
   - All tests pass
   - Code follows style guidelines
   - Documentation is updated
   - Commit messages follow conventions

2. **PR Description should include:**
   - Summary of changes
   - Related issue numbers (if applicable)
   - Testing performed
   - Screenshots (if UI changes)

3. **Review process:**
   - Maintainers will review your PR
   - Address any feedback or requested changes
   - Once approved, maintainers will merge

4. **After merge:**
   - Delete your branch
   - Update your fork
   - Celebrate! 🎉

## Project Structure

```
macos-trust/
├── macos_trust/           # Main package
│   ├── __init__.py
│   ├── cli.py            # Command-line interface
│   ├── engine.py         # Scan orchestration
│   ├── models.py         # Data models (Finding, Risk, ScanReport)
│   ├── rules.py          # Security analysis rules
│   ├── vendors.py        # Known vendor information
│   ├── collectors/       # Data collection modules
│   │   ├── codesign.py   # Code signature verification
│   │   ├── spctl.py      # Gatekeeper checks
│   │   └── quarantine.py # Quarantine attribute checks
│   ├── scanners/         # System scanning modules
│   │   ├── apps.py       # Application scanning
│   │   └── launchd.py    # LaunchAgent/Daemon scanning
│   ├── output/           # Output formatting
│   │   ├── formatters.py # Legacy formatters
│   │   └── render.py     # Modern rendering
│   └── util/             # Utility modules
│       ├── host.py       # Host information
│       ├── process.py    # Process execution
│       └── shell.py      # Shell command utilities
├── tests/                # Test suite
├── README.md             # Project overview
├── CONTRIBUTING.md       # This file
├── LICENSE               # MIT License
├── pyproject.toml        # Package configuration
└── requirements.txt      # Dependencies
```

## Adding New Features

### Adding a New Security Check

1. **Identify the check** - What are you detecting?
2. **Choose the right module:**
   - Collector: Gathers raw data from system
   - Scanner: Finds items to analyze
   - Rule: Analyzes data and creates findings

3. **Implement the check:**

**Example - Adding a new collector:**
```python
# macos_trust/collectors/new_check.py
def check_new_security_feature(path: str) -> dict[str, str]:
    """
    Check a new security feature.
    
    Args:
        path: File system path to check
        
    Returns:
        Dictionary with check results
    """
    result = run(["/usr/bin/some_tool", path])
    return {
        "status": "ok" if result.success else "fail",
        "details": result.out
    }
```

**Add analysis rule:**
```python
# In macos_trust/rules.py
def analyze_new_feature(item: dict, check_result: dict) -> list[Finding]:
    """Analyze results from new security check."""
    findings = []
    
    if check_result.get("status") == "fail":
        finding = Finding(
            id=f"item:{item['name']}:new_check",
            risk=Risk.HIGH,
            category="security",
            title="New security check failed",
            details="Description of the issue",
            recommendation="How to fix it",
            evidence=check_result,
            path=item.get("path")
        )
        findings.append(finding)
    
    return findings
```

**Add tests:**
```python
# In tests/test_macos_trust.py
def test_new_feature_check(self):
    """Test new security feature check."""
    from macos_trust.collectors.new_check import check_new_security_feature
    
    result = check_new_security_feature("/test/path")
    self.assertIn("status", result)
```

### Adding Vendor Information

To add a new known vendor:

```python
# In macos_trust/vendors.py
KNOWN_VENDORS: Dict[str, str] = {
    # ... existing vendors ...
    "TEAM_ID_HERE": "Vendor Name Here",
}
```

Find Team IDs by:
1. Running `macos-trust --verbose` on a signed app
2. Checking the `spctl_team_id` in evidence
3. Or: `codesign -dv /path/to/app 2>&1 | grep TeamIdentifier`

## Questions?

- Open an issue for general questions
- Tag issues with `question` label
- Check existing issues and discussions first

## License

By contributing, you agree that your contributions will be licensed under the MIT License.

---

Thank you for contributing to macos-trust! Your efforts help make macOS more secure for everyone.
