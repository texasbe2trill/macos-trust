# Security Policy

## Supported Versions

We take security seriously. This project helps users identify security issues on their Macs, so it's important that the tool itself is secure.

| Version | Supported          |
| ------- | ------------------ |
| main    | :white_check_mark: |
| < 1.0   | :white_check_mark: |

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

If you discover a security vulnerability in macos-trust, please report it privately:

1. **Email:** Send details to the maintainer(s) listed in the repository
2. **Subject Line:** Include `[SECURITY]` in the subject
3. **Include:**
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

### What to Expect

- **Acknowledgment:** Within 48 hours
- **Assessment:** Within 7 days we'll provide an initial assessment
- **Updates:** Regular updates on progress
- **Credit:** If you'd like, we'll credit you in the security advisory

## Security Considerations

### What This Tool Does

- **Read-only operations:** macos-trust only reads system information, it never modifies files or system settings
- **Local execution:** No network calls, no telemetry, all analysis happens locally
- **Privilege level:** Runs with user privileges, does not require root/admin

### What Could Go Wrong

- **Information disclosure:** The tool outputs system information that could be sensitive (app names, paths, etc.)
- **Parsing vulnerabilities:** Improper handling of system command output could be exploited
- **Dependency vulnerabilities:** Third-party dependencies could have security issues

### Best Practices for Users

1. **Review output:** Don't blindly share `macos-trust` output publicly (may contain sensitive paths)
2. **Keep updated:** Update to the latest version regularly
3. **Verify source:** Only install from official sources (PyPI, GitHub releases)
4. **JSON output:** Use `--json` flag when automating to avoid parsing issues

### For Contributors

When contributing:

1. **Never execute untrusted code:** Be careful with subprocess calls
2. **Validate input:** Always validate and sanitize inputs
3. **Error handling:** Handle errors gracefully without exposing sensitive info
4. **Dependencies:** Keep dependencies minimal and up to date
5. **Code review:** Security-sensitive changes require thorough review

## Known Limitations

- This tool identifies potential security issues but doesn't prevent them
- False positives are possible (especially with legitimate helper tools)
- The tool requires user interpretation of findings
- Risk ratings are heuristic-based and may not reflect actual threat level

## Security Updates

Security updates will be released as soon as possible after a vulnerability is confirmed. Check:

- GitHub Security Advisories
- Release notes
- Commit messages tagged with `[SECURITY]`

## Questions?

For general security questions about using the tool (not vulnerabilities), please:
- Open a GitHub issue with the `security` label
- Check existing documentation
- Review the README for security considerations
