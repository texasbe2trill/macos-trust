---
name: Vendor addition
about: Request adding a known vendor to reduce false positives
title: '[VENDOR] Add support for [Vendor Name]'
labels: vendor, enhancement
assignees: ''
---

## Vendor Information

**Vendor Name:** (e.g., Adobe Inc., Atlassian, etc.)

**Team ID:** (e.g., JQ525L2MZD)

**How to find Team ID:**
```bash
# Run macos-trust on one of their apps and look for spctl_team_id
macos-trust --verbose

# Or use codesign directly
codesign -dv /path/to/vendor/app 2>&1 | grep TeamIdentifier
```

## Why Add This Vendor?

Explain why this vendor should be in the known vendors list:
- [ ] Large, established software company
- [ ] Commonly installed on many Macs
- [ ] Currently generates false positive warnings
- [ ] Other: _____________

## Example Applications
List some well-known applications from this vendor:
- App Name 1
- App Name 2
- App Name 3

## Verification
- [ ] I have verified the Team ID is correct
- [ ] I have verified this is a legitimate vendor
- [ ] I understand this will reduce warning severity for this vendor's software

## Additional Context
Any other information about this vendor or why they should be added.
