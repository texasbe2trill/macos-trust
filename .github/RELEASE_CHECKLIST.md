# Release Checklist

Use this checklist when preparing a new release.

## Pre-Release

- [ ] All tests pass (`python -m pytest tests/ -v`)
- [ ] Code coverage is acceptable
- [ ] Documentation is up to date
  - [ ] README.md reflects new features
  - [ ] CHANGELOG.md is updated
  - [ ] CONTRIBUTING.md is current
- [ ] Version numbers updated
  - [ ] `pyproject.toml`
  - [ ] Any `__version__` constants
- [ ] All issues for this milestone are closed
- [ ] No known critical bugs
- [ ] Dependencies are up to date and secure

## Testing

- [ ] Test on multiple macOS versions (if possible)
  - [ ] macOS 13 (Ventura)
  - [ ] macOS 14 (Sonoma)
  - [ ] macOS 15 (Sequoia)
- [ ] Test on both architectures (if possible)
  - [ ] Intel (x86_64)
  - [ ] Apple Silicon (arm64)
- [ ] Test installation methods
  - [ ] `pip install` from source
  - [ ] `pipx install` from git
- [ ] Smoke test core functionality
  - [ ] `macos-trust`
  - [ ] `macos-trust --verbose`
  - [ ] `macos-trust --json --out test.json`
  - [ ] `macos-trust --min-risk HIGH`
  - [ ] `macos-trust --group-by-vendor`

## Release Process

- [ ] Create release branch (`release/vX.Y.Z`)
- [ ] Final version bump
- [ ] Update CHANGELOG.md with release date
- [ ] Commit: `chore: prepare vX.Y.Z release`
- [ ] Create and push tag (`git tag vX.Y.Z`)
- [ ] Create GitHub release
  - [ ] Use CHANGELOG content for release notes
  - [ ] Attach any relevant files
- [ ] Merge release branch to main
- [ ] Publish to PyPI (if ready)
  ```bash
  python -m build
  python -m twine upload dist/*
  ```

## Post-Release

- [ ] Verify release on GitHub
- [ ] Test installation from PyPI
  ```bash
  pipx install macos-trust
  macos-trust --version
  ```
- [ ] Announce release
  - [ ] GitHub Discussions
  - [ ] Social media (if applicable)
- [ ] Create milestone for next release
- [ ] Update documentation if needed
- [ ] Close milestone

## Rollback Plan

If critical issues are discovered:

1. Mark release as pre-release on GitHub
2. Create hotfix branch
3. Fix critical issues
4. Create patch release (vX.Y.Z+1)
5. Yank broken version from PyPI if published

---

**Template for Release Notes:**

```markdown
# macos-trust vX.Y.Z

[Brief description of this release]

## ✨ New Features
- Feature 1
- Feature 2

## 🐛 Bug Fixes
- Fix 1
- Fix 2

## 🔧 Improvements
- Improvement 1
- Improvement 2

## 📚 Documentation
- Doc update 1

## 🙏 Contributors
Thank you to everyone who contributed to this release!

- @contributor1
- @contributor2

## 📦 Installation
```bash
pipx install macos-trust
```

## 🔗 Full Changelog
[vX.Y.Z-1...vX.Y.Z](https://github.com/texasbe2trill/macos-trust/compare/vX.Y.Z-1...vX.Y.Z)
```
