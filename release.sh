#!/bin/bash
# Release script for macos-trust v0.2.0

set -e

VERSION="v0.2.0"
RELEASE_TITLE="v0.2.0 - SARIF Integration"

echo "🚀 Preparing release: $VERSION"
echo

# Ensure we're on main branch
CURRENT_BRANCH=$(git branch --show-current)
if [ "$CURRENT_BRANCH" != "main" ]; then
    echo "❌ Error: Must be on main branch (currently on $CURRENT_BRANCH)"
    exit 1
fi

# Ensure working directory is clean
if ! git diff-index --quiet HEAD --; then
    echo "❌ Error: Working directory has uncommitted changes"
    echo "   Please commit or stash changes before releasing"
    exit 1
fi

echo "✅ On main branch with clean working directory"
echo

# Run tests
echo "🧪 Running test suite..."
python -m pytest tests/ -v
if [ $? -ne 0 ]; then
    echo "❌ Tests failed - aborting release"
    exit 1
fi
echo "✅ All 23 tests passed"
echo

# Verify version in files
echo "📝 Verifying version numbers..."
if ! grep -q 'version = "0.2.0"' pyproject.toml; then
    echo "❌ Version mismatch in pyproject.toml"
    exit 1
fi
if ! grep -q '\[0.2.0\]' CHANGELOG.md; then
    echo "❌ Version missing in CHANGELOG.md"
    exit 1
fi
echo "✅ Version numbers verified"
echo

# Show what will be released
echo "📦 Release contents:"
echo "   - SARIF 2.1.0 output support"
echo "   - GitHub Actions workflow example"
echo "   - 2 new SARIF tests (23 total)"
echo "   - Updated documentation"
echo

# Create git tag
echo "🏷️  Creating git tag: $VERSION"
git tag -a $VERSION -m "$RELEASE_TITLE

New Features:
- SARIF 2.1.0 output format support (--sarif option)
- GitHub Actions workflow example for Code Scanning integration
- Comprehensive SARIF tests validating structure and level mapping

Changes:
- Test suite expanded from 21 to 23 tests
- README updated with SARIF integration examples
- CHANGELOG updated to reflect SARIF feature

See RELEASE_NOTES_v0.2.0.md for full details."

echo "✅ Tag created"
echo

# Push tag
echo "📤 Pushing tag to GitHub..."
git push origin $VERSION

echo "✅ Tag pushed"
echo

# Create GitHub release (requires gh CLI)
if command -v gh &> /dev/null; then
    echo "🎉 Creating GitHub release..."
    gh release create $VERSION \
        --title "$RELEASE_TITLE" \
        --notes-file RELEASE_NOTES_v0.2.0.md
    
    echo "✅ GitHub release created"
    echo
    echo "🌐 Release URL: https://github.com/texasbe2trill/macos-trust/releases/tag/$VERSION"
else
    echo "⚠️  gh CLI not found - skipping GitHub release creation"
    echo "   Create release manually at: https://github.com/texasbe2trill/macos-trust/releases/new"
    echo "   Tag: $VERSION"
    echo "   Title: $RELEASE_TITLE"
    echo "   Notes: Use RELEASE_NOTES_v0.2.0.md"
fi

echo
echo "✨ Release $VERSION complete!"
echo
echo "Next steps:"
echo "  1. Verify release at https://github.com/texasbe2trill/macos-trust/releases"
echo "  2. Test installation: pipx install git+https://github.com/texasbe2trill/macos-trust.git@$VERSION"
echo "  3. Announce on social media (optional)"
