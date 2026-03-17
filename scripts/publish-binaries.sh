#!/bin/bash

# Fortress Binary Publishing Script
# This script publishes binary distributions to various platforms

set -e

echo "Publishing Fortress Binary Distributions"

# Get version from Cargo.toml
VERSION=$(cargo metadata --no-deps --format-version 1 | grep -o '"version":"[^"]*"' | head -1 | cut -d'"' -f4)
echo "Publishing version: $VERSION"

# Check if we're on a tag
if [[ "$GITHUB_REF" == refs/tags/* ]]; then
    TAG_VERSION=${GITHUB_REF#refs/tags/}
    echo "Publishing from tag: $TAG_VERSION"
    
    if [[ "$TAG_VERSION" != "v$VERSION" ]]; then
        echo "Version mismatch: tag is $TAG_VERSION but Cargo.toml has $VERSION"
        exit 1
    fi
else
    echo "Not on a tag, skipping publishing"
    exit 0
fi

# Function to publish to NPM
publish_npm() {
    echo "Publishing to NPM..."
    
    cd crates/fortress-cli-napi
    
    # Check if NPM token is available
    if [[ -z "$NPM_TOKEN" ]]; then
        echo "NPM_TOKEN not set"
        return 1
    fi
    
    # Install dependencies and prepare
    npm install
    napi prepublish -t npm
    
    # Publish
    npm publish
    
    cd ../..
    echo "Published to NPM"
}

# Function to publish to PyPI
publish_pypi() {
    echo "Publishing to PyPI..."
    
    cd crates/fortress-python
    
    # Check if PyPI token is available
    if [[ -z "$PYPI_TOKEN" ]]; then
        echo "PYPI_TOKEN not set"
        return 1
    fi
    
    # Install maturin
    pip install maturin
    
    # Publish
    maturin publish --username __token__ --password "$PYPI_TOKEN"
    
    cd ../..
    echo "Published to PyPI"
}

# Function to create GitHub release
create_github_release() {
    echo "Creating GitHub release..."
    
    if [[ -z "$GITHUB_TOKEN" ]]; then
        echo "GITHUB_TOKEN not set"
        return 1
    fi
    
    # Create release notes
    RELEASE_NOTES="Fortress v$VERSION
    
## Installation

### NPM
\`\`\`bash
npm install -g fortress-cli
\`\`\`

### PyPI
\`\`\`bash
pip install fortress
\`\`\`

### Standalone CLI
Download the appropriate binary from the assets below.

## Changes
$(git log --pretty=format:"- %s" $(git describe --tags --abbrev=0 HEAD)^..HEAD)"

    # Create release using GitHub CLI
    gh release create "v$VERSION" \
        --title "Fortress v$VERSION" \
        --notes "$RELEASE_NOTES" \
        --latest \
        dist/cli-binaries/* \
        dist/python-wheels/* \
        dist/npm-binaries/*
    
    echo "GitHub release created"
}

# Main publishing logic
case "$1" in
    "npm")
        publish_npm
        ;;
    "pypi")
        publish_pypi
        ;;
    "github")
        create_github_release
        ;;
    "all")
        publish_npm
        publish_pypi
        create_github_release
        ;;
    *)
        echo "Usage: $0 {npm|pypi|github|all}"
        echo "  npm    - Publish to NPM registry"
        echo "  pypi   - Publish to PyPI registry"
        echo "  github - Create GitHub release"
        echo "  all    - Publish to all platforms"
        exit 1
        ;;
esac

echo "Publishing completed successfully!"
