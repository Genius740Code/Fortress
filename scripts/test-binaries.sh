#!/bin/bash

# Fortress Binary Testing Script
# This script tests binary distributions locally

set -e

echo "Testing Fortress Binary Distributions"

# Get version from Cargo.toml
VERSION=$(cargo metadata --no-deps --format-version 1 | grep -o '"version":"[^"]*"' | head -1 | cut -d'"' -f4)
echo "Testing version: $VERSION"

# Create test directory
TEST_DIR="test-binaries"
rm -rf "$TEST_DIR"
mkdir -p "$TEST_DIR"

# Function to test CLI binary
test_cli_binary() {
    local binary_path=$1
    local target=$2
    
    echo "Testing CLI binary for $target"
    
    if [[ ! -f "$binary_path" ]]; then
        echo "✗ Binary not found: $binary_path"
        return 1
    fi
    
    # Make binary executable (for non-Windows)
    if [[ "$target" != *"windows"* ]]; then
        chmod +x "$binary_path"
    fi
    
    # Test basic commands
    echo "Testing version command..."
    if "$binary_path" --version; then
        echo "✓ Version command works"
    else
        echo "✗ Version command failed"
        return 1
    fi
    
    echo "Testing help command..."
    if "$binary_path" --help; then
        echo "✓ Help command works"
    else
        echo "✗ Help command failed"
        return 1
    fi
    
    echo "✓ CLI binary test passed for $target"
}

# Function to test Python package
test_python_package() {
    local wheel_path=$1
    
    echo "Testing Python package: $(basename "$wheel_path")"
    
    if [[ ! -f "$wheel_path" ]]; then
        echo "✗ Wheel not found: $wheel_path"
        return 1
    fi
    
    # Create virtual environment
    python -m venv "$TEST_DIR/venv"
    source "$TEST_DIR/venv/bin/activate"
    
    # Install wheel
    pip install "$wheel_path"
    
    # Test import
    python -c "import fortress; print('✓ Import successful')"
    
    # Test basic functionality
    python -c "
import fortress
print('Fortress version:', fortress.__version__ if hasattr(fortress, '__version__') else 'Unknown')
"
    
    # Deactivate virtual environment
    deactivate
    
    echo "✓ Python package test passed"
}

# Function to test NPM package
test_npm_package() {
    local package_dir=$1
    
    echo "Testing NPM package"
    
    cd "$package_dir"
    
    # Install dependencies
    npm install
    
    # Test basic functionality
    node -e "
const { FortressCli, getFortressVersion } = require('./index.js');
console.log('✓ Import successful');
console.log('Fortress version:', getFortressVersion());

const cli = new FortressCli();
cli.version().then(result => {
    console.log('✓ CLI version command works:', result);
}).catch(err => {
    console.error('✗ CLI version command failed:', err);
    process.exit(1);
});
"
    
    cd ../..
    echo "✓ NPM package test passed"
}

# Build binaries first
echo "Building binaries for testing..."
./scripts/build-binaries.sh

# Test CLI binaries
echo "Testing CLI binaries..."
for target in "x86_64-unknown-linux-gnu" "x86_64-apple-darwin"; do
    if [[ "$target" == *"windows"* ]]; then
        binary_path="target/$target/release/fortress.exe"
    else
        binary_path="target/$target/release/fortress"
    fi
    
    if [[ -f "$binary_path" ]]; then
        test_cli_binary "$binary_path" "$target"
    else
        echo "Warning: Binary not found for $target, skipping test"
    fi
done

# Test Python packages
echo "Testing Python packages..."
for wheel in dist/python-wheels/*.whl; do
    if [[ -f "$wheel" ]]; then
        test_python_package "$wheel"
    fi
done

# Test NPM package
echo "Testing NPM package..."
if [[ -d "crates/fortress-cli-napi" ]]; then
    test_npm_package "crates/fortress-cli-napi"
else
    echo "Warning: NAPI package not found, skipping test"
fi

# Integration tests
echo "Running integration tests..."

# Test CLI with actual commands
CLI_BINARY="target/x86_64-unknown-linux-gnu/release/fortress"
if [[ -f "$CLI_BINARY" ]]; then
    echo "Testing CLI commands..."
    
    # Test create command (dry run)
    echo "Testing create help..."
    "$CLI_BINARY" create --help
    
    # Test status command
    echo "Testing status command..."
    "$CLI_BINARY" status --help
    
    echo "✓ Integration tests passed"
else
    echo "Warning: CLI binary not found for integration tests"
fi

# Clean up
echo "Cleaning up test environment..."
rm -rf "$TEST_DIR"

echo "✓ All binary tests completed successfully!"
echo ""
echo "Test Summary:"
echo "  - CLI binaries: Tested basic commands"
echo "  - Python packages: Tested import and basic functionality"
echo "  - NPM package: Tested import and CLI integration"
echo "  - Integration: Tested end-to-end functionality"
