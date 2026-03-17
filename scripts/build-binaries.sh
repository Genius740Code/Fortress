#!/bin/bash

# Fortress Binary Build Script
# This script builds all binary distributions for Fortress

set -e

echo "Building Fortress Binary Distributions"

# Get version from Cargo.toml
VERSION=$(cargo metadata --no-deps --format-version 1 | grep -o '"version":"[^"]*"' | head -1 | cut -d'"' -f4)
echo "Building version: $VERSION"

# Create output directory
DIST_DIR="dist"
rm -rf "$DIST_DIR"
mkdir -p "$DIST_DIR"

# Function to build for a specific target
build_target() {
    local target=$1
    local component=$2
    
    echo "Building $component for $target"
    
    case $component in
        "npm")
            cd crates/fortress-cli-napi
            npm install
            npm run build -- --target "$target" --release
            cd ../..
            ;;
        "python")
            cd crates/fortress-python
            maturin build --release --target "$target" --out dist
            cd ../..
            ;;
        "cli")
            cargo build --release --target "$target" --bin fortress
            ;;
    esac
}

# Define targets
TARGETS=(
    "x86_64-pc-windows-msvc"
    "i686-pc-windows-msvc"
    "x86_64-apple-darwin"
    "aarch64-apple-darwin"
    "x86_64-unknown-linux-gnu"
    "x86_64-unknown-linux-musl"
    "aarch64-unknown-linux-gnu"
    "armv7-unknown-linux-gnueabihf"
)

# Install Rust targets
echo "Installing Rust targets..."
for target in "${TARGETS[@]}"; do
    rustup target add "$target" || echo "Warning: Failed to add target $target"
done

# Build NPM binaries
echo "Building NPM binaries..."
for target in "${TARGETS[@]}"; do
    if build_target "$target" "npm"; then
        echo "✓ NPM build successful for $target"
    else
        echo "✗ NPM build failed for $target"
    fi
done

# Build Python wheels
echo "Building Python wheels..."
pip install maturin
for target in "${TARGETS[@]}"; do
    if build_target "$target" "python"; then
        echo "✓ Python build successful for $target"
    else
        echo "✗ Python build failed for $target"
    fi
done

# Build source distribution
echo "Building Python source distribution..."
cd crates/fortress-python
maturin build --sdist --out dist
cd ../..

# Build CLI binaries
echo "Building CLI binaries..."
for target in "${TARGETS[@]}"; do
    if build_target "$target" "cli"; then
        echo "✓ CLI build successful for $target"
    else
        echo "✗ CLI build failed for $target"
    fi
done

# Create archive files
echo "Creating distribution archives..."
cd "$DIST_DIR"

# Archive CLI binaries
mkdir -p cli-binaries
for target in "${TARGETS[@]}"; do
    if [[ "$target" == *"windows"* ]]; then
        binary_path="../target/$target/release/fortress.exe"
        archive_name="fortress-cli-$VERSION-$target.zip"
        if [ -f "$binary_path" ]; then
            cp "$binary_path" "fortress.exe"
            zip "$archive_name" fortress.exe
            mv "$archive_name" cli-binaries/
            rm fortress.exe
        fi
    else
        binary_path="../target/$target/release/fortress"
        archive_name="fortress-cli-$VERSION-$target.tar.gz"
        if [ -f "$binary_path" ]; then
            cp "$binary_path" fortress
            tar -czf "$archive_name" fortress
            mv "$archive_name" cli-binaries/
            rm fortress
        fi
    fi
done

# Move Python wheels to organized directory
mkdir -p python-wheels
mv ../crates/fortress-python/dist/*.whl python-wheels/ 2>/dev/null || true
mv ../crates/fortress-python/dist/*.tar.gz python-wheels/ 2>/dev/null || true

# Move NPM binaries to organized directory
mkdir -p npm-binaries
find ../crates/fortress-cli-napi -name "*.node" -exec cp {} npm-binaries/ \; 2>/dev/null || true

cd ..

echo "✓ Binary distribution build completed!"
echo "Distribution files available in: $DIST_DIR"
echo ""
echo "Contents:"
echo "  - cli-binaries/: Standalone CLI executables"
echo "  - python-wheels/: Python wheel packages"
echo "  - npm-binaries/: NAPI Node.js binaries"
echo ""
echo "To publish:"
echo "  NPM: cd crates/fortress-cli-napi && npm publish"
echo "  PyPI: cd crates/fortress-python && maturin publish"
echo "  GitHub: Create a release and upload artifacts"
