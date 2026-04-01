#!/bin/bash

# Build script for WASM Authentication Provider Plugin

echo "Building WASM Authentication Provider Plugin..."

# Install wasm-pack if not already installed
if ! command -v wasm-pack &> /dev/null; then
    echo "Installing wasm-pack..."
    curl https://rustwasm.github.io/wasm-pack/installer/init.sh -sSf | sh
fi

# Build the plugin
echo "Compiling to WebAssembly..."
cargo build --release --target wasm32-unknown-unknown

# Optimize the WASM file
echo "Optimizing WASM..."
wasm-opt -Os -O target/wasm32-unknown-unknown/release/wasm_auth_plugin.wasm \
    -o target/wasm32-unknown-unknown/release/wasm_auth_plugin_opt.wasm

# Copy to examples directory
cp target/wasm32-unknown-unknown/release/wasm_auth_plugin_opt.wasm ./wasm_auth_plugin.wasm

echo "Build complete! Output: wasm_auth_plugin.wasm"
echo "Plugin size: $(wc -c < wasm_auth_plugin.wasm) bytes"
