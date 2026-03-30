#!/bin/bash

# Build script for Fortress authentication WASM plugins
# This script compiles each authentication plugin to WebAssembly

set -e

echo "Building Fortress authentication plugins..."

# Create output directory
mkdir -p ../../target/wasm-plugins

# Build JWT plugin
echo "Building JWT plugin..."
cargo build --release --bin jwt_plugin --target wasm32-unknown-unknown
cp ../../target/wasm32-unknown-unknown/release/jwt_plugin.wasm ../../target/wasm-plugins/

# Build OAuth plugin  
echo "Building OAuth plugin..."
cargo build --release --bin oauth_plugin --target wasm32-unknown-unknown
cp ../../target/wasm32-unknown-unknown/release/oauth_plugin.wasm ../../target/wasm-plugins/

# Build SAML plugin
echo "Building SAML plugin..."
cargo build --release --bin saml_plugin --target wasm32-unknown-unknown
cp ../../target/wasm32-unknown-unknown/release/saml_plugin.wasm ../../target/wasm-plugins/

echo "Plugin build complete!"
echo "Generated WASM files:"
ls -la ../../target/wasm-plugins/

# Create plugin manifest
cat > ../../target/wasm-plugins/plugin-manifest.json << EOF
{
  "version": "1.0.0",
  "plugins": {
    "jwt": {
      "wasm_file": "jwt_plugin.wasm",
      "supported_methods": ["JWT", "Basic"],
      "capabilities": {
        "can_generate_tokens": true,
        "can_validate_tokens": true,
        "can_refresh_tokens": true,
        "supports_mfa": false,
        "supports_rbac": true
      }
    },
    "oauth": {
      "wasm_file": "oauth_plugin.wasm", 
      "supported_methods": ["OAuth"],
      "capabilities": {
        "can_generate_tokens": true,
        "can_validate_tokens": true,
        "can_refresh_tokens": true,
        "supports_mfa": true,
        "supports_rbac": true
      }
    },
    "saml": {
      "wasm_file": "saml_plugin.wasm",
      "supported_methods": ["SAML"],
      "capabilities": {
        "can_generate_tokens": false,
        "can_validate_tokens": true,
        "can_refresh_tokens": false,
        "supports_mfa": true,
        "supports_rbac": true
      }
    }
  }
}
EOF

echo "Plugin manifest created: ../../target/wasm-plugins/plugin-manifest.json"
