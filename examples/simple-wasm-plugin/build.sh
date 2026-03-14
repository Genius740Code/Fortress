#!/bin/bash

# Build script for Simple WebAssembly Plugin
# This script compiles the plugin to WebAssembly and creates a test package

set -e

echo "🔨 Building Simple WebAssembly Plugin..."

# Check if wasm target is installed
if ! rustup target list --installed | grep -q "wasm32-unknown-unknown"; then
    echo "📦 Installing WebAssembly target..."
    rustup target add wasm32-unknown-unknown
fi

# Build for WebAssembly
echo "🏗️  Compiling to WebAssembly..."
cargo build --release --target wasm32-unknown-unknown

# Create plugin package directory
PLUGIN_DIR="simple-wasm-plugin-0.1.0"
echo "📁 Creating plugin package: $PLUGIN_DIR"

rm -rf "$PLUGIN_DIR"
mkdir -p "$PLUGIN_DIR"

# Copy WebAssembly file
cp target/wasm32-unknown-unknown/release/simple_wasm_plugin.wasm "$PLUGIN_DIR/plugin.wasm"

# Create metadata.json
cat > "$PLUGIN_DIR/metadata.json" << 'EOF'
{
  "id": "simple-wasm-plugin",
  "name": "Simple WebAssembly Plugin",
  "version": "0.1.0",
  "description": "A simple WebAssembly plugin that provides basic text processing",
  "author": "Fortress Team",
  "license": "MIT",
  "capabilities": ["text_processing", "data_validation"],
  "entry_point": "process_text",
  "min_fortress_version": "0.1.0",
  "dependencies": [],
  "config_schema": {
    "type": "object",
    "properties": {
      "max_text_length": {
        "type": "integer",
        "default": 1000,
        "description": "Maximum text length to process"
      }
    }
  },
  "download_url": "https://github.com/Genius740Code/Fortress/plugins/simple-wasm-plugin-0.1.0.fplugin",
  "checksum": "",
  "size_bytes": 0,
  "download_count": 0,
  "rating": 0.0,
  "tags": ["text-processing", "simple", "example"],
  "last_updated": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
EOF

# Create README.md
cat > "$PLUGIN_DIR/README.md" << EOF
# Simple WebAssembly Plugin

A minimal, working WebAssembly plugin for Fortress that demonstrates basic text processing capabilities.

## Features

- Text transformation (uppercase, lowercase, reverse)
- Character counting
- Simple statistics tracking
- Memory-safe WebAssembly implementation

## Usage

### Build
\`\`\`bash
./build.sh
\`\`\`

### Install with Fortress CLI
\`\`\`bash
fortress plugin install simple-wasm-plugin
\`\`\`

### Use in Fortress
\`\`\`rust
use fortress_core::plugin::*;

let plugin = fortress.load_plugin("simple-wasm-plugin").await?;
let result = plugin.execute(PluginInput {
    action: "process_text".to_string(),
    data: serde_json::json!({
        "text": "Hello World",
        "operation": "uppercase"
    }),
    parameters: HashMap::new(),
}).await?;
\`\`\`

## API

### process_text(text, operation)
Processes text with the specified operation.

**Operations:**
- \`uppercase\` - Convert text to uppercase
- \`lowercase\` - Convert text to lowercase  
- \`reverse\` - Reverse the text
- \`count\` - Return character count
- \`trim\` - Remove whitespace

**Example:**
\`\`\`json
{
  "text": "Hello World",
  "operation": "uppercase"
}
\`\`\`

**Response:**
\`\`\`json
{
  "result": "HELLO WORLD",
  "original_length": 11,
  "processed_length": 11,
  "operation": "uppercase"
}
\`\`\`
EOF

# Create config.json (optional)
cat > "$PLUGIN_DIR/config.json" << EOF
{
  "max_text_length": 1000
}
EOF

# Create package (tar.gz)
echo "📦 Creating plugin package..."
tar -czf "$PLUGIN_DIR.fplugin" "$PLUGIN_DIR"

# Calculate checksum
CHECKSUM=$(sha256sum "$PLUGIN_DIR.fplugin" | cut -d' ' -f1)
echo "🔐 Checksum: $CHECKSUM"

# Update metadata with checksum
sed -i "s/\"checksum\": \"\"/\"checksum\": \"$CHECKSUM\"/" "$PLUGIN_DIR/metadata.json"
sed -i "s/\"size_bytes\": 0/\"size_bytes\": $(stat -c%s \"$PLUGIN_DIR.fplugin\")/" "$PLUGIN_DIR/metadata.json"

# Recreate package with updated metadata
tar -czf "$PLUGIN_DIR.fplugin" "$PLUGIN_DIR"

echo "✅ Plugin package created: $PLUGIN_DIR.fplugin"
echo "📊 Size: $(stat -c%s "$PLUGIN_DIR.fplugin") bytes"
echo "🔐 Checksum: $CHECKSUM"

# Test the plugin (optional)
if command -v fortress &> /dev/null; then
    echo "🧪 Testing plugin with Fortress..."
    echo "Plugin metadata:"
    cat "$PLUGIN_DIR/metadata.json" | jq '.'
else
    echo "💡 Install Fortress CLI to test the plugin"
fi

echo ""
echo "🎉 Simple WebAssembly plugin build complete!"
echo "📖 See README.md for usage instructions"
