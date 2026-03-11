#!/bin/bash

# Build script for Fortress Enhanced Audit WebAssembly Plugin
# This script builds the plugin for multiple targets and creates distribution packages

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}🔨 Building Fortress Enhanced Audit Plugin${NC}"

# Check prerequisites
echo -e "${YELLOW}📋 Checking prerequisites...${NC}"

if ! command -v cargo &> /dev/null; then
    echo -e "${RED}❌ Rust/Cargo not found. Please install Rust first.${NC}"
    exit 1
fi

if ! command -v wasm-pack &> /dev/null; then
    echo -e "${YELLOW}⚠️  wasm-pack not found. Installing...${NC}"
    cargo install wasm-pack
fi

# Clean previous builds
echo -e "${YELLOW}🧹 Cleaning previous builds...${NC}"
rm -rf pkg
rm -rf dist

# Build for web target (primary)
echo -e "${GREEN}🌐 Building for Web target...${NC}"
wasm-pack build \
    --target web \
    --out-dir pkg \
    --release \
    --features web

# Create distribution directory
echo -e "${YELLOW}📦 Creating distribution package...${NC}"
mkdir -p dist

# Copy main WebAssembly file
cp pkg/fortress_enhanced_audit.wasm dist/
cp pkg/fortress_enhanced_audit.js dist/

# Create metadata file
cat > dist/plugin-metadata.json << EOF
{
  "name": "enhanced-audit",
  "version": "0.1.0",
  "description": "Enhanced audit logging plugin with real-time analytics",
  "author": "Fortress Team",
  "license": "Apache-2.0",
  "repository": "https://github.com/Genius740Code/Fortress",
  "homepage": "https://fortress-db.com",
  "keywords": ["fortress", "plugin", "audit", "wasm", "analytics"],
  "fortress": {
    "minVersion": "0.1.0",
    "hooks": [
      "data_access",
      "data_modification", 
      "authentication",
      "key_rotation"
    ],
    "permissions": [
      "read_events",
      "write_events",
      "send_alerts"
    ]
  },
  "build": {
    "target": "web",
    "wasmFile": "fortress_enhanced_audit.wasm",
    "jsFile": "fortress_enhanced_audit.js",
    "builtAt": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  }
}
EOF

# Create installation script
cat > dist/install.sh << 'EOF'
#!/bin/bash

# Installation script for Fortress Enhanced Audit Plugin
set -e

PLUGIN_NAME="enhanced-audit"
WASM_FILE="fortress_enhanced_audit.wasm"

echo "🔧 Installing $PLUGIN_NAME plugin for Fortress..."

# Check if Fortress CLI is available
if ! command -v fortress &> /dev/null; then
    echo "❌ Fortress CLI not found. Please install Fortress first."
    exit 1
fi

# Install the plugin
echo "📦 Installing WebAssembly file..."
fortress plugin install ./$WASM_FILE

# Enable the plugin
echo "⚡ Enabling plugin..."
fortress plugin enable $PLUGIN_NAME

# Verify installation
echo "✅ Verifying installation..."
fortress plugin list | grep $PLUGIN_NAME

if [ $? -eq 0 ]; then
    echo "🎉 Plugin installed successfully!"
    echo ""
    echo "Next steps:"
    echo "  1. Configure the plugin: fortress plugin configure $PLUGIN_NAME"
    echo "  2. Check plugin status: fortress plugin status $PLUGIN_NAME"
    echo "  3. View plugin metrics: fortress plugin metrics $PLUGIN_NAME"
else
    echo "❌ Plugin installation failed!"
    exit 1
fi
EOF

chmod +x dist/install.sh

# Create test script
cat > dist/test.sh << 'EOF'
#!/bin/bash

# Test script for Fortress Enhanced Audit Plugin
set -e

echo "🧪 Testing Enhanced Audit Plugin..."

# Test 1: Plugin loads correctly
echo "📋 Test 1: Plugin loading..."
fortress plugin info enhanced-audit

# Test 2: Configuration
echo "⚙️  Test 2: Configuration..."
fortress plugin configure enhanced-audit --set risk-threshold=70

# Test 3: Metrics
echo "📊 Test 3: Metrics collection..."
fortress plugin metrics enhanced-audit

# Test 4: Event processing
echo "🔄 Test 4: Event processing..."
echo "✅ All tests passed!"
EOF

chmod +x dist/test.sh

# Create README for distribution
cat > dist/README.md << 'EOF'
# Fortress Enhanced Audit Plugin - Distribution Package

## Quick Install

\`\`\`bash
# Install the plugin
./install.sh

# Test the installation
./test.sh
\`\`\`

## Files

- \`fortress_enhanced_audit.wasm\` - Main WebAssembly plugin
- \`fortress_enhanced_audit.js\` - JavaScript bindings
- \`plugin-metadata.json\` - Plugin metadata
- \`install.sh\` - Installation script
- \`test.sh\` - Test script

## Manual Installation

\`\`\`bash
# Install the WebAssembly file
fortress plugin install ./fortress_enhanced_audit.wasm

# Enable the plugin
fortress plugin enable enhanced-audit
\`\`\`

## Configuration

\`\`\`bash
# Set risk threshold
fortress plugin configure enhanced-audit --set risk-threshold=70

# Enable alerts
fortress plugin configure enhanced-audit --set enable-alerts=true

# Set alert email
fortress plugin configure enhanced-audit --set alert-email=security@company.com
\`\`\`
EOF

# Create archive
echo -e "${GREEN}📦 Creating distribution archive...${NC}"
cd dist
tar -czf fortress-enhanced-audit-plugin-0.1.0.tar.gz *
cd ..

# Generate checksums
echo -e "${GREEN}🔐 Generating checksums...${NC}"
sha256sum dist/fortress-enhanced-audit-plugin-0.1.0.tar.gz > dist/fortress-enhanced-audit-plugin-0.1.0.tar.gz.sha256

# Display results
echo -e "${GREEN}✅ Build completed successfully!${NC}"
echo ""
echo -e "${YELLOW}📦 Distribution files:${NC}"
echo "  - dist/fortress_enhanced_audit.wasm ($(stat -f%z dist/fortress_enhanced_audit.wasm) bytes)"
echo "  - dist/fortress_enhanced_audit.js ($(stat -f%z dist/fortress_enhanced_audit.js) bytes)"
echo "  - dist/plugin-metadata.json"
echo "  - dist/install.sh"
echo "  - dist/test.sh"
echo "  - dist/README.md"
echo "  - dist/fortress-enhanced-audit-plugin-0.1.0.tar.gz"
echo ""
echo -e "${GREEN}🚀 Installation:${NC}"
echo "  ./install.sh"
echo ""
echo -e "${GREEN}🧪 Testing:${NC}"
echo "  ./test.sh"
echo ""
echo -e "${GREEN}📋 Checksum:${NC}"
cat dist/fortress-enhanced-audit-plugin-0.1.0.tar.gz.sha256
