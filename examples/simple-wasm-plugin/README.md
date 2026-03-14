# Simple WebAssembly Plugin

A minimal, working WebAssembly plugin for Fortress that demonstrates basic text processing capabilities.

## Overview

This is a **complete, working example** of a WebAssembly plugin that can be:
- ✅ Compiled to WebAssembly
- ✅ Packaged for Fortress
- ✅ Installed and executed
- ✅ Used as a reference for plugin development

## Features

- Text transformation (uppercase, lowercase, reverse)
- Character counting  
- Simple statistics tracking
- Memory-safe WebAssembly implementation
- Proper error handling
- JSON serialization/deserialization

## Quick Start

### 1. Build the Plugin

```bash
cd examples/simple-wasm-plugin
chmod +x build.sh
./build.sh
```

This will create `simple-wasm-plugin-0.1.0.fplugin` - a complete plugin package.

### 2. Install with Fortress

```bash
# From the Fortress repository root
fortress plugin install examples/simple-wasm-plugin/simple-wasm-plugin-0.1.0.fplugin
```

### 3. Use the Plugin

```rust
use fortress_core::plugin::*;
use serde_json::json;

// Load the plugin
let plugin = fortress.load_plugin("simple-wasm-plugin").await?;

// Execute text processing
let result = plugin.execute(PluginInput {
    action: "process_text".to_string(),
    data: json!({
        "text": "Hello World",
        "operation": "uppercase"
    }),
    parameters: HashMap::new(),
}).await?;

println!("Result: {}", result.data);
```

## API Reference

### Main Function: `process_text`

Processes text with the specified operation.

#### Parameters
- `text` (string): The text to process
- `operation` (string): The operation to perform

#### Operations
- `uppercase` - Convert text to uppercase
- `lowercase` - Convert text to lowercase  
- `reverse` - Reverse the text
- `count` - Return character count
- `trim` - Remove leading/trailing whitespace

#### Request Example
```json
{
  "text": "Hello World",
  "operation": "uppercase"
}
```

#### Response Example
```json
{
  "result": "HELLO WORLD",
  "original_length": 11,
  "processed_length": 11,
  "operation": "uppercase"
}
```

## Plugin Structure

```
simple-wasm-plugin-0.1.0/
├── plugin.wasm              # Compiled WebAssembly binary
├── metadata.json            # Plugin metadata
├── config.json             # Default configuration
└── README.md               # This file
```

## Development Guide

### Prerequisites

- Rust 1.70+ with WebAssembly target:
  ```bash
  rustup target add wasm32-unknown-unknown
  ```

### Project Structure

- `src/lib.rs` - Main plugin implementation
- `Cargo.toml` - Project configuration
- `build.sh` - Build and packaging script

### Key Concepts

1. **Plugin Metadata**: Static metadata that Fortress reads
2. **Entry Points**: C-exported functions for Fortress to call
3. **Memory Management**: Manual memory allocation/deallocation
4. **Error Handling**: Return null pointers on errors

### Creating Your Own Plugin

1. **Copy this example**:
   ```bash
   cp -r examples/simple-wasm-plugin examples/my-plugin
   cd examples/my-plugin
   ```

2. **Modify metadata** in `src/lib.rs`:
   ```rust
   pub static PLUGIN_METADATA: &str = r#"{
     "name": "my-plugin",
     "version": "0.1.0",
     "description": "My custom plugin",
     // ... other fields
   }"#;
   ```

3. **Implement your functions**:
   ```rust
   #[no_mangle]
   pub extern "C" fn my_function(
       plugin: *mut MyPlugin,
       request_ptr: *const u8,
       request_len: usize,
   ) -> *mut u8 {
       // Your implementation
   }
   ```

4. **Build and test**:
   ```bash
   ./build.sh
   fortress plugin install my-plugin-0.1.0.fplugin
   ```

## Testing

### Run Tests
```bash
cargo test
```

### Manual Testing
```bash
# Build the plugin
./build.sh

# Create a simple test (optional)
cat > test_plugin.js << 'EOF'
const fs = require('fs');

// Load the plugin (this would be done by Fortress)
const pluginBytes = fs.readFileSync('simple-wasm-plugin-0.1.0/plugin.wasm');
const metadata = JSON.parse(fs.readFileSync('simple-wasm-plugin-0.1.0/metadata.json', 'utf8'));

console.log('Plugin Metadata:', metadata);
console.log('Plugin Size:', pluginBytes.length, 'bytes');
EOF

node test_plugin.js
```

## Integration with Fortress

The plugin integrates with Fortress through:

1. **Plugin Loader**: Loads `.fplugin` packages
2. **WebAssembly Runtime**: Executes WASM safely
3. **Host Functions**: Provides Fortress APIs to plugins
4. **Memory Management**: Handles memory allocation/deallocation

## Security Considerations

- ✅ Sandboxed WebAssembly execution
- ✅ Memory access validation
- ✅ Input validation
- ✅ Error propagation
- ✅ Resource limits

## Troubleshooting

### Build Issues
```bash
# Ensure WebAssembly target is installed
rustup target add wasm32-unknown-unknown

# Check dependencies
cargo check --target wasm32-unknown-unknown
```

### Runtime Issues
- Check Fortress logs for plugin errors
- Verify plugin metadata format
- Ensure WebAssembly compatibility

## Next Steps

From this simple example, you can:

1. **Add more complex operations**
2. **Implement state management**
3. **Add configuration options**
4. **Use Fortress APIs** (when available)
5. **Add comprehensive tests**

## Resources

- [Fortress Plugin Development Guide](../../docs/PLUGIN_DEVELOPMENT.md)
- [WebAssembly Rust Book](https://rustwasm.github.io/docs/book/)
- [Fortress Core API Documentation](../../crates/fortress-core/src/plugin.rs)

---

**This is a working example** - not aspirational documentation. It can be built, installed, and executed today.
