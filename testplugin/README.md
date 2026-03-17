# Fortress Test Plugin

A comprehensive test plugin demonstrating the Fortress plugin system capabilities with WebAssembly support.

## Overview

This plugin serves as both a testing tool and a reference implementation for creating Fortress plugins. It demonstrates:

- **Basic Plugin Structure**: How to implement the Fortress plugin trait
- **Async Operations**: Asynchronous plugin execution with proper error handling
- **Configuration Management**: Plugin configuration validation and usage
- **Health Monitoring**: Plugin health checks and metrics reporting
- **WebAssembly Compatibility**: WASM-ready implementation for cross-platform deployment

## Features

### Core Actions
- **hello**: Greets a user by name with timestamp
- **echo**: Returns the input data unchanged (useful for testing)
- **status**: Returns plugin status and metrics
- **config**: Validates and returns current configuration

### Metrics & Monitoring
- **Execution Time**: Tracks how long each action takes
- **Memory Usage**: Monitors memory consumption during execution
- **Custom Metrics**: Allows adding custom performance indicators
- **Health Checks**: Regular health status reporting

### Configuration
- **Dynamic Configuration**: Runtime configuration updates
- **Validation**: Schema-based configuration validation
- **Environment Integration**: Seamless integration with Fortress environment

## Quick Start

### Prerequisites
- Rust 1.70+
- Fortress 0.1.0+
- wasm-pack (for WebAssembly compilation)

### Building the Plugin

#### Native Build
```bash
# Build for native testing
cargo build --release

# Run tests
cargo test
```

#### WebAssembly Build
```bash
# Install wasm-pack if not already installed
cargo install wasm-pack

# Build WebAssembly module
wasm-pack build --target web --out-dir pkg --release

# The compiled plugin will be in pkg/test_plugin.wasm
```

### Installation

#### Using Fortress CLI
```bash
# Install the plugin
fortress plugin install ./target/release/libtest_plugin.so

# Or for WebAssembly
fortress plugin install ./pkg/test_plugin.wasm

# Enable the plugin
fortress plugin enable TestPlugin

# Verify installation
fortress plugin list
```

#### Manual Installation
```bash
# Copy plugin to Fortress plugins directory
cp ./target/release/libtest_plugin.so ~/.fortress/plugins/

# Or for WebAssembly
cp ./pkg/test_plugin.wasm ~/.fortress/plugins/

# Restart Fortress to load the plugin
fortress restart
```

## Usage Examples

### Hello Action
```bash
# Call the hello action
fortress plugin execute TestPlugin hello '{"name": "Fortress User"}'

# Response
{
  "success": true,
  "data": {
    "message": "Hello, Fortress User!",
    "timestamp": "2024-01-15T10:30:00Z"
  },
  "metrics": {
    "execution_time_ms": 2,
    "memory_usage_bytes": 1024,
    "custom_metrics": {}
  }
}
```

### Echo Action
```bash
# Echo test data
fortress plugin execute TestPlugin echo '{"test": "value", "number": 42}'

# Response
{
  "success": true,
  "data": {
    "test": "value",
    "number": 42
  },
  "metrics": {
    "execution_time_ms": 1,
    "memory_usage_bytes": 512,
    "custom_metrics": {}
  }
}
```

### Plugin Status
```bash
# Check plugin health
fortress plugin health TestPlugin

# Response
{
  "healthy": true,
  "message": "TestPlugin plugin is healthy",
  "last_check": "2024-01-15T10:30:00Z"
}
```

## Configuration

### Default Configuration
```toml
[TestPlugin]
enabled = true
log_level = "info"
max_execution_time_ms = 5000
memory_limit_mb = 100

[custom_settings]
greeting_message = "Hello"
enable_metrics = true
```

### Updating Configuration
```bash
# Set configuration values
fortress plugin configure TestPlugin --set log_level=debug
fortress plugin configure TestPlugin --set max_execution_time_ms=10000

# View current configuration
fortress plugin config TestPlugin
```

## Plugin Interface

### Core Trait Implementation

The plugin implements the `Plugin` trait with the following methods:

```rust
#[async_trait]
pub trait Plugin {
    fn metadata(&self) -> &PluginMetadata;
    async fn initialize(&self, context: PluginContext) -> Result<()>;
    async fn execute(&self, input: PluginInput) -> Result<PluginResult>;
    async fn cleanup(&self) -> Result<()>;
    fn validate_config(&self, config: &HashMap<String, serde_json::Value>) -> Result<()>;
    async fn health_check(&self) -> Result<PluginHealth>;
}
```

### Plugin Metadata

```rust
pub struct PluginMetadata {
    pub id: String,
    pub name: String,
    pub version: String,
    pub description: String,
    pub author: String,
    pub capabilities: Vec<PluginCapability>,
    pub config_schema: Option<serde_json::Value>,
}
```

### Input/Output Structures

```rust
pub struct PluginInput {
    pub action: String,
    pub data: serde_json::Value,
    pub parameters: HashMap<String, serde_json::Value>,
}

pub struct PluginResult {
    pub success: bool,
    pub data: Option<serde_json::Value>,
    pub error: Option<String>,
    pub metrics: PluginMetrics,
}
```

## Development

### Project Structure
```
testplugin/
├── Cargo.toml              # Project configuration
├── src/
│   └── lib.rs            # Main plugin implementation
└── README.md             # This file
```

### Adding New Actions

1. **Add action handler** in the `execute` method:
```rust
"my_action" => {
    // Your implementation here
    Ok(PluginResult {
        success: true,
        data: Some(serde_json::json!({"result": "success"})),
        error: None,
        metrics: PluginMetrics {
            execution_time_ms: start_time.elapsed().as_millis() as u64,
            memory_usage_bytes: 0,
            custom_metrics: HashMap::new(),
        },
    })
}
```

2. **Add tests** for the new action:
```rust
#[tokio::test]
async fn test_my_action() {
    let plugin = TestPlugin::new();
    let input = PluginInput {
        action: "my_action".to_string(),
        data: serde_json::json!({}),
        parameters: HashMap::new(),
    };

    let result = plugin.execute(input).await.unwrap();
    assert!(result.success);
}
```

3. **Update documentation** with usage examples.

### Testing

```bash
# Run all tests
cargo test

# Run specific test
cargo test test_hello_action

# Run tests with output
cargo test -- --nocapture

# Run WebAssembly tests
wasm-pack test --headless --firefox
```

## Deployment

### Native Deployment
```bash
# Build release version
cargo build --release

# Deploy to production
cp target/release/libtest_plugin.so /opt/fortress/plugins/
```

### WebAssembly Deployment
```bash
# Build WebAssembly version
./build.sh

# Deploy WASM file
cp dist/test_plugin.wasm /opt/fortress/plugins/
```

### Docker Deployment
```dockerfile
FROM fortressdb/fortress:latest

COPY test_plugin.wasm /opt/fortress/plugins/
RUN fortress plugin enable TestPlugin
```

## Troubleshooting

### Common Issues

#### Plugin Not Loading
```bash
# Check plugin file permissions
ls -la ~/.fortress/plugins/

# Check plugin format
file ~/.fortress/plugins/test_plugin.so

# Verify plugin metadata
fortress plugin info TestPlugin
```

#### Action Not Found
```bash
# List available actions
fortress plugin actions TestPlugin

# Check plugin logs
fortress logs TestPlugin
```

#### Configuration Errors
```bash
# Validate configuration
fortress plugin validate TestPlugin

# Reset to defaults
fortress plugin reset TestPlugin
```

### Debug Mode
```bash
# Enable debug logging
fortress plugin configure TestPlugin --set log_level=debug

# View debug output
fortress logs TestPlugin --follow
```

## Performance

### Benchmarks
- **Hello Action**: ~1-2ms execution time
- **Echo Action**: ~1ms execution time
- **Memory Usage**: ~1KB per action
- **Startup Time**: ~10ms

### Optimization Tips
1. **Use async/await** for I/O operations
2. **Avoid blocking calls** in plugin code
3. **Cache expensive operations**
4. **Monitor memory usage** regularly
5. **Use custom metrics** for performance tracking

## Security

### Best Practices
1. **Validate all inputs** before processing
2. **Use secure memory handling** for sensitive data
3. **Implement proper error handling** without exposing internals
4. **Follow principle of least privilege** for plugin permissions
5. **Regular security audits** of plugin code

### Permissions
The plugin requires the following permissions:
- `read_config`: Read plugin configuration
- `write_metrics`: Write performance metrics
- `execute_actions`: Execute plugin actions

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Ensure all tests pass
6. Submit a pull request

## License

This plugin is licensed under the Apache License 2.0 - see the [LICENSE](../../LICENSE) file for details.

## Support

- **Documentation**: [Fortress Docs](https://docs.fortress-db.com)
- **Issues**: [GitHub Issues](https://github.com/Genius740Code/Fortress/issues)
- **Community**: [Discussions](https://github.com/Genius740Code/Fortress/discussions)

---

**Note**: This plugin is intended for testing and demonstration purposes. For production use, consider implementing proper error handling, logging, and security measures.
