# Fortress Plugin Architecture

## Overview

The Fortress plugin system provides a flexible and secure architecture for extending Fortress functionality with custom plugins. Users can create plugins that integrate with external APIs, handle specialized cryptographic operations, or implement custom business logic.

## Architecture Components

### Core Components

1. **Plugin Trait** - The main interface that all plugins must implement
2. **Plugin Registry** - Manages loaded plugins and provides discovery
3. **Plugin Manager** - Handles plugin lifecycle (loading, execution, cleanup)
4. **Plugin Context** - Provides secure access to Fortress internals
5. **Plugin Metadata** - Describes plugin capabilities and configuration

### Plugin Capabilities

Plugins can declare various capabilities:

- `SignTransaction` - Can sign transactions or data
- `VerifySignature` - Can verify digital signatures
- `GenerateKey` - Can generate cryptographic keys
- `Encrypt` - Can encrypt data
- `Decrypt` - Can decrypt data
- `Hash` - Can hash data
- `ApiIntegration` - Can interact with external APIs
- `SecretManagement` - Can manage secrets
- `Custom(String)` - Custom capabilities

## Plugin Development Guide

### Creating a Basic Plugin

```rust
use fortress_core::plugin::*;
use async_trait::async_trait;

struct MyPlugin {
    metadata: PluginMetadata,
    context: Option<PluginContext>,
}

#[async_trait]
impl Plugin for MyPlugin {
    fn metadata(&self) -> &PluginMetadata {
        &self.metadata
    }

    async fn initialize(&mut self, context: PluginContext) -> Result<()> {
        self.context = Some(context);
        // Initialize plugin resources
        Ok(())
    }

    async fn execute(&self, input: PluginInput) -> Result<PluginResult> {
        // Handle plugin execution
        match input.action.as_str() {
            "my_action" => {
                // Process input and return result
                Ok(PluginResult {
                    success: true,
                    data: Some(serde_json::json!({"result": "success"})),
                    error: None,
                    metrics: PluginMetrics {
                        execution_time_ms: 10,
                        memory_usage_bytes: 1024,
                        custom_metrics: HashMap::new(),
                    },
                })
            }
            _ => Err(FortressError::plugin("Unknown action")),
        }
    }

    async fn cleanup(&self) -> Result<()> {
        // Cleanup resources
        Ok(())
    }

    fn validate_config(&self, config: &HashMap<String, serde_json::Value>) -> Result<()> {
        // Validate plugin configuration
        Ok(())
    }

    async fn health_check(&self) -> Result<PluginHealth> {
        Ok(PluginHealth {
            healthy: true,
            message: "Plugin is healthy".to_string(),
            last_check: chrono::Utc::now(),
        })
    }
}
```

### Using the Plugin Macro

For convenience, Fortress provides a macro to simplify plugin creation:

```rust
fortress_plugin! {
    metadata: {
        id: "my-plugin",
        name: "My Plugin",
        version: "1.0.0",
        description: "A custom plugin",
        author: "Your Name",
        capabilities: [PluginCapability::Custom("my_capability")],
        config_schema: Some(serde_json::json!({
            "type": "object",
            "properties": {
                "api_key": {"type": "string"}
            },
            "required": ["api_key"]
        })),
    },
    MyPlugin {
        api_key: String,
        client: reqwest::Client,
    }
}
```

## Plugin Configuration

### Configuration Schema

Plugins should define a JSON schema for their configuration:

```json
{
    "type": "object",
    "properties": {
        "api_endpoint": {
            "type": "string",
            "description": "API endpoint URL"
        },
        "api_key": {
            "type": "string",
            "description": "API authentication key"
        },
        "timeout_seconds": {
            "type": "integer",
            "default": 30,
            "description": "Request timeout in seconds"
        }
    },
    "required": ["api_endpoint", "api_key"]
}
```

### Loading a Plugin

```rust
let plugin_manager = PluginManager::new();

// Create plugin instance
let plugin = Arc::new(MyPlugin::new());

// Configure plugin
let mut config = HashMap::new();
config.insert("api_endpoint".to_string(), 
    serde_json::Value::String("https://api.example.com".to_string()));
config.insert("api_key".to_string(), 
    serde_json::Value::String("your-api-key".to_string()));

// Load plugin
plugin_manager.load_plugin(plugin, config).await?;
```

## Plugin Examples

### 1. Sign Transaction Plugin

The `sign_transaction_plugin.rs` example demonstrates how to create a plugin for signing transactions:

- Supports multiple key types (secp256k1, ed25519, RSA)
- Provides signing and verification capabilities
- Includes external API integration
- Implements proper configuration validation

### 2. API Integration Plugin

```rust
struct ApiPlugin {
    client: reqwest::Client,
    base_url: String,
    api_key: String,
}

#[async_trait]
impl Plugin for ApiPlugin {
    async fn execute(&self, input: PluginInput) -> Result<PluginResult> {
        match input.action.as_str() {
            "call_api" => {
                let endpoint = input.data["endpoint"]
                    .as_str()
                    .ok_or_else(|| FortressError::plugin("Missing endpoint"))?;
                
                let url = format!("{}/{}", self.base_url, endpoint);
                let response = self.client
                    .get(&url)
                    .header("Authorization", format!("Bearer {}", self.api_key))
                    .send()
                    .await
                    .map_err(|e| FortressError::plugin(format!("API call failed: {}", e)))?;

                let data: serde_json::Value = response
                    .json()
                    .await
                    .map_err(|e| FortressError::plugin(format!("Failed to parse response: {}", e)))?;

                Ok(PluginResult {
                    success: true,
                    data: Some(data),
                    error: None,
                    metrics: PluginMetrics::default(),
                })
            }
            _ => Err(FortressError::plugin("Unknown action")),
        }
    }
}
```

## Security Considerations

### Plugin Isolation

- Plugins run in the same process as Fortress
- Plugin access to Fortress internals is controlled through `PluginContext`
- Sensitive operations require explicit permission grants

### Secure Configuration

- Never hardcode secrets in plugin code
- Use secure configuration management
- Validate all input parameters
- Implement proper error handling without exposing sensitive information

### Memory Safety

- Zero out sensitive data when possible
- Use secure memory allocation for private keys
- Implement proper cleanup in the `cleanup()` method

## Best Practices

### 1. Error Handling

```rust
// Good: Use FortressError for plugin-specific errors
Err(FortressError::plugin_with_id("Operation failed", plugin_id))

// Bad: Panic or expose internal errors
panic!("Internal error occurred");
```

### 2. Resource Management

```rust
#[async_trait]
impl Plugin for MyPlugin {
    async fn cleanup(&self) -> Result<()> {
        // Close connections
        // Zero sensitive memory
        // Release resources
        Ok(())
    }
}
```

### 3. Metrics and Monitoring

```rust
let start_time = std::time::Instant::now();
// ... plugin logic ...
let execution_time = start_time.elapsed().as_millis() as u64;

let mut custom_metrics = HashMap::new();
custom_metrics.insert("operation".to_string(), 
    serde_json::Value::String("sign_transaction".to_string()));

Ok(PluginResult {
    success: true,
    data: Some(result_data),
    error: None,
    metrics: PluginMetrics {
        execution_time_ms: execution_time,
        memory_usage_bytes: 0,
        custom_metrics,
    },
})
```

### 4. Configuration Validation

```rust
fn validate_config(&self, config: &HashMap<String, serde_json::Value>) -> Result<()> {
    // Check required fields
    if !config.contains_key("required_field") {
        return Err(FortressError::plugin("Missing required field: required_field"));
    }

    // Validate field types and values
    if let Some(timeout) = config.get("timeout") {
        if let Some(timeout_val) = timeout.as_u64() {
            if timeout_val > 300 {
                return Err(FortressError::plugin("Timeout too large (max 300 seconds)"));
            }
        } else {
            return Err(FortressError::plugin("Timeout must be a number"));
        }
    }

    Ok(())
}
```

## Plugin Discovery and Management

### Listing Available Plugins

```rust
let plugins = plugin_manager.registry().list_plugins().await;
for plugin in plugins {
    println!("Plugin: {} ({})", plugin.name, plugin.version);
    println!("Capabilities: {:?}", plugin.capabilities);
}
```

### Finding Plugins by Capability

```rust
let signing_plugins = plugin_manager.registry()
    .get_plugins_by_capability(&PluginCapability::SignTransaction)
    .await;

for plugin in signing_plugins {
    println!("Found signing plugin: {}", plugin.name);
}
```

### Health Monitoring

```rust
let health_status = plugin_manager.get_all_health_status().await;
for (plugin_id, health) in health_status {
    if !health.healthy {
        eprintln!("Plugin {} is unhealthy: {}", plugin_id, health.message);
    }
}
```

## Deployment

### Plugin Distribution

Plugins can be distributed as:
1. Rust crates that depend on `fortress-core`
2. Dynamic libraries (.dll, .so, .dylib)
3. WebAssembly modules (future feature)

### Configuration Files

Plugin configuration can be stored in:
- TOML configuration files
- Environment variables
- Secure secret management systems
- Fortress's own configuration system

Example TOML configuration:

```toml
[plugins.sign_transaction]
enabled = true
path = "/path/to/sign_transaction_plugin.so"
config = { private_key = "0x...", key_type = "secp256k1", network = "ethereum" }

[plugins.api_integration]
enabled = true
path = "/path/to/api_plugin.so"
config = { api_endpoint = "https://api.example.com", api_key = "${API_KEY}" }
```

## Future Enhancements

1. **WebAssembly Support** - Run plugins in isolated WASM runtimes
2. **Plugin Marketplace** - Centralized repository for sharing plugins
3. **Hot Reloading** - Load/unload plugins without restarting Fortress
4. **Plugin Sandboxing** - Enhanced security through process isolation
5. **Plugin Dependencies** - Support for plugins that depend on other plugins
6. **Version Management** - Handle plugin versioning and compatibility

## Troubleshooting

### Common Issues

1. **Plugin fails to load**
   - Check plugin dependencies
   - Verify configuration schema
   - Ensure plugin implements all required trait methods

2. **Plugin execution fails**
   - Check plugin health status
   - Review error logs
   - Validate input parameters

3. **Performance issues**
   - Monitor plugin execution metrics
   - Check for memory leaks
   - Optimize plugin code

### Debug Mode

Enable debug logging for plugin development:

```rust
use tracing::{info, warn, error};

#[async_trait]
impl Plugin for MyPlugin {
    async fn execute(&self, input: PluginInput) -> Result<PluginResult> {
        info!("Executing plugin action: {}", input.action);
        
        let result = self.process_input(&input).await;
        
        match &result {
            Ok(_) => info!("Plugin execution successful"),
            Err(e) => error!("Plugin execution failed: {}", e),
        }
        
        result
    }
}
```

This architecture provides a solid foundation for building secure, extensible plugins that integrate seamlessly with Fortress while maintaining security and performance.
