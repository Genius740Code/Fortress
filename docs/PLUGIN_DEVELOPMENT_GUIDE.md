# Fortress Plugin Development Guide

## Overview

Fortress provides multiple approaches to create plugins, from simple templates to fully generated plugins. Choose the approach that best fits your needs:

## 🚀 Quick Start Options

### 1. Template-Based Plugins (Easiest)
**Best for**: Simple operations, quick prototypes, learning

```rust
use fortress_core::prelude::*;
use fortress_core::plugin::*;

// Use the built-in template
let plugin = SimpleApiPlugin::new("My API", "https://api.example.com");
```

**Pros**:
- Minimal code required
- Built-in HTTP client
- Automatic error handling
- Zero boilerplate

**Cons**:
- Limited to HTTP API calls
- Less customization

### 2. Macro-Based Plugins (Easy)
**Best for**: Multiple actions, custom logic

```rust
create_simple_plugin! {
    name: MyPlugin,
    id: "my-plugin",
    description: "My custom plugin",
    actions: [
        "calculate" => handle_calculate,
        "validate" => handle_validate
    ],
    config: {
        timeout: u32,
        retries: u32,
    }
}
```

**Pros**:
- Very little boilerplate
- Multiple actions support
- Configuration handling
- Type-safe

**Cons**:
- Limited to simple handlers
- Less flexibility than full trait

### 3. Declarative Plugins (Intermediate)
**Best for**: Data transformations, simple workflows

```rust
let plugin = DeclarativePlugin::new("Text Processor", "Text operations")
    .add_action("uppercase", "Convert to uppercase", |input| {
        let text = input.data["text"].as_str().unwrap_or("");
        Ok(serde_json::json!({"result": text.to_uppercase()}))
    })
    .add_action("reverse", "Reverse text", |input| {
        let text = input.data["text"].as_str().unwrap_or("");
        Ok(serde_json::json!({"result": text.chars().rev().collect::<String>()}))
    })
    .build();
```

**Pros**:
- Fluent API
- Action chaining
- Good for simple logic
- No trait implementation needed

**Cons**:
- Limited to synchronous handlers
- Basic configuration only

### 4. Configuration-Based Plugins (Advanced)
**Best for**: Non-programmers, rapid prototyping, dynamic plugins

Create a JSON configuration file:

```json
{
    "name": "Weather Plugin",
    "id": "weather-api",
    "description": "Get weather information",
    "version": "1.0.0",
    "capabilities": ["api_integration"],
    "actions": {
        "get_weather": {
            "description": "Get weather for a city",
            "handler_type": "api",
            "parameters": {
                "city": {
                    "type": "string",
                    "required": true,
                    "description": "City name"
                }
            },
            "api_endpoint": "https://api.openweathermap.org/data/2.5/weather?q={city}&appid={api_key}"
        }
    },
    "config_schema": {
        "type": "object",
        "properties": {
            "api_key": {"type": "string", "description": "API key"}
        },
        "required": ["api_key"]
    }
}
```

Then load it:

```rust
let plugin = GeneratedPlugin::load_from_file("weather_plugin.json")?;
```

**Pros**:
- No Rust code required
- Dynamic plugin loading
- Easy for non-developers
- JSON/YAML configuration

**Cons**:
- Limited functionality
- Performance overhead
- Less type safety

### 5. Full Plugin Trait (Most Flexible)
**Best for**: Complex plugins, maximum control, production use

```rust
#[async_trait]
impl Plugin for MyPlugin {
    fn metadata(&self) -> &PluginMetadata { /* ... */ }
    async fn initialize(&self, context: PluginContext) -> Result<()> { /* ... */ }
    async fn execute(&self, input: PluginInput) -> Result<PluginResult> { /* ... */ }
    async fn cleanup(&self) -> Result<()> { /* ... */ }
    fn validate_config(&self, config: &HashMap<String, serde_json::Value>) -> Result<()> { /* ... */ }
    async fn health_check(&self) -> Result<PluginHealth> { /* ... */ }
}
```

**Pros**:
- Full control over behavior
- Async operations support
- Complex configuration
- Best performance
- Complete error handling

**Cons**:
- More boilerplate
- Steeper learning curve

## 📋 Choosing the Right Approach

| Use Case | Recommended Approach | Why |
|------------|-------------------|------|
| **Quick API integration** | Template-Based | Built-in HTTP client, minimal code |
| **Multiple simple actions** | Macro-Based | Automatic action routing, type-safe |
| **Data transformations** | Declarative | Fluent API, clear logic flow |
| **Non-developer users** | Configuration-Based | No coding required, JSON-based |
| **Complex business logic** | Full Trait | Maximum flexibility and control |
| **Production plugins** | Full Trait | Best performance, complete error handling |
| **Learning/Prototyping** | Template or Macro | Easy to start, good documentation |

## 🛠️ Development Workflow

### Step 1: Choose Your Approach
Start with the simplest approach that meets your needs. You can always migrate to more complex approaches later.

### Step 2: Create Plugin Structure
```bash
# Create plugin directory
mkdir my-fortress-plugin
cd my-fortress-plugin

# Create Cargo.toml
cat > Cargo.toml << EOF
[package]
name = "my-fortress-plugin"
version = "0.1.0"
edition = "2021"

[lib]
crate-type = ["cdylib", "rlib"]

[dependencies]
fortress-core = { path = "../fortress/crates/fortress-core" }
tokio = { version = "1.0", features = ["full"] }
serde = { version = "1.0", features = ["derive"] }
async-trait = "0.1"
EOF
```

### Step 3: Implement Plugin
Choose one of the approaches above and implement your plugin.

### Step 4: Test Plugin
```rust
#[tokio::main]
async fn main() -> Result<()> {
    let plugin_manager = PluginManager::new();
    let plugin = Arc::new(MyPlugin::new());
    let config = HashMap::new();
    
    plugin_manager.load_plugin(plugin, config).await?;
    
    let result = plugin_manager.execute_plugin(
        "my-plugin",
        PluginInput {
            action: "my_action".to_string(),
            data: serde_json::json!({"key": "value"}),
            parameters: HashMap::new(),
        }
    ).await?;
    
    println!("Result: {}", serde_json::to_string_pretty(&result)?);
    Ok(())
}
```

### Step 5: Package and Deploy
```bash
# Build plugin
cargo build --release

# Deploy to Fortress plugins directory
cp target/release/libmy_fortress_plugin.dll ~/.fortress/plugins/
```

## 🔧 Plugin Capabilities

Choose capabilities that match your plugin's functionality:

```rust
let capabilities = vec![
    PluginCapability::SignTransaction,    // For cryptographic signing
    PluginCapability::VerifySignature,    // For signature verification
    PluginCapability::GenerateKey,         // For key generation
    PluginCapability::Encrypt,             // For data encryption
    PluginCapability::Decrypt,             // For data decryption
    PluginCapability::Hash,                // For hashing operations
    PluginCapability::ApiIntegration,      // For external API calls
    PluginCapability::SecretManagement,    // For secret storage/management
    PluginCapability::Custom("my_capability".to_string()), // Custom capabilities
];
```

## 📝 Best Practices

### 1. Error Handling
```rust
// Good: Use FortressError for plugin-specific errors
Err(FortressError::plugin("Operation failed: {}", error_message))

// Bad: Panic or expose internal errors
panic!("Internal error occurred");
```

### 2. Configuration Validation
```rust
fn validate_config(&self, config: &HashMap<String, serde_json::Value>) -> Result<()> {
    // Check required fields
    if !config.contains_key("api_key") {
        return Err(FortressError::plugin("Missing required field: api_key"));
    }
    
    // Validate field types and values
    if let Some(timeout) = config.get("timeout") {
        if let Some(timeout_val) = timeout.as_u64() {
            if timeout_val > 300 {
                return Err(FortressError::plugin("Timeout too large (max 300 seconds)"));
            }
        }
    }
    
    Ok(())
}
```

### 3. Metrics and Monitoring
```rust
async fn execute(&self, input: PluginInput) -> Result<PluginResult> {
    let start_time = std::time::Instant::now();
    
    // ... your plugin logic ...
    
    let execution_time = start_time.elapsed().as_millis() as u64;
    let mut custom_metrics = HashMap::new();
    custom_metrics.insert("operation".to_string(), 
        serde_json::Value::String(input.action.clone()));
    
    Ok(PluginResult {
        success: true,
        data: Some(result_data),
        error: None,
        metrics: PluginMetrics {
            execution_time_ms: execution_time,
            memory_usage_bytes: 0, // Could be implemented with memory profiling
            custom_metrics,
        },
    })
}
```

### 4. Security Considerations
- Never hardcode secrets in plugin code
- Use secure configuration management
- Validate all input parameters
- Implement proper error handling without exposing sensitive information
- Zero out sensitive memory when possible

### 5. Performance Optimization
- Use async operations for I/O-bound tasks
- Cache expensive operations when appropriate
- Minimize allocations in hot paths
- Use appropriate data structures

## 🚀 Advanced Features

### Plugin Composition
Combine multiple plugins for complex workflows:

```rust
// Chain plugins together
let text_result = plugin_manager.execute_plugin("text-processor", text_input).await?;
let api_result = plugin_manager.execute_plugin("api-client", api_input).await?;
let crypto_result = plugin_manager.execute_plugin("crypto", crypto_input).await?;
```

### Plugin Dependencies
Future versions will support plugin dependencies:

```rust
// Planned feature
let plugin = PluginBuilder::new("advanced-plugin")
    .depends_on("crypto-plugin")
    .depends_on("api-client")
    .build();
```

### Hot Reloading
Future versions will support hot plugin reloading:

```rust
// Planned feature
plugin_manager.reload_plugin("my-plugin").await?;
```

## 🔍 Debugging and Testing

### Unit Testing
```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_plugin_execution() {
        let plugin = MyPlugin::new();
        let input = PluginInput {
            action: "test".to_string(),
            data: serde_json::json!({"value": 42}),
            parameters: HashMap::new(),
        };

        let result = plugin.execute(input).await;
        assert!(result.is_ok());
        
        let plugin_result = result.unwrap();
        assert!(plugin_result.success);
        assert!(plugin_result.data.is_some());
    }
}
```

### Integration Testing
```rust
#[tokio::test]
async fn test_plugin_integration() {
    let plugin_manager = PluginManager::new();
    let plugin = Arc::new(MyPlugin::new());
    let config = HashMap::new();
    
    plugin_manager.load_plugin(plugin, config).await.unwrap();
    
    let result = plugin_manager.execute_plugin(
        "my-plugin",
        PluginInput {
            action: "test".to_string(),
            data: serde_json::json!({"value": 42}),
            parameters: HashMap::new(),
        }
    ).await.unwrap();
    
    assert!(result.success);
}
```

### Debug Logging
```rust
use tracing::{info, warn, error};

#[async_trait]
impl Plugin for MyPlugin {
    async fn execute(&self, input: PluginInput) -> Result<PluginResult> {
        info!("Executing action: {}", input.action);
        
        match self.process_input(&input).await {
            Ok(result) => {
                info!("Action completed successfully");
                Ok(result)
            }
            Err(e) => {
                error!("Action failed: {}", e);
                Err(e)
            }
        }
    }
}
```

## 📚 Examples Repository

Check out these example plugins:

1. **Sign Transaction Plugin** (`examples/sign_transaction_plugin.rs`)
   - Cryptographic signing
   - Multiple key types
   - API integration

2. **Plugin Templates** (`examples/plugin_templates.rs`)
   - Multiple creation approaches
   - Best practices
   - Performance examples

3. **Configuration-Based Plugins** (`examples/config_based_plugins.rs`)
   - JSON-based plugin definition
   - Script execution
   - API integration

4. **Math Plugin** (in templates)
   - Simple calculations
   - Multiple actions
   - Type safety

5. **Text Processing Plugin** (in templates)
   - String transformations
   - Declarative approach
   - Easy to extend

## 🤝 Contributing

We welcome contributions to the plugin system! Areas for improvement:

1. **More Templates**: Add templates for common use cases
2. **Better Scripting**: Support for Python, JavaScript in plugins
3. **Plugin Marketplace**: Central repository for sharing plugins
4. **Performance**: Optimize plugin loading and execution
5. **Documentation**: Improve guides and examples

## 🆘 Getting Help

- **Documentation**: Check `PLUGIN_ARCHITECTURE.md` for technical details
- **Examples**: Browse the `examples/` directory
- **Issues**: Report bugs and request features on GitHub
- **Community**: Join our Discord for discussions and support

Happy plugin development! 🎉
