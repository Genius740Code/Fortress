//! Plugin Templates and Simplified Plugin Creation
//! 
//! This file demonstrates various approaches to make plugin creation easier:
//! 1. Template-based plugins
//! 2. Macro-based plugin generation
//! 3. Declarative plugin configuration
//! 4. Simplified plugin traits for common use cases

use fortress_core::prelude::*;
use fortress_core::plugin::*;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ============================================================================
// TEMPLATE 1: Simple API Plugin Template
// ============================================================================

/// Simple API plugin template for basic HTTP API integration
pub struct SimpleApiPlugin {
    metadata: PluginMetadata,
    client: reqwest::Client,
    base_url: String,
    api_key: Option<String>,
}

impl SimpleApiPlugin {
    /// Create a new simple API plugin
    pub fn new(name: &str, base_url: &str) -> Self {
        Self {
            metadata: PluginMetadata {
                id: format!("simple-api-{}", name.to_lowercase().replace(' ', "-")),
                name: name.to_string(),
                version: "1.0.0".to_string(),
                description: format!("Simple API plugin for {}", name),
                author: "Fortress Team".to_string(),
                capabilities: vec![PluginCapability::ApiIntegration],
                config_schema: Some(serde_json::json!({
                    "type": "object",
                    "properties": {
                        "api_key": {"type": "string", "description": "API authentication key"},
                        "timeout": {"type": "integer", "default": 30, "description": "Request timeout in seconds"}
                    }
                })
            }),
            client: reqwest::Client::new(),
            base_url: base_url.to_string(),
            api_key: None,
        }
    }
}

#[async_trait]
impl Plugin for SimpleApiPlugin {
    fn metadata(&self) -> &PluginMetadata {
        &self.metadata
    }

    async fn initialize(&self, context: PluginContext) -> Result<()> {
        // Extract API key from config if provided
        if let Some(api_key) = context.config.get("api_key") {
            // In a real implementation, store this securely
        }
        Ok(())
    }

    async fn execute(&self, input: PluginInput) -> Result<PluginResult> {
        let start_time = std::time::Instant::now();
        
        match input.action.as_str() {
            "get" | "post" | "put" | "delete" => {
                let method = input.action.to_uppercase();
                let endpoint = input.data["endpoint"]
                    .as_str()
                    .ok_or_else(|| FortressError::plugin("Missing endpoint"))?;
                
                let url = format!("{}/{}", self.base_url, endpoint);
                
                let mut request = match method.as_str() {
                    "GET" => self.client.get(&url),
                    "POST" => self.client.post(&url),
                    "PUT" => self.client.put(&url),
                    "DELETE" => self.client.delete(&url),
                    _ => return Err(FortressError::plugin("Unsupported HTTP method")),
                };
                
                // Add API key if available
                if let Some(api_key) = &self.api_key {
                    request = request.header("Authorization", format!("Bearer {}", api_key));
                }
                
                // Add JSON body for POST/PUT
                if matches!(method.as_str(), "POST" | "PUT") {
                    if let Some(body) = input.data.get("body") {
                        request = request.json(body);
                    }
                }
                
                let response = request
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
                    metrics: PluginMetrics {
                        execution_time_ms: start_time.elapsed().as_millis() as u64,
                        memory_usage_bytes: 0,
                        custom_metrics: HashMap::new(),
                    },
                })
            }
            _ => Err(FortressError::plugin(format!("Unknown action: {}", input.action))),
        }
    }

    async fn cleanup(&self) -> Result<()> {
        Ok(())
    }

    fn validate_config(&self, config: &HashMap<String, serde_json::Value>) -> Result<()> {
        // Validate timeout if provided
        if let Some(timeout) = config.get("timeout") {
            if let Some(timeout_val) = timeout.as_u64() {
                if timeout_val > 300 {
                    return Err(FortressError::plugin("Timeout too large (max 300 seconds)"));
                }
            }
        }
        Ok(())
    }

    async fn health_check(&self) -> Result<PluginHealth> {
        Ok(PluginHealth {
            healthy: true,
            message: "API plugin is healthy".to_string(),
            last_check: chrono::Utc::now(),
        })
    }
}

// ============================================================================
// TEMPLATE 2: Macro-Based Plugin Creation
// ============================================================================

/// Macro to create simple plugins with minimal boilerplate
#[macro_export]
macro_rules! create_simple_plugin {
    (
        name: $name:expr,
        id: $id:expr,
        description: $description:expr,
        actions: [$($action:expr => $handler:expr),* $(,)?],
        config: {
            $($config_field:ident: $config_type:ty),* $(,)?
        }
    ) => {
        #[derive(Debug)]
        struct $name {
            metadata: $crate::plugin::PluginMetadata,
            $($config_field: $config_type,)*
        }

        impl $name {
            fn new() -> Self {
                Self {
                    metadata: $crate::plugin::PluginMetadata {
                        id: $id.to_string(),
                        name: $name.to_string(),
                        version: "1.0.0".to_string(),
                        description: $description.to_string(),
                        author: "Fortress Team".to_string(),
                        capabilities: vec![$crate::plugin::PluginCapability::Custom("simple".to_string())],
                        config_schema: None,
                    },
                    $($config_field: Default::default(),)*
                }
            }
        }

        #[async_trait::async_trait]
        impl $crate::plugin::Plugin for $name {
            fn metadata(&self) -> &$crate::plugin::PluginMetadata {
                &self.metadata
            }

            async fn initialize(&self, _context: $crate::plugin::PluginContext) -> $crate::error::Result<()> {
                Ok(())
            }

            async fn execute(&self, input: $crate::plugin::PluginInput) -> $crate::error::Result<$crate::plugin::PluginResult> {
                let start_time = std::time::Instant::now();
                
                let result = match input.action.as_str() {
                    $(
                        $action => $handler(&self, &input).await,
                    )*
                    _ => Err($crate::error::FortressError::plugin(format!("Unknown action: {}", input.action))),
                };

                let execution_time = start_time.elapsed().as_millis() as u64;
                
                match result {
                    Ok(data) => Ok($crate::plugin::PluginResult {
                        success: true,
                        data: Some(data),
                        error: None,
                        metrics: $crate::plugin::PluginMetrics {
                            execution_time_ms: execution_time,
                            memory_usage_bytes: 0,
                            custom_metrics: std::collections::HashMap::new(),
                        },
                    }),
                    Err(e) => Ok($crate::plugin::PluginResult {
                        success: false,
                        data: None,
                        error: Some(e.to_string()),
                        metrics: $crate::plugin::PluginMetrics {
                            execution_time_ms: execution_time,
                            memory_usage_bytes: 0,
                            custom_metrics: std::collections::HashMap::new(),
                        },
                    }),
                }
            }

            async fn cleanup(&self) -> $crate::error::Result<()> {
                Ok(())
            }

            fn validate_config(&self, _config: &std::collections::HashMap<String, serde_json::Value>) -> $crate::error::Result<()> {
                Ok(())
            }

            async fn health_check(&self) -> $crate::error::Result<$crate::plugin::PluginHealth> {
                Ok($crate::plugin::PluginHealth {
                    healthy: true,
                    message: "Plugin is healthy".to_string(),
                    last_check: chrono::Utc::now(),
                })
            }
        }
    };
}

// Example usage of the macro
create_simple_plugin! {
    name: MathPlugin,
    id: "math-operations",
    description: "Simple mathematical operations plugin",
    actions: [
        "add" => handle_add,
        "multiply" => handle_multiply,
        "square" => handle_square
    ],
    config: {
        precision: u32,
    }
}

async fn handle_add(plugin: &MathPlugin, input: &PluginInput) -> Result<serde_json::Value> {
    let a = input.data["a"].as_f64().ok_or_else(|| FortressError::plugin("Invalid 'a' value"))?;
    let b = input.data["b"].as_f64().ok_or_else(|| FortressError::plugin("Invalid 'b' value"))?;
    
    Ok(serde_json::json!({
        "result": a + b,
        "operation": "add"
    }))
}

async fn handle_multiply(plugin: &MathPlugin, input: &PluginInput) -> Result<serde_json::Value> {
    let a = input.data["a"].as_f64().ok_or_else(|| FortressError::plugin("Invalid 'a' value"))?;
    let b = input.data["b"].as_f64().ok_or_else(|| FortressError::plugin("Invalid 'b' value"))?;
    
    Ok(serde_json::json!({
        "result": a * b,
        "operation": "multiply"
    }))
}

async fn handle_square(plugin: &MathPlugin, input: &PluginInput) -> Result<serde_json::Value> {
    let value = input.data["value"].as_f64().ok_or_else(|| FortressError::plugin("Invalid 'value'"))?;
    
    Ok(serde_json::json!({
        "result": value * value,
        "operation": "square"
    }))
}

// ============================================================================
// TEMPLATE 3: Declarative Plugin Configuration
// ============================================================================

/// Declarative plugin definition using configuration
#[derive(Debug, Clone)]
pub struct PluginAction {
    pub name: String,
    pub description: String,
    pub handler: fn(&PluginInput) -> Result<serde_json::Value>,
}

#[derive(Debug)]
pub struct DeclarativePlugin {
    metadata: PluginMetadata,
    actions: HashMap<String, PluginAction>,
}

impl DeclarativePlugin {
    pub fn new(name: &str, description: &str) -> Self {
        Self {
            metadata: PluginMetadata {
                id: format!("declarative-{}", name.to_lowercase().replace(' ', "-')),
                name: name.to_string(),
                version: "1.0.0".to_string(),
                description: description.to_string(),
                author: "Fortress Team".to_string(),
                capabilities: vec![PluginCapability::Custom("declarative".to_string())],
                config_schema: None,
            },
            actions: HashMap::new(),
        }
    }

    pub fn add_action(mut self, name: &str, description: &str, handler: fn(&PluginInput) -> Result<serde_json::Value>) -> Self {
        self.actions.insert(name.to_string(), PluginAction {
            name: name.to_string(),
            description: description.to_string(),
            handler,
        });
        self
    }

    pub fn build(self) -> Self {
        self
    }
}

#[async_trait]
impl Plugin for DeclarativePlugin {
    fn metadata(&self) -> &PluginMetadata {
        &self.metadata
    }

    async fn initialize(&self, _context: PluginContext) -> Result<()> {
        Ok(())
    }

    async fn execute(&self, input: PluginInput) -> Result<PluginResult> {
        let start_time = std::time::Instant::now();
        
        match self.actions.get(&input.action) {
            Some(action) => {
                match (action.handler)(&input) {
                    Ok(data) => Ok(PluginResult {
                        success: true,
                        data: Some(data),
                        error: None,
                        metrics: PluginMetrics {
                            execution_time_ms: start_time.elapsed().as_millis() as u64,
                            memory_usage_bytes: 0,
                            custom_metrics: HashMap::new(),
                        },
                    }),
                    Err(e) => Ok(PluginResult {
                        success: false,
                        data: None,
                        error: Some(e.to_string()),
                        metrics: PluginMetrics {
                            execution_time_ms: start_time.elapsed().as_millis() as u64,
                            memory_usage_bytes: 0,
                            custom_metrics: HashMap::new(),
                        },
                    }),
                }
            }
            None => Err(FortressError::plugin(format!("Unknown action: {}", input.action))),
        }
    }

    async fn cleanup(&self) -> Result<()> {
        Ok(())
    }

    fn validate_config(&self, _config: &HashMap<String, serde_json::Value>) -> Result<()> {
        Ok(())
    }

    async fn health_check(&self) -> Result<PluginHealth> {
        Ok(PluginHealth {
            healthy: true,
            message: "Declarative plugin is healthy".to_string(),
            last_check: chrono::Utc::now(),
        })
    }
}

// ============================================================================
// TEMPLATE 4: Plugin Builder Pattern
// ============================================================================

pub struct PluginBuilder {
    metadata: PluginMetadata,
}

impl PluginBuilder {
    pub fn new(name: &str) -> Self {
        Self {
            metadata: PluginMetadata {
                id: format!("builder-{}", name.to_lowercase().replace(' ', "-')),
                name: name.to_string(),
                version: "1.0.0".to_string(),
                description: String::new(),
                author: "Fortress Team".to_string(),
                capabilities: Vec::new(),
                config_schema: None,
            },
        }
    }

    pub fn description(mut self, description: &str) -> Self {
        self.metadata.description = description.to_string();
        self
    }

    pub fn version(mut self, version: &str) -> Self {
        self.metadata.version = version.to_string();
        self
    }

    pub fn author(mut self, author: &str) -> Self {
        self.metadata.author = author.to_string();
        self
    }

    pub fn capability(mut self, capability: PluginCapability) -> Self {
        self.metadata.capabilities.push(capability);
        self
    }

    pub fn config_schema(mut self, schema: serde_json::Value) -> Self {
        self.metadata.config_schema = Some(schema);
        self
    }

    pub fn build_simple_handler(self) -> SimpleHandlerPlugin {
        SimpleHandlerPlugin {
            metadata: self.metadata,
            handlers: HashMap::new(),
        }
    }
}

#[derive(Debug)]
pub struct SimpleHandlerPlugin {
    metadata: PluginMetadata,
    handlers: HashMap<String, fn(&PluginInput) -> Result<serde_json::Value>>,
}

impl SimpleHandlerPlugin {
    pub fn add_handler(mut self, action: &str, handler: fn(&PluginInput) -> Result<serde_json::Value>) -> Self {
        self.handlers.insert(action.to_string(), handler);
        self
    }
}

#[async_trait]
impl Plugin for SimpleHandlerPlugin {
    fn metadata(&self) -> &PluginMetadata {
        &self.metadata
    }

    async fn initialize(&self, _context: PluginContext) -> Result<()> {
        Ok(())
    }

    async fn execute(&self, input: PluginInput) -> Result<PluginResult> {
        let start_time = std::time::Instant::now();
        
        match self.handlers.get(&input.action) {
            Some(handler) => {
                match (handler)(&input) {
                    Ok(data) => Ok(PluginResult {
                        success: true,
                        data: Some(data),
                        error: None,
                        metrics: PluginMetrics {
                            execution_time_ms: start_time.elapsed().as_millis() as u64,
                            memory_usage_bytes: 0,
                            custom_metrics: HashMap::new(),
                        },
                    }),
                    Err(e) => Ok(PluginResult {
                        success: false,
                        data: None,
                        error: Some(e.to_string()),
                        metrics: PluginMetrics {
                            execution_time_ms: start_time.elapsed().as_millis() as u64,
                            memory_usage_bytes: 0,
                            custom_metrics: HashMap::new(),
                        },
                    }),
                }
            }
            None => Err(FortressError::plugin(format!("Unknown action: {}", input.action))),
        }
    }

    async fn cleanup(&self) -> Result<()> {
        Ok(())
    }

    fn validate_config(&self, _config: &HashMap<String, serde_json::Value>) -> Result<()> {
        Ok(())
    }

    async fn health_check(&self) -> Result<PluginHealth> {
        Ok(PluginHealth {
            healthy: true,
            message: "Simple handler plugin is healthy".to_string(),
            last_check: chrono::Utc::now(),
        })
    }
}

// ============================================================================
// EXAMPLE USAGE
// ============================================================================

#[tokio::main]
async fn main() -> Result<()> {
    let plugin_manager = PluginManager::new();

    // Example 1: Simple API Plugin
    let api_plugin = Arc::new(SimpleApiPlugin::new("JSONPlaceholder", "https://jsonplaceholder.typicode.com"));
    let api_config = HashMap::new();
    plugin_manager.load_plugin(api_plugin, api_config).await?;

    // Example 2: Declarative Plugin
    let text_plugin = DeclarativePlugin::new("Text Operations", "Simple text processing operations")
        .add_action("uppercase", "Convert text to uppercase", |input| {
            let text = input.data["text"]
                .as_str()
                .ok_or_else(|| FortressError::plugin("Missing 'text' field"))?;
            Ok(serde_json::json!({
                "result": text.to_uppercase(),
                "original": text
            }))
        })
        .add_action("reverse", "Reverse text", |input| {
            let text = input.data["text"]
                .as_str()
                .ok_or_else(|| FortressError::plugin("Missing 'text' field"))?;
            Ok(serde_json::json!({
                "result": text.chars().rev().collect::<String>(),
                "original": text
            }))
        })
        .build();

    let text_plugin = Arc::new(text_plugin);
    let text_config = HashMap::new();
    plugin_manager.load_plugin(text_plugin, text_config).await?;

    // Example 3: Builder Pattern Plugin
    let calc_plugin = PluginBuilder::new("Calculator")
        .description("Simple calculator plugin")
        .capability(PluginCapability::Custom("calculation"))
        .build_simple_handler()
        .add_handler("add", |input| {
            let a = input.data["a"].as_f64().ok_or_else(|| FortressError::plugin("Invalid 'a'"))?;
            let b = input.data["b"].as_f64().ok_or_else(|| FortressError::plugin("Invalid 'b'"))?;
            Ok(serde_json::json!({"result": a + b}))
        })
        .add_handler("subtract", |input| {
            let a = input.data["a"].as_f64().ok_or_else(|| FortressError::plugin("Invalid 'a'"))?;
            let b = input.data["b"].as_f64().ok_or_else(|| FortressError::plugin("Invalid 'b'"))?;
            Ok(serde_json::json!({"result": a - b}))
        });

    let calc_plugin = Arc::new(calc_plugin);
    let calc_config = HashMap::new();
    plugin_manager.load_plugin(calc_plugin, calc_config).await?;

    // Test the plugins
    println!("Testing API plugin:");
    let api_result = plugin_manager.execute_plugin(
        "simple-api-jsonplaceholder", 
        PluginInput {
            action: "get".to_string(),
            data: serde_json::json!({"endpoint": "posts/1"}),
            parameters: HashMap::new(),
        }
    ).await?;
    println!("API Result: {}", serde_json::to_string_pretty(&api_result)?);

    println!("\nTesting text plugin:");
    let text_result = plugin_manager.execute_plugin(
        "declarative-text-operations",
        PluginInput {
            action: "uppercase".to_string(),
            data: serde_json::json!({"text": "hello world"}),
            parameters: HashMap::new(),
        }
    ).await?;
    println!("Text Result: {}", serde_json::to_string_pretty(&text_result)?);

    println!("\nTesting calculator plugin:");
    let calc_result = plugin_manager.execute_plugin(
        "builder-calculator",
        PluginInput {
            action: "add".to_string(),
            data: serde_json::json!({"a": 5, "b": 3}),
            parameters: HashMap::new(),
        }
    ).await?;
    println!("Calc Result: {}", serde_json::to_string_pretty(&calc_result)?);

    Ok(())
}
