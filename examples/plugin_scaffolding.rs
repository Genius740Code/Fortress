//! Plugin Scaffolding Tool
//! 
//! This tool helps generate plugin scaffolding code quickly.
//! Run it with different options to create different types of plugins.

use std::env;
use std::fs;
use std::path::Path;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    
    if args.len() < 3 {
        print_usage();
        return Ok(());
    }
    
    let plugin_type = &args[1];
    let plugin_name = &args[2];
    
    match plugin_type.as_str() {
        "template" => create_template_plugin(plugin_name),
        "macro" => create_macro_plugin(plugin_name),
        "declarative" => create_declarative_plugin(plugin_name),
        "config" => create_config_plugin(plugin_name),
        "full" => create_full_plugin(plugin_name),
        _ => {
            eprintln!("Unknown plugin type: {}", plugin_type);
            print_usage();
            Ok(())
        }
    }
}

fn print_usage() {
    println!("Plugin Scaffolding Tool");
    println!("");
    println!("Usage: cargo run --example plugin_scaffolding <type> <name>");
    println!("");
    println!("Types:");
    println!("  template     - Simple template-based plugin");
    println!("  macro        - Macro-based plugin with multiple actions");
    println!("  declarative  - Declarative plugin with fluent API");
    println!("  config       - Configuration-based plugin (JSON)");
    println!("  full         - Full plugin trait implementation");
    println!("");
    println!("Examples:");
    println!("  cargo run --example plugin_scaffolding template MyApiPlugin");
    println!("  cargo run --example plugin_scaffolding macro CalculatorPlugin");
    println!("  cargo run --example plugin_scaffolding declarative TextProcessor");
}

fn create_template_plugin(name: &str) -> Result<(), Box<dyn std::error::Error>> {
    let dir_name = name.to_lowercase().replace('_', "-");
    fs::create_dir_all(&dir_name)?;
    
    // Cargo.toml
    let cargo_toml = format!(
        r#"[package]
name = "{}"
version = "0.1.0"
edition = "2021"

[lib]
crate-type = ["cdylib", "rlib"]

[dependencies]
fortress-core = {{ path = "../../crates/fortress-core" }}
tokio = {{ version = "1.0", features = ["full"] }}
serde = {{ version = "1.0", features = ["derive"] }}
async-trait = "0.1"
reqwest = {{ version = "0.11", features = ["json"] }}
"#, name);
    
    fs::write(format!("{}/Cargo.toml", dir_name), cargo_toml)?;
    
    // lib.rs
    let lib_rs = format!(
        r#"use fortress_core::prelude::*;
use fortress_core::plugin::*;
use async_trait::async_trait;
use serde::{{Deserialize, Serialize}};
use std::collections::HashMap;

pub struct {} {{
    metadata: PluginMetadata,
    client: reqwest::Client,
    base_url: String,
}}

impl {} {{
    pub fn new(base_url: &str) -> Self {{
        Self {{
            metadata: PluginMetadata {{
                id: "{}".to_string(),
                name: "{}".to_string(),
                version: "1.0.0".to_string(),
                description: "Template-based API plugin".to_string(),
                author: "Fortress Team".to_string(),
                capabilities: vec![PluginCapability::ApiIntegration],
                config_schema: Some(serde_json::json!({{
                    "type": "object",
                    "properties": {{
                        "api_key": {{"type": "string", "description": "API authentication key"}},
                        "timeout": {{"type": "integer", "default": 30, "description": "Request timeout in seconds"}}
                    }}
                }}),
            }},
            client: reqwest::Client::new(),
            base_url: base_url.to_string(),
        }}
    }}
}}

#[async_trait]
impl Plugin for {} {{
    fn metadata(&self) -> &PluginMetadata {{
        &self.metadata
    }}

    async fn initialize(&self, context: PluginContext) -> Result<()> {{
        // Extract API key from config if provided
        if let Some(api_key) = context.config.get("api_key") {{
            // Store API key securely for later use
            println!("API key configured");
        }}
        Ok(())
    }}

    async fn execute(&self, input: PluginInput) -> Result<PluginResult> {{
        let start_time = std::time::Instant::now();
        
        match input.action.as_str() {{
            "get" => {{
                let endpoint = input.data["endpoint"]
                    .as_str()
                    .ok_or_else(|| FortressError::plugin("Missing endpoint"))?;
                
                let url = format!("{}/{{}}", self.base_url, endpoint);
                
                let response = self.client
                    .get(&url)
                    .send()
                    .await
                    .map_err(|e| FortressError::plugin(format!("API call failed: {{}}", e)))?;

                let data: serde_json::Value = response
                    .json()
                    .await
                    .map_err(|e| FortressError::plugin(format!("Failed to parse response: {{}}", e)))?;

                Ok(PluginResult {{
                    success: true,
                    data: Some(data),
                    error: None,
                    metrics: PluginMetrics {{
                        execution_time_ms: start_time.elapsed().as_millis() as u64,
                        memory_usage_bytes: 0,
                        custom_metrics: HashMap::new(),
                    }},
                }})
            }}
            _ => Err(FortressError::plugin(format!("Unknown action: {{}}", input.action))),
        }}
    }}

    async fn cleanup(&self) -> Result<()> {{
        Ok(())
    }}

    fn validate_config(&self, config: &HashMap<String, serde_json::Value>) -> Result<()> {{
        // Validate configuration
        if let Some(timeout) = config.get("timeout") {{
            if let Some(timeout_val) = timeout.as_u64() {{
                if timeout_val > 300 {{
                    return Err(FortressError::plugin("Timeout too large (max 300 seconds)"));
                }}
            }}
        }}
        Ok(())
    }}

    async fn health_check(&self) -> Result<PluginHealth> {{
        Ok(PluginHealth {{
            healthy: true,
            message: "Template plugin is healthy".to_string(),
            last_check: chrono::Utc::now(),
        }})
    }}
}}
"#, name, name, name.to_lowercase().replace('_', "-"), name, name, name);
    
    fs::write(format!("{}/src/lib.rs", dir_name), lib_rs)?;
    fs::create_dir_all(format!("{}/src", dir_name))?;
    
    println!("✓ Template plugin '{}' created in {}/", name, dir_name);
    println!("");
    println!("Next steps:");
    println!("1. cd {}", dir_name);
    println!("2. Edit src/lib.rs to customize your plugin");
    println!("3. cargo build");
    println!("4. Test with: cargo test");
    
    Ok(())
}

fn create_macro_plugin(name: &str) -> io::Result<()> {
    let dir_name = name.to_lowercase().replace('_', "-");
    fs::create_dir_all(&dir_name)?;
    
    // Cargo.toml
    let cargo_toml = format!(r#"[package]
name = "{}"
version = "0.1.0"
edition = "2021"

[lib]
crate-type = ["cdylib", "rlib"]

[dependencies]
fortress-core = {{ path = "../../crates/fortress-core" }}
tokio = {{ version = "1.0", features = ["full"] }}
serde = {{ version = "1.0", features = ["derive"] }}
async-trait = "0.1"
"#, name);
    
    fs::write(format!("{}/Cargo.toml", dir_name), cargo_toml)?;
    
    // lib.rs
    let lib_rs = format!(r#"use fortress_core::prelude::*;
use fortress_core::plugin::*;
use async_trait::async_trait;
use serde::{{Deserialize, Serialize}};
use std::collections::HashMap;

// Import the macro from fortress_core
use fortress_core::create_simple_plugin;

// Define action handlers
async fn handle_action1(plugin: &{}, input: &PluginInput) -> Result<serde_json::Value> {{
    // Your action logic here
    let value = input.data["value"]
        .as_f64()
        .ok_or_else(|| FortressError::plugin("Invalid 'value'"))?;
    
    Ok(serde_json::json!({{
        "result": value * 2,
        "operation": "double"
    }}))
}}

async fn handle_action2(plugin: &{}, input: &PluginInput) -> Result<serde_json::Value> {{
    // Your action logic here
    let text = input.data["text"]
        .as_str()
        .ok_or_else(|| FortressError::plugin("Invalid 'text'"))?;
    
    Ok(serde_json::json!({{
        "result": text.to_uppercase(),
        "operation": "uppercase"
    }}))
}}

// Create the plugin using the macro
create_simple_plugin! {{
    name: {},
    id: "{}",
    description: "Macro-based plugin with multiple actions",
    actions: [
        "action1" => handle_action1,
        "action2" => handle_action2
    ],
    config: {{
        timeout: u32,
        retries: u32,
    }}
}}

#[cfg(test)]
mod tests {{
    use super::*;

    #[tokio::test]
    async fn test_action1() {{
        let plugin = {}::new();
        let input = PluginInput {{
            action: "action1".to_string(),
            data: serde_json::json!({{"value": 21}}),
            parameters: HashMap::new(),
        }};

        let result = plugin.execute(input).await.unwrap();
        assert!(result.success);
        
        let data = result.data.unwrap();
        assert_eq!(data["result"], 42.0);
        assert_eq!(data["operation"], "double");
    }}

    #[tokio::test]
    async fn test_action2() {{
        let plugin = {}::new();
        let input = PluginInput {{
            action: "action2".to_string(),
            data: serde_json::json!({{"text": "hello"}}),
            parameters: HashMap::new(),
        }};

        let result = plugin.execute(input).await.unwrap();
        assert!(result.success);
        
        let data = result.data.unwrap();
        assert_eq!(data["result"], "HELLO");
        assert_eq!(data["operation"], "uppercase");
    }}
}}
"#, name, name, name, name, name, name);
    
    fs::write(format!("{}/src/lib.rs", dir_name), lib_rs)?;
    fs::create_dir_all(format!("{}/src", dir_name))?;
    
    println!("✓ Macro plugin '{}' created in {}/", name, dir_name);
    println!("");
    println!("Next steps:");
    println!("1. cd {}", dir_name);
    println!("2. Customize action handlers in src/lib.rs");
    println!("3. Add more actions if needed");
    println!("4. cargo build");
    println!("5. Test with: cargo test");
    
    Ok(())
}

fn create_declarative_plugin(name: &str) -> io::Result<()> {
    let dir_name = name.to_lowercase().replace('_', "-");
    fs::create_dir_all(&dir_name)?;
    
    // Cargo.toml
    let cargo_toml = format!(r#"[package]
name = "{}"
version = "0.1.0"
edition = "2021"

[lib]
crate-type = ["cdylib", "rlib"]

[dependencies]
fortress-core = {{ path = "../../crates/fortress-core" }}
tokio = {{ version = "1.0", features = ["full"] }}
serde = {{ version = "1.0", features = ["derive"] }}
async-trait = "0.1"
"#, name);
    
    fs::write(format!("{}/Cargo.toml", dir_name), cargo_toml)?;
    
    // lib.rs
    let lib_rs = format!(r#"use fortress_core::prelude::*;
use fortress_core::plugin::*;
use async_trait::async_trait;
use serde::{{Deserialize, Serialize}};
use std::collections::HashMap;

pub fn create_plugin() -> impl Plugin {{
    DeclarativePlugin::new("{}", "Declarative plugin with fluent API")
        .add_action("process", "Process data", |input| {{
            let data = input.data.get("data")
                .ok_or_else(|| FortressError::plugin("Missing 'data' field"))?;
            
            // Your processing logic here
            let processed = match data {{
                serde_json::Value::String(s) => {{
                    serde_json::json!({{
                        "original": s,
                        "length": s.len(),
                        "uppercase": s.to_uppercase(),
                        "reversed": s.chars().rev().collect::<String>()
                    }})
                }}
                serde_json::Value::Number(n) => {{
                    serde_json::json!({{
                        "original": n,
                        "doubled": n.as_f64().unwrap_or(0.0) * 2.0,
                        "squared": n.as_f64().unwrap_or(0.0) * n.as_f64().unwrap_or(0.0)
                    }})
                }}
                _ => {{
                    serde_json::json!({{
                        "original": data,
                        "type": data_type(data)
                    }})
                }}
            }};
            
            Ok(processed)
        }})
        .add_action("validate", "Validate data", |input| {{
            let data = input.data.get("data")
                .ok_or_else(|| FortressError::plugin("Missing 'data' field"))?;
            
            // Your validation logic here
            let is_valid = match data {{
                serde_json::Value::String(s) => !s.is_empty(),
                serde_json::Value::Number(n) => n.as_f64().unwrap_or(0.0) > 0.0,
                serde_json::Value::Bool(_) => true,
                _ => false,
            }};
            
            Ok(serde_json::json!({{
                "valid": is_valid,
                "data_type": data_type(data)
            }}))
        }})
        .add_action("transform", "Transform data", |input| {{
            let data = input.data.get("data")
                .ok_or_else(|| FortressError::plugin("Missing 'data' field"))?;
            let transform_type = input.data.get("transform")
                .and_then(|t| t.as_str())
                .unwrap_or("identity");
            
            let transformed = match transform_type {{
                "uppercase" => data.as_str().unwrap_or("").to_uppercase(),
                "lowercase" => data.as_str().unwrap_or("").to_lowercase(),
                "reverse" => data.as_str().unwrap_or("").chars().rev().collect::<String>(),
                "identity" => data.clone(),
                _ => return Err(FortressError::plugin(format!("Unknown transform: {{}}", transform_type))),
            }};
            
            Ok(serde_json::json!({{
                "original": data,
                "transformed": transformed,
                "transform_type": transform_type
            }}))
        }})
        .build()
}}

fn data_type(value: &serde_json::Value) -> &'static str {{
    match value {{
        serde_json::Value::Null => "null",
        serde_json::Value::Bool(_) => "boolean",
        serde_json::Value::Number(_) => "number",
        serde_json::Value::String(_) => "string",
        serde_json::Value::Array(_) => "array",
        serde_json::Value::Object(_) => "object",
    }}
}}

#[cfg(test)]
mod tests {{
    use super::*;

    #[tokio::test]
    async fn test_process_action() {{
        let plugin = create_plugin();
        let input = PluginInput {{
            action: "process".to_string(),
            data: serde_json::json!({{"data": "hello world"}}),
            parameters: HashMap::new(),
        }};

        let result = plugin.execute(input).await.unwrap();
        assert!(result.success);
        
        let data = result.data.unwrap();
        assert_eq!(data["original"], "hello world");
        assert_eq!(data["length"], 11);
        assert_eq!(data["uppercase"], "HELLO WORLD");
        assert_eq!(data["reversed"], "dlrow olleh");
    }}

    #[tokio::test]
    async fn test_validate_action() {{
        let plugin = create_plugin();
        let input = PluginInput {{
            action: "validate".to_string(),
            data: serde_json::json!({{"data": "valid string"}}),
            parameters: HashMap::new(),
        }};

        let result = plugin.execute(input).await.unwrap();
        assert!(result.success);
        
        let data = result.data.unwrap();
        assert_eq!(data["valid"], true);
        assert_eq!(data["data_type"], "string");
    }}
}}
"#, name);
    
    fs::write(format!("{}/src/lib.rs", dir_name), lib_rs)?;
    fs::create_dir_all(format!("{}/src", dir_name))?;
    
    println!("✓ Declarative plugin '{}' created in {}/", name, dir_name);
    println!("");
    println!("Next steps:");
    println!("1. cd {}", dir_name);
    println!("2. Customize actions in src/lib.rs");
    println!("3. Add more actions with .add_action()");
    println!("4. cargo build");
    println!("5. Test with: cargo test");
    
    Ok(())
}

fn create_config_plugin(name: &str) -> io::Result<()> {
    let dir_name = name.to_lowercase().replace('_', "-");
    fs::create_dir_all(&dir_name)?;
    
    // Create JSON configuration
    let config_json = format!(r#"{{
    "name": "{}",
    "id": "{}",
    "description": "Configuration-based plugin",
    "version": "1.0.0",
    "author": "Generated Plugin",
    "capabilities": ["custom"],
    "actions": {{
        "process": {{
            "description": "Process input data",
            "handler_type": "script",
            "parameters": {{
                "input": {{
                    "type": "string",
                    "required": true,
                    "description": "Input data to process"
                }}
            }},
            "script": "return input.input.toUpperCase();"
        }},
        "calculate": {{
            "description": "Perform calculation",
            "handler_type": "script",
            "parameters": {{
                "a": {{
                    "type": "number",
                    "required": true,
                    "description": "First number"
                }},
                "b": {{
                    "type": "number",
                    "required": true,
                    "description": "Second number"
                }}
            }},
            "script": "return input.a + input.b;"
        }}
    }},
    "config_schema": {{
        "type": "object",
        "properties": {{
            "timeout": {{
                "type": "integer",
                "default": 30,
                "description": "Operation timeout in seconds"
            }}
        }}
    }}
}}"#, name, name);
    
    fs::write(format!("{}/plugin.json", dir_name), config_json)?;
    
    // Cargo.toml
    let cargo_toml = format!(r#"[package]
name = "{}"
version = "0.1.0"
edition = "2021"

[lib]
crate-type = ["cdylib", "rlib"]

[dependencies]
fortress-core = {{ path = "../../crates/fortress-core" }}
tokio = {{ version = "1.0", features = ["full"] }}
serde = {{ version = "1.0", features = ["derive"] }}
async-trait = "0.1"
"#, name);
    
    fs::write(format!("{}/Cargo.toml", dir_name), cargo_toml)?;
    
    // lib.rs
    let lib_rs = format!(r#"use fortress_core::prelude::*;
use fortress_core::plugin::*;
use async_trait::async_trait;
use serde::{{Deserialize, Serialize}};
use std::collections::HashMap;
use std::fs;

pub fn load_plugin() -> Result<impl Plugin> {{
    GeneratedPlugin::load_from_file("plugin.json")
}}

#[tokio::main]
async fn main() -> Result<()> {{
    let plugin_manager = PluginManager::new();
    let plugin = Arc::new(load_plugin()?);
    let config = HashMap::new();
    
    plugin_manager.load_plugin(plugin, config).await?;
    
    // Test the plugin
    let result = plugin_manager.execute_plugin(
        "{}",
        PluginInput {{
            action: "process".to_string(),
            data: serde_json::json!({{"input": "hello world"}}),
            parameters: HashMap::new(),
        }}
    ).await?;
    
    println!("Process result: {{}}", serde_json::to_string_pretty(&result)?);
    
    let calc_result = plugin_manager.execute_plugin(
        "{}",
        PluginInput {{
            action: "calculate".to_string(),
            data: serde_json::json!({{"a": 10, "b": 5}}),
            parameters: HashMap::new(),
        }}
    ).await?;
    
    println!("Calculate result: {{}}", serde_json::to_string_pretty(&calc_result)?);
    
    Ok(())
}}
"#, name, name);
    
    fs::write(format!("{}/src/lib.rs", dir_name), lib_rs)?;
    fs::create_dir_all(format!("{}/src", dir_name))?;
    
    println!("✓ Configuration-based plugin '{}' created in {}/", name, dir_name);
    println!("");
    println!("Next steps:");
    println!("1. cd {}", dir_name);
    println!("2. Edit plugin.json to customize actions");
    println!("3. cargo run --bin main");
    println!("4. Test with different inputs");
    
    Ok(())
}

fn create_full_plugin(name: &str) -> io::Result<()> {
    let dir_name = name.to_lowercase().replace('_', "-");
    fs::create_dir_all(&dir_name)?;
    
    // Cargo.toml
    let cargo_toml = format!(r#"[package]
name = "{}"
version = "0.1.0"
edition = "2021"

[lib]
crate-type = ["cdylib", "rlib"]

[dependencies]
fortress-core = {{ path = "../../crates/fortress-core" }}
tokio = {{ version = "1.0", features = ["full"] }}
serde = {{ version = "1.0", features = ["derive"] }}
async-trait = "0.1"
"#, name);
    
    fs::write(format!("{}/Cargo.toml", dir_name), cargo_toml)?;
    
    // lib.rs
    let lib_rs = format!(r#"use fortress_core::prelude::*;
use fortress_core::plugin::*;
use async_trait::async_trait;
use serde::{{Deserialize, Serialize}};
use std::collections::HashMap;

pub struct {} {{
    metadata: PluginMetadata,
    // Add your plugin fields here
    state: Option<PluginState>,
}}

#[derive(Debug)]
struct PluginState {{
    // Add your state fields here
    initialized: bool,
    config: HashMap<String, serde_json::Value>,
}}

impl {} {{
    pub fn new() -> Self {{
        Self {{
            metadata: PluginMetadata {{
                id: "{}".to_string(),
                name: "{}".to_string(),
                version: "1.0.0".to_string(),
                description: "Full plugin trait implementation".to_string(),
                author: "Fortress Team".to_string(),
                capabilities: vec![
                    PluginCapability::Custom("full_plugin".to_string())
                ],
                config_schema: Some(serde_json::json!({{
                    "type": "object",
                    "properties": {{
                        "setting1": {{
                            "type": "string",
                            "description": "First setting"
                        }},
                        "setting2": {{
                            "type": "integer", 
                            "default": 42,
                            "description": "Second setting"
                        }}
                    }}
                }}),
            }},
            state: None,
        }}
    }}
}}

#[async_trait]
impl Plugin for {} {{
    fn metadata(&self) -> &PluginMetadata {{
        &self.metadata
    }}

    async fn initialize(&self, context: PluginContext) -> Result<()> {{
        println!("Initializing {} plugin", self.metadata.name);
        
        // Store configuration and initialize state
        let state = PluginState {{
            initialized: true,
            config: context.config.clone(),
        }};
        
        // Note: In a real implementation, you'd need to handle state differently
        // since we can't modify self in &self method
        // This is a limitation of the current design
        
        println!("Plugin initialized with config: {{:?}}", context.config);
        Ok(())
    }}

    async fn execute(&self, input: PluginInput) -> Result<PluginResult> {{
        let start_time = std::time::Instant::now();
        
        let result = match input.action.as_str() {{
            "status" => {{
                // Return plugin status
                Ok(serde_json::json!({{
                    "plugin": self.metadata.name,
                    "version": self.metadata.version,
                    "healthy": true,
                    "timestamp": chrono::Utc::now()
                }}))
            }}
            "configure" => {{
                // Update configuration (this is just an example)
                if let Some(new_config) = input.data.get("config") {{
                    println!("Updating configuration: {{:?}}", new_config);
                    // In a real implementation, you'd update your plugin state
                }}
                
                Ok(serde_json::json!({{
                    "message": "Configuration updated",
                    "config": input.data.get("config")
                }}))
            }}
            "custom_action" => {{
                // Your custom action logic here
                let param1 = input.data.get("param1");
                let param2 = input.data.get("param2");
                
                Ok(serde_json::json!({{
                    "received_params": {{
                        "param1": param1,
                        "param2": param2
                    }},
                    "processed": true,
                    "timestamp": chrono::Utc::now()
                }}))
            }}
            _ => Err(FortressError::plugin(format!("Unknown action: {{}}", input.action))),
        }};

        let execution_time = start_time.elapsed().as_millis() as u64;
        
        match result {{
            Ok(data) => Ok(PluginResult {{
                success: true,
                data: Some(data),
                error: None,
                metrics: PluginMetrics {{
                    execution_time_ms: execution_time,
                    memory_usage_bytes: 0,
                    custom_metrics: {{
                        let mut metrics = HashMap::new();
                        metrics.insert("action".to_string(), 
                            serde_json::Value::String(input.action.clone()));
                        metrics
                    }},
                }},
            }}),
            Err(e) => Ok(PluginResult {{
                success: false,
                data: None,
                error: Some(e.to_string()),
                metrics: PluginMetrics {{
                    execution_time_ms: execution_time,
                    memory_usage_bytes: 0,
                    custom_metrics: {{
                        let mut metrics = HashMap::new();
                        metrics.insert("action".to_string(), 
                            serde_json::Value::String(input.action.clone()));
                        metrics
                    }},
                }},
            }}),
        }}
    }}

    async fn cleanup(&self) -> Result<()> {{
        println!("Cleaning up {} plugin", self.metadata.name);
        // Cleanup resources here
        Ok(())
    }}

    fn validate_config(&self, config: &HashMap<String, serde_json::Value>) -> Result<()> {{
        // Validate configuration
        if let Some(setting1) = config.get("setting1") {{
            if !setting1.is_string() {{
                return Err(FortressError::plugin("setting1 must be a string"));
            }}
        }}
        
        if let Some(setting2) = config.get("setting2") {{
            if !setting2.is_number() {{
                return Err(FortressError::plugin("setting2 must be a number"));
            }}
        }}
        
        println!("Configuration validated successfully");
        Ok(())
    }}

    async fn health_check(&self) -> Result<PluginHealth> {{
        Ok(PluginHealth {{
            healthy: true,
            message: format!("{{}} plugin is healthy", self.metadata.name),
            last_check: chrono::Utc::now(),
        }})
    }}
}}

#[cfg(test)]
mod tests {{
    use super::*;

    #[tokio::test]
    async fn test_plugin_metadata() {{
        let plugin = {}::new();
        let metadata = plugin.metadata();
        
        assert_eq!(metadata.id, "{}");
        assert_eq!(metadata.name, "{}");
        assert_eq!(metadata.version, "1.0.0");
        assert!(metadata.capabilities.contains(&PluginCapability::Custom("full_plugin".to_string())));
    }}

    #[tokio::test]
    async fn test_status_action() {{
        let plugin = {}::new();
        let input = PluginInput {{
            action: "status".to_string(),
            data: serde_json::Value::Null,
            parameters: HashMap::new(),
        }};

        let result = plugin.execute(input).await.unwrap();
        assert!(result.success);
        
        let data = result.data.unwrap();
        assert_eq!(data["plugin"], "{}");
        assert_eq!(data["version"], "1.0.0");
        assert_eq!(data["healthy"], true);
    }}

    #[tokio::test]
    async fn test_config_validation() {{
        let plugin = {}::new();
        
        // Valid config
        let mut valid_config = HashMap::new();
        valid_config.insert("setting1".to_string(), serde_json::Value::String("test".to_string()));
        valid_config.insert("setting2".to_string(), serde_json::Value::Number(serde_json::Number::from(42)));
        assert!(plugin.validate_config(&valid_config).is_ok());
        
        // Invalid config
        let mut invalid_config = HashMap::new();
        invalid_config.insert("setting1".to_string(), serde_json::Value::Number(123));
        assert!(plugin.validate_config(&invalid_config).is_err());
    }}
}}
"#, name, name, name, name, name, name, name, name, name);
    
    fs::write(format!("{}/src/lib.rs", dir_name), lib_rs)?;
    fs::create_dir_all(format!("{}/src", dir_name))?;
    
    println!("✓ Full plugin '{}' created in {}/", name, dir_name);
    println!("");
    println!("Next steps:");
    println!("1. cd {}", dir_name);
    println!("2. Customize the PluginState struct and plugin logic");
    println!("3. Add more actions to the execute method");
    println!("4. Update configuration schema as needed");
    println!("5. cargo build");
    println!("6. Test with: cargo test");
    
    Ok(())
}
