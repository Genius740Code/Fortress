//! Simple Plugin Scaffolding Tool
//! 
//! Usage: cargo run --example simple_scaffolding <plugin_name>

use std::env;
use std::fs;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    
    if args.len() != 2 {
        println!("Usage: cargo run --example simple_scaffolding <plugin_name>");
        println!("");
        println!("Example: cargo run --example simple_scaffolding MyPlugin");
        return Ok(());
    }
    
    let plugin_name = &args[1];
    let dir_name = plugin_name.to_lowercase().replace('_', "-");
    
    // Create directory
    fs::create_dir_all(&dir_name)?;
    fs::create_dir_all(format!("{}/src", dir_name))?;
    
    // Create Cargo.toml
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
"#, plugin_name);
    
    fs::write(format!("{}/Cargo.toml", dir_name), cargo_toml)?;
    
    // Create lib.rs with template
    let lib_rs = format!(
        r#"use fortress_core::prelude::*;
use fortress_core::plugin::*;
use async_trait::async_trait;
use serde::{{Deserialize, Serialize}};
use std::collections::HashMap;

pub struct {plugin_name} {{
    metadata: PluginMetadata,
}}

impl {plugin_name} {{
    pub fn new() -> Self {{
        Self {{
            metadata: PluginMetadata {{
                id: "{plugin_name}".to_string(),
                name: "{plugin_name}".to_string(),
                version: "1.0.0".to_string(),
                description: "A Fortress plugin".to_string(),
                author: "Fortress Team".to_string(),
                capabilities: vec![PluginCapability::Custom("custom".to_string())],
                config_schema: None,
            }},
        }}
    }}
}}

#[async_trait]
impl Plugin for {plugin_name} {{
    fn metadata(&self) -> &PluginMetadata {{
        &self.metadata
    }}

    async fn initialize(&self, _context: PluginContext) -> Result<()> {{
        println!("Initializing {plugin_name} plugin", self.metadata.name);
        Ok(())
    }}

    async fn execute(&self, input: PluginInput) -> Result<PluginResult> {{
        let start_time = std::time::Instant::now();
        
        match input.action.as_str() {{
            "hello" => {{
                let name = input.data["name"]
                    .as_str()
                    .unwrap_or("World");
                
                Ok(PluginResult {{
                    success: true,
                    data: Some(serde_json::json!({{
                        "message": format!("Hello, {{}}!", name),
                        "timestamp": chrono::Utc::now()
                    }})),
                    error: None,
                    metrics: PluginMetrics {{
                        execution_time_ms: start_time.elapsed().as_millis() as u64,
                        memory_usage_bytes: 0,
                        custom_metrics: HashMap::new(),
                    }},
                }})
            }}
            "echo" => {{
                Ok(PluginResult {{
                    success: true,
                    data: Some(input.data.clone()),
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
        println!("Cleaning up {plugin_name} plugin", self.metadata.name);
        Ok(())
    }}

    fn validate_config(&self, _config: &HashMap<String, serde_json::Value>) -> Result<()> {{
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
    async fn test_hello_action() {{
        let plugin = {plugin_name}::new();
        let input = PluginInput {{
            action: "hello".to_string(),
            data: serde_json::json!({{"name": "Fortress"}}),
            parameters: HashMap::new(),
        }};

        let result = plugin.execute(input).await.unwrap();
        assert!(result.success);
        
        let data = result.data.unwrap();
        assert_eq!(data["message"], "Hello, Fortress!");
    }}

    #[tokio::test]
    async fn test_echo_action() {{
        let plugin = {plugin_name}::new();
        let input = PluginInput {{
            action: "echo".to_string(),
            data: serde_json::json!({{"test": "value"}}),
            parameters: HashMap::new(),
        }};

        let result = plugin.execute(input).await.unwrap();
        assert!(result.success);
        
        let data = result.data.unwrap();
        assert_eq!(data["test"], "value");
    }}
}}
"#, 
        plugin_name = plugin_name
    );
    
    fs::write(format!("{}/src/lib.rs", dir_name), lib_rs)?;
    
    println!("✓ Plugin '{}' created successfully", plugin_name);
    println!("");
    println!("Directory: {}/", dir_name);
    println!("");
    println!("Next steps:");
    println!("1. cd {}", dir_name);
    println!("2. Edit src/lib.rs to customize your plugin");
    println!("3. cargo build");
    println!("4. Test with: cargo test");
    println!("");
    println!("Available actions in this template:");
    println!("- hello: Says hello to a name");
    println!("- echo: Echoes back the input data");
    
    Ok(())
}
