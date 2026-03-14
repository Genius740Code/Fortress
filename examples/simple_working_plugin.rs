//! Simple Working Plugin Example
//! 
//! This example demonstrates a complete end-to-end plugin workflow:
//! 1. Creating a simple plugin inline
//! 2. Registering it with the plugin manager
//! 3. Executing plugin actions
//! 4. Handling results and errors

use std::collections::HashMap;
use std::sync::Arc;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimplePluginMetadata {
    pub id: String,
    pub name: String,
    pub version: String,
    pub description: String,
    pub author: String,
}

pub struct SimplePlugin {
    metadata: SimplePluginMetadata,
}

impl SimplePlugin {
    pub fn new() -> Self {
        Self {
            metadata: SimplePluginMetadata {
                id: "simple-plugin".to_string(),
                name: "Simple Plugin".to_string(),
                version: "1.0.0".to_string(),
                description: "A simple working plugin example".to_string(),
                author: "Fortress Team".to_string(),
            },
        }
    }

    async fn execute_hello(&self, input: &serde_json::Value) -> Result<serde_json::Value, Box<dyn std::error::Error + Send + Sync>> {
        let name = input.get("name")
            .and_then(|v| v.as_str())
            .unwrap_or("World");
        
        Ok(serde_json::json!({
            "message": format!("Hello, {}!", name),
            "timestamp": chrono::Utc::now(),
            "plugin": self.metadata.name
        }))
    }

    async fn execute_echo(&self, input: &serde_json::Value) -> Result<serde_json::Value, Box<dyn std::error::Error + Send + Sync>> {
        Ok(input.clone())
    }
}

#[async_trait]
pub trait Plugin: Send + Sync {
    fn metadata(&self) -> &SimplePluginMetadata;
    async fn execute(&self, action: &str, input: serde_json::Value) -> Result<serde_json::Value, Box<dyn std::error::Error + Send + Sync>>;
    async fn health_check(&self) -> Result<bool, Box<dyn std::error::Error + Send + Sync>>;
}

#[async_trait]
impl Plugin for SimplePlugin {
    fn metadata(&self) -> &SimplePluginMetadata {
        &self.metadata
    }

    async fn execute(&self, action: &str, input: serde_json::Value) -> Result<serde_json::Value, Box<dyn std::error::Error + Send + Sync>> {
        match action {
            "hello" => self.execute_hello(&input).await,
            "echo" => self.execute_echo(&input).await,
            _ => Err(format!("Unknown action: {}", action).into()),
        }
    }

    async fn health_check(&self) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
        Ok(true)
    }
}

pub struct PluginManager {
    plugins: Arc<tokio::sync::RwLock<HashMap<String, Arc<dyn Plugin>>>>,
}

impl PluginManager {
    pub fn new() -> Self {
        Self {
            plugins: Arc::new(tokio::sync::RwLock::new(HashMap::new())),
        }
    }

    pub async fn register_plugin(&self, plugin: Arc<dyn Plugin>) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let plugin_id = plugin.metadata().id.clone();
        let mut plugins = self.plugins.write().await;
        plugins.insert(plugin_id, plugin);
        Ok(())
    }

    pub async fn execute_plugin(
        &self,
        plugin_id: &str,
        action: String,
        data: serde_json::Value,
    ) -> Result<PluginExecutionResult, Box<dyn std::error::Error + Send + Sync>> {
        let plugins = self.plugins.read().await;
        let plugin = plugins.get(plugin_id)
            .ok_or_else(|| format!("Plugin '{}' not found", plugin_id))?;

        let start_time = std::time::Instant::now();
        
        let result = plugin.execute(&action, data).await;
        let execution_time = start_time.elapsed().as_millis() as u64;

        match result {
            Ok(data) => Ok(PluginExecutionResult {
                success: true,
                data: Some(data),
                error: None,
                execution_time_ms: execution_time,
            }),
            Err(e) => Ok(PluginExecutionResult {
                success: false,
                data: None,
                error: Some(e.to_string()),
                execution_time_ms: execution_time,
            }),
        }
    }

    pub async fn list_plugins(&self) -> Vec<SimplePluginMetadata> {
        let plugins = self.plugins.read().await;
        plugins.values()
            .map(|plugin| plugin.metadata().clone())
            .collect()
    }

    pub async fn health_check_all(&self) -> HashMap<String, bool> {
        let plugins = self.plugins.read().await;
        let mut results = HashMap::new();
        
        for (id, plugin) in plugins.iter() {
            let health = plugin.health_check().await.unwrap_or(false);
            results.insert(id.clone(), health);
        }
        
        results
    }
}

#[derive(Debug, Serialize)]
pub struct PluginExecutionResult {
    pub success: bool,
    pub data: Option<serde_json::Value>,
    pub error: Option<String>,
    pub execution_time_ms: u64,
}

#[tokio::main]
async fn main() -> color_eyre::eyre::Result<()> {
    println!("🚀 Fortress Plugin System - Working Example");
    println!("==========================================");

    // Create plugin manager
    let plugin_manager = PluginManager::new();
    
    // Create and register the simple plugin
    println!("\n📦 Creating and registering SimplePlugin...");
    let simple_plugin = Arc::new(SimplePlugin::new());
    
    plugin_manager.register_plugin(simple_plugin.clone()).await
        .map_err(|e| color_eyre::eyre::eyre!("Failed to register plugin: {}", e))?;
    
    println!("✅ SimplePlugin registered successfully!");
    println!("   Plugin ID: {}", simple_plugin.metadata().id);
    println!("   Plugin Name: {}", simple_plugin.metadata().name);
    println!("   Version: {}", simple_plugin.metadata().version);
    println!("   Description: {}", simple_plugin.metadata().description);

    // Test the "hello" action
    println!("\n🔧 Testing 'hello' action...");
    let hello_result = plugin_manager.execute_plugin(
        "simple-plugin",
        "hello".to_string(),
        serde_json::json!({
            "name": "Fortress Developer"
        }),
    ).await
        .map_err(|e| color_eyre::eyre::eyre!("Failed to execute hello action: {}", e))?;
    
    if hello_result.success {
        println!("✅ Hello action successful!");
        if let Some(data) = hello_result.data {
            println!("   Response: {}", serde_json::to_string_pretty(&data)?);
        }
        println!("   Execution time: {}ms", hello_result.execution_time_ms);
    } else {
        println!("❌ Hello action failed: {:?}", hello_result.error);
    }

    // Test the "echo" action
    println!("\n🔧 Testing 'echo' action...");
    let echo_result = plugin_manager.execute_plugin(
        "simple-plugin",
        "echo".to_string(),
        serde_json::json!({
            "message": "Hello from Fortress!",
            "timestamp": "2026-03-14T15:09:00Z",
            "data": {
                "type": "test",
                "values": [1, 2, 3, 4, 5]
            }
        }),
    ).await
        .map_err(|e| color_eyre::eyre::eyre!("Failed to execute echo action: {}", e))?;
    
    if echo_result.success {
        println!("✅ Echo action successful!");
        if let Some(data) = echo_result.data {
            println!("   Echoed data: {}", serde_json::to_string_pretty(&data)?);
        }
        println!("   Execution time: {}ms", echo_result.execution_time_ms);
    } else {
        println!("❌ Echo action failed: {:?}", echo_result.error);
    }

    // Test error handling with invalid action
    println!("\n🔧 Testing error handling with invalid action...");
    let invalid_result = plugin_manager.execute_plugin(
        "simple-plugin",
        "invalid_action".to_string(),
        serde_json::json!({"test": "data"}),
    ).await;
    
    match invalid_result {
        Ok(result) => {
            if !result.success {
                println!("✅ Error handling working correctly!");
                println!("   Expected error: {:?}", result.error);
            } else {
                println!("⚠️  Unexpected success with invalid action");
            }
        }
        Err(e) => {
            println!("✅ Error handling working correctly!");
            println!("   Expected error: {}", e);
        }
    }

    // List all registered plugins
    println!("\n📋 Registered plugins:");
    let plugins = plugin_manager.list_plugins().await;
    for plugin in plugins {
        println!("   - {} v{} ({})", plugin.name, plugin.version, plugin.id);
    }

    // Get plugin health status
    println!("\n🏥 Plugin health status:");
    let health_status = plugin_manager.health_check_all().await;
    for (plugin_id, healthy) in health_status {
        println!("   {}: {}", plugin_id, 
            if healthy { "✅ Healthy" } else { "❌ Unhealthy" }
        );
    }

    println!("\n🎉 Plugin example completed successfully!");
    println!("\n💡 This demonstrates that a plugin system can work!");
    println!("   - Plugin registration ✅");
    println!("   - Action execution ✅");
    println!("   - Error handling ✅");
    println!("   - Health monitoring ✅");
    println!("   - Plugin discovery ✅");

    println!("\n📝 Next steps for a complete plugin system:");
    println!("   1. Integrate with fortress-core plugin traits");
    println!("   2. Add proper WebAssembly runtime support");
    println!("   3. Implement plugin marketplace functionality");
    println!("   4. Add plugin sandboxing and security");

    Ok(())
}
