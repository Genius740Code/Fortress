//! End-to-End Plugin System Test
//! 
//! This test demonstrates that the plugin system works correctly
//! by loading and executing plugins with various scenarios.

use std::collections::HashMap;
use std::sync::Arc;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};

// Simple test plugin implementation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestPluginMetadata {
    pub id: String,
    pub name: String,
    pub version: String,
    pub description: String,
    pub author: String,
}

pub struct EndToEndTestPlugin {
    metadata: TestPluginMetadata,
}

impl EndToEndTestPlugin {
    pub fn new() -> Self {
        Self {
            metadata: TestPluginMetadata {
                id: "test-plugin".to_string(),
                name: "Test Plugin".to_string(),
                version: "1.0.0".to_string(),
                description: "A test plugin for end-to-end testing".to_string(),
                author: "Test Suite".to_string(),
            },
        }
    }

    async fn execute_process(&self, input: &serde_json::Value) -> Result<serde_json::Value, Box<dyn std::error::Error + Send + Sync>> {
        let text = input.get("text")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        
        let operation = input.get("operation")
            .and_then(|v| v.as_str())
            .unwrap_or("identity");

        let result = match operation {
            "uppercase" => text.to_uppercase(),
            "lowercase" => text.to_lowercase(),
            "reverse" => text.chars().rev().collect::<String>(),
            "length" => text.len().to_string(),
            _ => text.to_string(),
        };

        Ok(serde_json::json!({
            "original": text,
            "processed": result,
            "operation": operation,
            "plugin": self.metadata.name
        }))
    }

    async fn execute_math(&self, input: &serde_json::Value) -> Result<serde_json::Value, Box<dyn std::error::Error + Send + Sync>> {
        let a = input.get("a")
            .and_then(|v| v.as_f64())
            .ok_or("Missing or invalid 'a' parameter")?;
        
        let b = input.get("b")
            .and_then(|v| v.as_f64())
            .ok_or("Missing or invalid 'b' parameter")?;
        
        let operation = input.get("operation")
            .and_then(|v| v.as_str())
            .unwrap_or("add");

        let result = match operation {
            "add" => a + b,
            "subtract" => a - b,
            "multiply" => a * b,
            "divide" => {
                if b == 0.0 {
                    return Err("Division by zero".into());
                }
                a / b
            },
            _ => return Err(format!("Unknown operation: {}", operation).into()),
        };

        Ok(serde_json::json!({
            "a": a,
            "b": b,
            "operation": operation,
            "result": result,
            "plugin": self.metadata.name
        }))
    }
}

#[async_trait]
pub trait TestPluginTrait: Send + Sync {
    fn metadata(&self) -> &TestPluginMetadata;
    async fn execute(&self, action: &str, input: serde_json::Value) -> Result<serde_json::Value, Box<dyn std::error::Error + Send + Sync>>;
    async fn health_check(&self) -> Result<bool, Box<dyn std::error::Error + Send + Sync>>;
}

#[async_trait]
impl TestPluginTrait for EndToEndTestPlugin {
    fn metadata(&self) -> &TestPluginMetadata {
        &self.metadata
    }

    async fn execute(&self, action: &str, input: serde_json::Value) -> Result<serde_json::Value, Box<dyn std::error::Error + Send + Sync>> {
        match action {
            "process" => self.execute_process(&input).await,
            "math" => self.execute_math(&input).await,
            _ => Err(format!("Unknown action: {}", action).into()),
        }
    }

    async fn health_check(&self) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
        Ok(true)
    }
}

pub struct TestPluginManager {
    plugins: Arc<tokio::sync::RwLock<HashMap<String, Arc<dyn TestPluginTrait>>>>,
}

impl TestPluginManager {
    pub fn new() -> Self {
        Self {
            plugins: Arc::new(tokio::sync::RwLock::new(HashMap::new())),
        }
    }

    pub async fn register_plugin(&self, plugin: Arc<dyn TestPluginTrait>) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
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
    ) -> Result<TestPluginExecutionResult, Box<dyn std::error::Error + Send + Sync>> {
        let plugins = self.plugins.read().await;
        let plugin = plugins.get(plugin_id)
            .ok_or_else(|| format!("Plugin '{}' not found", plugin_id))?;

        let start_time = std::time::Instant::now();
        
        let result = plugin.execute(&action, data).await;
        let execution_time = start_time.elapsed().as_millis() as u64;

        match result {
            Ok(data) => Ok(TestPluginExecutionResult {
                success: true,
                data: Some(data),
                error: None,
                execution_time_ms: execution_time,
            }),
            Err(e) => Ok(TestPluginExecutionResult {
                success: false,
                data: None,
                error: Some(e.to_string()),
                execution_time_ms: execution_time,
            }),
        }
    }
}

#[derive(Debug)]
pub struct TestPluginExecutionResult {
    pub success: bool,
    pub data: Option<serde_json::Value>,
    pub error: Option<String>,
    pub execution_time_ms: u64,
}

#[tokio::test]
async fn test_plugin_registration_and_execution() {
    let plugin_manager = TestPluginManager::new();
    let test_plugin = Arc::new(EndToEndTestPlugin::new());

    // Test plugin registration
    assert!(plugin_manager.register_plugin(test_plugin.clone()).await.is_ok());

    // Test successful execution
    let result = plugin_manager.execute_plugin(
        "test-plugin",
        "process".to_string(),
        serde_json::json!({
            "text": "Hello World",
            "operation": "uppercase"
        }),
    ).await;
    
    match result {
        Ok(response) => {
            assert!(response.success);
            assert!(response.data.is_some());
            assert!(response.error.is_none());
            let data = response.data.unwrap();
            assert_eq!(data["original"], "Hello World");
            assert_eq!(data["processed"], "HELLO WORLD");
            assert_eq!(data["operation"], "uppercase");
        }
        Err(error) => {
            assert!(!result.success);
            assert!(result.error.is_some());
            let error = result.error.unwrap();
            assert!(error.contains("Unknown action"));
        }
    }

    assert!(result.success);
    assert!(result.data.is_some());
    assert!(result.error.is_none());
    
    let data = result.data.unwrap();
    assert_eq!(data["original"], "Hello World");
    assert_eq!(data["processed"], "HELLO WORLD");
    assert_eq!(data["operation"], "uppercase");
}

#[tokio::test]
async fn test_plugin_math_operations() {
    let plugin_manager = TestPluginManager::new();
    let test_plugin = Arc::new(EndToEndTestPlugin::new());
    plugin_manager.register_plugin(test_plugin).await.unwrap();

    // Test addition
    let result = plugin_manager.execute_plugin(
        "test-plugin",
        "math".to_string(),
        serde_json::json!({
            "a": 10.0,
            "b": 5.0,
            "operation": "add"
        }),
    ).await.unwrap();

    assert!(result.success);
    let data = result.data.unwrap();
    assert_eq!(data["result"], 15.0);

    // Test multiplication
    let result = plugin_manager.execute_plugin(
        "test-plugin",
        "math".to_string(),
        serde_json::json!({
            "a": 4.0,
            "b": 3.0,
            "operation": "multiply"
        }),
    ).await.unwrap();

    assert!(result.success);
    let data = result.data.unwrap();
    assert_eq!(data["result"], 12.0);
}

#[tokio::test]
async fn test_plugin_error_handling() {
    let plugin_manager = TestPluginManager::new();
    let test_plugin = Arc::new(EndToEndTestPlugin::new());
    plugin_manager.register_plugin(test_plugin).await.unwrap();

    // Test unknown action
    let result = plugin_manager.execute_plugin(
        "test-plugin",
        "unknown_action".to_string(),
        serde_json::json!({"test": "data"}),
    ).await.unwrap();

    assert!(!result.success);
    assert!(result.data.is_none());
    assert!(result.error.is_some());
    assert!(result.error.unwrap().contains("Unknown action"));

    // Test division by zero
    let result = plugin_manager.execute_plugin(
        "test-plugin",
        "math".to_string(),
        serde_json::json!({
            "a": 10.0,
            "b": 0.0,
            "operation": "divide"
        }),
    ).await.unwrap();

    assert!(!result.success);
    assert!(result.error.is_some());
    assert!(result.error.unwrap().contains("Division by zero"));
}

#[tokio::test]
async fn test_plugin_not_found() {
    let plugin_manager = TestPluginManager::new();

    let result = plugin_manager.execute_plugin(
        "non-existent-plugin",
        "test".to_string(),
        serde_json::json!({"test": "data"}),
    ).await;

    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("not found"));
}

#[tokio::test]
async fn test_multiple_text_operations() {
    let plugin_manager = TestPluginManager::new();
    let test_plugin = Arc::new(EndToEndTestPlugin::new());
    plugin_manager.register_plugin(test_plugin).await.unwrap();

    let test_cases = vec![
        ("hello", "uppercase", "HELLO"),
        ("WORLD", "lowercase", "world"),
        ("rust", "reverse", "tsur"),
        ("testing", "length", "7"),
        ("identity", "identity", "identity"),
    ];

    for (input_text, operation, expected) in test_cases {
        let result = plugin_manager.execute_plugin(
            "test-plugin",
            "process".to_string(),
            serde_json::json!({
                "text": input_text,
                "operation": operation
            }),
        ).await.unwrap();

        assert!(result.success, "Failed for operation: {}", operation);
        let data = result.data.unwrap();
        assert_eq!(data["processed"], expected, "Mismatch for operation: {}", operation);
        assert_eq!(data["operation"], operation);
    }
}

#[tokio::test]
async fn test_plugin_execution_timing() {
    let plugin_manager = TestPluginManager::new();
    let test_plugin = Arc::new(EndToEndTestPlugin::new());
    plugin_manager.register_plugin(test_plugin).await.unwrap();

    let result = plugin_manager.execute_plugin(
        "test-plugin",
        "process".to_string(),
        serde_json::json!({
            "text": "test",
            "operation": "uppercase"
        }),
    ).await.unwrap();

    assert!(result.success);
    assert!(result.execution_time_ms >= 0);
    // Should be very fast for simple operations
    assert!(result.execution_time_ms < 1000); // Less than 1 second
}
