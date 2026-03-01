use fortress_core::prelude::*;
use fortress_core::plugin::*;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

pub struct TestPlugin {
    metadata: PluginMetadata,
}

impl TestPlugin {
    pub fn new() -> Self {
        Self {
            metadata: PluginMetadata {
                id: "TestPlugin".to_string(),
                name: "TestPlugin".to_string(),
                version: "1.0.0".to_string(),
                description: "A Fortress plugin".to_string(),
                author: "Fortress Team".to_string(),
                capabilities: vec![PluginCapability::Custom("custom".to_string())],
                config_schema: None,
            },
        }
    }
}

#[async_trait]
impl Plugin for TestPlugin {
    fn metadata(&self) -> &PluginMetadata {
        &self.metadata
    }

    async fn initialize(&self, _context: PluginContext) -> Result<()> {
        println!("Initializing TestPlugin plugin", self.metadata.name);
        Ok(())
    }

    async fn execute(&self, input: PluginInput) -> Result<PluginResult> {
        let start_time = std::time::Instant::now();
        
        match input.action.as_str() {
            "hello" => {
                let name = input.data["name"]
                    .as_str()
                    .unwrap_or("World");
                
                Ok(PluginResult {
                    success: true,
                    data: Some(serde_json::json!({
                        "message": format!("Hello, {}!", name),
                        "timestamp": chrono::Utc::now()
                    })),
                    error: None,
                    metrics: PluginMetrics {
                        execution_time_ms: start_time.elapsed().as_millis() as u64,
                        memory_usage_bytes: 0,
                        custom_metrics: HashMap::new(),
                    },
                })
            }
            "echo" => {
                Ok(PluginResult {
                    success: true,
                    data: Some(input.data.clone()),
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
        println!("Cleaning up TestPlugin plugin", self.metadata.name);
        Ok(())
    }

    fn validate_config(&self, _config: &HashMap<String, serde_json::Value>) -> Result<()> {
        Ok(())
    }

    async fn health_check(&self) -> Result<PluginHealth> {
        Ok(PluginHealth {
            healthy: true,
            message: format!("{} plugin is healthy", self.metadata.name),
            last_check: chrono::Utc::now(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_hello_action() {
        let plugin = TestPlugin::new();
        let input = PluginInput {
            action: "hello".to_string(),
            data: serde_json::json!({"name": "Fortress"}),
            parameters: HashMap::new(),
        };

        let result = plugin.execute(input).await.unwrap();
        assert!(result.success);
        
        let data = result.data.unwrap();
        assert_eq!(data["message"], "Hello, Fortress!");
    }

    #[tokio::test]
    async fn test_echo_action() {
        let plugin = TestPlugin::new();
        let input = PluginInput {
            action: "echo".to_string(),
            data: serde_json::json!({"test": "value"}),
            parameters: HashMap::new(),
        };

        let result = plugin.execute(input).await.unwrap();
        assert!(result.success);
        
        let data = result.data.unwrap();
        assert_eq!(data["test"], "value");
    }
}
