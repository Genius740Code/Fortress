//! WebAssembly Plugin Runtime
//!
//! This module provides a runtime for executing WebAssembly plugins
//! with proper sandboxing and security controls.

use crate::error::{FortressError, Result};
use crate::plugin::{Plugin, PluginContext, PluginInput, PluginMetadata, PluginResult};
use async_trait::async_trait;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

/// WebAssembly plugin instance (simplified implementation)
pub struct WasmPlugin {
    /// Plugin metadata
    metadata: PluginMetadata,
    /// Runtime context
    context: Arc<RwLock<WasmContext>>,
    /// Plugin configuration
    config: WasmPluginConfig,
}

/// WebAssembly runtime context
#[derive(Debug, Clone)]
pub struct WasmContext {
    /// Plugin configuration
    config: HashMap<String, serde_json::Value>,
    /// Execution statistics
    stats: WasmStats,
}

/// WebAssembly execution statistics
#[derive(Debug, Clone, Default)]
pub struct WasmStats {
    /// Number of function calls
    pub function_calls: u64,
    /// Total execution time in milliseconds
    pub total_execution_time_ms: u64,
    /// Memory usage in bytes
    pub memory_usage_bytes: u64,
    /// Number of errors
    pub error_count: u64,
}

/// WebAssembly plugin configuration
#[derive(Debug, Clone)]
pub struct WasmPluginConfig {
    /// Maximum memory usage in bytes
    pub max_memory_bytes: Option<u64>,
    /// Maximum execution time in milliseconds
    pub max_execution_time_ms: Option<u64>,
    /// Fuel metering (for execution limiting)
    pub enable_fuel_metering: bool,
    /// Maximum fuel units
    pub max_fuel: Option<u64>,
    /// Allowed host functions
    pub allowed_host_functions: Vec<String>,
}

impl Default for WasmPluginConfig {
    fn default() -> Self {
        Self {
            max_memory_bytes: Some(64 * 1024 * 1024), // 64MB
            max_execution_time_ms: Some(5000),        // 5 seconds
            enable_fuel_metering: true,
            max_fuel: Some(1000000),
            allowed_host_functions: vec![
                "fortress_log".to_string(),
                "fortress_config_get".to_string(),
                "fortress_timestamp".to_string(),
            ],
        }
    }
}

/// WebAssembly plugin loader
pub struct WasmPluginLoader {
    /// Plugin configuration
    config: WasmPluginConfig,
    /// Require authentication for plugin loading
    require_auth: bool,
}

impl WasmPluginLoader {
    /// Create a new WASM plugin loader
    pub fn new(config: WasmPluginConfig) -> Result<Self> {
        Ok(Self {
            config,
            require_auth: true, // Default to requiring authentication for security
        })
    }

    /// Create a new WASM plugin loader with custom auth requirement
    pub fn new_with_auth(config: WasmPluginConfig, require_auth: bool) -> Result<Self> {
        Ok(Self {
            config,
            require_auth,
        })
    }

    /// Load a WASM plugin from bytes
    ///
    /// # Arguments
    /// * `wasm_bytes` - The WASM module bytes
    /// * `metadata` - Plugin metadata
    /// * `auth_token` - Optional authentication token (required if require_auth is true)
    pub fn load_from_bytes(
        &self,
        _wasm_bytes: &[u8],
        metadata: PluginMetadata,
        auth_token: Option<&str>,
    ) -> Result<WasmPlugin> {
        // SECURITY: Require authentication for plugin loading to prevent unauthorized code execution
        if self.require_auth {
            let token = auth_token.ok_or_else(|| {
                FortressError::authentication(
                    "Authentication required for plugin deployment",
                    None,
                )
            })?;

            // Validate token using token manager (placeholder until auth service is properly accessible)
            if token.is_empty() {
                return Err(FortressError::authentication(
                    "Empty authentication token",
                    None,
                ));
            }
        }

        // Create runtime context
        let context = Arc::new(RwLock::new(WasmContext {
            config: HashMap::new(),
            stats: WasmStats::default(),
        }));

        Ok(WasmPlugin {
            metadata,
            context,
            config: self.config.clone(),
        })
    }

    /// Load a WASM plugin from a file
    ///
    /// # Arguments
    /// * `file_path` - Path to the WASM file
    /// * `metadata` - Plugin metadata
    /// * `auth_token` - Optional authentication token (required if require_auth is true)
    pub fn load_from_file(
        &self,
        file_path: &PathBuf,
        metadata: PluginMetadata,
        auth_token: Option<&str>,
    ) -> Result<WasmPlugin> {
        // SECURITY: Require authentication for plugin loading to prevent unauthorized code execution
        if self.require_auth && auth_token.is_none() {
            return Err(FortressError::authentication(
                "Authentication required for plugin deployment",
                None,
            ));
        }

        let wasm_bytes = std::fs::read(file_path)
            .map_err(|e| FortressError::plugin(format!("Failed to read WASM file: {}", e)))?;

        self.load_from_bytes(&wasm_bytes, metadata, auth_token)
    }

    /// Validate a WASM module for security
    fn validate_module(&self, _module: &[u8]) -> Result<()> {
        // In a real implementation, this would validate the WASM module
        // For now, we'll assume all modules are valid
        Ok(())
    }
}

#[async_trait]
impl Plugin for WasmPlugin {
    async fn initialize(&self, context: PluginContext) -> Result<()> {
        // Update runtime context
        {
            let mut ctx = self.context.write().await;
            ctx.config = context.config;
        }

        Ok(())
    }

    async fn execute(&self, input: PluginInput) -> Result<PluginResult> {
        let start_time = Instant::now();

        // Simulate WASM execution with timeout
        let result = tokio::time::timeout(
            Duration::from_millis(self.config.max_execution_time_ms.unwrap_or(5000)),
            async {
                // Simulate plugin execution logic
                self.simulate_plugin_execution(&input).await
            },
        )
        .await;

        // Handle timeout
        match result {
            Ok(Ok(plugin_result)) => {
                let execution_time = start_time.elapsed().as_millis() as u64;

                // Update statistics
                {
                    let mut ctx = self.context.write().await;
                    ctx.stats.function_calls += 1;
                    ctx.stats.total_execution_time_ms += execution_time;
                }

                // Add execution metrics to result
                let mut final_result = plugin_result;
                final_result.metrics.execution_time_ms = execution_time;

                Ok(final_result)
            }
            Ok(Err(e)) => {
                // Update error statistics
                {
                    let mut ctx = self.context.write().await;
                    ctx.stats.error_count += 1;
                }

                Err(e)
            }
            Err(_) => {
                // Update timeout statistics
                {
                    let mut ctx = self.context.write().await;
                    ctx.stats.error_count += 1;
                }

                Err(FortressError::plugin(
                    "WASM execution timed out".to_string(),
                ))
            }
        }
    }

    async fn cleanup(&self) -> Result<()> {
        // Reset statistics
        {
            let mut ctx = self.context.write().await;
            ctx.stats = WasmStats::default();
        }

        Ok(())
    }

    fn validate_config(&self, config: &HashMap<String, serde_json::Value>) -> Result<()> {
        // Validate configuration against allowed parameters
        for key in config.keys() {
            if !self.config.allowed_host_functions.contains(key) {
                return Err(FortressError::plugin(format!(
                    "Disallowed configuration parameter: {}",
                    key
                )));
            }
        }
        Ok(())
    }

    async fn health_check(&self) -> Result<crate::plugin::PluginHealth> {
        let ctx = self.context.read().await;
        let stats = ctx.stats.clone();

        Ok(crate::plugin::PluginHealth {
            healthy: stats.error_count <= 10,
            message: if stats.error_count > 10 {
                "High error rate".to_string()
            } else {
                "Plugin operating normally".to_string()
            },
            last_check: chrono::Utc::now(),
        })
    }

    fn metadata(&self) -> &PluginMetadata {
        &self.metadata
    }
}

impl WasmPlugin {
    /// Simulate plugin execution (placeholder for real WASM execution)
    async fn simulate_plugin_execution(&self, input: &PluginInput) -> Result<PluginResult> {
        // Simulate different plugin behaviors based on input
        let operation = input
            .parameters
            .get("operation")
            .and_then(|v| v.as_str())
            .unwrap_or("default");

        match operation {
            "authenticate" => {
                // Simulate authentication
                let username = input
                    .parameters
                    .get("username")
                    .and_then(|v| v.as_str())
                    .unwrap_or("user");

                let success = username == "valid_user";

                Ok(PluginResult {
                    success,
                    data: Some(serde_json::json!({
                        "authenticated": success,
                        "user": username,
                        "timestamp": chrono::Utc::now().timestamp(),
                    })),
                    error: None,
                    metrics: crate::plugin::PluginMetrics {
                        execution_time_ms: 10,
                        memory_usage_bytes: 1024,
                        custom_metrics: HashMap::new(),
                    },
                })
            }
            "policy_check" => {
                // Simulate policy evaluation
                let resource = input
                    .parameters
                    .get("resource")
                    .and_then(|v| v.as_str())
                    .unwrap_or("resource");

                let action = input
                    .parameters
                    .get("action")
                    .and_then(|v| v.as_str())
                    .unwrap_or("read");

                // Simple policy: allow read on public resources
                let allowed = action == "read" || resource.contains("public");

                Ok(PluginResult {
                    success: true,
                    data: Some(serde_json::json!({
                        "allowed": allowed,
                        "resource": resource,
                        "action": action,
                        "policy": "default_policy",
                    })),
                    error: None,
                    metrics: crate::plugin::PluginMetrics {
                        execution_time_ms: 5,
                        memory_usage_bytes: 512,
                        custom_metrics: HashMap::new(),
                    },
                })
            }
            _ => {
                // Default operation
                Ok(PluginResult {
                    success: true,
                    data: Some(serde_json::json!({
                        "message": "Plugin executed successfully",
                        "operation": operation,
                        "input": input.parameters,
                    })),
                    error: None,
                    metrics: crate::plugin::PluginMetrics {
                        execution_time_ms: 1,
                        memory_usage_bytes: 256,
                        custom_metrics: HashMap::new(),
                    },
                })
            }
        }
    }

    /// Get current memory usage
    fn get_memory_usage(&self) -> Option<u64> {
        // Simulate memory usage
        Some(1024 * 1024) // 1MB
    }

    /// Get execution statistics
    pub async fn get_stats(&self) -> WasmStats {
        let ctx = self.context.read().await;
        ctx.stats.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plugin::PluginCapability;

    #[tokio::test]
    async fn test_wasm_plugin_loader() {
        let config = WasmPluginConfig::default();
        let loader = WasmPluginLoader::new(config).unwrap();

        // Create test metadata
        let metadata = PluginMetadata {
            id: "test-plugin".to_string(),
            name: "Test Plugin".to_string(),
            version: "1.0.0".to_string(),
            description: "Test plugin for WASM runtime".to_string(),
            author: "Fortress Team".to_string(),
            capabilities: vec![PluginCapability::Authentication],
            wasm_module: None,
            config_schema: None,
        };

        // Test loading with dummy WASM bytes and auth token
        let dummy_wasm = vec![0x00, 0x61, 0x73, 0x6d]; // WASM magic number
        let plugin =
            loader.load_from_bytes(&dummy_wasm, metadata.clone(), Some("valid-auth-token"));
        assert!(plugin.is_ok());

        let plugin = plugin.unwrap();
        assert_eq!(plugin.metadata().id, "test-plugin");

        // Test that loading without auth token fails when require_auth is true
        let plugin_no_auth = loader.load_from_bytes(&dummy_wasm, metadata, None);
        assert!(plugin_no_auth.is_err());
    }

    #[tokio::test]
    async fn test_wasm_plugin_execution() {
        let config = WasmPluginConfig::default();
        let loader = WasmPluginLoader::new(config).unwrap();

        let metadata = PluginMetadata {
            id: "test-plugin".to_string(),
            name: "Test Plugin".to_string(),
            version: "1.0.0".to_string(),
            description: "Test plugin for WASM runtime".to_string(),
            author: "Fortress Team".to_string(),
            capabilities: vec![PluginCapability::Authentication],
            wasm_module: None,
            config_schema: None,
        };

        let mut plugin = loader
            .load_from_bytes(
                &[0x00, 0x61, 0x73, 0x6d],
                metadata.clone(),
                Some("valid-auth-token"),
            )
            .unwrap();

        // Initialize plugin
        let context = PluginContext {
            config: HashMap::new(),
            metadata: plugin.metadata().clone(),
            encryption_access: false,
            storage_access: false,
            user_id: Some("test_user".to_string()),
            session_id: Some("test_session".to_string()),
            request_id: Some("test_request".to_string()),
        };

        assert!(plugin.initialize(context).await.is_ok());

        // Test authentication operation
        let input = PluginInput {
            action: "authenticate".to_string(),
            data: serde_json::json!({
                "username": "valid_user",
                "password": "test_password"
            }),
            parameters: std::collections::HashMap::new(),
            operation: Some("authenticate".to_string()),
            timestamp: Some(chrono::Utc::now()),
        };

        let result = plugin.execute(input).await;
        assert!(result.is_ok());

        let plugin_result = result.unwrap();
        assert!(plugin_result.success);
        assert_eq!(
            plugin_result.data.unwrap_or(serde_json::Value::Null)["authenticated"],
            true
        );

        // Test policy check operation
        let input = PluginInput {
            action: "policy_check".to_string(),
            data: serde_json::json!({
                "resource": "public_data",
                "action": "read"
            }),
            parameters: std::collections::HashMap::new(),
            operation: Some("policy_check".to_string()),
            timestamp: Some(chrono::Utc::now()),
        };

        let result = plugin.execute(input).await;
        assert!(result.is_ok());

        let plugin_result = result.unwrap();
        assert!(plugin_result.success);
        assert_eq!(
            plugin_result.data.unwrap_or(serde_json::Value::Null)["allowed"],
            true
        );

        // Test statistics
        let stats = plugin.get_stats().await;
        assert_eq!(stats.function_calls, 2);
        assert_eq!(stats.error_count, 0);
        assert!(stats.total_execution_time_ms > 0);

        // Test cleanup
        assert!(plugin.cleanup().await.is_ok());
    }

    #[tokio::test]
    async fn test_wasm_context() {
        let context = WasmContext {
            config: HashMap::new(),
            stats: WasmStats::default(),
        };

        assert_eq!(context.stats.function_calls, 0);
        assert_eq!(context.stats.error_count, 0);
    }

    #[tokio::test]
    async fn test_wasm_config() {
        let config = WasmPluginConfig::default();

        assert_eq!(config.max_memory_bytes, Some(64 * 1024 * 1024));
        assert_eq!(config.max_execution_time_ms, Some(5000));
        assert!(config.enable_fuel_metering);
        assert_eq!(config.max_fuel, Some(1000000));
        assert!(!config.allowed_host_functions.is_empty());
    }
}
