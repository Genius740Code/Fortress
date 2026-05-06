//! Plugin System for Fortress
//! 
//! This module provides a flexible plugin architecture that allows users to create
//! custom plugins that can integrate with external APIs and services. Plugins can
//! be used for various purposes such as signing transactions, interacting with
//! blockchain networks, or connecting to external key management systems.

use crate::error::{FortressError, Result};
use async_trait::async_trait;
use chrono;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Plugin metadata that describes the plugin's capabilities and configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginMetadata {
    /// Unique identifier for the plugin
    pub id: String,
    /// Human-readable name of the plugin
    pub name: String,
    /// Plugin version
    pub version: String,
    /// Plugin description
    pub description: String,
    /// Plugin author
    pub author: String,
    /// List of capabilities this plugin provides
    pub capabilities: Vec<PluginCapability>,
    /// Configuration schema for the plugin
    pub config_schema: Option<serde_json::Value>,
    /// WASM module for the plugin (optional)
    pub wasm_module: Option<Vec<u8>>,
}

/// Plugin capabilities that define what actions a plugin can perform
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum PluginCapability {
    /// Can sign transactions or data
    SignTransaction,
    /// Can verify signatures
    VerifySignature,
    /// Can generate keys
    GenerateKey,
    /// Can encrypt data
    Encrypt,
    /// Can decrypt data
    Decrypt,
    /// Can hash data
    Hash,
    /// Can interact with external APIs
    ApiIntegration,
    /// Can manage secrets
    SecretManagement,
    /// Can authenticate users
    Authentication,
    /// Custom capability
    Custom(String),
}

/// Plugin execution context that provides access to Fortress internals
#[derive(Debug, Clone)]
pub struct PluginContext {
    /// Plugin configuration
    pub config: HashMap<String, serde_json::Value>,
    /// Plugin metadata
    pub metadata: PluginMetadata,
    /// Access to Fortress encryption system
    pub encryption_access: bool,
    /// Access to Fortress storage system
    pub storage_access: bool,
    /// User ID for the current operation
    pub user_id: Option<String>,
    /// Session ID for the current operation
    pub session_id: Option<String>,
    /// Request ID for tracking
    pub request_id: Option<String>,
}

/// Plugin execution result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginResult {
    /// Whether the plugin execution was successful
    pub success: bool,
    /// Result data
    pub data: Option<serde_json::Value>,
    /// Error message if execution failed
    pub error: Option<String>,
    /// Execution metrics
    pub metrics: PluginMetrics,
}

/// Plugin execution metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginMetrics {
    /// Execution time in milliseconds
    pub execution_time_ms: u64,
    /// Memory usage in bytes
    pub memory_usage_bytes: u64,
    /// Custom metrics provided by the plugin
    pub custom_metrics: HashMap<String, serde_json::Value>,
}

/// Main plugin trait that all plugins must implement
#[async_trait]
pub trait Plugin: Send + Sync {
    /// Get plugin metadata
    fn metadata(&self) -> &PluginMetadata;
    
    /// Initialize plugin with given context
    async fn initialize(&self, context: PluginContext) -> Result<()>;
    
    /// Execute plugin with given input
    async fn execute(&self, input: PluginInput) -> Result<PluginResult>;
    
    /// Execute plugin with given input and context
    async fn execute_with_context(&self, input: PluginInput, _context: &PluginContext) -> Result<PluginResult> {
        // Default implementation just calls execute without context
        self.execute(input).await
    }
    
    /// Cleanup resources when the plugin is being unloaded
    async fn cleanup(&self) -> Result<()>;
    
    /// Validate plugin configuration
    fn validate_config(&self, config: &HashMap<String, serde_json::Value>) -> Result<()>;
    
    /// Get plugin health status
    async fn health_check(&self) -> Result<PluginHealth>;
}

/// Plugin input data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginInput {
    /// Input action to perform
    pub action: String,
    /// Input data
    pub data: serde_json::Value,
    /// Additional parameters
    pub parameters: HashMap<String, serde_json::Value>,
    /// Operation type
    pub operation: Option<String>,
    /// Timestamp for the operation
    pub timestamp: Option<chrono::DateTime<chrono::Utc>>,
}

/// Plugin health status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginHealth {
    /// Whether the plugin is healthy
    pub healthy: bool,
    /// Health status message
    pub message: String,
    /// Last check timestamp
    pub last_check: chrono::DateTime<chrono::Utc>,
}

/// Plugin registry for managing loaded plugins
pub struct PluginRegistry {
    plugins: Arc<RwLock<HashMap<String, Arc<dyn Plugin>>>>,
    metadata: Arc<RwLock<HashMap<String, PluginMetadata>>>,
    plugin_contexts: Arc<RwLock<HashMap<String, PluginContext>>>,
}

impl std::fmt::Debug for PluginRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PluginRegistry")
            .field("plugin_count", &self.plugins.try_read().map(|p| p.len()).unwrap_or(0))
            .field("metadata_count", &self.metadata.try_read().map(|m| m.len()).unwrap_or(0))
            .field("plugin_contexts_count", &self.plugin_contexts.try_read().map(|p| p.len()).unwrap_or(0))
            .finish()
    }
}

impl PluginRegistry {
    /// Create a new plugin registry
    pub fn new() -> Self {
        Self {
            plugins: Arc::new(RwLock::new(HashMap::new())),
            metadata: Arc::new(RwLock::new(HashMap::new())),
            plugin_contexts: Arc::new(RwLock::new(HashMap::new())),
        }
    }
    
    /// Register a new plugin
    pub async fn register_plugin(&self, plugin: Arc<dyn Plugin>) -> Result<()> {
        let metadata = plugin.metadata().clone();
        let plugin_id = metadata.id.clone();
        
        // Validate plugin configuration
        plugin.validate_config(&HashMap::new())?;
        
        // Store plugin and metadata
        {
            let mut plugins = self.plugins.write().await;
            plugins.insert(plugin_id.clone(), plugin);
        }
        
        {
            let mut metadata_map = self.metadata.write().await;
            metadata_map.insert(plugin_id, metadata);
        }
        
        Ok(())
    }
    
    /// Get a plugin by ID
    pub async fn get_plugin(&self, plugin_id: &str) -> Result<Arc<dyn Plugin>> {
        let plugins = self.plugins.read().await;
        plugins
            .get(plugin_id)
            .cloned()
            .ok_or_else(|| FortressError::plugin(format!("Plugin '{}' not found", plugin_id)))
    }
    
    /// Get plugin context by ID
    pub async fn get_plugin_context(&self, plugin_id: &str) -> Option<PluginContext> {
        let contexts = self.plugin_contexts.read().await;
        contexts.get(plugin_id).cloned()
    }
    
    /// Set plugin context
    pub async fn set_plugin_context(&self, plugin_id: &str, context: PluginContext) {
        let mut contexts = self.plugin_contexts.write().await;
        contexts.insert(plugin_id.to_string(), context);
    }
    
    /// List all registered plugins
    pub async fn list_plugins(&self) -> Vec<PluginMetadata> {
        let metadata = self.metadata.read().await;
        metadata.values().cloned().collect()
    }
    
    /// Get plugins by capability
    pub async fn get_plugins_by_capability(&self, capability: &PluginCapability) -> Vec<PluginMetadata> {
        let metadata = self.metadata.read().await;
        metadata
            .values()
            .filter(|m| m.capabilities.contains(capability))
            .cloned()
            .collect()
    }
    
    /// Unregister a plugin
    pub async fn unregister_plugin(&self, plugin_id: &str) -> Result<()> {
        // Get plugin for cleanup
        let plugin = {
            let plugins = self.plugins.read().await;
            plugins.get(plugin_id).cloned()
        };
        
        if let Some(plugin) = plugin {
            // Cleanup plugin
            plugin.cleanup().await?;
        }
        
        // Remove from registry
        {
            let mut plugins = self.plugins.write().await;
            plugins.remove(plugin_id);
        }
        
        // Remove from metadata
        {
            let mut metadata = self.metadata.write().await;
            metadata.remove(plugin_id);
        }
        
        // Remove from contexts
        {
            let mut contexts = self.plugin_contexts.write().await;
            contexts.remove(plugin_id);
        }
        
        Ok(())
    }
}

impl Default for PluginRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Plugin manager for handling plugin lifecycle
#[derive(Debug)]
pub struct PluginManager {
    registry: Arc<PluginRegistry>,
    plugin_configs: Arc<RwLock<HashMap<String, HashMap<String, serde_json::Value>>>>,
}

impl PluginManager {
    /// Create a new plugin manager
    pub fn new() -> Self {
        Self {
            registry: Arc::new(PluginRegistry::new()),
            plugin_configs: Arc::new(RwLock::new(HashMap::new())),
        }
    }
    
    /// Load and initialize a plugin
    pub async fn load_plugin(
        &self,
        plugin: Arc<dyn Plugin>,
        config: HashMap<String, serde_json::Value>,
    ) -> Result<()> {
        let plugin_id = {
            let metadata = plugin.metadata();
            metadata.id.clone()
        };
        
        // Store configuration
        {
            let mut configs = self.plugin_configs.write().await;
            configs.insert(plugin_id.clone(), config);
        }
        
        // Create plugin context
        let context = PluginContext {
            config: {
                let configs = self.plugin_configs.read().await;
                configs.get(&plugin_id).cloned().unwrap_or_default()
            },
            metadata: plugin.metadata().clone(),
            encryption_access: true,
            storage_access: true,
            user_id: None,
            session_id: None,
            request_id: None,
        };
        
        // Store plugin context in registry
        self.registry.set_plugin_context(&plugin_id, context).await;
        
        // Register plugin
        self.registry.register_plugin(plugin).await?;
        
        Ok(())
    }
    
    /// Execute a plugin
    pub async fn execute_plugin(
        &self,
        plugin_id: &str,
        input: PluginInput,
    ) -> Result<PluginResult> {
        let plugin = self.registry.get_plugin(plugin_id).await?;
        plugin.execute(input).await
    }
    
    /// Get plugin registry
    pub fn registry(&self) -> &Arc<PluginRegistry> {
        &self.registry
    }
    
    /// Get health status of all plugins
    pub async fn get_all_health_status(&self) -> HashMap<String, PluginHealth> {
        let plugins = self.registry.plugins.read().await;
        let mut health_status = HashMap::new();
        
        for (id, plugin) in plugins.iter() {
            if let Ok(health) = plugin.health_check().await {
                health_status.insert(id.clone(), health);
            }
        }
        
        health_status
    }
}

impl Default for PluginManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Macro to help create plugin implementations
#[macro_export]
macro_rules! fortress_plugin {
    (
        metadata: {
            id: $id:expr,
            name: $name:expr,
            version: $version:expr,
            description: $description:expr,
            author: $author:expr,
            capabilities: [$($capability:expr),* $(,)?],
            $(config_schema: $config_schema:expr,)?
        },
        $struct_name:ident {
            $($field_name:ident: $field_type:ty),* $(,)?
        }
    ) => {
        #[derive(Debug)]
        struct $struct_name {
            $($field_name: $field_type,)*
            metadata: $crate::plugin::PluginMetadata,
        }
        
        impl $struct_name {
            fn new() -> Self {
                Self {
                    $($field_name: Default::default(),)*
                    metadata: $crate::plugin::PluginMetadata {
                        id: $id.to_string(),
                        name: $name.to_string(),
                        version: $version.to_string(),
                        description: $description.to_string(),
                        author: $author.to_string(),
                        capabilities: vec![$($capability,)*],
                        config_schema: $config_schema,
                    },
                }
            }
        }
        
        #[async_trait::async_trait]
        impl $crate::plugin::Plugin for $struct_name {
            fn metadata(&self) -> &$crate::plugin::PluginMetadata {
                &self.metadata
            }
            
            async fn initialize(&self, _context: $crate::plugin::PluginContext) -> $crate::error::Result<()> {
                // Context is handled by the plugin manager
                Ok(())
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
            
            async fn execute(&self, input: $crate::plugin::PluginInput) -> $crate::error::Result<$crate::plugin::PluginResult> {
                // Default implementation
                self.execute_with_context(input, &$crate::plugin::PluginContext {
                    config: std::collections::HashMap::new(),
                    metadata: self.metadata.clone(),
                    encryption_access: false,
                    storage_access: false,
                    user_id: None,
                    session_id: None,
                    request_id: None,
                }).await
            }
            
            async fn execute_with_context(&self, input: $crate::plugin::PluginInput, context: &$crate::plugin::PluginContext) -> $crate::error::Result<$crate::plugin::PluginResult> {
                // Default implementation - can be overridden by specific plugins
                self.execute(input).await
            }
        }
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use tokio::time::{sleep, Duration};

    // Test plugin implementation
    #[derive(Debug)]
    struct TestPlugin {
        metadata: PluginMetadata,
        initialized: std::sync::Arc<tokio::sync::RwLock<bool>>,
        execution_count: std::sync::Arc<tokio::sync::RwLock<u64>>,
    }

    impl TestPlugin {
        fn new(id: &str, name: &str, capabilities: Vec<PluginCapability>) -> Self {
            Self {
                metadata: PluginMetadata {
                    id: id.to_string(),
                    name: name.to_string(),
                    version: "1.0.0".to_string(),
                    description: "Test plugin".to_string(),
                    author: "Test Author".to_string(),
                    capabilities,
                    config_schema: None,
                    wasm_module: None,
                },
                initialized: std::sync::Arc::new(tokio::sync::RwLock::new(false)),
                execution_count: std::sync::Arc::new(tokio::sync::RwLock::new(0)),
            }
        }

        async fn is_initialized(&self) -> bool {
            *self.initialized.read().await
        }

        async fn get_execution_count(&self) -> u64 {
            *self.execution_count.read().await
        }
    }

    #[async_trait]
    impl Plugin for TestPlugin {
        fn metadata(&self) -> &PluginMetadata {
            &self.metadata
        }

        async fn initialize(&self, _context: PluginContext) -> Result<()> {
            let mut initialized = self.initialized.write().await;
            *initialized = true;
            Ok(())
        }

        async fn execute(&self, input: PluginInput) -> Result<PluginResult> {
            let mut count = self.execution_count.write().await;
            *count += 1;

            let result = PluginResult {
                success: true,
                data: Some(serde_json::json!({
                    "action": input.action,
                    "execution_count": *count,
                    "timestamp": chrono::Utc::now().to_rfc3339()
                })),
                error: None,
                metrics: PluginMetrics {
                    execution_time_ms: 10,
                    memory_usage_bytes: 1024,
                    custom_metrics: HashMap::new(),
                },
            };

            Ok(result)
        }

        async fn cleanup(&self) -> Result<()> {
            let mut initialized = self.initialized.write().await;
            *initialized = false;
            Ok(())
        }

        fn validate_config(&self, _config: &HashMap<String, serde_json::Value>) -> Result<()> {
            Ok(())
        }

        async fn health_check(&self) -> Result<PluginHealth> {
            let initialized = *self.initialized.read().await;
            Ok(PluginHealth {
                healthy: initialized,
                message: if initialized { "Plugin is healthy" } else { "Plugin not initialized" }.to_string(),
                last_check: chrono::Utc::now(),
            })
        }
    }

    #[tokio::test]
    async fn test_plugin_metadata() {
        let capabilities = vec![
            PluginCapability::SignTransaction,
            PluginCapability::Encrypt,
            PluginCapability::ApiIntegration,
        ];
        
        let plugin = TestPlugin::new("test-plugin", "Test Plugin", capabilities);
        let metadata = plugin.metadata();

        assert_eq!(metadata.id, "test-plugin");
        assert_eq!(metadata.name, "Test Plugin");
        assert_eq!(metadata.version, "1.0.0");
        assert_eq!(metadata.description, "Test plugin");
        assert_eq!(metadata.author, "Test Author");
        assert_eq!(metadata.capabilities.len(), 3);
        assert!(metadata.capabilities.contains(&PluginCapability::SignTransaction));
        assert!(metadata.capabilities.contains(&PluginCapability::Encrypt));
        assert!(metadata.capabilities.contains(&PluginCapability::ApiIntegration));
        assert!(metadata.config_schema.is_none());
    }

    #[tokio::test]
    async fn test_plugin_lifecycle() -> Result<()> {
        let plugin = TestPlugin::new("lifecycle-test", "Lifecycle Test", vec![]);
        
        // Initially not initialized
        assert!(!plugin.is_initialized().await);
        assert_eq!(plugin.get_execution_count().await, 0);

        // Initialize plugin
        let context = PluginContext {
            config: HashMap::new(),
            metadata: plugin.metadata().clone(),
            encryption_access: true,
            storage_access: false,
            user_id: None,
            session_id: None,
            request_id: None,
        };
        
        plugin.initialize(context).await?;
        assert!(plugin.is_initialized().await);

        // Execute plugin
        let input = PluginInput {
            action: "test_action".to_string(),
            data: serde_json::json!({"test": "data"}),
            parameters: HashMap::new(),
            operation: None,
            timestamp: None,
        };

        let result = plugin.execute(input).await?;
        assert!(result.success);
        assert!(result.data.is_some());
        assert_eq!(plugin.get_execution_count().await, 1);

        // Health check
        let health = plugin.health_check().await?;
        assert!(health.healthy);
        assert_eq!(health.message, "Plugin is healthy");

        // Cleanup plugin
        plugin.cleanup().await?;
        assert!(!plugin.is_initialized().await);

        Ok(())
    }

    #[tokio::test]
    async fn test_plugin_registry() -> Result<()> {
        let registry = PluginRegistry::new();
        
        // Create test plugin
        let plugin = TestPlugin::new(
            "registry-test",
            "Registry Test",
            vec![PluginCapability::SignTransaction],
        );
        let plugin_arc = Arc::new(plugin);

        // Register plugin
        registry.register_plugin(plugin_arc.clone()).await?;

        // List plugins
        let plugins = registry.list_plugins().await;
        assert_eq!(plugins.len(), 1);
        assert_eq!(plugins[0].id, "registry-test");

        // Get plugin
        let retrieved_plugin = registry.get_plugin("registry-test").await?;
        assert_eq!(retrieved_plugin.metadata().id, "registry-test");

        // Get plugins by capability
        let signing_plugins = registry.get_plugins_by_capability(&PluginCapability::SignTransaction).await;
        assert_eq!(signing_plugins.len(), 1);
        assert_eq!(signing_plugins[0].id, "registry-test");

        let encrypt_plugins = registry.get_plugins_by_capability(&PluginCapability::Encrypt).await;
        assert_eq!(encrypt_plugins.len(), 0);

        // Plugin context management
        let context = PluginContext {
            config: HashMap::new(),
            metadata: plugin_arc.metadata().clone(),
            encryption_access: true,
            storage_access: false,
            user_id: None,
            session_id: None,
            request_id: None,
        };

        registry.set_plugin_context("registry-test", context.clone()).await;
        let retrieved_context = registry.get_plugin_context("registry-test").await;
        assert!(retrieved_context.is_some());
        let retrieved_context = retrieved_context.unwrap();
        assert_eq!(retrieved_context.encryption_access, true);
        assert_eq!(retrieved_context.storage_access, false);

        // Unregister plugin
        registry.unregister_plugin("registry-test").await?;
        let plugins_after = registry.list_plugins().await;
        assert_eq!(plugins_after.len(), 0);

        // Should fail to get unregistered plugin
        let result = registry.get_plugin("registry-test").await;
        assert!(result.is_err());

        Ok(())
    }

    #[tokio::test]
    async fn test_plugin_manager() -> Result<()> {
        let manager = PluginManager::new();
        
        // Create test plugin
        let plugin = TestPlugin::new(
            "manager-test",
            "Manager Test",
            vec![PluginCapability::Encrypt, PluginCapability::Decrypt],
        );
        let plugin_arc = Arc::new(plugin);

        // Load plugin with configuration
        let mut config = HashMap::new();
        config.insert("test_param".to_string(), serde_json::json!("test_value"));

        manager.load_plugin(plugin_arc.clone(), config).await?;

        // Execute plugin
        let input = PluginInput {
            action: "encrypt".to_string(),
            data: serde_json::json!({"data": "test_data"}),
            parameters: HashMap::new(),
            operation: None,
            timestamp: None,
        };

        let result = manager.execute_plugin("manager-test", input).await?;
        assert!(result.success);
        assert!(result.data.is_some());

        // Get all health status
        let health_status = manager.get_all_health_status().await;
        assert_eq!(health_status.len(), 1);
        assert!(health_status.contains_key("manager-test"));

        let health = health_status.get("manager-test").unwrap();
        assert!(health.healthy);

        Ok(())
    }

    #[tokio::test]
    async fn test_plugin_execution_with_context() -> Result<()> {
        let plugin = TestPlugin::new("context-test", "Context Test", vec![]);
        
        let input = PluginInput {
            action: "test_action".to_string(),
            data: serde_json::json!({"test": "data"}),
            parameters: HashMap::new(),
            operation: Some("test_operation".to_string()),
            timestamp: Some(chrono::Utc::now()),
        };

        let context = PluginContext {
            config: {
                let mut config = HashMap::new();
                config.insert("test_config".to_string(), serde_json::json!("config_value"));
                config
            },
            metadata: plugin.metadata().clone(),
            encryption_access: true,
            storage_access: true,
            user_id: None,
            session_id: None,
            request_id: None,
        };

        let result = plugin.execute_with_context(input, &context).await?;
        assert!(result.success);
        assert!(result.data.is_some());

        Ok(())
    }

    #[tokio::test]
    async fn test_plugin_error_handling() -> Result<()> {
        // Create a plugin that fails validation
        #[derive(Debug)]
        struct FailingPlugin {
            metadata: PluginMetadata,
        }

        impl FailingPlugin {
            fn new() -> Self {
                Self {
                    metadata: PluginMetadata {
                        id: "failing-plugin".to_string(),
                        name: "Failing Plugin".to_string(),
                        version: "1.0.0".to_string(),
                        description: "A plugin that fails validation".to_string(),
                        author: "Test Author".to_string(),
                        capabilities: vec![PluginCapability::SignTransaction],
                        config_schema: None,
                        wasm_module: None,
                    },
                }
            }
        }

        #[async_trait]
        impl Plugin for FailingPlugin {
            fn metadata(&self) -> &PluginMetadata {
                &self.metadata
            }

            async fn initialize(&self, _context: PluginContext) -> Result<()> {
                Ok(())
            }

            async fn execute(&self, _input: PluginInput) -> Result<PluginResult> {
                Err(FortressError::plugin("Test execution failure"))
            }

            async fn cleanup(&self) -> Result<()> {
                Ok(())
            }

            fn validate_config(&self, _config: &HashMap<String, serde_json::Value>) -> Result<()> {
                Err(FortressError::plugin("Configuration validation failed"))
            }

            async fn health_check(&self) -> Result<PluginHealth> {
                Ok(PluginHealth {
                    healthy: false,
                    message: "Plugin is unhealthy".to_string(),
                    last_check: chrono::Utc::now(),
                })
            }
        }

        let plugin = FailingPlugin::new();
        let plugin_arc = Arc::new(plugin);
        let registry = PluginRegistry::new();

        // Should fail to register due to validation error
        let result = registry.register_plugin(plugin_arc).await;
        assert!(result.is_err());

        Ok(())
    }

    #[tokio::test]
    async fn test_plugin_capability_equality() {
        assert_eq!(PluginCapability::SignTransaction, PluginCapability::SignTransaction);
        assert_ne!(PluginCapability::SignTransaction, PluginCapability::Encrypt);
        assert_eq!(PluginCapability::Custom("test".to_string()), PluginCapability::Custom("test".to_string()));
        assert_ne!(PluginCapability::Custom("test1".to_string()), PluginCapability::Custom("test2".to_string()));
    }

    #[tokio::test]
    async fn test_plugin_serialization() {
        let metadata = PluginMetadata {
            id: "test-plugin".to_string(),
            name: "Test Plugin".to_string(),
            version: "1.0.0".to_string(),
            description: "A test plugin".to_string(),
            author: "Test Author".to_string(),
            capabilities: vec![PluginCapability::SignTransaction, PluginCapability::Encrypt],
            config_schema: Some(serde_json::json!({
                "type": "object",
                "properties": {
                    "api_key": {"type": "string"}
                }
            })),
            wasm_module: None,
        };

        // Test serialization
        let json = serde_json::to_string(&metadata).expect("Failed to serialize metadata");
        assert!(!json.is_empty());

        // Test deserialization
        let deserialized: PluginMetadata = serde_json::from_str(&json).expect("Failed to deserialize metadata");
        assert_eq!(deserialized.id, metadata.id);
        assert_eq!(deserialized.name, metadata.name);
        assert_eq!(deserialized.capabilities, metadata.capabilities);
        assert!(deserialized.config_schema.is_some());
    }

    #[tokio::test]
    async fn test_plugin_result_serialization() {
        let result = PluginResult {
            success: true,
            data: Some(serde_json::json!({
                "result": "success",
                "value": 42
            })),
            error: None,
            metrics: PluginMetrics {
                execution_time_ms: 100,
                memory_usage_bytes: 2048,
                custom_metrics: {
                    let mut metrics = HashMap::new();
                    metrics.insert("custom_metric".to_string(), serde_json::json!(123));
                    metrics
                },
            },
        };

        // Test serialization
        let json = serde_json::to_string(&result).expect("Failed to serialize result");
        assert!(!json.is_empty());

        // Test deserialization
        let deserialized: PluginResult = serde_json::from_str(&json).expect("Failed to deserialize result");
        assert_eq!(deserialized.success, result.success);
        assert!(deserialized.data.is_some());
        assert_eq!(deserialized.metrics.execution_time_ms, 100);
        assert_eq!(deserialized.metrics.memory_usage_bytes, 2048);
        assert!(deserialized.metrics.custom_metrics.contains_key("custom_metric"));
    }

    #[tokio::test]
    async fn test_plugin_health_serialization() {
        let health = PluginHealth {
            healthy: true,
            message: "All systems operational".to_string(),
            last_check: chrono::Utc::now(),
        };

        // Test serialization
        let json = serde_json::to_string(&health).expect("Failed to serialize health");
        assert!(!json.is_empty());

        // Test deserialization
        let deserialized: PluginHealth = serde_json::from_str(&json).expect("Failed to deserialize health");
        assert_eq!(deserialized.healthy, health.healthy);
        assert_eq!(deserialized.message, health.message);
    }

    #[tokio::test]
    async fn test_concurrent_plugin_access() -> Result<()> {
        let registry = Arc::new(PluginRegistry::new());
        
        // Create and register multiple plugins
        for i in 0..5 {
            let plugin = TestPlugin::new(
                &format!("concurrent-test-{}", i),
                &format!("Concurrent Test {}", i),
                vec![PluginCapability::Encrypt],
            );
            let plugin_arc = Arc::new(plugin);
            registry.register_plugin(plugin_arc).await?;
        }

        // Concurrent access tasks
        let mut handles = Vec::new();
        for i in 0..10 {
            let registry_clone = registry.clone();
            let handle = tokio::spawn(async move {
                let plugin_id = format!("concurrent-test-{}", i % 5);
                let result = registry_clone.get_plugin(&plugin_id).await;
                assert!(result.is_ok());
                
                let plugins = registry_clone.list_plugins().await;
                assert_eq!(plugins.len(), 5);
            });
            handles.push(handle);
        }

        // Wait for all tasks to complete
        for handle in handles {
            handle.await.expect("Task panicked");
        }

        Ok(())
    }

    #[tokio::test]
    async fn test_plugin_input_validation() {
        let input = PluginInput {
            action: "test_action".to_string(),
            data: serde_json::json!({"key": "value"}),
            parameters: {
                let mut params = HashMap::new();
                params.insert("param1".to_string(), serde_json::json!("value1"));
                params.insert("param2".to_string(), serde_json::json!(42));
                params
            },
            operation: None,
            timestamp: None,
        };

        assert_eq!(input.action, "test_action");
        assert!(input.data.is_object());
        assert_eq!(input.parameters.len(), 2);
        assert!(input.parameters.contains_key("param1"));
        assert!(input.parameters.contains_key("param2"));
    }

    #[tokio::test]
    async fn test_plugin_context_access_controls() {
        let context1 = PluginContext {
            config: HashMap::new(),
            metadata: PluginMetadata {
                id: "test".to_string(),
                name: "Test".to_string(),
                version: "1.0.0".to_string(),
                description: "Test".to_string(),
                author: "Test".to_string(),
                capabilities: vec![],
                config_schema: None,
                wasm_module: None,
            },
            encryption_access: true,
            storage_access: false,
            user_id: None,
            session_id: None,
            request_id: None,
        };

        let context2 = PluginContext {
            config: HashMap::new(),
            metadata: PluginMetadata {
                id: "test".to_string(),
                name: "Test".to_string(),
                version: "1.0.0".to_string(),
                description: "Test".to_string(),
                author: "Test".to_string(),
                capabilities: vec![],
                config_schema: None,
                wasm_module: None,
            },
            encryption_access: false,
            storage_access: true,
            user_id: None,
            session_id: None,
            request_id: None,
        };

        assert!(context1.encryption_access);
        assert!(!context1.storage_access);
        assert!(!context2.encryption_access);
        assert!(context2.storage_access);
    }

    #[tokio::test]
    async fn test_plugin_registry_debug_format() {
        let registry = PluginRegistry::new();
        
        // Add some plugins
        let plugin1 = TestPlugin::new("debug-test-1", "Debug Test 1", vec![]);
        let plugin2 = TestPlugin::new("debug-test-2", "Debug Test 2", vec![]);
        
        registry.register_plugin(Arc::new(plugin1)).await.unwrap();
        registry.register_plugin(Arc::new(plugin2)).await.unwrap();

        let debug_str = format!("{:?}", registry);
        assert!(debug_str.contains("PluginRegistry"));
        assert!(debug_str.contains("plugin_count"));
        assert!(debug_str.contains("metadata_count"));
        assert!(debug_str.contains("plugin_contexts_count"));
    }

    #[tokio::test]
    async fn test_plugin_manager_default() {
        let manager = PluginManager::default();
        let plugins = manager.registry().list_plugins().await;
        assert_eq!(plugins.len(), 0);
    }

    #[tokio::test]
    async fn test_plugin_registry_default() {
        let registry = PluginRegistry::default();
        let plugins = registry.list_plugins().await;
        assert_eq!(plugins.len(), 0);
    }

    #[tokio::test]
    async fn test_plugin_capability_custom() {
        let custom_cap1 = PluginCapability::Custom("custom_capability".to_string());
        let custom_cap2 = PluginCapability::Custom("another_capability".to_string());
        
        assert_ne!(custom_cap1, custom_cap2);
        
        // Test serialization of custom capabilities
        let metadata = PluginMetadata {
            id: "custom-test".to_string(),
            name: "Custom Test".to_string(),
            version: "1.0.0".to_string(),
            description: "Test custom capabilities".to_string(),
            author: "Test".to_string(),
            capabilities: vec![custom_cap1.clone(), custom_cap2.clone()],
            config_schema: None,
            wasm_module: None,
        };

        let json = serde_json::to_string(&metadata).expect("Failed to serialize");
        let deserialized: PluginMetadata = serde_json::from_str(&json).expect("Failed to deserialize");
        
        assert_eq!(deserialized.capabilities.len(), 2);
        assert!(deserialized.capabilities.contains(&custom_cap1));
        assert!(deserialized.capabilities.contains(&custom_cap2));
    }

    #[tokio::test]
    async fn test_plugin_complex_scenario() -> Result<()> {
        let manager = PluginManager::new();
        
        // Create multiple plugins with different capabilities
        let signing_plugin = TestPlugin::new(
            "signing-plugin",
            "Signing Plugin",
            vec![PluginCapability::SignTransaction, PluginCapability::VerifySignature],
        );
        
        let crypto_plugin = TestPlugin::new(
            "crypto-plugin",
            "Crypto Plugin",
            vec![PluginCapability::Encrypt, PluginCapability::Decrypt, PluginCapability::GenerateKey],
        );
        
        let api_plugin = TestPlugin::new(
            "api-plugin",
            "API Plugin",
            vec![PluginCapability::ApiIntegration, PluginCapability::SecretManagement],
        );

        // Load all plugins
        manager.load_plugin(Arc::new(signing_plugin), HashMap::new()).await?;
        manager.load_plugin(Arc::new(crypto_plugin), HashMap::new()).await?;
        manager.load_plugin(Arc::new(api_plugin), HashMap::new()).await?;

        // Verify all plugins are loaded
        let plugins = manager.registry().list_plugins().await;
        assert_eq!(plugins.len(), 3);

        // Test capability filtering
        let signing_plugins = manager.registry().get_plugins_by_capability(&PluginCapability::SignTransaction).await;
        assert_eq!(signing_plugins.len(), 1);
        assert_eq!(signing_plugins[0].id, "signing-plugin");

        let encrypt_plugins = manager.registry().get_plugins_by_capability(&PluginCapability::Encrypt).await;
        assert_eq!(encrypt_plugins.len(), 1);
        assert_eq!(encrypt_plugins[0].id, "crypto-plugin");

        let api_plugins = manager.registry().get_plugins_by_capability(&PluginCapability::ApiIntegration).await;
        assert_eq!(api_plugins.len(), 1);
        assert_eq!(api_plugins[0].id, "api-plugin");

        // Execute all plugins
        for plugin_id in ["signing-plugin", "crypto-plugin", "api-plugin"] {
            let input = PluginInput {
                action: "test".to_string(),
                data: serde_json::json!({"plugin_id": plugin_id}),
                parameters: HashMap::new(),
                operation: None,
                timestamp: None,
            };

            let result = manager.execute_plugin(plugin_id, input).await?;
            assert!(result.success);
        }

        // Check health of all plugins
        let health_status = manager.get_all_health_status().await;
        assert_eq!(health_status.len(), 3);
        
        for (plugin_id, health) in health_status.iter() {
            assert!(health.healthy, "Plugin {} should be healthy", plugin_id);
        }

        Ok(())
    }
}
