//! Plugin System for Fortress
//! 
//! This module provides a flexible plugin architecture that allows users to create
//! custom plugins that can integrate with external APIs and services. Plugins can
//! be used for various purposes such as signing transactions, interacting with
//! blockchain networks, or connecting to external key management systems.

use crate::error::{FortressError, Result};
use async_trait::async_trait;
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
                }).await
            }
            
            async fn execute_with_context(&self, input: $crate::plugin::PluginInput, context: &$crate::plugin::PluginContext) -> $crate::error::Result<$crate::plugin::PluginResult> {
                // Default implementation - can be overridden by specific plugins
                self.execute(input).await
            }
        }
    };
}
