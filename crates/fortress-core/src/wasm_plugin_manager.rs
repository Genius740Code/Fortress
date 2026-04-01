//! WebAssembly Plugin Manager
//! 
//! This module provides comprehensive plugin management for WASM-based policy evaluators
//! and authentication providers, making Fortress the most extensible security platform.

use crate::error::{FortressError, Result};
use crate::plugin::{PluginMetadata, PluginCapability};
use crate::wasm_runtime::{WasmPlugin, WasmPluginConfig, WasmPluginLoader};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;

/// Plugin manager for handling WASM-based plugins
pub struct WasmPluginManager {
    /// Policy evaluator registry
    policy_registry: Arc<PolicyEvaluatorRegistry>,
    /// Authentication provider registry
    auth_registry: Arc<AuthProviderRegistry>,
    /// WASM plugin loader
    plugin_loader: Arc<WasmPluginLoader>,
    /// Loaded plugins
    plugins: Arc<RwLock<HashMap<String, Arc<WasmPlugin>>>>,
    /// Plugin configurations
    plugin_configs: Arc<RwLock<HashMap<String, WasmPluginConfig>>>,
    /// Manager configuration
    config: WasmPluginManagerConfig,
}

/// Plugin manager configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WasmPluginManagerConfig {
    /// Maximum number of plugins to load
    pub max_plugins: usize,
    /// Default plugin configuration
    pub default_plugin_config: WasmPluginConfig,
    /// Plugin directory paths
    pub plugin_directories: Vec<PathBuf>,
    /// Auto-load plugins on startup
    pub auto_load: bool,
    /// Enable plugin hot-reloading
    pub enable_hot_reload: bool,
    /// Plugin validation settings
    pub validation: PluginValidationConfig,
}

/// Plugin validation configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginValidationConfig {
    /// Require digital signatures
    pub require_signature: bool,
    /// Allowed plugin capabilities
    pub allowed_capabilities: Vec<String>,
    /// Maximum plugin size in bytes
    pub max_plugin_size: u64,
    /// Plugin timeout in milliseconds
    pub plugin_timeout_ms: u64,
}

impl Default for WasmPluginManagerConfig {
    fn default() -> Self {
        Self {
            max_plugins: 100,
            default_plugin_config: WasmPluginConfig::default(),
            plugin_directories: vec![
                PathBuf::from("./plugins"),
                PathBuf::from("./examples"),
            ],
            auto_load: true,
            enable_hot_reload: false,
            validation: PluginValidationConfig {
                require_signature: false,
                allowed_capabilities: vec![
                    "policy_evaluation".to_string(),
                    "authentication".to_string(),
                    "encryption".to_string(),
                    "storage".to_string(),
                ],
                max_plugin_size: 10 * 1024 * 1024, // 10MB
                plugin_timeout_ms: 5000, // 5 seconds
            },
        }
    }
}

/// Plugin information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginInfo {
    /// Plugin metadata
    pub metadata: PluginMetadata,
    /// Plugin type
    pub plugin_type: PluginType,
    /// Plugin status
    pub status: PluginStatus,
    /// Load timestamp
    pub loaded_at: chrono::DateTime<chrono::Utc>,
    /// Plugin size in bytes
    pub size_bytes: u64,
    /// Plugin version
    pub version: String,
}

/// Plugin types
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum PluginType {
    PolicyEvaluator,
    AuthProvider,
    EncryptionProvider,
    StorageProvider,
    Custom(String),
}

/// Plugin status
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum PluginStatus {
    Loaded,
    Active,
    Inactive,
    Error(String),
    Unloaded,
}

impl WasmPluginManager {
    /// Create a new WASM plugin manager
    pub fn new(config: WasmPluginManagerConfig) -> Self {
        Self {
            policy_registry: Arc::new(PolicyEvaluatorRegistry::new()),
            auth_registry: Arc::new(AuthProviderRegistry::new()),
            plugin_loader: Arc::new(WasmPluginLoader::new()),
            plugins: Arc::new(RwLock::new(HashMap::new())),
            plugin_configs: Arc::new(RwLock::new(HashMap::new())),
            config,
        }
    }

    /// Initialize the plugin manager
    pub async fn initialize(&self) -> Result<()> {
        tracing::info!("Initializing WASM Plugin Manager");

        // Auto-load plugins if enabled
        if self.config.auto_load {
            self.load_all_plugins().await?;
        }

        tracing::info!("WASM Plugin Manager initialized successfully");
        Ok(())
    }

    /// Load a WASM plugin from file
    pub async fn load_plugin(&self, plugin_path: &PathBuf) -> Result<PluginInfo> {
        tracing::info!("Loading WASM plugin: {:?}", plugin_path);

        // Validate plugin file
        self.validate_plugin_file(plugin_path).await?;

        // Read plugin file
        let plugin_bytes = tokio::fs::read(plugin_path)
            .await
            .map_err(|e| FortressError::plugin(format!("Failed to read plugin file: {}", e)))?;

        // Extract plugin metadata (simplified - in production would read from WASM exports)
        let metadata = self.extract_plugin_metadata(&plugin_bytes)?;

        // Validate plugin capabilities
        self.validate_plugin_capabilities(&metadata)?;

        // Create WASM plugin
        let mut plugin = self.plugin_loader.from_bytes(&plugin_bytes, metadata.clone())?;

        // Initialize plugin
        let config = self.config.default_plugin_config.clone();
        let plugin_config = HashMap::new();
        plugin.initialize(plugin_config).await?;

        // Determine plugin type and register accordingly
        let plugin_type = self.determine_plugin_type(&metadata);

        match plugin_type {
            PluginType::PolicyEvaluator => {
                let policy_evaluator = Arc::new(WasmPolicyEvaluator::new(
                    metadata.clone(),
                    crate::wasm_policy::PolicyEvaluatorConfig::default(),
                ));
                self.policy_registry.register_evaluator(metadata.id.clone(), policy_evaluator).await;
            },
            PluginType::AuthProvider => {
                let auth_provider = Arc::new(WasmAuthProvider::new(
                    metadata.clone(),
                    crate::wasm_auth::AuthProviderConfig::default(),
                ));
                self.auth_registry.register_provider(metadata.id.clone(), auth_provider).await;
            },
            _ => {
                // Store generic plugin
                let mut plugins = self.plugins.write().await;
                plugins.insert(metadata.id.clone(), Arc::new(plugin));
            }
        }

        // Store plugin configuration
        {
            let mut configs = self.plugin_configs.write().await;
            configs.insert(metadata.id.clone(), config);
        }

        let plugin_info = PluginInfo {
            metadata: metadata.clone(),
            plugin_type,
            status: PluginStatus::Loaded,
            loaded_at: chrono::Utc::now(),
            size_bytes: plugin_bytes.len() as u64,
            version: metadata.version,
        };

        tracing::info!("Successfully loaded plugin: {}", metadata.name);
        Ok(plugin_info)
    }

    /// Unload a plugin
    pub async fn unload_plugin(&self, plugin_id: &str) -> Result<()> {
        tracing::info!("Unloading plugin: {}", plugin_id);

        // Remove from registries
        self.policy_registry.evaluators.write().await.remove(plugin_id);
        self.auth_registry.providers.write().await.remove(plugin_id);

        // Remove from plugins
        {
            let mut plugins = self.plugins.write().await;
            plugins.remove(plugin_id);
        }

        // Remove configuration
        {
            let mut configs = self.plugin_configs.write().await;
            configs.remove(plugin_id);
        }

        tracing::info!("Successfully unloaded plugin: {}", plugin_id);
        Ok(())
    }

    /// Evaluate policy using registered evaluator
    pub async fn evaluate_policy(&self, evaluator_id: &str, context: PolicyContext) -> Result<PolicyResult> {
        let evaluator = self.policy_registry.get_evaluator(evaluator_id).await
            .ok_or_else(|| FortressError::plugin(format!("Policy evaluator '{}' not found", evaluator_id)))?;
        
        evaluator.evaluate(context).await
    }

    /// Authenticate using registered provider
    pub async fn authenticate(&self, provider_id: &str, context: AuthContext) -> Result<AuthResult> {
        let provider = self.auth_registry.get_provider(provider_id).await
            .ok_or_else(|| FortressError::plugin(format!("Auth provider '{}' not found", provider_id)))?;
        
        provider.authenticate(context).await
    }

    /// List all loaded plugins
    pub async fn list_plugins(&self) -> Vec<PluginInfo> {
        let mut plugins = Vec::new();
        
        // List policy evaluators
        let evaluator_ids = self.policy_registry.list_evaluators().await;
        for id in evaluator_ids {
            if let Some(evaluator) = self.policy_registry.get_evaluator(&id).await {
                plugins.push(PluginInfo {
                    metadata: evaluator.metadata().clone(),
                    plugin_type: PluginType::PolicyEvaluator,
                    status: PluginStatus::Active,
                    loaded_at: chrono::Utc::now(),
                    size_bytes: 0,
                    version: evaluator.metadata().version.clone(),
                });
            }
        }

        // List auth providers
        let provider_ids = self.auth_registry.list_providers().await;
        for id in provider_ids {
            if let Some(provider) = self.auth_registry.get_provider(&id).await {
                plugins.push(PluginInfo {
                    metadata: provider.metadata().clone(),
                    plugin_type: PluginType::AuthProvider,
                    status: PluginStatus::Active,
                    loaded_at: chrono::Utc::now(),
                    size_bytes: 0,
                    version: provider.metadata().version.clone(),
                });
            }
        }

        plugins
    }

    /// Get plugin by ID
    pub async fn get_plugin(&self, plugin_id: &str) -> Option<PluginInfo> {
        // Check policy evaluators
        if let Some(evaluator) = self.policy_registry.get_evaluator(plugin_id).await {
            return Some(PluginInfo {
                metadata: evaluator.metadata().clone(),
                plugin_type: PluginType::PolicyEvaluator,
                status: PluginStatus::Active,
                loaded_at: chrono::Utc::now(),
                size_bytes: 0,
                version: evaluator.metadata().version.clone(),
            });
        }

        // Check auth providers
        if let Some(provider) = self.auth_registry.get_provider(plugin_id).await {
            return Some(PluginInfo {
                metadata: provider.metadata().clone(),
                plugin_type: PluginType::AuthProvider,
                status: PluginStatus::Active,
                loaded_at: chrono::Utc::now(),
                size_bytes: 0,
                version: provider.metadata().version.clone(),
            });
        }

        None
    }

    /// Load all plugins from configured directories
    async fn load_all_plugins(&self) -> Result<()> {
        tracing::info!("Loading plugins from configured directories");

        for directory in &self.config.plugin_directories {
            if !directory.exists() {
                tracing::warn!("Plugin directory does not exist: {:?}", directory);
                continue;
            }

            let mut entries = tokio::fs::read_dir(directory).await
                .map_err(|e| FortressError::plugin(format!("Failed to read plugin directory: {}", e)))?;

            while let Some(entry) = entries.next_entry().await
                .map_err(|e| FortressError::plugin(format!("Failed to read directory entry: {}", e)))? {
                
                let path = entry.path();
                if path.extension().and_then(|s| s.to_str()) == Some("wasm") {
                    match self.load_plugin(&path).await {
                        Ok(_) => tracing::debug!("Loaded plugin: {:?}", path),
                        Err(e) => tracing::error!("Failed to load plugin {:?}: {}", path, e),
                    }
                }
            }
        }

        Ok(())
    }

    /// Validate plugin file
    async fn validate_plugin_file(&self, plugin_path: &PathBuf) -> Result<()> {
        // Check file size
        let metadata = tokio::fs::metadata(plugin_path).await
            .map_err(|e| FortressError::plugin(format!("Failed to get plugin metadata: {}", e)))?;

        if metadata.len() > self.config.validation.max_plugin_size {
            return Err(FortressError::plugin(format!(
                "Plugin file too large: {} bytes (max: {} bytes)",
                metadata.len(),
                self.config.validation.max_plugin_size
            )));
        }

        // Check file extension
        if plugin_path.extension().and_then(|s| s.to_str()) != Some("wasm") {
            return Err(FortressError::plugin("Plugin file must have .wasm extension".to_string()));
        }

        Ok(())
    }

    /// Extract plugin metadata from WASM bytes
    fn extract_plugin_metadata(&self, _plugin_bytes: &[u8]) -> Result<PluginMetadata> {
        // In a real implementation, this would read metadata from WASM exports
        // For this example, we'll create a placeholder metadata
        Ok(PluginMetadata {
            id: Uuid::new_v4().to_string(),
            name: "WASM Plugin".to_string(),
            version: "1.0.0".to_string(),
            description: "A WebAssembly plugin".to_string(),
            author: "Fortress".to_string(),
            capabilities: vec![PluginCapability::Custom("wasm_plugin".to_string())],
            config_schema: None,
        })
    }

    /// Validate plugin capabilities
    fn validate_plugin_capabilities(&self, metadata: &PluginMetadata) -> Result<()> {
        for capability in &metadata.capabilities {
            let cap_str = match capability {
                PluginCapability::Custom(name) => name,
                _ => continue,
            };

            if !self.config.validation.allowed_capabilities.contains(cap_str) {
                return Err(FortressError::plugin(format!(
                    "Plugin capability '{}' is not allowed",
                    cap_str
                )));
            }
        }

        Ok(())
    }

    /// Determine plugin type from metadata
    fn determine_plugin_type(&self, metadata: &PluginMetadata) -> PluginType {
        for capability in &metadata.capabilities {
            match capability {
                PluginCapability::Custom(name) if name == "policy_evaluation" => {
                    return PluginType::PolicyEvaluator;
                },
                PluginCapability::Custom(name) if name == "authentication" => {
                    return PluginType::AuthProvider;
                },
                PluginCapability::Custom(name) if name == "encryption" => {
                    return PluginType::EncryptionProvider;
                },
                PluginCapability::Custom(name) if name == "storage" => {
                    return PluginType::StorageProvider;
                },
                PluginCapability::Custom(name) => {
                    return PluginType::Custom(name.clone());
                },
                _ => continue,
            }
        }

        PluginType::Custom("unknown".to_string())
    }

    /// Get plugin manager statistics
    pub async fn get_stats(&self) -> PluginManagerStats {
        let policy_evaluators = self.policy_registry.list_evaluators().await.len();
        let auth_providers = self.auth_registry.list_providers().await.len();
        let total_plugins = policy_evaluators + auth_providers;

        PluginManagerStats {
            total_plugins,
            policy_evaluators,
            auth_providers,
            max_plugins: self.config.max_plugins,
            plugin_directories: self.config.plugin_directories.clone(),
        }
    }

    /// Reload a plugin
    pub async fn reload_plugin(&self, plugin_id: &str) -> Result<()> {
        tracing::info!("Reloading plugin: {}", plugin_id);

        // Get current plugin info
        if let Some(plugin_info) = self.get_plugin(plugin_id).await {
            // Unload current plugin
            self.unload_plugin(plugin_id).await?;

            // Note: In a real implementation, we would need to track the original file path
            // For this example, we'll just log the action
            tracing::info!("Plugin {} unloaded for reload", plugin_id);
        }

        Err(FortressError::plugin("Plugin reload requires original file path".to_string()))
    }
}

/// Plugin manager statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginManagerStats {
    /// Total number of loaded plugins
    pub total_plugins: usize,
    /// Number of policy evaluators
    pub policy_evaluators: usize,
    /// Number of authentication providers
    pub auth_providers: usize,
    /// Maximum number of plugins allowed
    pub max_plugins: usize,
    /// Plugin directories
    pub plugin_directories: Vec<PathBuf>,
}

impl Default for WasmPluginManager {
    fn default() -> Self {
        Self::new(WasmPluginManagerConfig::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    use std::fs;

    #[tokio::test]
    async fn test_plugin_manager_initialization() {
        let config = WasmPluginManagerConfig::default();
        let manager = WasmPluginManager::new(config);
        
        let result = manager.initialize().await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_plugin_listing() {
        let manager = WasmPluginManager::default();
        let plugins = manager.list_plugins().await;
        
        // Should be empty initially
        assert_eq!(plugins.len(), 0);
    }

    #[tokio::test]
    async fn test_plugin_stats() {
        let manager = WasmPluginManager::default();
        let stats = manager.get_stats().await;
        
        assert_eq!(stats.total_plugins, 0);
        assert_eq!(stats.policy_evaluators, 0);
        assert_eq!(stats.auth_providers, 0);
    }

    #[tokio::test]
    async fn test_plugin_validation() {
        let temp_dir = TempDir::new().unwrap();
        let plugin_path = temp_dir.path().join("test.wasm");
        
        // Create a test WASM file
        fs::write(&plugin_path, b"test_wasm_content").unwrap();
        
        let config = WasmPluginManagerConfig::default();
        let manager = WasmPluginManager::new(config);
        
        // This should succeed for file validation
        let result = manager.validate_plugin_file(&plugin_path).await;
        assert!(result.is_ok());
    }
}
