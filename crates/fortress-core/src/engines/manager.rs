//! Engine manager for coordinating secret engine operations

use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use crate::error::{FortressError, Result, SecretsErrorCode};
use super::base::*;
use super::types::*;
use super::registry::*;
use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};

/// Manager for coordinating secret engine operations
pub struct EngineManager {
    registry: Arc<EngineRegistry>,
    mount_table: Arc<RwLock<HashMap<String, String>>>, // path -> engine_name
    default_engine: String,
}

impl EngineManager {
    /// Create a new engine manager
    pub fn new() -> Self {
        Self {
            registry: Arc::new(EngineRegistry::new()),
            mount_table: Arc::new(RwLock::new(HashMap::new())),
            default_engine: "kv".to_string(),
        }
    }
    
    /// Register an engine type
    pub async fn register_engine_type(&self, factory: Box<dyn EngineFactory>) -> Result<()> {
        self.registry.register_factory(factory).await
    }
    
    /// Mount an engine at a specific path
    pub async fn mount_engine(&self, path: &str, engine_name: &str, config: &serde_json::Value) -> Result<()> {
        // Create engine configuration
        let engine_config = EngineConfig {
            name: engine_name.to_string(),
            version: "1.0.0".to_string(),
            enabled: true,
            mount_path: format!("{}/", path.trim_end_matches('/')),
            description: None,
            config: config.clone(),
        };
        
        // Create and store engine instance with initialization
        let engine = self.registry.create_and_initialize_engine(&engine_config, config).await?;
        
        // Update mount table
        let mut mount_table = self.mount_table.write().await;
        mount_table.insert(format!("{}/", path.trim_end_matches('/')), engine_name.to_string());
        
        Ok(())
    }
    
    /// Resolve which engine handles a given path
    pub async fn resolve_engine(&self, path: &str) -> Result<String> {
        let mount_table = self.mount_table.read().await;
        
        // Find most specific mount
        let mut best_match = None;
        let mut best_length = 0;
        
        for (mount_path, engine_name) in mount_table.iter() {
            if path.starts_with(mount_path) && mount_path.len() > best_length {
                best_match = Some(engine_name.clone());
                best_length = mount_path.len();
            }
        }
        
        best_match.ok_or_else(|| FortressError::engine("No engine mounted for path", SecretsErrorCode::EngineNotFound))
    }
    
    /// Get the engine for a specific path
    pub async fn get_engine_for_path(&self, path: &str) -> Result<Arc<dyn SecretsEngine>> {
        let engine_name = self.resolve_engine(path).await?;
        self.registry.get_engine(&engine_name).await
    }
    
    /// Execute an operation on the appropriate engine
    pub async fn execute_operation(&self, path: &str, operation: &str, context: &Context) -> Result<serde_json::Value> {
        let engine = self.get_engine_for_path(path).await?;
        
        match operation {
            "read" => {
                let secret = engine.read_secret(path, context).await?;
                Ok(serde_json::to_value(secret)?)
            }
            "write" => {
                // Extract secret data from context parameters
                let data = context.parameters.get("data")
                    .ok_or_else(|| FortressError::engine("Missing data parameter", SecretsErrorCode::InvalidInput))?;
                let secret: Secret = serde_json::from_value(data.clone())?;
                
                engine.write_secret(path, &secret, context).await?;
                Ok(serde_json::json!({"status": "success"}))
            }
            "delete" => {
                engine.delete_secret(path, context).await?;
                Ok(serde_json::json!({"status": "success"}))
            }
            "list" => {
                let secrets = engine.list_secrets(path, context).await?;
                Ok(serde_json::to_value(secrets)?)
            }
            "renew" => {
                let lease_id = context.parameters.get("lease_id")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| FortressError::engine("Missing lease_id parameter", SecretsErrorCode::InvalidInput))?;
                let increment = context.parameters.get("increment")
                    .and_then(|v| v.as_u64())
                    .map(|d| chrono::Duration::seconds(d as i64))
                    .unwrap_or_else(|| chrono::Duration::hours(1));
                
                let new_ttl = engine.renew_lease(lease_id, increment, context).await?;
                Ok(serde_json::json!({
                    "lease_id": lease_id,
                    "ttl": new_ttl.num_seconds()
                }))
            }
            "revoke" => {
                let lease_id = context.parameters.get("lease_id")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| FortressError::engine("Missing lease_id parameter", SecretsErrorCode::InvalidInput))?;
                
                engine.revoke_lease(lease_id, context).await?;
                Ok(serde_json::json!({"status": "success"}))
            }
            "rotate" => {
                let secret = engine.rotate_secret(path, context).await?;
                Ok(serde_json::to_value(secret)?)
            }
            "metadata" => {
                let metadata = engine.get_secret_metadata(path, context).await?;
                Ok(serde_json::to_value(metadata)?)
            }
            "health" => {
                let health = engine.health_check().await?;
                Ok(serde_json::to_value(health)?)
            }
            _ => Err(FortressError::engine(format!("Unsupported operation: {}", operation), SecretsErrorCode::InvalidOperation))
        }
    }
    
    /// List all mounted engines
    pub async fn list_mounts(&self) -> HashMap<String, String> {
        let mount_table = self.mount_table.read().await;
        mount_table.clone()
    }
    
    /// Unmount an engine
    pub async fn unmount_engine(&self, path: &str) -> Result<()> {
        let engine_name = self.resolve_engine(path).await?;
        
        // Remove from mount table
        let mut mount_table = self.mount_table.write().await;
        mount_table.remove(&format!("{}/", path.trim_end_matches('/')));
        
        // Remove engine instance
        self.registry.remove_engine(&engine_name).await?;
        
        Ok(())
    }
    
    /// Get engine capabilities
    pub async fn get_engine_capabilities(&self, path: &str) -> Result<EngineCapabilities> {
        let engine = self.get_engine_for_path(path).await?;
        Ok(engine.capabilities())
    }
    
    /// Perform health check on all engines
    pub async fn health_check_all(&self) -> Result<HashMap<String, EngineHealth>> {
        let mut results = HashMap::new();
        let instances = self.registry.list_instances().await;
        
        for instance_name in instances {
            if let Ok(engine) = self.registry.get_engine(&instance_name).await {
                if let Ok(health) = engine.health_check().await {
                    results.insert(instance_name, health);
                }
            }
        }
        
        Ok(results)
    }
    
    /// Get registry reference
    pub fn registry(&self) -> &Arc<EngineRegistry> {
        &self.registry
    }
}

impl Default for EngineManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Mount information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MountInfo {
    pub path: String,
    pub engine: String,
    pub description: Option<String>,
    pub config: serde_json::Value,
    pub mounted_at: DateTime<Utc>,
}

impl EngineManager {
    /// Get detailed mount information
    pub async fn get_mount_info(&self) -> Result<Vec<MountInfo>> {
        let mount_table = self.mount_table.read().await;
        let mut mounts = Vec::new();
        
        for (path, engine_name) in mount_table.iter() {
            if let Ok(engine) = self.registry.get_engine(engine_name).await {
                let mount_info = MountInfo {
                    path: path.clone(),
                    engine: engine_name.clone(),
                    description: Some(format!("{} engine v{}", engine.name(), engine.version())),
                    config: serde_json::Value::Null, // Would need to store this separately
                    mounted_at: Utc::now(), // Would need to store this separately
                };
                mounts.push(mount_info);
            }
        }
        
        Ok(mounts)
    }
}
