//! Key-Value secret engine implementation

use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use crate::error::{FortressError, Result, SecretsErrorCode};
use super::base::*;
use super::types::*;
use chrono::{DateTime, Utc};

/// KV Engine configuration
#[derive(Debug, Clone)]
pub struct KvEngineConfig {
    pub max_versions: u64,
    pub default_ttl: Option<chrono::Duration>,
    pub cas_required: bool,
}

/// Key-Value secret engine
pub struct KvEngine {
    storage: Arc<RwLock<HashMap<String, Secret>>>,
    config: KvEngineConfig,
    name: String,
}

impl KvEngine {
    /// Create a new KV engine
    pub fn new(config: KvEngineConfig) -> Self {
        Self {
            storage: Arc::new(RwLock::new(HashMap::new())),
            config,
            name: "kv".to_string(),
        }
    }
    
    /// Create a KV engine with default configuration
    pub fn default() -> Self {
        Self::new(KvEngineConfig {
            max_versions: 10,
            default_ttl: None,
            cas_required: false,
        })
    }
}

#[async_trait]
impl SecretsEngine for KvEngine {
    fn name(&self) -> &str {
        &self.name
    }

    fn version(&self) -> &str {
        "1.0.0"
    }

    fn capabilities(&self) -> EngineCapabilities {
        EngineCapabilities {
            supports_lease: true,
            supports_rotation: true,
            supports_dynamic_secrets: false,
            supports_signing: false,
            supports_encryption: false,
            supported_operations: vec![
                "read".to_string(),
                "write".to_string(),
                "delete".to_string(),
                "list".to_string(),
                "metadata".to_string(),
            ],
        }
    }

    async fn initialize(&mut self, config: &serde_json::Value) -> Result<()> {
        // Parse configuration
        if let Some(max_versions) = config.get("max_versions").and_then(|v| v.as_u64()) {
            self.config.max_versions = max_versions;
        }
        
        if let Some(cas_required) = config.get("cas_required").and_then(|v| v.as_bool()) {
            self.config.cas_required = cas_required;
        }
        
        if let Some(ttl_seconds) = config.get("default_ttl_seconds").and_then(|v| v.as_i64()) {
            self.config.default_ttl = Some(chrono::Duration::seconds(ttl_seconds));
        }
        
        tracing::info!("KV engine initialized with max_versions: {}, cas_required: {}", 
                     self.config.max_versions, self.config.cas_required);
        
        Ok(())
    }

    async fn shutdown(&mut self) -> Result<()> {
        // Clear storage
        let mut storage = self.storage.write().await;
        storage.clear();
        tracing::info!("KV engine shutdown complete");
        Ok(())
    }

    async fn read_secret(&self, path: &str, _context: &Context) -> Result<Secret> {
        let storage = self.storage.read().await;
        storage.get(path)
            .cloned()
            .ok_or_else(|| FortressError::secrets_with_code(format!("Secret not found at path: {}", path), Some("kv".to_string()), SecretsErrorCode::SecretNotFound))
    }

    async fn write_secret(&self, path: &str, data: &Secret, context: &Context) -> Result<()> {
        let mut storage = self.storage.write().await;
        
        // Check CAS requirement
        if self.config.cas_required {
            if let Some(existing) = storage.get(path) {
                if existing.version != data.version {
                    return Err(FortressError::secrets_with_code("CAS check failed - version mismatch".to_string(), Some("kv".to_string()), SecretsErrorCode::InvalidVersion));
                }
            }
        }
        
        let mut secret = data.clone();
        secret.updated_time = chrono::Utc::now();
        secret.metadata.created_by = context.token.token.entity_id.clone();
        
        // Increment version for new secrets or updates
        if storage.contains_key(path) {
            secret.version += 1;
        } else {
            secret.version = 1;
        }
        
        storage.insert(path.to_string(), secret);
        Ok(())
    }

    async fn delete_secret(&self, path: &str, _context: &Context) -> Result<()> {
        let mut storage = self.storage.write().await;
        if storage.remove(path).is_none() {
            return Err(FortressError::secrets_with_code(format!("Secret not found at path: {}", path), Some("kv".to_string()), SecretsErrorCode::SecretNotFound));
        }
        Ok(())
    }

    async fn list_secrets(&self, path: &str, _context: &Context) -> Result<Vec<String>> {
        let storage = self.storage.read().await;
        let mut secrets = Vec::new();
        
        let search_path = path.trim_end_matches('/');
        
        for key in storage.keys() {
            if key.starts_with(search_path) {
                // Only include direct children, not nested paths
                let relative_path = if search_path.is_empty() {
                    key.as_str()
                } else {
                    &key[search_path.len()..]
                };
                
                if relative_path.starts_with('/') {
                    let remaining = &relative_path[1..];
                    if !remaining.contains('/') {
                        secrets.push(remaining.to_string());
                    }
                } else if !relative_path.contains('/') {
                    secrets.push(relative_path.to_string());
                }
            }
        }
        
        Ok(secrets)
    }

    async fn renew_lease(&self, lease_id: &str, increment: chrono::Duration, _context: &Context) -> Result<chrono::Duration> {
        // KV engine doesn't have complex lease management, just return the increment
        tracing::debug!("Renewing lease {} for {} seconds", lease_id, increment.num_seconds());
        Ok(increment)
    }

    async fn revoke_lease(&self, lease_id: &str, _context: &Context) -> Result<()> {
        // KV engine doesn't have complex lease management
        tracing::debug!("Revoking lease {}", lease_id);
        Ok(())
    }

    async fn rotate_secret(&self, path: &str, context: &Context) -> Result<Secret> {
        let mut storage = self.storage.write().await;
        
        // Get existing secret or create new one
        let existing_secret = storage.get(path).cloned();
        
        let new_data = if let Some(mut secret) = existing_secret {
            // Update existing secret
            if let Some(obj) = secret.data.as_object_mut() {
                obj.insert("rotated_at".to_string(), 
                          serde_json::Value::String(chrono::Utc::now().to_rfc3339()));
                obj.insert("rotated_by".to_string(), 
                          serde_json::Value::String(context.token.token.entity_id.clone()));
                obj.insert("rotation_version".to_string(), 
                          serde_json::Value::Number(serde_json::Number::from(secret.version + 1)));
            }
            secret
        } else {
            // Create new secret
            Secret {
                data: serde_json::json!({
                    "created_at": chrono::Utc::now().to_rfc3339(),
                    "created_by": context.token.token.entity_id,
                    "rotation_version": 1
                }),
                metadata: SecretMetadata {
                    created_by: context.token.token.entity_id.clone(),
                    ttl: self.config.default_ttl,
                    max_versions: Some(self.config.max_versions),
                    cas_required: self.config.cas_required,
                    custom_metadata: HashMap::new(),
                },
                lease_id: None,
                created_time: chrono::Utc::now(),
                updated_time: chrono::Utc::now(),
                version: 1,
            }
        };
        
        storage.insert(path.to_string(), new_data.clone());
        Ok(new_data)
    }

    async fn get_secret_metadata(&self, path: &str, _context: &Context) -> Result<SecretMetadata> {
        let storage = self.storage.read().await;
        storage.get(path)
            .map(|secret| secret.metadata.clone())
            .ok_or_else(|| FortressError::secrets_with_code(format!("Secret not found at path: {}", path), Some("kv".to_string()), SecretsErrorCode::SecretNotFound))
    }

    async fn health_check(&self) -> Result<EngineHealth> {
        let storage = self.storage.read().await;
        let secret_count = storage.len();
        
        Ok(EngineHealth {
            healthy: true,
            message: Some(format!("KV engine healthy with {} secrets", secret_count)),
            last_check: chrono::Utc::now(),
            metrics: Some(EngineMetrics {
                operations_per_second: 0.0,
                average_response_time: chrono::Duration::milliseconds(5),
                error_rate: 0.0,
                active_connections: 0,
                memory_usage: (secret_count * 1024) as u64, // Estimate
            }),
        })
    }
}

impl Default for KvEngine {
    fn default() -> Self {
        Self::default()
    }
}
