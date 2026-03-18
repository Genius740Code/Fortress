//! # KV (Key-Value) Secrets Engine
//!
//! Vault-compatible KV secrets engine implementation.
//!
//! ## Features
//!
//! - **Versioning**: Complete secret history with configurable retention
//! - **TTL Support**: Time-limited secrets with automatic expiration
//! - **Path-based Organization**: Hierarchical secret storage
//! - **Metadata Support**: Custom metadata for secrets
//!
//! ## Usage
//!
//! ```rust,no_run
//! use fortress_core::secrets_kv::KvEngine;
//!
//! let engine = KvEngine::new();
//!
//! // Store a secret
//! engine.write("secret/myapp", &json!({
//!     "username": "admin",
//!     "password": "secret123"
//! })).await?;
//!
//! // Read latest version
//! let secret = engine.read("secret/myapp").await?;
//!
//! // Read specific version
//! let secret_v1 = engine.read_version("secret/myapp", 1).await?;
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

use crate::error::{FortressError, Result};
use crate::secrets::{EngineStatus, EngineStats, EngineType, LeaseInfo, Secret, SecretMetadata, SecretsEngine};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// KV secrets engine configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KvConfig {
    /// Maximum versions to keep per secret
    pub max_versions: u32,
    /// Default TTL for secrets
    pub default_ttl: Option<u64>,
    /// Enable case sensitivity for paths
    pub case_sensitive: bool,
    /// Enable automatic cleanup of expired versions
    pub auto_cleanup: bool,
}

impl Default for KvConfig {
    fn default() -> Self {
        Self {
            max_versions: 10,
            default_ttl: None,
            case_sensitive: false,
            auto_cleanup: true,
        }
    }
}

/// Versioned secret data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VersionedSecret {
    /// Secret data
    pub data: serde_json::Value,
    /// Version number
    pub version: u64,
    /// Creation timestamp
    pub created_at: chrono::DateTime<chrono::Utc>,
    /// Deletion timestamp (if soft-deleted)
    pub deleted_at: Option<chrono::DateTime<chrono::Utc>>,
    /// Custom metadata
    pub custom_metadata: HashMap<String, String>,
}

/// KV secrets engine implementation
#[derive(Debug)]
pub struct KvEngine {
    /// Engine configuration
    config: Arc<RwLock<KvConfig>>,
    /// Secret storage by path
    secrets: Arc<RwLock<HashMap<String, KvSecretEntry>>>,
    /// Lease management
    leases: Arc<RwLock<HashMap<String, LeaseInfo>>>,
    /// Statistics
    stats: Arc<RwLock<EngineStats>>,
}

/// KV secret entry with version history
#[derive(Debug)]
struct KvSecretEntry {
    /// Path to the secret
    path: String,
    /// Version history
    versions: HashMap<u64, VersionedSecret>,
    /// Current version
    current_version: u64,
    /// Next version number
    next_version: u64,
}

impl KvEngine {
    /// Create new KV engine
    pub fn new() -> Self {
        Self::with_config(KvConfig::default())
    }

    /// Create KV engine with custom configuration
    pub fn with_config(config: KvConfig) -> Self {
        Self {
            config: Arc::new(RwLock::new(config)),
            secrets: Arc::new(RwLock::new(HashMap::new())),
            leases: Arc::new(RwLock::new(HashMap::new())),
            stats: Arc::new(RwLock::new(EngineStats {
                total_secrets: 0,
                active_leases: 0,
                operations: HashMap::new(),
                last_operation: None,
            })),
        }
    }

    /// Read a specific version of a secret
    pub async fn read_version(&self, path: &str, version: u64) -> Result<Option<Secret>> {
        self.record_operation("read_version").await;
        
        let secrets = self.secrets.read().await;
        let leases = self.leases.read().await;
        
        if let Some(entry) = secrets.get(path) {
            if let Some(versioned) = entry.versions.get(&version) {
                let lease_id = format!("kv:{}:{}", path, version);
                let lease = leases.get(&lease_id).cloned();
                
                let secret = Secret {
                    data: versioned.data.clone(),
                    metadata: SecretMetadata {
                        version: versioned.version,
                        created_at: versioned.created_at,
                        updated_at: None,
                        lease,
                        custom: versioned.custom_metadata.clone(),
                    },
                };
                
                Ok(Some(secret))
            } else {
                Ok(None)
            }
        } else {
            Ok(None)
        }
    }

    /// Get all versions of a secret
    pub async fn list_versions(&self, path: &str) -> Result<Vec<u64>> {
        let secrets = self.secrets.read().await;
        
        if let Some(entry) = secrets.get(path) {
            let mut versions: Vec<u64> = entry.versions.keys().cloned().collect();
            versions.sort();
            Ok(versions)
        } else {
            Ok(vec![])
        }
    }

    /// Delete a specific version
    pub async fn delete_version(&self, path: &str, version: u64) -> Result<()> {
        self.record_operation("delete_version").await;
        
        let mut secrets = self.secrets.write().await;
        
        if let Some(entry) = secrets.get_mut(path) {
            if let Some(versioned) = entry.versions.get_mut(&version) {
                versioned.deleted_at = Some(chrono::Utc::now());
                Ok(())
            } else {
                Err(FortressError::secrets("Version not found".to_string()))
            }
        } else {
            Err(FortressError::secrets("Secret not found".to_string()))
        }
    }

    /// Permanently destroy a secret and all versions
    pub async fn destroy(&self, path: &str) -> Result<()> {
        self.record_operation("destroy").await;
        
        let mut secrets = self.secrets.write().await;
        let mut leases = self.leases.write().await;
        
        // Remove all leases for this path
        let lease_ids: Vec<String> = leases.keys()
            .filter(|id| id.starts_with(&format!("kv:{}:", path)))
            .cloned()
            .collect();
        
        for lease_id in lease_ids {
            leases.remove(&lease_id);
        }
        
        // Remove the secret entry
        secrets.remove(path);
        
        Ok(())
    }

    /// Record an operation in statistics
    async fn record_operation(&self, operation: &str) {
        let mut stats = self.stats.write().await;
        *stats.operations.entry(operation.to_string()).or_insert(0) += 1;
        stats.last_operation = Some(chrono::Utc::now());
    }

    /// Generate lease ID for KV secret
    fn generate_lease_id(&self, path: &str, version: u64) -> String {
        format!("kv:{}:{}", path, version)
    }

    /// Create lease for a secret
    async fn create_lease(&self, path: &str, version: u64) -> Result<Option<LeaseInfo>> {
        let config = self.config.read().await;
        
        if let Some(ttl) = config.default_ttl {
            let lease_id = self.generate_lease_id(path, version);
            let lease = LeaseInfo {
                lease_id: lease_id.clone(),
                ttl,
                created_at: chrono::Utc::now(),
                renewable: true,
                max_ttl: Some(ttl * 24), // 24x the default TTL
            };
            
            let mut leases = self.leases.write().await;
            leases.insert(lease_id, lease.clone());
            
            // Update stats
            {
                let mut stats = self.stats.write().await;
                stats.active_leases = leases.len() as u64;
            }
            
            Ok(Some(lease))
        } else {
            Ok(None)
        }
    }

    /// Cleanup old versions based on configuration
    async fn cleanup_old_versions(&self, entry: &mut KvSecretEntry) {
        let config = self.config.read().await;
        
        if entry.versions.len() > config.max_versions as usize {
            let mut versions_to_remove: Vec<u64> = entry.versions.keys().cloned().collect();
            versions_to_remove.sort();
            
            // Keep the latest max_versions
            let remove_count = versions_to_remove.len() - config.max_versions as usize;
            for version in versions_to_remove.iter().take(remove_count) {
                entry.versions.remove(version);
            }
        }
    }
}

#[async_trait::async_trait]
impl SecretsEngine for KvEngine {
    fn name(&self) -> &str {
        "kv"
    }

    fn engine_type(&self) -> EngineType {
        EngineType::Kv
    }

    async fn write(&self, path: &str, data: &serde_json::Value) -> Result<Secret> {
        self.record_operation("write").await;
        
        let mut secrets = self.secrets.write().await;
        let config = self.config.read().await;
        
        let entry = secrets.entry(path.to_string()).or_insert_with(|| KvSecretEntry {
            path: path.to_string(),
            versions: HashMap::new(),
            current_version: 0,
            next_version: 1,
        });
        
        let version = entry.next_version;
        entry.next_version += 1;
        entry.current_version = version;
        
        let versioned = VersionedSecret {
            data: data.clone(),
            version,
            created_at: chrono::Utc::now(),
            deleted_at: None,
            custom_metadata: HashMap::new(),
        };
        
        entry.versions.insert(version, versioned);
        
        // Cleanup old versions if needed
        drop(config);
        self.cleanup_old_versions(entry).await;
        
        // Update stats
        {
            let mut stats = self.stats.write().await;
            stats.total_secrets = secrets.len() as u64;
        }
        
        // Create lease if configured
        let lease = self.create_lease(path, version).await?;
        
        Ok(Secret {
            data: data.clone(),
            metadata: SecretMetadata {
                version,
                created_at: chrono::Utc::now(),
                updated_at: None,
                lease,
                custom: HashMap::new(),
            },
        })
    }

    async fn read(&self, path: &str) -> Result<Option<Secret>> {
        self.record_operation("read").await;
        
        let secrets = self.secrets.read().await;
        
        if let Some(entry) = secrets.get(path) {
            if let Some(versioned) = entry.versions.get(&entry.current_version) {
                let lease_id = self.generate_lease_id(path, versioned.version);
                let lease = {
                    let leases = self.leases.read().await;
                    leases.get(&lease_id).cloned()
                };
                
                Ok(Some(Secret {
                    data: versioned.data.clone(),
                    metadata: SecretMetadata {
                        version: versioned.version,
                        created_at: versioned.created_at,
                        updated_at: None,
                        lease,
                        custom: versioned.custom_metadata.clone(),
                    },
                }))
            } else {
                Ok(None)
            }
        } else {
            Ok(None)
        }
    }

    async fn delete(&self, path: &str) -> Result<()> {
        self.record_operation("delete").await;
        
        let mut secrets = self.secrets.write().await;
        let mut leases = self.leases.write().await;
        
        // Remove all leases for this path
        let lease_ids: Vec<String> = leases.keys()
            .filter(|id| id.starts_with(&format!("kv:{}:", path)))
            .cloned()
            .collect();
        
        for lease_id in lease_ids {
            leases.remove(&lease_id);
        }
        
        // Remove the secret
        secrets.remove(path);
        
        // Update stats
        {
            let mut stats = self.stats.write().await;
            stats.total_secrets = secrets.len() as u64;
            stats.active_leases = leases.len() as u64;
        }
        
        Ok(())
    }

    async fn list(&self, path: &str) -> Result<Vec<String>> {
        self.record_operation("list").await;
        
        let secrets = self.secrets.read().await;
        let config = self.config.read().await;
        
        let mut results = Vec::new();
        
        for secret_path in secrets.keys() {
            let normalized_path = if config.case_sensitive {
                secret_path.clone()
            } else {
                secret_path.to_lowercase()
            };
            
            let normalized_search = if config.case_sensitive {
                path.to_string()
            } else {
                path.to_lowercase()
            };
            
            if normalized_path.starts_with(&normalized_search) {
                results.push(secret_path.clone());
            }
        }
        
        results.sort();
        Ok(results)
    }

    async fn renew(&self, lease_id: &str, increment: Option<u64>) -> Result<LeaseInfo> {
        self.record_operation("renew").await;
        
        let mut leases = self.leases.write().await;
        
        if let Some(lease) = leases.get_mut(lease_id) {
            let increment = increment.unwrap_or(lease.ttl);
            let new_ttl = lease.ttl + increment;
            
            // Check max TTL
            if let Some(max_ttl) = lease.max_ttl {
                if new_ttl > max_ttl {
                    return Err(FortressError::secrets("Lease TTL exceeds maximum".to_string()));
                }
            }
            
            lease.ttl = new_ttl;
            lease.created_at = chrono::Utc::now();
            
            Ok(lease.clone())
        } else {
            Err(FortressError::secrets("Lease not found".to_string()))
        }
    }

    async fn revoke(&self, lease_id: &str) -> Result<()> {
        self.record_operation("revoke").await;
        
        let mut leases = self.leases.write().await;
        leases.remove(lease_id);
        
        // Update stats
        {
            let mut stats = self.stats.write().await;
            stats.active_leases = leases.len() as u64;
        }
        
        Ok(())
    }

    async fn configure(&mut self, config: serde_json::Value) -> Result<()> {
        let kv_config: KvConfig = serde_json::from_value(config)
            .map_err(|e| FortressError::secrets(format!("Invalid configuration: {}", e)))?;
        
        let mut self_config = self.config.write().await;
        *self_config = kv_config;
        
        Ok(())
    }

    async fn status(&self) -> Result<EngineStatus> {
        let config = self.config.read().await;
        let _secrets = self.secrets.read().await;
        let _leases = self.leases.read().await;
        let stats = self.stats.read().await;
        
        Ok(EngineStatus {
            name: self.name().to_string(),
            engine_type: self.engine_type(),
            initialized: true,
            config: serde_json::to_value(&*config).unwrap_or_default(),
            stats: stats.clone(),
        })
    }
}

impl Default for KvEngine {
    fn default() -> Self {
        Self::new()
    }
}
