//! # Secrets Engine System
//!
//! Vault-inspired secrets engine system for dynamic secret management.
//!
//! ## Features
//!
//! - **Pluggable Architecture**: Multiple secrets engines (KV, Database, Cloud)
//! - **Dynamic Secrets**: Automatic generation and rotation
//! - **Versioning**: Complete secret history with rollback
//! - **Lease Management**: Time-limited access with automatic expiration
//!
//! ## Example
//!
//! ```rust,no_run
//! use fortress_core::secrets::{SecretsEngine, KvEngine, DatabaseEngine};
//!
//! let mut engine = SecretsEngine::new();
//!
//! // Enable KV store
//! engine.register("kv/", Box::new(KvEngine::new()))?;
//!
//! // Store a secret
//! engine.write("kv/myapp/database", &json!({
//!     "username": "app_user",
//!     "password": "generated_password"
//! }))?;
//!
//! // Read a secret
//! let secret = engine.read("kv/myapp/database")?;
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

use crate::error::{FortressError, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Secret data structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Secret {
    /// Secret data
    pub data: serde_json::Value,
    /// Secret metadata
    pub metadata: SecretMetadata,
}

/// Secret metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretMetadata {
    /// Secret version
    pub version: u64,
    /// Creation timestamp
    pub created_at: chrono::DateTime<chrono::Utc>,
    /// Last updated timestamp
    pub updated_at: Option<chrono::DateTime<chrono::Utc>>,
    /// Lease information
    pub lease: Option<LeaseInfo>,
    /// Custom metadata
    pub custom: HashMap<String, String>,
}

/// Lease information for time-limited secrets
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LeaseInfo {
    /// Lease ID
    pub lease_id: String,
    /// Time to live in seconds
    pub ttl: u64,
    /// Lease creation time
    pub created_at: chrono::DateTime<chrono::Utc>,
    /// Whether lease is renewable
    pub renewable: bool,
    /// Maximum TTL for renewals
    pub max_ttl: Option<u64>,
}

/// Secrets engine trait
#[async_trait::async_trait]
pub trait SecretsEngine: Send + Sync {
    /// Engine name
    fn name(&self) -> &str;
    
    /// Engine type
    fn engine_type(&self) -> EngineType;
    
    /// Write a secret
    async fn write(&self, path: &str, data: &serde_json::Value) -> Result<Secret>;
    
    /// Read a secret
    async fn read(&self, path: &str) -> Result<Option<Secret>>;
    
    /// Delete a secret
    async fn delete(&self, path: &str) -> Result<()>;
    
    /// List secrets at path
    async fn list(&self, path: &str) -> Result<Vec<String>>;
    
    /// Renew a lease
    async fn renew(&self, lease_id: &str, increment: Option<u64>) -> Result<LeaseInfo>;
    
    /// Revoke a lease
    async fn revoke(&self, lease_id: &str) -> Result<()>;
    
    /// Engine configuration
    async fn configure(&mut self, config: serde_json::Value) -> Result<()>;
    
    /// Get engine status
    async fn status(&self) -> Result<EngineStatus>;
}

/// Secrets engine type
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum EngineType {
    /// Key-Value store
    Kv,
    /// Database credential generator
    Database,
    /// Dynamic secrets generator
    Dynamic,
    /// Cloud provider secrets
    Cloud(CloudProvider),
    /// PKI certificates
    Pki,
    /// SSH certificates
    Ssh,
    /// Transit encryption
    Transit,
    /// Custom engine
    Custom(String),
}

/// Cloud providers
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum CloudProvider {
    /// Amazon Web Services
    Aws,
    /// Microsoft Azure
    Azure,
    /// Google Cloud Platform
    Gcp,
}

/// Engine status information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EngineStatus {
    /// Engine name
    pub name: String,
    /// Engine type
    pub engine_type: EngineType,
    /// Whether engine is initialized
    pub initialized: bool,
    /// Engine configuration
    pub config: serde_json::Value,
    /// Statistics
    pub stats: EngineStats,
}

/// Engine statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EngineStats {
    /// Total secrets stored
    pub total_secrets: u64,
    /// Active leases
    pub active_leases: u64,
    /// Operations count
    pub operations: HashMap<String, u64>,
    /// Last operation time
    pub last_operation: Option<chrono::DateTime<chrono::Utc>>,
}

/// Main secrets engine manager
pub struct SecretsEngineManager {
    /// Registered engines by path prefix
    engines: Arc<RwLock<HashMap<String, Box<dyn SecretsEngine>>>>,
    /// Lease manager
    lease_manager: Arc<RwLock<LeaseManager>>,
    /// Global configuration
    config: Arc<RwLock<SecretsConfig>>,
}

/// Secrets engine configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretsConfig {
    /// Default lease TTL
    pub default_lease_ttl: u64,
    /// Maximum lease TTL
    pub max_lease_ttl: u64,
    /// Lease cleanup interval
    pub lease_cleanup_interval: u64,
    /// Enable versioning
    pub enable_versioning: bool,
    /// Maximum versions per secret
    pub max_versions: u32,
}

impl Default for SecretsConfig {
    fn default() -> Self {
        Self {
            default_lease_ttl: 3600, // 1 hour
            max_lease_ttl: 86400,    // 24 hours
            lease_cleanup_interval: 300, // 5 minutes
            enable_versioning: true,
            max_versions: 10,
        }
    }
}

/// Lease manager for handling time-limited secrets
#[derive(Debug)]
pub struct LeaseManager {
    /// Active leases
    leases: HashMap<String, LeaseInfo>,
    /// Lease renewal tasks
    renewal_tasks: HashMap<String, tokio::task::JoinHandle<()>>,
}

impl SecretsEngineManager {
    /// Create new secrets engine manager
    pub fn new() -> Self {
        Self {
            engines: Arc::new(RwLock::new(HashMap::new())),
            lease_manager: Arc::new(RwLock::new(LeaseManager::new())),
            config: Arc::new(RwLock::new(SecretsConfig::default())),
        }
    }

    /// Register a secrets engine
    pub async fn register(&self, path: &str, engine: Box<dyn SecretsEngine>) -> Result<()> {
        let mut engines = self.engines.write().await;
        engines.insert(path.to_string(), engine);
        Ok(())
    }

    /// Write a secret
    pub async fn write(&self, path: &str, data: &serde_json::Value) -> Result<Secret> {
        let engine_prefix = self.find_engine(path).await?;
        let engines = self.engines.read().await;
        let engine = engines.get(&engine_prefix).unwrap();
        engine.write(path, data).await
    }

    /// Read a secret
    pub async fn read(&self, path: &str) -> Result<Option<Secret>> {
        let engine_prefix = self.find_engine(path).await?;
        let engines = self.engines.read().await;
        let engine = engines.get(&engine_prefix).unwrap();
        engine.read(path).await
    }

    /// Delete a secret
    pub async fn delete(&self, path: &str) -> Result<()> {
        let engine_prefix = self.find_engine(path).await?;
        let engines = self.engines.read().await;
        let engine = engines.get(&engine_prefix).unwrap();
        engine.delete(path).await
    }

    /// List secrets
    pub async fn list(&self, path: &str) -> Result<Vec<String>> {
        let engine_prefix = self.find_engine(path).await?;
        let engines = self.engines.read().await;
        let engine = engines.get(&engine_prefix).unwrap();
        engine.list(path).await
    }

    /// Renew a lease
    pub async fn renew(&self, lease_id: &str, increment: Option<u64>) -> Result<LeaseInfo> {
        let engine_prefix = self.find_lease_engine(lease_id).await?;
        let engines = self.engines.read().await;
        let engine = engines.get(&engine_prefix).unwrap();
        let lease = engine.renew(lease_id, increment).await?;
        
        // Update lease in manager
        {
            let mut manager = self.lease_manager.write().await;
            manager.update_lease(lease_id, lease.clone()).await?;
        }
        
        Ok(lease)
    }

    /// Revoke a lease
    pub async fn revoke(&self, lease_id: &str) -> Result<()> {
        let engine_prefix = self.find_lease_engine(lease_id).await?;
        let engines = self.engines.read().await;
        let engine = engines.get(&engine_prefix).unwrap();
        engine.revoke(lease_id).await?;
        
        // Remove lease from manager
        {
            let mut manager = self.lease_manager.write().await;
            manager.remove_lease(lease_id).await;
        }
        
        Ok(())
    }

    /// Find the appropriate engine for a path
    async fn find_engine(&self, path: &str) -> Result<String> {
        let engines = self.engines.read().await;
        
        // Find the most specific path match
        let mut best_match = None;
        let mut best_length = 0;
        
        for (prefix, _) in engines.iter() {
            if path.starts_with(prefix) && prefix.len() > best_length {
                best_match = Some(prefix.clone());
                best_length = prefix.len();
            }
        }
        
        best_match.ok_or_else(|| FortressError::secrets("No engine found for path".to_string()))
    }

    /// Find engine that owns a lease
    async fn find_lease_engine(&self, _lease_id: &str) -> Result<String> {
        let engines = self.engines.read().await;
        
        // For now, return the first available engine
        // In practice, you'd want to maintain a mapping of lease_id -> engine
        if let Some(prefix) = engines.keys().next() {
            Ok(prefix.clone())
        } else {
            Err(FortressError::secrets("No engines available".to_string()))
        }
    }

    /// Get all registered engines
    pub async fn list_engines(&self) -> Vec<String> {
        let engines = self.engines.read().await;
        engines.keys().cloned().collect()
    }

    /// Cleanup expired leases
    pub async fn cleanup_expired_leases(&self) -> Result<u64> {
        let mut manager = self.lease_manager.write().await;
        manager.cleanup_expired().await
    }
}

impl LeaseManager {
    /// Create new lease manager
    pub fn new() -> Self {
        Self {
            leases: HashMap::new(),
            renewal_tasks: HashMap::new(),
        }
    }

    /// Add a new lease
    pub async fn add_lease(&mut self, lease_id: String, lease: LeaseInfo) -> Result<()> {
        self.leases.insert(lease_id.clone(), lease);
        Ok(())
    }

    /// Update an existing lease
    pub async fn update_lease(&mut self, lease_id: &str, lease: LeaseInfo) -> Result<()> {
        self.leases.insert(lease_id.to_string(), lease);
        Ok(())
    }

    /// Remove a lease
    pub async fn remove_lease(&mut self, lease_id: &str) {
        self.leases.remove(lease_id);
        self.renewal_tasks.remove(lease_id);
    }

    /// Get lease information
    pub async fn get_lease(&self, lease_id: &str) -> Option<&LeaseInfo> {
        self.leases.get(lease_id)
    }

    /// Cleanup expired leases
    pub async fn cleanup_expired(&mut self) -> Result<u64> {
        let now = chrono::Utc::now();
        let mut expired_count = 0;
        
        self.leases.retain(|_, lease| {
            let expired = lease.created_at + chrono::Duration::seconds(lease.ttl as i64) < now;
            if expired {
                expired_count += 1;
            }
            !expired
        });
        
        Ok(expired_count)
    }

    /// Get all active leases
    pub async fn list_leases(&self) -> Vec<(String, LeaseInfo)> {
        self.leases.iter().map(|(id, lease)| (id.clone(), lease.clone())).collect()
    }
}

impl Default for LeaseManager {
    fn default() -> Self {
        Self::new()
    }
}

impl Default for SecretsEngineManager {
    fn default() -> Self {
        Self::new()
    }
}
