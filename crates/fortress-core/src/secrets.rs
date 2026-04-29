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

use crate::error::{FortressError, Result, SecretsErrorCode};
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
        let engine = engines.get(&engine_prefix).ok_or_else(|| FortressError::secrets_with_code(
            format!("Engine not found for prefix: {}", engine_prefix),
            Some(engine_prefix),
            SecretsErrorCode::EngineNotFound,
        ))?;
        engine.write(path, data).await
    }

    /// Read a secret
    pub async fn read(&self, path: &str) -> Result<Option<Secret>> {
        let engine_prefix = self.find_engine(path).await?;
        let engines = self.engines.read().await;
        let engine = engines.get(&engine_prefix).ok_or_else(|| FortressError::secrets_with_code(
            format!("Engine not found for prefix: {}", engine_prefix),
            Some(engine_prefix),
            SecretsErrorCode::EngineNotFound,
        ))?;
        engine.read(path).await
    }

    /// Delete a secret
    pub async fn delete(&self, path: &str) -> Result<()> {
        let engine_prefix = self.find_engine(path).await?;
        let engines = self.engines.read().await;
        let engine = engines.get(&engine_prefix).ok_or_else(|| FortressError::secrets_with_code(
            format!("Engine not found for prefix: {}", engine_prefix),
            Some(engine_prefix),
            SecretsErrorCode::EngineNotFound,
        ))?;
        engine.delete(path).await
    }

    /// List secrets
    pub async fn list(&self, path: &str) -> Result<Vec<String>> {
        let engine_prefix = self.find_engine(path).await?;
        let engines = self.engines.read().await;
        let engine = engines.get(&engine_prefix).ok_or_else(|| FortressError::secrets_with_code(
            format!("Engine not found for prefix: {}", engine_prefix),
            Some(engine_prefix),
            SecretsErrorCode::EngineNotFound,
        ))?;
        engine.list(path).await
    }

    /// Renew a lease
    pub async fn renew(&self, lease_id: &str, increment: Option<u64>) -> Result<LeaseInfo> {
        let engine_prefix = self.find_lease_engine(lease_id).await?;
        let engines = self.engines.read().await;
        let engine = engines.get(&engine_prefix).ok_or_else(|| FortressError::secrets_with_code(
            format!("Engine not found for prefix: {}", engine_prefix),
            Some(engine_prefix),
            SecretsErrorCode::EngineNotFound,
        ))?;
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
        let engine = engines.get(&engine_prefix).ok_or_else(|| FortressError::secrets_with_code(
            format!("Engine not found for prefix: {}", engine_prefix),
            Some(engine_prefix),
            SecretsErrorCode::EngineNotFound,
        ))?;
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

    /// Write a secret with metadata
    pub async fn write_with_metadata(&self, path: &str, data: &serde_json::Value, _metadata: Option<serde_json::Value>) -> Result<Secret> {
        let engine_prefix = self.find_engine(path).await?;
        let engines = self.engines.read().await;
        let engine = engines.get(&engine_prefix).ok_or_else(|| FortressError::secrets_with_code(
            format!("Engine not found for prefix: {}", engine_prefix),
            Some(engine_prefix),
            SecretsErrorCode::EngineNotFound,
        ))?;
        
        // For now, just call write - the metadata can be handled by individual engines
        engine.write(path, data).await
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

#[cfg(test)]
mod tests {
    use super::*;
    
    /// Test secret creation and retrieval
    #[tokio::test]
    async fn test_secret_write_and_read() {
        let manager = SecretsEngineManager::new();
        let secret_data = b"test secret data";
        
        // Write secret
        let result = manager.write("test-secret", secret_data, Some(3600)).await;
        assert!(result.is_ok(), "Secret write should succeed");
        
        // Read secret
        let result = manager.read("test-secret").await;
        assert!(result.is_ok(), "Secret read should succeed");
        
        let secret = result.unwrap();
        assert_eq!(secret.data, secret_data);
        assert_eq!(secret.metadata.name, "test-secret");
        assert_eq!(secret.metadata.data_type, "binary");
        assert!(secret.lease.is_some(), "Secret should have a lease");
    }
    
    /// Test secret with custom metadata
    #[tokio::test]
    async fn test_secret_with_metadata() {
        let manager = SecretsEngineManager::new();
        let secret_data = b"secret with metadata";
        let custom_metadata = vec![
            ("environment".to_string(), "production".to_string()),
            ("owner".to_string(), "team-a".to_string()),
        ];
        
        // Write secret with custom metadata
        let result = manager.write_with_metadata(
            "metadata-secret",
            secret_data,
            Some(7200),
            custom_metadata,
        ).await;
        
        assert!(result.is_ok(), "Secret write with metadata should succeed");
        
        // Read secret and verify metadata
        let result = manager.read("metadata-secret").await;
        assert!(result.is_ok(), "Secret read should succeed");
        
        let secret = result.unwrap();
        assert_eq!(secret.data, secret_data);
        assert_eq!(secret.metadata.name, "metadata-secret");
        assert_eq!(secret.metadata.custom_metadata.len(), 2);
        assert_eq!(secret.metadata.custom_metadata.get("environment"), Some(&"production".to_string()));
        assert_eq!(secret.metadata.custom_metadata.get("owner"), Some(&"team-a".to_string()));
    }
    
    /// Test secret deletion
    #[tokio::test]
    async fn test_secret_deletion() {
        let manager = SecretsEngineManager::new();
        let secret_data = b"secret to delete";
        
        // Write secret
        let result = manager.write("delete-secret", secret_data, Some(1800)).await;
        assert!(result.is_ok(), "Secret write should succeed");
        
        // Verify secret exists
        let result = manager.read("delete-secret").await;
        assert!(result.is_ok(), "Secret should exist before deletion");
        
        // Delete secret
        let result = manager.delete("delete-secret").await;
        assert!(result.is_ok(), "Secret deletion should succeed");
        
        // Verify secret is deleted
        let result = manager.read("delete-secret").await;
        assert!(result.is_err(), "Secret should not exist after deletion");
    }
    
    /// Test secret listing
    #[tokio::test]
    async fn test_secret_listing() {
        let manager = SecretsEngineManager::new();
        
        // Create multiple secrets
        let secrets = vec![
            ("secret-1", b"data 1"),
            ("secret-2", b"data 2"),
            ("secret-3", b"data 3"),
        ];
        
        for (name, data) in &secrets {
            let result = manager.write(name, data, Some(3600)).await;
            assert!(result.is_ok(), "Secret write should succeed");
        }
        
        // List secrets
        let result = manager.list("*").await;
        assert!(result.is_ok(), "Secret listing should succeed");
        
        let secret_list = result.unwrap();
        assert_eq!(secret_list.len(), 3, "Should list all 3 secrets");
        
        // Verify all secrets are in the list
        for (name, _) in &secrets {
            let found = secret_list.iter().any(|s| s.name == *name);
            assert!(found, "Secret {} should be in the list", name);
        }
    }
    
    /// Test secret listing with pattern
    #[tokio::test]
    async fn test_secret_listing_with_pattern() {
        let manager = SecretsEngineManager::new();
        
        // Create secrets with different prefixes
        let secrets = vec![
            ("db-connection", b"database connection string"),
            ("db-password", b"database password"),
            ("api-key", b"api authentication key"),
        ];
        
        for (name, data) in &secrets {
            let result = manager.write(name, data, Some(3600)).await;
            assert!(result.is_ok(), "Secret write should succeed");
        }
        
        // List secrets with db- prefix
        let result = manager.list("db-*").await;
        assert!(result.is_ok(), "Pattern listing should succeed");
        
        let db_secrets = result.unwrap();
        assert_eq!(db_secrets.len(), 2, "Should list 2 db secrets");
        
        // Verify only db secrets are returned
        for secret in &db_secrets {
            assert!(secret.name.starts_with("db-"), "Secret should start with db-");
        }
    }
    
    /// Test lease renewal
    #[tokio::test]
    async fn test_lease_renewal() {
        let manager = SecretsEngineManager::new();
        let secret_data = b"renewable secret";
        
        // Write secret with short TTL
        let result = manager.write("renew-secret", secret_data, Some(60)).await;
        assert!(result.is_ok(), "Secret write should succeed");
        
        // Get initial lease
        let result = manager.read("renew-secret").await;
        assert!(result.is_ok(), "Secret read should succeed");
        
        let secret = result.unwrap();
        let initial_lease = secret.lease.unwrap();
        let initial_ttl = initial_lease.ttl;
        
        // Wait a bit and renew
        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
        
        let result = manager.renew("renew-secret").await;
        assert!(result.is_ok(), "Lease renewal should succeed");
        
        let renewed_lease = result.unwrap();
        assert!(renewed_lease.expires_at > initial_lease.expires_at, "Renewed lease should expire later");
        assert_eq!(renewed_lease.ttl, initial_ttl, "TTL should remain the same");
    }
    
    /// Test lease revocation
    #[tokio::test]
    async fn test_lease_revocation() {
        let manager = SecretsEngineManager::new();
        let secret_data = b"revocable secret";
        
        // Write secret
        let result = manager.write("revoke-secret", secret_data, Some(3600)).await;
        assert!(result.is_ok(), "Secret write should succeed");
        
        // Get lease
        let result = manager.read("revoke-secret").await;
        assert!(result.is_ok(), "Secret read should succeed");
        
        let secret = result.unwrap();
        assert!(secret.lease.is_some(), "Secret should have a lease");
        
        // Revoke lease
        let result = manager.revoke("revoke-secret").await;
        assert!(result.is_ok(), "Lease revocation should succeed");
        
        // Verify lease is revoked
        let result = manager.read("revoke-secret").await;
        assert!(result.is_err(), "Secret read should fail after revocation");
    }
    
    /// Test lease expiration
    #[tokio::test]
    async fn test_lease_expiration() {
        let mut manager = SecretsEngineManager::new();
        let secret_data = b"expiring secret";
        
        // Write secret with very short TTL
        let result = manager.write("expire-secret", secret_data, Some(1)).await;
        assert!(result.is_ok(), "Secret write should succeed");
        
        // Wait for expiration
        tokio::time::sleep(tokio::time::Duration::from_millis(1100)).await;
        
        // Cleanup expired leases
        let result = manager.cleanup_expired().await;
        assert!(result.is_ok(), "Cleanup should succeed");
        
        let expired_count = result.unwrap();
        assert!(expired_count > 0, "Should have cleaned up expired leases");
        
        // Verify secret is no longer accessible
        let result = manager.read("expire-secret").await;
        assert!(result.is_err(), "Secret read should fail after expiration");
    }
    
    /// Test secrets engine registration
    #[tokio::test]
    async fn test_engine_registration() {
        let mut manager = SecretsEngineManager::new();
        
        // Register custom engine
        let engine = TestSecretsEngine::new();
        let result = manager.register_engine("custom", Box::new(engine)).await;
        assert!(result.is_ok(), "Engine registration should succeed");
        
        // Verify engine is registered
        let engines = manager.list_engines().await;
        assert!(engines.contains(&"custom".to_string()), "Custom engine should be registered");
        
        // Unregister engine
        let result = manager.unregister_engine("custom").await;
        assert!(result.is_ok(), "Engine unregistration should succeed");
        
        // Verify engine is unregistered
        let engines = manager.list_engines().await;
        assert!(!engines.contains(&"custom".to_string()), "Custom engine should be unregistered");
    }
    
    /// Test secrets engine configuration
    #[tokio::test]
    async fn test_engine_configuration() {
        let mut manager = SecretsEngineManager::new();
        
        // Configure global settings
        let config = SecretsConfig {
            default_ttl: Some(7200),
            max_ttl: Some(86400),
            auto_renewal: Some(true),
            cleanup_interval: Some(300),
        };
        
        let result = manager.configure(config).await;
        assert!(result.is_ok(), "Configuration should succeed");
        
        // Write secret to test configuration
        let secret_data = b"configured secret";
        let result = manager.write("configured-secret", secret_data, None).await;
        assert!(result.is_ok(), "Secret write should succeed");
        
        // Verify default TTL was applied
        let result = manager.read("configured-secret").await;
        assert!(result.is_ok(), "Secret read should succeed");
        
        let secret = result.unwrap();
        let lease = secret.lease.unwrap();
        assert_eq!(lease.ttl, 7200, "Should use configured default TTL");
    }
    
    /// Test error handling for non-existent secrets
    #[tokio::test]
    async fn test_non_existent_secret() {
        let manager = SecretsEngineManager::new();
        
        // Try to read non-existent secret
        let result = manager.read("non-existent-secret").await;
        assert!(result.is_err(), "Reading non-existent secret should fail");
        
        // Try to delete non-existent secret
        let result = manager.delete("non-existent-secret").await;
        assert!(result.is_err(), "Deleting non-existent secret should fail");
        
        // Try to renew non-existent lease
        let result = manager.renew("non-existent-secret").await;
        assert!(result.is_err(), "Renewing non-existent lease should fail");
        
        // Try to revoke non-existent lease
        let result = manager.revoke("non-existent-secret").await;
        assert!(result.is_err(), "Revoking non-existent lease should fail");
    }
    
    /// Test concurrent secret operations
    #[tokio::test]
    async fn test_concurrent_operations() {
        let manager = SecretsEngineManager::new();
        
        // Perform multiple operations concurrently
        let mut handles = Vec::new();
        for i in 0..10 {
            let secret_name = format!("concurrent-secret-{}", i);
            let secret_data = format!("data {}", i).into_bytes();
            let manager_clone = manager.clone();
            
            let handle = tokio::spawn(async move {
                manager_clone.write(&secret_name, &secret_data, Some(3600)).await
            });
            handles.push(handle);
        }
        
        // Wait for all writes to complete
        for handle in handles {
            let result = handle.await.expect("Task should complete");
            assert!(result.is_ok(), "Concurrent secret write should succeed");
        }
        
        // Verify all secrets were written
        let result = manager.list("concurrent-secret-*").await;
        assert!(result.is_ok(), "Listing concurrent secrets should succeed");
        
        let secrets = result.unwrap();
        assert_eq!(secrets.len(), 10, "Should have written 10 secrets");
    }
    
    /// Test lease manager functionality
    #[tokio::test]
    async fn test_lease_manager() {
        let mut lease_manager = LeaseManager::new();
        
        // Create multiple leases
        let lease_ids = vec![
            "lease-1".to_string(),
            "lease-2".to_string(),
            "lease-3".to_string(),
        ];
        
        for lease_id in &lease_ids {
            let lease = LeaseInfo {
                ttl: 3600,
                created_at: chrono::Utc::now(),
                expires_at: chrono::Utc::now() + chrono::Duration::seconds(3600),
                renewable: true,
            };
            
            lease_manager.create_lease(lease_id.clone(), lease).await;
        }
        
        // List leases
        let leases = lease_manager.list_leases();
        assert_eq!(leases.len(), 3, "Should have 3 leases");
        
        // Verify all lease IDs are present
        for lease_id in &lease_ids {
            let found = leases.iter().any(|(id, _)| id == lease_id);
            assert!(found, "Lease {} should be in the list", lease_id);
        }
        
        // Test lease renewal
        let result = lease_manager.renew_lease(&lease_ids[0]).await;
        assert!(result.is_ok(), "Lease renewal should succeed");
        
        // Test lease revocation
        let result = lease_manager.revoke_lease(&lease_ids[1]).await;
        assert!(result.is_ok(), "Lease revocation should succeed");
        
        // Verify revoked lease is gone
        let leases = lease_manager.list_leases();
        let revoked_found = leases.iter().any(|(id, _)| id == &lease_ids[1]);
        assert!(!revoked_found, "Revoked lease should not be in the list");
    }
    
    // Test secrets engine implementation
    struct TestSecretsEngine {
        secrets: std::collections::HashMap<String, Vec<u8>>,
    }
    
    impl TestSecretsEngine {
        fn new() -> Self {
            Self {
                secrets: std::collections::HashMap::new(),
            }
        }
    }
    
    #[async_trait::async_trait]
    impl SecretsEngine for TestSecretsEngine {
        async fn write(&mut self, name: &str, data: &[u8], _ttl: Option<u32>) -> Result<()> {
            self.secrets.insert(name.to_string(), data.to_vec());
            Ok(())
        }
        
        async fn read(&self, name: &str) -> Result<Secret> {
            match self.secrets.get(name) {
                Some(data) => {
                    let metadata = SecretMetadata {
                        name: name.to_string(),
                        data_type: "binary".to_string(),
                        created_at: chrono::Utc::now(),
                        updated_at: chrono::Utc::now(),
                        version: 1,
                        custom_metadata: std::collections::HashMap::new(),
                    };
                    
                    let lease = LeaseInfo {
                        ttl: 3600,
                        created_at: chrono::Utc::now(),
                        expires_at: chrono::Utc::now() + chrono::Duration::seconds(3600),
                        renewable: true,
                    };
                    
                    Ok(Secret {
                        data: data.clone(),
                        metadata,
                        lease: Some(lease),
                    })
                }
                None => Err(FortressError::secrets(
                    "Secret not found".to_string(),
                    None,
                    SecretsErrorCode::SecretNotFound,
                )),
            }
        }
        
        async fn delete(&mut self, name: &str) -> Result<()> {
            self.secrets.remove(name);
            Ok(())
        }
        
        async fn list(&self, pattern: &str) -> Result<Vec<SecretMetadata>> {
            let pattern_regex = regex::Regex::new(pattern.replace('*', ".*")).unwrap();
            let mut secrets = Vec::new();
            
            for (name, _) in &self.secrets {
                if pattern_regex.is_match(name) {
                    let metadata = SecretMetadata {
                        name: name.clone(),
                        data_type: "binary".to_string(),
                        created_at: chrono::Utc::now(),
                        updated_at: chrono::Utc::now(),
                        version: 1,
                        custom_metadata: std::collections::HashMap::new(),
                    };
                    secrets.push(metadata);
                }
            }
            
            Ok(secrets)
        }
        
        async fn renew(&mut self, name: &str) -> Result<LeaseInfo> {
            // For test purposes, just return a renewed lease
            Ok(LeaseInfo {
                ttl: 3600,
                created_at: chrono::Utc::now(),
                expires_at: chrono::Utc::now() + chrono::Duration::seconds(7200), // Extended TTL
                renewable: true,
            })
        }
        
        async fn revoke(&mut self, name: &str) -> Result<()> {
            // For test purposes, just remove the secret
            self.secrets.remove(name);
            Ok(())
        }
        
        async fn configure(&mut self, _config: SecretsConfig) -> Result<()> {
            // For test purposes, just return success
            Ok(())
        }
        
        async fn health_check(&self) -> Result<bool> {
            // For test purposes, always return healthy
            Ok(true)
        }
    }
}
