//! # Secrets Management System
//!
//! Vault-inspired secrets engine with dynamic secrets, versioning, and lease management.

use crate::error::Result;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use chrono::{DateTime, Utc};

/// Secret data structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Secret {
    /// Secret data
    pub data: serde_json::Value,
    /// Metadata
    pub metadata: SecretMetadata,
    /// Lease information
    pub lease: Option<LeaseInfo>,
}

/// Secret metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretMetadata {
    /// Secret name
    pub name: String,
    /// Secret version
    pub version: u64,
    /// Creation time
    pub created_at: DateTime<Utc>,
    /// Last updated time
    pub updated_at: Option<DateTime<Utc>>,
    /// Creator
    pub created_by: Option<String>,
    /// Tags
    pub tags: HashMap<String, String>,
    /// Custom metadata
    pub custom: HashMap<String, serde_json::Value>,
}

/// Lease information for secrets
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LeaseInfo {
    /// Lease ID
    pub lease_id: String,
    /// Lease duration in seconds
    pub ttl: u64,
    /// Maximum lease TTL in seconds
    pub max_ttl: Option<u64>,
    /// Lease creation time
    pub created_at: DateTime<Utc>,
    /// Lease expiration time
    pub expires_at: DateTime<Utc>,
    /// Whether lease is renewable
    pub renewable: bool,
    /// Maximum number of renewals
    pub max_renewals: Option<u32>,
    /// Current renewal count
    pub renewal_count: u32,
}

/// Secrets engine trait
#[async_trait]
pub trait SecretsEngine: Send + Sync {
    /// Write a secret
    async fn write(&self, path: &str, data: &serde_json::Value) -> Result<Secret>;
    
    /// Read a secret
    async fn read(&self, path: &str) -> Result<Option<Secret>>;
    
    /// Delete a secret
    async fn delete(&self, path: &str) -> Result<()>;
    
    /// List secrets
    async fn list(&self, path: &str) -> Result<Vec<String>>;
    
    /// Renew a lease
    async fn renew(&self, lease_id: &str, increment: Option<u64>) -> Result<LeaseInfo>;
    
    /// Revoke a lease
    async fn revoke(&self, lease_id: &str) -> Result<()>;
    
    /// Configure engine
    async fn configure(&self, config: serde_json::Value) -> Result<()>;
    
    /// Get engine status
    async fn status(&self) -> Result<EngineStatus>;
    
    /// Get engine type
    fn engine_type(&self) -> EngineType;
    
    /// Get engine name
    fn name(&self) -> &str;
}

/// Engine types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EngineType {
    /// KV engine
    Kv,
    /// Database engine
    Database,
    /// Dynamic secrets engine
    Dynamic,
    /// PKI engine
    Pki,
    /// Transit engine
    Transit,
    /// Custom engine
    Custom(String),
}

/// Engine status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EngineStatus {
    /// Engine name
    pub name: String,
    /// Engine type
    pub engine_type: EngineType,
    /// Whether engine is initialized
    pub initialized: bool,
    /// Whether engine is active
    pub active: bool,
    /// Last activity time
    pub last_activity: DateTime<Utc>,
    /// Engine configuration
    pub config: serde_json::Value,
    /// Engine statistics
    pub stats: EngineStats,
}

/// Engine statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EngineStats {
    /// Total operations
    pub total_operations: u64,
    /// Successful operations
    pub successful_operations: u64,
    /// Failed operations
    pub failed_operations: u64,
    /// Average operation time in milliseconds
    pub avg_operation_time_ms: f64,
    /// Number of active leases
    pub active_leases: u64,
    /// Number of stored secrets
    pub stored_secrets: u64,
    /// Total number of secrets (alias for stored_secrets)
    pub total_secrets: u64,
    /// Operations breakdown
    pub operations: std::collections::HashMap<String, u64>,
    /// Last operation time
    pub last_operation: Option<DateTime<Utc>>,
}

/// Secrets engine manager
pub struct SecretsEngineManager {
    engines: HashMap<String, Box<dyn SecretsEngine>>,
    config: SecretsConfig,
}

/// Secrets configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretsConfig {
    /// Default lease TTL in seconds
    pub default_lease_ttl: u64,
    /// Maximum lease TTL in seconds
    pub max_lease_ttl: u64,
    /// Whether to automatically revoke expired leases
    pub auto_revoke: bool,
    /// Lease cleanup interval in seconds
    pub cleanup_interval: u64,
    /// Maximum number of secrets per engine
    pub max_secrets_per_engine: u64,
}

impl Default for SecretsConfig {
    fn default() -> Self {
        Self {
            default_lease_ttl: 3600, // 1 hour
            max_lease_ttl: 86400,    // 24 hours
            auto_revoke: true,
            cleanup_interval: 300,  // 5 minutes
            max_secrets_per_engine: 10000,
        }
    }
}

impl SecretsEngineManager {
    /// Create a new secrets engine manager
    pub fn new(config: SecretsConfig) -> Self {
        Self {
            engines: HashMap::new(),
            config,
        }
    }
    
    /// Register a secrets engine
    pub fn register_engine(&mut self, name: String, engine: Box<dyn SecretsEngine>) -> Result<()> {
        self.engines.insert(name, engine);
        Ok(())
    }
    
    /// Get an engine by name
    pub fn get_engine(&self, name: &str) -> Option<&dyn SecretsEngine> {
        self.engines.get(name).map(|engine| engine.as_ref())
    }
    
    /// List all engines
    pub fn list_engines(&self) -> Vec<String> {
        self.engines.keys().cloned().collect()
    }
    
    /// Get configuration
    pub fn config(&self) -> &SecretsConfig {
        &self.config
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::FortressError;
    use futures::future::join_all;
    use uuid::Uuid;

    #[tokio::test]
    async fn test_secret_lifecycle() -> Result<()> {
        let manager = SecretsEngineManager::new(SecretsConfig::default());
        let engine = TestKvEngine::new();
        
        // Test secret creation
        let test_data = serde_json::json!({
            "username": "testuser",
            "password": "testpass"
        });
        
        let secret = engine.write("test/secret", &test_data).await?;
        assert_eq!(secret.metadata.name, "test/secret");
        assert!(secret.metadata.version > 0);
        
        // Test secret retrieval
        let retrieved = engine.read("test/secret").await?;
        assert!(retrieved.is_some());
        
        let retrieved_secret = retrieved.unwrap();
        assert_eq!(retrieved_secret.data, test_data);
        
        // Test secret deletion
        engine.delete("test/secret").await?;
        let deleted = engine.read("test/secret").await?;
        assert!(deleted.is_none());
        
        Ok(())
    }

    #[tokio::test]
    async fn test_lease_management() -> Result<()> {
        let engine = TestKvEngine::new();
        
        // Create a secret with lease
        let test_data = serde_json::json!({"key": "value"});
        let secret = engine.write("leased/secret", &test_data).await?;
        
        assert!(secret.lease.is_some());
        let lease = secret.lease.unwrap();
        assert!(lease.ttl > 0);
        assert!(lease.renewable);
        
        // Test lease renewal
        let renewed_lease = engine.renew(&lease.lease_id, Some(3600)).await?;
        assert!(renewed_lease.expires_at > lease.expires_at);
        assert_eq!(renewed_lease.renewal_count, lease.renewal_count + 1);
        
        // Test lease revocation
        engine.revoke(&lease.lease_id).await?;
        
        Ok(())
    }

    #[tokio::test]
    async fn test_concurrent_operations() -> Result<()> {
        let engine = TestKvEngine::new();
        
        // Test concurrent writes
        let mut write_handles = Vec::new();
        for i in 0..10 {
            let engine_clone = engine.clone();
            let handle = tokio::spawn(async move {
                let data = serde_json::json!({"index": i});
                engine_clone.write(&format!("concurrent/{}", i), &data).await
            });
            write_handles.push(handle);
        }
        
        let write_results = join_all(write_handles).await;
        for result in write_results {
            assert!(result.is_ok());
            assert!(result.unwrap().is_ok());
        }
        
        Ok(())
    }

    /// Test KV engine implementation
    #[derive(Debug, Clone)]
    struct TestKvEngine {
        secrets: std::sync::Arc<tokio::sync::RwLock<HashMap<String, Secret>>>,
        leases: std::sync::Arc<tokio::sync::RwLock<HashMap<String, LeaseInfo>>>,
    }

    impl TestKvEngine {
        fn new() -> Self {
            Self {
                secrets: std::sync::Arc::new(tokio::sync::RwLock::new(HashMap::new())),
                leases: std::sync::Arc::new(tokio::sync::RwLock::new(HashMap::new())),
            }
        }
    }

    #[async_trait]
    impl SecretsEngine for TestKvEngine {
        async fn write(&self, path: &str, data: &serde_json::Value) -> Result<Secret> {
            let lease_id = format!("lease_{}", Uuid::new_v4());
            let lease = LeaseInfo {
                lease_id: lease_id.clone(),
                ttl: 3600,
                max_ttl: Some(86400),
                created_at: Utc::now(),
                expires_at: Utc::now() + chrono::Duration::seconds(3600),
                renewable: true,
                max_renewals: Some(5),
                renewal_count: 0,
            };
            
            let secret = Secret {
                data: data.clone(),
                metadata: SecretMetadata {
                    name: path.to_string(),
                    version: 1,
                    created_at: Utc::now(),
                    updated_at: None,
                    created_by: Some("test".to_string()),
                    tags: HashMap::new(),
                    custom: HashMap::new(),
                },
                lease: Some(lease.clone()),
            };
            
            {
                let mut secrets = self.secrets.write().await;
                secrets.insert(path.to_string(), secret.clone());
            }
            
            {
                let mut leases = self.leases.write().await;
                leases.insert(lease_id, lease);
            }
            
            Ok(secret)
        }

        async fn read(&self, path: &str) -> Result<Option<Secret>> {
            let secrets = self.secrets.read().await;
            Ok(secrets.get(path).cloned())
        }

        async fn delete(&self, path: &str) -> Result<()> {
            let mut secrets = self.secrets.write().await;
            secrets.remove(path);
            Ok(())
        }

        async fn list(&self, path: &str) -> Result<Vec<String>> {
            let secrets = self.secrets.read().await;
            let mut keys = Vec::new();
            
            for key in secrets.keys() {
                if key.starts_with(path) {
                    keys.push(key.clone());
                }
            }
            
            keys.sort();
            Ok(keys)
        }

        async fn renew(&self, lease_id: &str, increment: Option<u64>) -> Result<LeaseInfo> {
            let mut leases = self.leases.write().await;
            if let Some(lease) = leases.get_mut(lease_id) {
                if let Some(max_renewals) = lease.max_renewals {
                    if lease.renewal_count >= max_renewals {
                        return Err(FortressError::secrets("Maximum renewals exceeded"));
                    }
                }
                
                lease.renewal_count += 1;
                let increment = increment.unwrap_or(lease.ttl);
                lease.ttl = increment;
                lease.expires_at = Utc::now() + chrono::Duration::seconds(increment as i64);
                
                Ok(lease.clone())
            } else {
                Err(FortressError::secrets("Lease not found"))
            }
        }

        async fn revoke(&self, lease_id: &str) -> Result<()> {
            let mut leases = self.leases.write().await;
            leases.remove(lease_id);
            Ok(())
        }

        async fn configure(&self, _config: serde_json::Value) -> Result<()> {
            Ok(())
        }

        async fn status(&self) -> Result<EngineStatus> {
            let secrets = self.secrets.read().await;
            let leases = self.leases.read().await;
            
            Ok(EngineStatus {
                name: self.name().to_string(),
                engine_type: EngineType::Kv,
                initialized: true,
                active: true,
                last_activity: Utc::now(),
                config: serde_json::json!({}),
                stats: EngineStats {
                    total_operations: 0,
                    successful_operations: 0,
                    failed_operations: 0,
                    avg_operation_time_ms: 0.0,
                    active_leases: leases.len() as u64,
                    stored_secrets: secrets.len() as u64,
                    total_secrets: secrets.len() as u64,
                    operations: std::collections::HashMap::new(),
                    last_operation: Some(Utc::now()),
                },
            })
        }

        fn engine_type(&self) -> EngineType {
            EngineType::Kv
        }

        fn name(&self) -> &str {
            "TestKvEngine"
        }
    }
}
