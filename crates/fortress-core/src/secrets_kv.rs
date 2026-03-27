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
use crate::storage::{StorageBackend, InMemoryStorage, FileSystemStorage};
#[cfg(feature = "cloud-storage")]
use crate::storage::S3Storage;
use crate::encryption::{EncryptionAlgorithm, Aegis256};
use crate::secure_audit::SecureAuditLogger;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use base64::Engine;

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
    /// Encryption-at-rest enabled
    pub encryption_at_rest: bool,
    /// Storage backend for persistence
    pub storage_backend: Option<String>,
    /// Master key for encryption (in production, should come from KMS/HSM)
    pub master_key: Option<String>,
}

impl Default for KvConfig {
    fn default() -> Self {
        Self {
            max_versions: 10,
            default_ttl: None,
            case_sensitive: false,
            auto_cleanup: true,
            encryption_at_rest: true, // Enable by default for security
            storage_backend: Some("memory".to_string()), // Default to memory for compatibility
            master_key: None, // Will generate if not provided
        }
    }
}

/// Versioned secret data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VersionedSecret {
    /// Encrypted secret data (or plaintext if encryption disabled)
    pub data: serde_json::Value,
    /// Version number
    pub version: u64,
    /// Creation timestamp
    pub created_at: chrono::DateTime<chrono::Utc>,
    /// Deletion timestamp (if soft-deleted)
    pub deleted_at: Option<chrono::DateTime<chrono::Utc>>,
    /// Custom metadata
    pub custom_metadata: HashMap<String, String>,
    /// Whether data is encrypted
    pub is_encrypted: bool,
    /// Encryption nonce (if encrypted)
    pub encryption_nonce: Option<String>,
}

/// KV secrets engine implementation with Barrier pattern
#[derive(Debug)]
pub struct KvEngine {
    /// Engine configuration
    config: Arc<RwLock<KvConfig>>,
    /// Secret metadata cache only (full data stored in backend)
    secret_metadata: Arc<RwLock<HashMap<String, KvSecretMetadata>>>,
    /// Lease management
    leases: Arc<RwLock<HashMap<String, LeaseInfo>>>,
    /// Statistics
    stats: Arc<RwLock<EngineStats>>,
    /// Storage backend for persistence (the actual data store)
    storage: Arc<dyn StorageBackend>,
    /// Encryption algorithm (the Barrier)
    encryption: Arc<Box<dyn EncryptionAlgorithm>>,
    /// Master encryption key
    master_key: Arc<RwLock<Vec<u8>>>,
    /// Simple cache for frequently accessed encrypted data
    barrier_cache: Arc<RwLock<HashMap<String, Vec<u8>>>>,
    /// Secure audit logger
    audit_logger: Arc<SecureAuditLogger>,
}

/// Lightweight metadata for secrets (stored in memory, full data encrypted at rest)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KvSecretMetadata {
    /// Path to the secret
    pub path: String,
    /// Current version number
    pub current_version: u64,
    /// Next version number
    pub next_version: u64,
    /// Creation timestamp
    pub created_at: chrono::DateTime<chrono::Utc>,
    /// Last updated timestamp
    pub updated_at: chrono::DateTime<chrono::Utc>,
    /// Number of versions
    pub version_count: u64,
    /// Whether this secret is encrypted at rest
    pub encrypted_at_rest: bool,
}

/// KV secret entry with version history (stored encrypted in backend)
#[derive(Debug, Clone, Serialize, Deserialize)]
struct KvSecretEntry {
    /// Path to the secret
    path: String,
    /// Version history
    versions: HashMap<u64, VersionedSecret>,
    /// Current version
    current_version: u64,
    /// Next version
    next_version: u64,
}

impl KvEngine {
    /// Create new KV engine
    pub fn new() -> Self {
        Self::with_config(KvConfig::default())
    }

    /// Create KV engine with custom configuration
    pub fn with_config(config: KvConfig) -> Self {
        // Initialize master key
        let master_key = if let Some(key_str) = &config.master_key {
            base64::engine::general_purpose::STANDARD.decode(key_str)
                .unwrap_or_else(|_| {
                    // Generate new key if decoding fails
                    Self::generate_master_key()
                })
        } else {
            Self::generate_master_key()
        };

        // Initialize storage backend
        let storage: Arc<dyn StorageBackend> = match config.storage_backend.as_deref() {
            Some("memory") => Arc::new(InMemoryStorage::new()),
            Some("file") => {
                match FileSystemStorage::new("data/secrets") {
                    Ok(fs) => Arc::new(fs),
                    Err(e) => {
                        log::warn!("Failed to create file storage, falling back to memory: {}", e);
                        Arc::new(InMemoryStorage::new())
                    }
                }
            },
            #[cfg(feature = "cloud-storage")]
            Some("s3") => {
                // For S3, we need to use a blocking approach since this is not async
                log::warn!("S3 storage requires async initialization, falling back to memory");
                Arc::new(InMemoryStorage::new())
            },
            #[cfg(not(feature = "cloud-storage"))]
            Some("s3") => {
                log::warn!("S3 storage requested but cloud-storage feature not enabled, falling back to memory");
                Arc::new(InMemoryStorage::new())
            },
            _ => Arc::new(InMemoryStorage::new()),
        };

        Self {
            config: Arc::new(RwLock::new(config)),
            secret_metadata: Arc::new(RwLock::new(HashMap::new())),
            leases: Arc::new(RwLock::new(HashMap::new())),
            stats: Arc::new(RwLock::new(EngineStats {
                total_secrets: 0,
                active_leases: 0,
                operations: HashMap::new(),
                last_operation: None,
            })),
            storage,
            encryption: Arc::new(Box::new(Aegis256::new())),
            master_key: Arc::new(RwLock::new(master_key)),
            barrier_cache: Arc::new(RwLock::new(HashMap::new())), // Simple HashMap cache
            audit_logger: Arc::new(SecureAuditLogger::new()),
        }
    }

    /// Generate a secure master key
    fn generate_master_key() -> Vec<u8> {
        use rand::RngCore;
        let mut key = vec![0u8; 32]; // 256-bit key for AEGIS-256
        rand::thread_rng().fill_bytes(&mut key);
        key
    }

    /// Barrier: Encrypt and serialize secret data for storage
    async fn barrier_encrypt_and_serialize(&self, data: &serde_json::Value) -> Result<Vec<u8>> {
        let config = self.config.read().await;
        
        if !config.encryption_at_rest {
            // If encryption disabled, just serialize
            return serde_json::to_vec(data)
                .map_err(|e| FortressError::secrets(format!("Failed to serialize secret data: {}", e)));
        }
        
        let master_key = self.master_key.read().await;
        
        // Serialize the data first
        let data_bytes = serde_json::to_vec(data)
            .map_err(|e| FortressError::secrets(format!("Failed to serialize secret data: {}", e)))?;
        
        // Apply the Barrier: encrypt the serialized data
        let encrypted_data = self.encryption.encrypt(&data_bytes, &master_key)
            .map_err(|e| FortressError::secrets(format!("Failed to encrypt secret data: {}", e)))?;
        
        Ok(encrypted_data)
    }

    /// Barrier: Decrypt and deserialize secret data from storage
    async fn barrier_decrypt_and_deserialize(&self, encrypted_data: &[u8]) -> Result<serde_json::Value> {
        let config = self.config.read().await;
        
        if !config.encryption_at_rest {
            // If encryption disabled, just deserialize
            return serde_json::from_slice(encrypted_data)
                .map_err(|e| FortressError::secrets(format!("Failed to deserialize secret data: {}", e)));
        }
        
        let master_key = self.master_key.read().await;
        
        // Apply the Barrier: decrypt the data
        let decrypted_bytes = self.encryption.decrypt(encrypted_data, &master_key)
            .map_err(|e| FortressError::secrets(format!("Failed to decrypt secret data: {}", e)))?;
        
        // Deserialize the decrypted data
        let decrypted_json: serde_json::Value = serde_json::from_slice(&decrypted_bytes)
            .map_err(|e| FortressError::secrets(format!("Failed to deserialize decrypted data: {}", e)))?;
        
        Ok(decrypted_json)
    }

    /// Store encrypted secret data using the Barrier pattern
    async fn barrier_store_secret(&self, path: &str, entry: &KvSecretEntry) -> Result<()> {
        // Serialize the complete secret entry
        let serialized_entry = serde_json::to_vec(entry)
            .map_err(|e| FortressError::secrets(format!("Failed to serialize secret entry: {}", e)))?;
        
        // Apply Barrier: encrypt the serialized entry
        let master_key = self.master_key.read().await;
        let encrypted_entry = self.encryption.encrypt(&serialized_entry, &master_key)
            .map_err(|e| FortressError::secrets(format!("Failed to encrypt secret entry: {}", e)))?;
        
        // Store encrypted data in backend
        let storage_key = format!("kv/secrets/{}", path);
        self.storage.put(&storage_key, &encrypted_entry).await
            .map_err(|e| FortressError::secrets(format!("Failed to store encrypted secret: {}", e)))?;
        
        // Update cache with encrypted data
        {
            let mut cache = self.barrier_cache.write().await;
            cache.insert(path.to_string(), encrypted_entry);
        }
        
        Ok(())
    }

    /// Load and decrypt secret data using the Barrier pattern
    async fn barrier_load_secret(&self, path: &str) -> Result<Option<KvSecretEntry>> {
        // Check cache first
        let cache_key = path.to_string();
        let maybe_cached_data = {
            let cache = self.barrier_cache.read().await;
            cache.get(&cache_key).cloned()
        };
        
        if let Some(encrypted_data) = maybe_cached_data {
            // Decrypt cached data
            let master_key = self.master_key.read().await;
            let decrypted_data = self.encryption.decrypt(&encrypted_data, &master_key)
                .map_err(|e| FortressError::secrets(format!("Failed to decrypt cached secret: {}", e)))?;
            
            let entry: KvSecretEntry = serde_json::from_slice(&decrypted_data)
                .map_err(|e| FortressError::secrets(format!("Failed to deserialize cached secret: {}", e)))?;
            return Ok(Some(entry));
        }
        
        // Load from storage backend
        let storage_key = format!("kv/secrets/{}", path);
        
        if let Some(encrypted_data) = self.storage.get(&storage_key).await
            .map_err(|e| FortressError::secrets(format!("Failed to load secret from storage: {}", e)))? {
            
            // Apply Barrier: decrypt the data
            let master_key = self.master_key.read().await;
            let decrypted_data = self.encryption.decrypt(&encrypted_data, &master_key)
                .map_err(|e| FortressError::secrets(format!("Failed to decrypt secret data: {}", e)))?;
            
            // Deserialize the decrypted entry
            let entry: KvSecretEntry = serde_json::from_slice(&decrypted_data)
                .map_err(|e| FortressError::secrets(format!("Failed to deserialize secret entry: {}", e)))?;
            
            // Update cache
            {
                let mut cache = self.barrier_cache.write().await;
                cache.insert(path.to_string(), encrypted_data);
            }
            
            Ok(Some(entry))
        } else {
            Ok(None)
        }
    }

    /// Initialize metadata from storage on startup using Barrier pattern
    pub async fn initialize_from_storage(&self) -> Result<()> {
        let prefix = "kv/secrets/";
        let keys = self.storage.list_prefix(prefix).await
            .map_err(|e| FortressError::secrets(format!("Failed to list secrets from storage: {}", e)))?;
        
        let mut metadata = self.secret_metadata.write().await;
        let mut loaded_count = 0;
        
        for key in keys {
            // Extract path from storage key
            let path = match key.strip_prefix(prefix) {
                Some(p) => p,
                None => continue,
            };
            
            // Load and decrypt secret entry using Barrier
            if let Ok(Some(entry)) = self.barrier_load_secret(path).await {
                // Create lightweight metadata for memory cache
                let secret_metadata = KvSecretMetadata {
                    path: path.to_string(),
                    current_version: entry.current_version,
                    next_version: entry.next_version,
                    created_at: entry.versions.values()
                        .min_by_key(|v| v.created_at)
                        .map(|v| v.created_at)
                        .unwrap_or_else(|| chrono::Utc::now()),
                    updated_at: entry.versions.values()
                        .max_by_key(|v| v.created_at)
                        .map(|v| v.created_at)
                        .unwrap_or_else(|| chrono::Utc::now()),
                    version_count: entry.versions.len() as u64,
                    encrypted_at_rest: self.config.read().await.encryption_at_rest,
                };
                
                metadata.insert(path.to_string(), secret_metadata);
                loaded_count += 1;
            }
        }
        
        // Update stats
        {
            let mut stats = self.stats.write().await;
            stats.total_secrets = metadata.len() as u64;
        }
        
        if loaded_count > 0 {
            log::info!("Loaded {} secret metadata from encrypted storage", loaded_count);
        }
        
        Ok(())
    }

    /// Decrypt secret data (backward compatibility method)
    async fn decrypt_secret_data(&self, encrypted_data: &serde_json::Value, nonce: &str) -> Result<serde_json::Value> {
        let config = self.config.read().await;
        
        if !config.encryption_at_rest {
            return Ok(encrypted_data.clone());
        }
        
        let master_key = self.master_key.read().await;
        
        // Extract encrypted data
        let encrypted_str = encrypted_data.get("data")
            .and_then(|v| v.as_str())
            .ok_or_else(|| FortressError::secrets("Invalid encrypted data format".to_string()))?;
        
        let mut encrypted_bytes = base64::engine::general_purpose::STANDARD.decode(encrypted_str)
            .map_err(|e| FortressError::secrets(format!("Failed to decode encrypted data: {}", e)))?;
        
        // Extract nonce from end of encrypted data
        let nonce_len = 12; // AEGIS-256 nonce length
        if encrypted_bytes.len() < nonce_len {
            return Err(FortressError::secrets("Invalid encrypted data length".to_string()));
        }
        
        let data_with_nonce = encrypted_bytes.clone();
        let _extracted_nonce = encrypted_bytes.split_off(encrypted_bytes.len() - nonce_len);
        
        // Decrypt data
        let decrypted_bytes = self.encryption.decrypt(&encrypted_bytes, &master_key)
            .map_err(|e| FortressError::secrets(format!("Failed to decrypt secret data: {}", e)))?;
        
        // Parse back to JSON
        let decrypted_json: serde_json::Value = serde_json::from_slice(&decrypted_bytes)
            .map_err(|e| FortressError::secrets(format!("Failed to deserialize decrypted data: {}", e)))?;
        
        Ok(decrypted_json)
    }

    /// Read a specific version of a secret using Barrier pattern
    pub async fn read_version(&self, path: &str, version: u64) -> Result<Option<Secret>> {
        self.record_operation("read_version").await;
        
        // Load full secret entry using Barrier (decrypts from storage)
        let entry = match self.barrier_load_secret(path).await? {
            Some(entry) => entry,
            None => return Ok(None),
        };
        
        let leases = self.leases.read().await;
        
        if let Some(versioned) = entry.versions.get(&version) {
            let lease_id = format!("kv:{}:{}", path, version);
            let lease = leases.get(&lease_id).cloned();
            
            // Decrypt data using Barrier if needed
            let decrypted_data = if versioned.is_encrypted {
                // For backward compatibility, handle old encrypted format
                if let Some(nonce) = &versioned.encryption_nonce {
                    self.decrypt_secret_data(&versioned.data, nonce).await?
                } else {
                    // Data should already be decrypted by Barrier
                    versioned.data.clone()
                }
            } else {
                versioned.data.clone()
            };
            
            let secret = Secret {
                data: decrypted_data,
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
    }

    /// Get all versions of a secret using Barrier pattern
    pub async fn list_versions(&self, path: &str) -> Result<Vec<u64>> {
        // Load full secret entry using Barrier
        match self.barrier_load_secret(path).await? {
            Some(entry) => {
                let mut versions: Vec<u64> = entry.versions.keys().cloned().collect();
                versions.sort();
                Ok(versions)
            },
            None => Ok(vec![])
        }
    }

    /// Delete a specific version using Barrier pattern
    pub async fn delete_version(&self, path: &str, version: u64) -> Result<()> {
        self.record_operation("delete_version").await;
        
        // Load full secret entry using Barrier
        let mut entry = match self.barrier_load_secret(path).await? {
            Some(entry) => entry,
            None => return Err(FortressError::secrets("Secret not found".to_string())),
        };
        
        if let Some(versioned) = entry.versions.get_mut(&version) {
            versioned.deleted_at = Some(chrono::Utc::now());
            
            // Store updated entry using Barrier
            self.barrier_store_secret(path, &entry).await?;
            
            // Update metadata
            {
                let mut metadata = self.secret_metadata.write().await;
                if let Some(meta) = metadata.get_mut(path) {
                    meta.updated_at = chrono::Utc::now();
                    meta.version_count = entry.versions.len() as u64;
                }
            }
            
            Ok(())
        } else {
            Err(FortressError::secrets("Version not found".to_string()))
        }
    }

    /// Permanently destroy a secret and all versions using Barrier pattern
    pub async fn destroy(&self, path: &str) -> Result<()> {
        self.record_operation("destroy").await;
        
        let mut leases = self.leases.write().await;
        
        // Remove all leases for this path
        let lease_ids: Vec<String> = leases.keys()
            .filter(|id| id.starts_with(&format!("kv:{}:", path)))
            .cloned()
            .collect();
        
        for lease_id in lease_ids {
            leases.remove(&lease_id);
        }
        
        // Remove from encrypted storage
        let storage_key = format!("kv/secrets/{}", path);
        self.storage.delete(&storage_key).await
            .map_err(|e| FortressError::secrets(format!("Failed to delete secret from storage: {}", e)))?;
        
        // Remove from cache
        {
            let mut cache = self.barrier_cache.write().await;
            cache.remove(path);
        }
        
        // Remove from metadata
        {
            let mut metadata = self.secret_metadata.write().await;
            metadata.remove(path);
        }
        
        // Update stats
        {
            let mut stats = self.stats.write().await;
            stats.total_secrets = self.secret_metadata.read().await.len() as u64;
            stats.active_leases = leases.len() as u64;
        }
        
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

    /// Cleanup old versions based on configuration using Barrier pattern
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
        
        let config = self.config.read().await;
        
        // Load existing entry or create new one using Barrier
        let mut entry = match self.barrier_load_secret(path).await? {
            Some(entry) => entry,
            None => KvSecretEntry {
                path: path.to_string(),
                versions: HashMap::new(),
                current_version: 0,
                next_version: 1,
            },
        };
        
        let version = entry.next_version;
        entry.next_version += 1;
        entry.current_version = version;
        
        // Create versioned secret with Barrier encryption
        let versioned = VersionedSecret {
            data: data.clone(), // Store as-is (Barrier handles encryption at storage level)
            version,
            created_at: chrono::Utc::now(),
            deleted_at: None,
            custom_metadata: HashMap::new(),
            is_encrypted: config.encryption_at_rest, // Mark as encrypted for backward compatibility
            encryption_nonce: None, // Barrier handles nonce internally
        };
        
        entry.versions.insert(version, versioned);
        
        // Cleanup old versions if needed
        drop(config);
        self.cleanup_old_versions(&mut entry).await;
        
        // Store using Barrier (encrypts and serializes)
        let store_result = self.barrier_store_secret(path, &entry).await;
        
        // Log write operation with enhanced metadata
        let principal = "system"; // In a real implementation, this would be authenticated user
        
        let outcome = if store_result.is_ok() { "success" } else { "failure" };
        if let Err(e) = self.audit_logger.log_secret_write(principal, path, version, outcome).await {
            log::warn!("Failed to log audit entry: {}", e);
        }
        
        // Propagate storage error if any
        store_result?;
        
        // Update metadata cache
        {
            let mut metadata = self.secret_metadata.write().await;
            let secret_metadata = KvSecretMetadata {
                path: path.to_string(),
                current_version: entry.current_version,
                next_version: entry.next_version,
                created_at: entry.versions.values()
                    .min_by_key(|v| v.created_at)
                    .map(|v| v.created_at)
                    .unwrap_or_else(|| chrono::Utc::now()),
                updated_at: chrono::Utc::now(),
                version_count: entry.versions.len() as u64,
                encrypted_at_rest: self.config.read().await.encryption_at_rest,
            };
            metadata.insert(path.to_string(), secret_metadata);
        }
        
        // Update stats
        {
            let mut stats = self.stats.write().await;
            stats.total_secrets = self.secret_metadata.read().await.len() as u64;
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
        
        // Load full secret entry using Barrier
        let result = self.barrier_load_secret(path).await;
        
        // Log read operation with enhanced metadata
        let principal = "system"; // In a real implementation, this would be authenticated user
        
        let outcome = if result.is_ok() { "success" } else { "failure" };
        if let Err(e) = self.audit_logger.log_access(principal, path, "read", outcome).await {
            log::warn!("Failed to log audit entry: {}", e);
        }
        
        let entry = result?;
        
        match entry {
            Some(entry) => {
                let leases = self.leases.read().await;
                
                if let Some(versioned) = entry.versions.get(&entry.current_version) {
                    let lease_id = self.generate_lease_id(path, versioned.version);
                    let lease = leases.get(&lease_id).cloned();
                    
                    // Data is already decrypted by Barrier
                    let decrypted_data = versioned.data.clone();
                    
                    Ok(Some(Secret {
                        data: decrypted_data,
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
            },
            None => Ok(None)
        }
    }

    async fn delete(&self, path: &str) -> Result<()> {
        self.record_operation("delete").await;
        
        // Log the delete operation
        let _principal = "system"; // In a real implementation, this would be authenticated user
        
        let mut leases = self.leases.write().await;
        
        // Remove all leases for this path
        let lease_ids: Vec<String> = leases.keys()
            .filter(|id| id.starts_with(&format!("kv:{}:", path)))
            .cloned()
            .collect();
        
        for lease_id in lease_ids.clone() {
            leases.remove(&lease_id);
        }
        
        // Remove from encrypted storage
        let storage_key = format!("kv/secrets/{}", path);
        let storage_result = self.storage.delete(&storage_key).await;
        
        // Log delete operation
        let principal = "system"; // In a real implementation, this would be authenticated user
        
        let outcome = if storage_result.is_ok() { "success" } else { "failure" };
        if let Err(e) = self.audit_logger.log_secret_delete(principal, path, outcome).await {
            log::warn!("Failed to log audit entry: {}", e);
        }
        
        // Propagate storage error if any
        storage_result?;
        
        // Remove from cache
        {
            let mut cache = self.barrier_cache.write().await;
            cache.remove(path);
        }
        
        // Remove from metadata
        {
            let mut metadata = self.secret_metadata.write().await;
            metadata.remove(path);
        }
        
        // Update stats
        {
            let mut stats = self.stats.write().await;
            stats.total_secrets = self.secret_metadata.read().await.len() as u64;
            stats.active_leases = leases.len() as u64;
        }
        
        Ok(())
    }

    async fn list(&self, path: &str) -> Result<Vec<String>> {
        self.record_operation("list").await;
        
        let metadata = self.secret_metadata.read().await;
        let config = self.config.read().await;
        
        let mut results = Vec::new();
        
        for secret_path in metadata.keys() {
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
        
        // Log list operation with enhanced metadata
        let principal = "system"; // In a real implementation, this would be authenticated user
        
        let outcome = "success";
        if let Err(e) = self.audit_logger.log_access(principal, path, "list", outcome).await {
            log::warn!("Failed to log audit entry: {}", e);
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
        let _metadata = self.secret_metadata.read().await;
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::MemoryStorage;
    use serde_json::json;

    #[tokio::test]
    async fn test_encryption_at_rest() {
        let config = KvConfig {
            encryption_at_rest: true,
            storage_backend: Some("memory".to_string()),
            ..Default::default()
        };
        
        let engine = KvEngine::with_config(config);
        
        // Store a secret
        let secret_data = json!({
            "username": "admin",
            "password": "super-secret-password"
        });
        
        let secret = engine.write("test/secret", &secret_data).await.unwrap();
        assert_eq!(secret.data, secret_data);
        
        // Read it back
        let retrieved = engine.read("test/secret").await.unwrap();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().data, secret_data);
        
        // Verify data is encrypted in storage
        let storage_key = "kv/secrets/test/secret";
        let stored_data = engine.storage.get(storage_key).await.unwrap().unwrap();
        let entry: KvSecretEntry = serde_json::from_slice(&stored_data).unwrap();
        let versioned = &entry.versions[&1];
        assert!(versioned.is_encrypted);
        assert!(versioned.encryption_nonce.is_some());
        assert!(versioned.data.get("encrypted").unwrap().as_bool().unwrap());
    }

    #[tokio::test]
    async fn test_persistence_across_restarts() {
        let config = KvConfig {
            encryption_at_rest: true,
            storage_backend: Some("memory".to_string()),
            ..Default::default()
        };
        
        // Create first engine instance
        let engine1 = KvEngine::with_config(config.clone());
        
        // Store a secret
        let secret_data = json!({
            "api_key": "sk-1234567890abcdef",
            "token": "token_secret_value"
        });
        
        engine1.write("persistent/secret", &secret_data).await.unwrap();
        
        // Create second engine instance (simulating restart)
        let engine2 = KvEngine::with_config(config);
        
        // Initialize from storage
        engine2.initialize_from_storage().await.unwrap();
        
        // Read the secret - should be available
        let retrieved = engine2.read("persistent/secret").await.unwrap();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().data, secret_data);
    }

    #[tokio::test]
    async fn test_no_encryption_mode() {
        let config = KvConfig {
            encryption_at_rest: false,
            storage_backend: Some("memory".to_string()),
            ..Default::default()
        };
        
        let engine = KvEngine::with_config(config);
        
        // Store a secret
        let secret_data = json!({
            "plaintext": "this-is-not-encrypted"
        });
        
        engine.write("plain/secret", &secret_data).await.unwrap();
        
        // Verify data is not encrypted in storage
        let storage_key = "kv/secrets/plain/secret";
        let stored_data = engine.storage.get(storage_key).await.unwrap().unwrap();
        let entry: KvSecretEntry = serde_json::from_slice(&stored_data).unwrap();
        let versioned = &entry.versions[&1];
        assert!(!versioned.is_encrypted);
        assert!(versioned.encryption_nonce.is_none());
        assert_eq!(versioned.data, secret_data);
    }

    #[tokio::test]
    async fn test_master_key_generation() {
        let engine = KvEngine::new();
        let master_key = engine.master_key.read().await;
        assert_eq!(master_key.len(), 32); // 256-bit key
        
        // Verify key is different for another instance
        let engine2 = KvEngine::new();
        let master_key2 = engine2.master_key.read().await;
        assert_ne!(*master_key, *master_key2);
    }

    #[tokio::test]
    async fn test_encryption_decryption_roundtrip() {
        let engine = KvEngine::new();
        
        let original_data = json!({
            "sensitive_field": "highly_confidential_data",
            "numbers": [1, 2, 3, 4, 5],
            "nested": {
                "inner": "secret_value"
            }
        });
        
        // Encrypt
        let (encrypted, nonce) = engine.encrypt_secret_data(&original_data).await.unwrap();
        assert_ne!(encrypted, original_data);
        
        // Decrypt
        let decrypted = engine.decrypt_secret_data(&encrypted, &nonce).await.unwrap();
        assert_eq!(decrypted, original_data);
    }

    #[tokio::test]
    async fn test_kv_encryption_basic() {
        println!("Testing KV secrets engine with encryption...");
        
        // Create engine with encryption enabled
        let config = KvConfig {
            max_versions: 10,
            default_ttl: Some(3600),
            case_sensitive: false,
            auto_cleanup: true,
            encryption_at_rest: true,
            storage_backend: Some("memory".to_string()),
            master_key: None,
        };
        
        let engine = KvEngine::with_config(config);
        
        // Write a secret
        let secret_data = json!({
            "username": "admin",
            "password": "super-secret"
        });
        
        let result = engine.write("secret/app", &secret_data).await;
        assert!(result.is_ok(), "Failed to write secret: {:?}", result.err());
        println!("✅ Secret written successfully with encryption");
        
        // Read the secret back
        let retrieved_secret = engine.read("secret/app").await;
        assert!(retrieved_secret.is_ok(), "Failed to read secret: {:?}", retrieved_secret.err());
        println!("✅ Secret retrieved successfully");
        
        // Verify data matches
        if let Ok(Some(secret)) = retrieved_secret {
            let data = secret.data.as_object().unwrap();
            assert_eq!(data.get("username").unwrap().as_str().unwrap(), "admin");
            assert_eq!(data.get("password").unwrap().as_str().unwrap(), "super-secret");
            println!("✅ Secret data verified");
        } else {
            panic!("Expected to find secret but got None");
        }
        
        // Check engine status
        let status = engine.status().await;
        assert!(status.is_ok(), "Failed to get status: {:?}", status.err());
        
        if let Ok(status) = status {
            assert_eq!(status.engine_type, EngineType::Kv);
            assert_eq!(status.stats.total_secrets, 1);
            println!("✅ Engine status verified");
        }
        
        println!("🎉 All encryption tests passed!");
    }

    #[tokio::test]
    async fn test_kv_no_encryption() {
        println!("Testing KV secrets engine without encryption...");
        
        // Create engine without encryption
        let config = KvConfig {
            max_versions: 5,
            default_ttl: None,
            case_sensitive: true,
            auto_cleanup: true,
            encryption_at_rest: false,
            storage_backend: Some("memory".to_string()),
            master_key: None,
        };
        
        let engine = KvEngine::with_config(config);
        
        // Write a secret
        let secret_data = json!({
            "public": "data"
        });
        
        let result = engine.write("public/data", &secret_data).await;
        assert!(result.is_ok(), "Failed to write secret: {:?}", result.err());
        
        // Read the secret back
        let retrieved_secret = engine.read("public/data").await;
        assert!(retrieved_secret.is_ok(), "Failed to read secret: {:?}", retrieved_secret.err());
        assert!(retrieved_secret.unwrap().is_some(), "Expected to find secret but got None");
        
        println!("✅ Non-encrypted mode works correctly");
        println!("🎉 All non-encryption tests passed!");
    }
}
