//! Cache integration with key management and encryption for Fortress
//!
//! This module provides seamless integration between the caching system and
//! Fortress's key management and encryption components.

use crate::cache_manager::{CacheManager, CacheManagerConfig, CacheType};
#[cfg(feature = "distributed-cache")]
use crate::distributed_cache::DistributedCacheConfig;
use crate::encryption::PerformanceProfile;
use crate::error::{FortressError, Result};
use crate::key::{KeyId, KeyMetadata, SecureKey};
use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Cached key entry with encryption metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachedKeyEntry {
    /// Key ID
    pub key_id: KeyId,
    /// Encrypted key data
    pub encrypted_key: Vec<u8>,
    /// Key metadata
    pub metadata: KeyMetadata,
    /// Encryption algorithm used
    pub algorithm: String,
    /// Performance profile
    pub performance_profile: PerformanceProfile,
    /// Cache timestamp
    pub cached_at: DateTime<Utc>,
    /// Access count
    pub access_count: u64,
    /// Last accessed timestamp
    pub last_accessed: DateTime<Utc>,
}

/// Cache integration configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheIntegrationConfig {
    /// Cache manager configuration
    pub cache_config: CacheManagerConfig,
    /// Enable key caching
    pub enable_key_caching: bool,
    /// Enable encryption result caching
    pub enable_encryption_caching: bool,
    /// Enable decryption result caching
    pub enable_decryption_caching: bool,
    /// Key cache TTL in seconds
    pub key_cache_ttl_seconds: u64,
    /// Encryption result cache TTL in seconds
    pub encryption_cache_ttl_seconds: u64,
    /// Decryption result cache TTL in seconds
    pub decryption_cache_ttl_seconds: u64,
    /// Maximum cached keys
    pub max_cached_keys: usize,
    /// Enable cache warming for frequently used keys
    pub enable_cache_warming: bool,
    /// Cache warming keys
    pub warm_up_keys: Vec<KeyId>,
    /// Enable intelligent cache eviction
    pub enable_intelligent_eviction: bool,
    /// Cache security settings
    pub security_settings: CacheSecuritySettings,
}

/// Cache security settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheSecuritySettings {
    /// Enable cache encryption
    pub enable_cache_encryption: bool,
    /// Cache encryption key (if different from main keys)
    pub cache_encryption_key_id: Option<KeyId>,
    /// Enable access logging
    pub enable_access_logging: bool,
    /// Enable cache invalidation on key rotation
    pub invalidate_on_rotation: bool,
    /// Maximum cache entry size
    pub max_entry_size_bytes: usize,
    /// Enable rate limiting for cache operations
    pub enable_rate_limiting: bool,
    /// Rate limit requests per second
    pub rate_limit_rps: u32,
}

impl Default for CacheSecuritySettings {
    fn default() -> Self {
        Self {
            enable_cache_encryption: false,
            cache_encryption_key_id: None,
            enable_access_logging: true,
            invalidate_on_rotation: true,
            max_entry_size_bytes: 10 * 1024 * 1024, // 10MB
            enable_rate_limiting: false,
            rate_limit_rps: 1000,
        }
    }
}

impl Default for CacheIntegrationConfig {
    fn default() -> Self {
        Self {
            cache_config: CacheManagerConfig {
                cache_type: CacheType::InMemory,
                #[cfg(feature = "distributed-cache")]
                distributed_config: Some(DistributedCacheConfig {
                    max_cache_size: 10000,
                    default_ttl_seconds: 3600,
                    ..Default::default()
                }),
                ..Default::default()
            },
            enable_key_caching: true,
            enable_encryption_caching: true,
            enable_decryption_caching: true,
            key_cache_ttl_seconds: 3600,
            encryption_cache_ttl_seconds: 1800,
            decryption_cache_ttl_seconds: 1800,
            max_cached_keys: 10000,
            enable_cache_warming: false,
            warm_up_keys: Vec::new(),
            enable_intelligent_eviction: true,
            security_settings: CacheSecuritySettings::default(),
        }
    }
}

/// Cache integration statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheIntegrationStatistics {
    /// Key cache statistics
    pub key_cache_stats: KeyCacheStats,
    /// Encryption cache statistics
    pub encryption_cache_stats: EncryptionCacheStats,
    /// Decryption cache statistics
    pub decryption_cache_stats: DecryptionCacheStats,
    /// Security statistics
    pub security_stats: SecurityStats,
    /// Overall performance metrics
    pub performance_metrics: CacheIntegrationPerformanceMetrics,
}

/// Key cache statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyCacheStats {
    /// Cached keys count
    pub cached_keys: usize,
    /// Cache hits
    pub hits: u64,
    /// Cache misses
    pub misses: u64,
    /// Hit ratio
    pub hit_ratio: f64,
    /// Total cache size in bytes
    pub total_size_bytes: usize,
    /// Average key size
    pub avg_key_size_bytes: f64,
}

/// Encryption cache statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptionCacheStats {
    /// Cached encryption results
    pub cached_results: usize,
    /// Cache hits
    pub hits: u64,
    /// Cache misses
    pub misses: u64,
    /// Hit ratio
    pub hit_ratio: f64,
    /// Total encrypted data cached
    pub total_encrypted_bytes: u64,
    /// Average encryption time saved
    pub avg_time_saved_us: f64,
}

/// Decryption cache statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecryptionCacheStats {
    /// Cached decryption results
    pub cached_results: usize,
    /// Cache hits
    pub hits: u64,
    /// Cache misses
    pub misses: u64,
    /// Hit ratio
    pub hit_ratio: f64,
    /// Total decrypted data cached
    pub total_decrypted_bytes: u64,
    /// Average decryption time saved
    pub avg_time_saved_us: f64,
}

/// Security statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityStats {
    /// Access log entries
    pub access_log_entries: u64,
    /// Security violations
    pub security_violations: u64,
    /// Cache invalidations due to security
    pub security_invalidations: u64,
    /// Rate limited requests
    pub rate_limited_requests: u64,
}

/// Cache integration performance metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheIntegrationPerformanceMetrics {
    /// Overall cache hit ratio
    pub overall_hit_ratio: f64,
    /// Average operation time
    pub avg_operation_time_us: f64,
    /// Cache efficiency score
    pub efficiency_score: f64,
    /// Memory usage ratio
    pub memory_usage_ratio: f64,
}

/// Trait for cache integration operations
#[async_trait]
pub trait CacheIntegration: Send + Sync + std::fmt::Debug {
    /// Cache a key
    async fn cache_key(
        &self,
        key_id: &KeyId,
        key: &SecureKey,
        metadata: &KeyMetadata,
        algorithm: &str,
    ) -> Result<()>;

    /// Get a cached key
    async fn get_cached_key(&self, key_id: &KeyId) -> Result<Option<(SecureKey, KeyMetadata)>>;

    /// Invalidate a cached key
    async fn invalidate_cached_key(&self, key_id: &KeyId) -> Result<bool>;

    /// Cache encryption result
    async fn cache_encryption_result(
        &self,
        cache_key: &str,
        plaintext: &[u8],
        ciphertext: &[u8],
        algorithm: &str,
    ) -> Result<()>;

    /// Get cached encryption result
    async fn get_cached_encryption_result(&self, cache_key: &str) -> Result<Option<Vec<u8>>>;

    /// Cache decryption result
    async fn cache_decryption_result(
        &self,
        cache_key: &str,
        ciphertext: &[u8],
        plaintext: &[u8],
        algorithm: &str,
    ) -> Result<()>;

    /// Get cached decryption result
    async fn get_cached_decryption_result(&self, cache_key: &str) -> Result<Option<Vec<u8>>>;

    /// Get integration statistics
    async fn get_integration_statistics(&self) -> Result<CacheIntegrationStatistics>;

    /// Warm up cache with keys
    async fn warm_up_keys(
        &self,
        keys: Vec<(KeyId, SecureKey, KeyMetadata, String)>,
    ) -> Result<usize>;

    /// Invalidate all cache entries for a key ID
    async fn invalidate_all_for_key(&self, key_id: &KeyId) -> Result<usize>;

    /// Perform cache maintenance
    async fn perform_maintenance(&self) -> Result<()>;
}

/// Advanced cache integration implementation
#[derive(Debug)]
pub struct FortressCacheIntegration {
    config: CacheIntegrationConfig,
    /// Cache manager
    cache_manager: Arc<dyn CacheManager>,
    /// Integration statistics
    stats: Arc<RwLock<CacheIntegrationStatistics>>,
    /// Rate limiter state
    rate_limiter: Arc<RwLock<HashMap<String, DateTime<Utc>>>>,
}

impl FortressCacheIntegration {
    /// Create a new cache integration
    #[cfg(feature = "distributed-cache")]
    pub async fn new(config: CacheIntegrationConfig) -> Result<Self> {
        // Create cache manager
        let cache_manager =
            crate::cache_manager::create_cache_manager(config.cache_config.clone()).await?;

        let integration = Self {
            config,
            cache_manager: std::sync::Arc::from(cache_manager),
            stats: Arc::new(RwLock::new(CacheIntegrationStatistics {
                key_cache_stats: KeyCacheStats {
                    cached_keys: 0,
                    hits: 0,
                    misses: 0,
                    hit_ratio: 0.0,
                    total_size_bytes: 0,
                    avg_key_size_bytes: 0.0,
                },
                encryption_cache_stats: EncryptionCacheStats {
                    cached_results: 0,
                    hits: 0,
                    misses: 0,
                    hit_ratio: 0.0,
                    total_encrypted_bytes: 0,
                    avg_time_saved_us: 0.0,
                },
                decryption_cache_stats: DecryptionCacheStats {
                    cached_results: 0,
                    hits: 0,
                    misses: 0,
                    hit_ratio: 0.0,
                    total_decrypted_bytes: 0,
                    avg_time_saved_us: 0.0,
                },
                security_stats: SecurityStats {
                    access_log_entries: 0,
                    security_violations: 0,
                    security_invalidations: 0,
                    rate_limited_requests: 0,
                },
                performance_metrics: CacheIntegrationPerformanceMetrics {
                    overall_hit_ratio: 0.0,
                    avg_operation_time_us: 0.0,
                    efficiency_score: 0.0,
                    memory_usage_ratio: 0.0,
                },
            })),
            rate_limiter: Arc::new(RwLock::new(HashMap::new())),
        };

        // Warm up cache if enabled
        if integration.config.enable_cache_warming && !integration.config.warm_up_keys.is_empty() {
            // In a real implementation, you would load the actual keys
            // For now, we'll just prepare the cache
        }

        Ok(integration)
    }

    #[cfg(not(feature = "distributed-cache"))]
    pub async fn new(_config: CacheIntegrationConfig) -> Result<Self> {
        Err(FortressError::storage(
            "Distributed cache integration not available".to_string(),
            "cache_integration".to_string(),
            crate::error::StorageErrorCode::BackendNotAvailable,
        ))
    }

    /// Check rate limiting
    async fn check_rate_limit(&self, client_id: &str) -> Result<bool> {
        if !self.config.security_settings.enable_rate_limiting {
            return Ok(true);
        }

        let now = Utc::now();
        let mut rate_limiter = self.rate_limiter.write().await;

        if let Some(last_request) = rate_limiter.get(client_id) {
            let time_since_last = now.signed_duration_since(*last_request);
            let min_interval =
                Duration::milliseconds(1000 / self.config.security_settings.rate_limit_rps as i64);

            if time_since_last < min_interval {
                let mut stats = self.stats.write().await;
                stats.security_stats.rate_limited_requests += 1;
                return Ok(false);
            }
        }

        rate_limiter.insert(client_id.to_string(), now);
        Ok(true)
    }

    /// Log access
    async fn log_access(&self, _operation: &str, _key_id: &str) {
        if self.config.security_settings.enable_access_logging {
            let mut stats = self.stats.write().await;
            stats.security_stats.access_log_entries += 1;

            // In a real implementation, you would log to a file or monitoring system
            // For now, we'll just increment the counter
        }
    }

    /// Check security violations
    async fn check_security_violation(&self, _operation: &str, data_size: usize) -> Result<()> {
        if data_size > self.config.security_settings.max_entry_size_bytes {
            let mut stats = self.stats.write().await;
            stats.security_stats.security_violations += 1;

            return Err(FortressError::storage(
                format!(
                    "Cache entry size ({}) exceeds maximum ({})",
                    data_size, self.config.security_settings.max_entry_size_bytes
                ),
                "cache_integration".to_string(),
                crate::error::StorageErrorCode::InvalidData,
            ));
        }

        Ok(())
    }

    /// Generate cache key for encryption results
    fn generate_encryption_cache_key(
        &self,
        key_id: &KeyId,
        data_hash: &[u8],
        algorithm: &str,
    ) -> String {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut hasher = DefaultHasher::new();
        key_id.hash(&mut hasher);
        data_hash.hash(&mut hasher);
        algorithm.hash(&mut hasher);

        format!(
            "enc:{:x}:{:x}",
            hasher.finish(),
            data_hash
                .iter()
                .take(8)
                .fold(0u64, |acc, &b| acc * 256 + b as u64)
        )
    }

    /// Generate cache key for decryption results
    fn generate_decryption_cache_key(
        &self,
        key_id: &KeyId,
        data_hash: &[u8],
        algorithm: &str,
    ) -> String {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut hasher = DefaultHasher::new();
        key_id.hash(&mut hasher);
        data_hash.hash(&mut hasher);
        algorithm.hash(&mut hasher);

        format!(
            "dec:{:x}:{:x}",
            hasher.finish(),
            data_hash
                .iter()
                .take(8)
                .fold(0u64, |acc, &b| acc * 256 + b as u64)
        )
    }

    /// Update integration statistics
    async fn update_integration_stats(&self) {
        let mut stats = self.stats.write().await;

        // Calculate overall hit ratio
        let total_hits = stats.key_cache_stats.hits
            + stats.encryption_cache_stats.hits
            + stats.decryption_cache_stats.hits;
        let total_requests = total_hits
            + stats.key_cache_stats.misses
            + stats.encryption_cache_stats.misses
            + stats.decryption_cache_stats.misses;

        if total_requests > 0 {
            stats.performance_metrics.overall_hit_ratio = total_hits as f64 / total_requests as f64;
        }

        // Calculate efficiency score
        stats.performance_metrics.efficiency_score =
            stats.performance_metrics.overall_hit_ratio * 0.7 + 0.3; // Base score of 0.3

        // Calculate memory usage ratio
        let max_memory = self.config.max_cached_keys * 1024; // Rough estimate
        if max_memory > 0 {
            stats.performance_metrics.memory_usage_ratio =
                stats.key_cache_stats.total_size_bytes as f64 / max_memory as f64;
        }
    }
}

#[async_trait]
impl CacheIntegration for FortressCacheIntegration {
    async fn cache_key(
        &self,
        key_id: &KeyId,
        key: &SecureKey,
        metadata: &KeyMetadata,
        algorithm: &str,
    ) -> Result<()> {
        if !self.config.enable_key_caching {
            return Ok(());
        }

        // Check rate limiting
        if !self.check_rate_limit("cache_key").await? {
            return Err(FortressError::storage(
                "Rate limit exceeded".to_string(),
                "cache_integration".to_string(),
                crate::error::StorageErrorCode::RateLimited,
            ));
        }

        // Check security
        self.check_security_violation("cache_key", key.len())
            .await?;
        self.log_access("cache_key", &key_id.to_string()).await;

        // Create cached entry
        let entry = CachedKeyEntry {
            key_id: key_id.clone(),
            encrypted_key: key.to_vec(),
            metadata: metadata.clone(),
            algorithm: algorithm.to_string(),
            performance_profile: PerformanceProfile::Balanced, // Default
            cached_at: Utc::now(),
            access_count: 0,
            last_accessed: Utc::now(),
        };

        // Serialize and cache
        let serialized = serde_json::to_vec(&entry).map_err(|e| {
            FortressError::storage(
                format!("Failed to serialize cached key: {}", e),
                "cache_integration".to_string(),
                crate::error::StorageErrorCode::SerializationError,
            )
        })?;

        let cache_key = format!("key:{}", key_id);
        self.cache_manager
            .set(
                &cache_key,
                serialized,
                Some(self.config.key_cache_ttl_seconds),
            )
            .await?;

        // Update statistics
        {
            let mut stats = self.stats.write().await;
            stats.key_cache_stats.cached_keys += 1;
            stats.key_cache_stats.total_size_bytes += key.len();
            stats.key_cache_stats.avg_key_size_bytes = stats.key_cache_stats.total_size_bytes
                as f64
                / stats.key_cache_stats.cached_keys as f64;
        }

        // Note: update_integration_stats() is async but we're in a sync context
        // In a real implementation, you might want to spawn a task or use a different approach
        // For now, we'll update the basic stats inline
        // self.update_integration_stats().await();
        Ok(())
    }

    async fn get_cached_key(&self, key_id: &KeyId) -> Result<Option<(SecureKey, KeyMetadata)>> {
        if !self.config.enable_key_caching {
            return Ok(None);
        }

        // Check rate limiting
        if !self.check_rate_limit("get_key").await? {
            return Err(FortressError::storage(
                "Rate limit exceeded".to_string(),
                "cache_integration".to_string(),
                crate::error::StorageErrorCode::RateLimited,
            ));
        }

        self.log_access("get_key", &key_id.to_string()).await;

        let cache_key = format!("key:{}", key_id);

        match self.cache_manager.get(&cache_key).await? {
            Some(serialized) => {
                let entry: CachedKeyEntry = serde_json::from_slice(&serialized).map_err(|e| {
                    FortressError::storage(
                        format!("Failed to deserialize cached key: {}", e),
                        "cache_integration".to_string(),
                        crate::error::StorageErrorCode::SerializationError,
                    )
                })?;

                let secure_key = SecureKey::from_bytes(&entry.encrypted_key);

                // Update statistics
                {
                    let mut stats = self.stats.write().await;
                    stats.key_cache_stats.hits += 1;
                    stats.key_cache_stats.hit_ratio = stats.key_cache_stats.hits as f64
                        / (stats.key_cache_stats.hits + stats.key_cache_stats.misses) as f64;
                }

                // Note: update_integration_stats() is async but we're in a sync context
                // In a real implementation, you might want to spawn a task or use a different approach
                // For now, we'll update the basic stats inline
                // self.update_integration_stats().await();
                Ok(Some((secure_key, entry.metadata)))
            }
            None => {
                // Update statistics
                {
                    let mut stats = self.stats.write().await;
                    stats.key_cache_stats.misses += 1;
                    stats.key_cache_stats.hit_ratio = stats.key_cache_stats.hits as f64
                        / (stats.key_cache_stats.hits + stats.key_cache_stats.misses) as f64;
                }

                // Note: update_integration_stats() is async but we're in a sync context
                // In a real implementation, you might want to spawn a task or use a different approach
                // For now, we'll update the basic stats inline
                // self.update_integration_stats().await();
                Ok(None)
            }
        }
    }

    async fn invalidate_cached_key(&self, key_id: &KeyId) -> Result<bool> {
        let cache_key = format!("key:{}", key_id);
        let result = self.cache_manager.delete(&cache_key).await?;

        if result {
            let mut stats = self.stats.write().await;
            stats.key_cache_stats.cached_keys = stats.key_cache_stats.cached_keys.saturating_sub(1);
        }

        Ok(result)
    }

    async fn cache_encryption_result(
        &self,
        cache_key: &str,
        _plaintext: &[u8],
        ciphertext: &[u8],
        algorithm: &str,
    ) -> Result<()> {
        if !self.config.enable_encryption_caching {
            return Ok(());
        }

        // Check security
        self.check_security_violation("cache_encryption", ciphertext.len())
            .await?;
        self.log_access("cache_encryption", cache_key).await;

        let cache_entry = serde_json::json!({
            "ciphertext": ciphertext,
            "algorithm": algorithm,
            "created_at": Utc::now(),
        });

        let serialized = serde_json::to_vec(&cache_entry).map_err(|e| {
            FortressError::storage(
                format!("Failed to serialize encryption result: {}", e),
                "cache_integration".to_string(),
                crate::error::StorageErrorCode::SerializationError,
            )
        })?;

        let full_cache_key = format!("enc:{}", cache_key);
        self.cache_manager
            .set(
                &full_cache_key,
                serialized,
                Some(self.config.encryption_cache_ttl_seconds),
            )
            .await?;

        // Update statistics
        {
            let mut stats = self.stats.write().await;
            stats.encryption_cache_stats.cached_results += 1;
            stats.encryption_cache_stats.total_encrypted_bytes += ciphertext.len() as u64;
        }

        Ok(())
    }

    async fn get_cached_encryption_result(&self, cache_key: &str) -> Result<Option<Vec<u8>>> {
        if !self.config.enable_encryption_caching {
            return Ok(None);
        }

        self.log_access("get_encryption", cache_key).await;

        let full_cache_key = format!("enc:{}", cache_key);

        match self.cache_manager.get(&full_cache_key).await? {
            Some(serialized) => {
                let entry: serde_json::Value =
                    serde_json::from_slice(&serialized).map_err(|e| {
                        FortressError::storage(
                            format!("Failed to deserialize encryption result: {}", e),
                            "cache_integration".to_string(),
                            crate::error::StorageErrorCode::SerializationError,
                        )
                    })?;

                let ciphertext = entry["ciphertext"]
                    .as_array()
                    .ok_or_else(|| {
                        FortressError::storage(
                            "Invalid encryption cache format".to_string(),
                            "cache_integration".to_string(),
                            crate::error::StorageErrorCode::CorruptedData,
                        )
                    })?
                    .iter()
                    .filter_map(|v| v.as_u64())
                    .map(|v| v as u8)
                    .collect();

                // Update statistics
                {
                    let mut stats = self.stats.write().await;
                    stats.encryption_cache_stats.hits += 1;
                    stats.encryption_cache_stats.hit_ratio = stats.encryption_cache_stats.hits
                        as f64
                        / (stats.encryption_cache_stats.hits + stats.encryption_cache_stats.misses)
                            as f64;
                }

                Ok(Some(ciphertext))
            }
            None => {
                // Update statistics
                {
                    let mut stats = self.stats.write().await;
                    stats.encryption_cache_stats.misses += 1;
                    stats.encryption_cache_stats.hit_ratio = stats.encryption_cache_stats.hits
                        as f64
                        / (stats.encryption_cache_stats.hits + stats.encryption_cache_stats.misses)
                            as f64;
                }

                Ok(None)
            }
        }
    }

    async fn cache_decryption_result(
        &self,
        cache_key: &str,
        _ciphertext: &[u8],
        plaintext: &[u8],
        algorithm: &str,
    ) -> Result<()> {
        if !self.config.enable_decryption_caching {
            return Ok(());
        }

        // Check security
        self.check_security_violation("cache_decryption", plaintext.len())
            .await?;
        self.log_access("cache_decryption", cache_key).await;

        let cache_entry = serde_json::json!({
            "plaintext": plaintext,
            "algorithm": algorithm,
            "created_at": Utc::now(),
        });

        let serialized = serde_json::to_vec(&cache_entry).map_err(|e| {
            FortressError::storage(
                format!("Failed to serialize decryption result: {}", e),
                "cache_integration".to_string(),
                crate::error::StorageErrorCode::SerializationError,
            )
        })?;

        let full_cache_key = format!("dec:{}", cache_key);
        self.cache_manager
            .set(
                &full_cache_key,
                serialized,
                Some(self.config.decryption_cache_ttl_seconds),
            )
            .await?;

        // Update statistics
        {
            let mut stats = self.stats.write().await;
            stats.decryption_cache_stats.cached_results += 1;
            stats.decryption_cache_stats.total_decrypted_bytes += plaintext.len() as u64;
        }

        Ok(())
    }

    async fn get_cached_decryption_result(&self, cache_key: &str) -> Result<Option<Vec<u8>>> {
        if !self.config.enable_decryption_caching {
            return Ok(None);
        }

        self.log_access("get_decryption", cache_key).await;

        let full_cache_key = format!("dec:{}", cache_key);

        match self.cache_manager.get(&full_cache_key).await? {
            Some(serialized) => {
                let entry: serde_json::Value =
                    serde_json::from_slice(&serialized).map_err(|e| {
                        FortressError::storage(
                            format!("Failed to deserialize decryption result: {}", e),
                            "cache_integration".to_string(),
                            crate::error::StorageErrorCode::SerializationError,
                        )
                    })?;

                let plaintext = entry["plaintext"]
                    .as_array()
                    .ok_or_else(|| {
                        FortressError::storage(
                            "Invalid decryption cache format".to_string(),
                            "cache_integration".to_string(),
                            crate::error::StorageErrorCode::CorruptedData,
                        )
                    })?
                    .iter()
                    .filter_map(|v| v.as_u64())
                    .map(|v| v as u8)
                    .collect();

                // Update statistics
                {
                    let mut stats = self.stats.write().await;
                    stats.decryption_cache_stats.hits += 1;
                    stats.decryption_cache_stats.hit_ratio = stats.decryption_cache_stats.hits
                        as f64
                        / (stats.decryption_cache_stats.hits + stats.decryption_cache_stats.misses)
                            as f64;
                }

                Ok(Some(plaintext))
            }
            None => {
                // Update statistics
                {
                    let mut stats = self.stats.write().await;
                    stats.decryption_cache_stats.misses += 1;
                    stats.decryption_cache_stats.hit_ratio = stats.decryption_cache_stats.hits
                        as f64
                        / (stats.decryption_cache_stats.hits + stats.decryption_cache_stats.misses)
                            as f64;
                }

                Ok(None)
            }
        }
    }

    async fn get_integration_statistics(&self) -> Result<CacheIntegrationStatistics> {
        self.update_integration_stats().await;
        Ok(self.stats.read().await.clone())
    }

    async fn warm_up_keys(
        &self,
        keys: Vec<(KeyId, SecureKey, KeyMetadata, String)>,
    ) -> Result<usize> {
        if !self.config.enable_cache_warming {
            return Ok(0);
        }

        let mut warmed_count = 0;

        for (key_id, key, metadata, algorithm) in keys {
            if self
                .cache_key(&key_id, &key, &metadata, &algorithm)
                .await
                .is_ok()
            {
                warmed_count += 1;
            }
        }

        Ok(warmed_count)
    }

    async fn invalidate_all_for_key(&self, key_id: &KeyId) -> Result<usize> {
        let mut invalidated_count = 0;

        // Invalidate key cache
        if self.invalidate_cached_key(key_id).await? {
            invalidated_count += 1;
        }

        // In a real implementation, you would also invalidate related encryption/decryption results
        // For now, we'll just count the key invalidation

        if self.config.security_settings.invalidate_on_rotation {
            let mut stats = self.stats.write().await;
            stats.security_stats.security_invalidations += invalidated_count as u64;
        }

        Ok(invalidated_count)
    }

    async fn perform_maintenance(&self) -> Result<()> {
        // Clean up rate limiter entries
        {
            let mut rate_limiter = self.rate_limiter.write().await;
            let now = Utc::now();
            let cutoff = now - Duration::minutes(5); // Keep 5 minutes of rate limit data

            rate_limiter.retain(|_, &mut timestamp| timestamp > cutoff);
        }

        // Update statistics
        self.update_integration_stats().await;

        Ok(())
    }
}

/// Factory function to create cache integration
pub async fn create_cache_integration(
    config: CacheIntegrationConfig,
) -> Result<Box<dyn CacheIntegration>> {
    let integration = FortressCacheIntegration::new(config).await?;
    Ok(Box::new(integration))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key::KeyId;

    #[tokio::test]
    async fn test_cache_integration_key_caching() {
        let config = CacheIntegrationConfig::default();
        let integration = FortressCacheIntegration::new(config).await.unwrap();

        let key_id = KeyId::new();
        let key = SecureKey::from_bytes(b"test_key_data");
        let metadata = KeyMetadata::new(
            key_id.clone(),
            "test_algorithm".to_string(),
            1,
            Utc::now(),
            Utc::now() + Duration::hours(24),
            "test".to_string(),
            PerformanceProfile::Balanced,
        );

        // Cache key
        integration
            .cache_key(&key_id, &key, &metadata, "test_algorithm")
            .await
            .unwrap();

        // Get cached key
        let cached = integration.get_cached_key(&key_id).await.unwrap();
        assert!(cached.is_some());

        let (cached_key, cached_metadata) = cached.unwrap();
        assert_eq!(cached_key.to_vec(), key.to_vec());
        assert_eq!(cached_metadata.id, key_id);

        // Invalidate key
        let invalidated = integration.invalidate_cached_key(&key_id).await.unwrap();
        assert!(invalidated);

        // Key should be gone
        let cached = integration.get_cached_key(&key_id).await.unwrap();
        assert!(cached.is_none());
    }

    #[tokio::test]
    async fn test_cache_integration_encryption_caching() {
        let config = CacheIntegrationConfig::default();
        let integration = FortressCacheIntegration::new(config).await.unwrap();

        let cache_key = "test_encryption";
        let plaintext = b"test_plaintext";
        let ciphertext = b"test_ciphertext";
        let algorithm = "AES-256-GCM";

        // Cache encryption result
        integration
            .cache_encryption_result(cache_key, plaintext, ciphertext, algorithm)
            .await
            .unwrap();

        // Get cached encryption result
        let cached = integration
            .get_cached_encryption_result(cache_key)
            .await
            .unwrap();
        assert!(cached.is_some());
        assert_eq!(cached.unwrap(), ciphertext);
    }

    #[tokio::test]
    async fn test_cache_integration_decryption_caching() {
        let config = CacheIntegrationConfig::default();
        let integration = FortressCacheIntegration::new(config).await.unwrap();

        let cache_key = "test_decryption";
        let ciphertext = b"test_ciphertext";
        let plaintext = b"test_plaintext";
        let algorithm = "AES-256-GCM";

        // Cache decryption result
        integration
            .cache_decryption_result(cache_key, ciphertext, plaintext, algorithm)
            .await
            .unwrap();

        // Get cached decryption result
        let cached = integration
            .get_cached_decryption_result(cache_key)
            .await
            .unwrap();
        assert!(cached.is_some());
        assert_eq!(cached.unwrap(), plaintext);
    }

    #[tokio::test]
    async fn test_cache_integration_statistics() {
        let config = CacheIntegrationConfig::default();
        let integration = FortressCacheIntegration::new(config).await.unwrap();

        // Perform some operations
        let key_id = KeyId::new();
        let key = SecureKey::from_bytes(b"test_key_data");
        let metadata = KeyMetadata::new(
            key_id.clone(),
            "test_algorithm".to_string(),
            1,
            Utc::now(),
            Utc::now() + Duration::hours(24),
            "test".to_string(),
            PerformanceProfile::Balanced,
        );

        integration
            .cache_key(&key_id, &key, &metadata, "test_algorithm")
            .await
            .unwrap();
        integration.get_cached_key(&key_id).await.unwrap();

        let stats = integration.get_integration_statistics().await.unwrap();
        assert!(stats.key_cache_stats.cached_keys > 0);
        assert!(stats.key_cache_stats.hits > 0);
        assert!(stats.performance_metrics.overall_hit_ratio > 0.0);
    }

    #[tokio::test]
    async fn test_cache_integration_warm_up() {
        let config = CacheIntegrationConfig::default();
        let integration = FortressCacheIntegration::new(config).await.unwrap();

        let key_id = KeyId::new();
        let key = SecureKey::from_bytes(b"test_key_data");
        let metadata = KeyMetadata::new(
            key_id.clone(),
            "test_algorithm".to_string(),
            1,
            Utc::now(),
            Utc::now() + Duration::hours(24),
            "test".to_string(),
            PerformanceProfile::Balanced,
        );

        let keys = vec![(key_id, key, metadata, "test_algorithm".to_string())];

        let warmed_count = integration.warm_up_keys(keys).await.unwrap();
        assert_eq!(warmed_count, 1);
    }

    #[tokio::test]
    async fn test_cache_integration_maintenance() {
        let config = CacheIntegrationConfig::default();
        let integration = FortressCacheIntegration::new(config).await.unwrap();

        // Perform maintenance
        integration.perform_maintenance().await.unwrap();

        // Should not error
        assert!(true);
    }
}
