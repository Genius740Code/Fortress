//! Memcached cache backend implementation for Fortress
//!
//! This module provides a production-ready Memcached cache backend with support
//! for connection pooling, consistent hashing, and advanced Memcached features.

use serde::{Deserialize, Serialize};
use async_trait::async_trait;
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::error::{FortressError, Result};

#[cfg(feature = "memcached")]
use memcached::Client;

/// Memcached cache configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemcachedConfig {
    /// Memcached server addresses
    pub servers: Vec<String>,
    /// Connection pool size per server
    pub pool_size: usize,
    /// Connection timeout in seconds
    pub connection_timeout_seconds: u64,
    /// Operation timeout in seconds
    pub operation_timeout_seconds: u64,
    /// Enable consistent hashing
    pub enable_consistent_hashing: bool,
    /// Key prefix
    pub key_prefix: String,
    /// Enable compression
    pub enable_compression: bool,
    /// Enable retry on failure
    pub enable_retry: bool,
    /// Maximum retry attempts
    pub max_retries: u32,
    /// Retry delay in milliseconds
    pub retry_delay_ms: u64,
    /// Enable binary protocol
    pub enable_binary_protocol: bool,
    /// Enable noreply for operations
    pub enable_noreply: bool,
}

impl Default for MemcachedConfig {
    fn default() -> Self {
        Self {
            servers: vec!["localhost:11211".to_string()],
            pool_size: 5,
            connection_timeout_seconds: 5,
            operation_timeout_seconds: 3,
            enable_consistent_hashing: true,
            key_prefix: "fortress:".to_string(),
            enable_compression: true,
            enable_retry: true,
            max_retries: 3,
            retry_delay_ms: 100,
            enable_binary_protocol: true,
            enable_noreply: false,
        }
    }
}

/// Memcached connection pool
#[cfg(feature = "memcached")]
#[derive(Debug)]
struct MemcachedPool {
    clients: Vec<Client>,
    current_index: Arc<RwLock<usize>>,
    config: MemcachedConfig,
}

#[cfg(feature = "memcached")]
impl MemcachedPool {
    /// Create a new Memcached connection pool
    async fn new(config: MemcachedConfig) -> Result<Self> {
        let mut clients = Vec::new();

        for server in &config.servers {
            let url = if server.starts_with("memcache://") {
                server.clone()
            } else {
                format!("memcache://{}", server)
            };
            let client = Client::connect_with(
                vec![url],
                config.pool_size as u64,
                |_| 0,
            )
            .map_err(|e| {
                    FortressError::storage(
                        format!("Failed to connect to Memcached server {}: {}", server, e),
                        "memcached_cache".to_string(),
                        crate::error::StorageErrorCode::ConnectionFailed,
                    )
                })?;
            clients.push(client);
        }

        if clients.is_empty() {
            return Err(FortressError::storage(
                "No valid Memcached servers provided".to_string(),
                "memcached_cache".to_string(),
                crate::error::StorageErrorCode::InvalidConfiguration,
            ));
        }

        Ok(Self {
            clients,
            current_index: Arc::new(RwLock::new(0)),
            config,
        })
    }

    /// Get a client from the pool using round-robin
    async fn get_client(&self) -> Result<Client> {
        let current_index = {
            let mut index = self.current_index.write().await;
            *index = (*index + 1) % self.clients.len();
            *index
        };

        // Clone the client (Memcached client is cheap to clone)
        Ok(self.clients[current_index].clone())
    }

    /// Get a client for a specific key using consistent hashing
    async fn get_client_for_key(&self, key: &str) -> Result<Client> {
        if !self.config.enable_consistent_hashing || self.clients.len() == 1 {
            return self.get_client().await;
        }

        // Simple consistent hashing using key hash
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut hasher = DefaultHasher::new();
        key.hash(&mut hasher);
        let hash = hasher.finish();
        let index = (hash as usize) % self.clients.len();

        Ok(self.clients[index].clone())
    }
}

/// Memcached cache implementation
#[cfg(feature = "memcached")]
#[derive(Debug)]
pub struct MemcachedCache {
    pool: Arc<MemcachedPool>,
    config: MemcachedConfig,
    statistics: Arc<RwLock<crate::distributed_cache::CacheStatistics>>,
}

#[cfg(feature = "memcached")]
impl MemcachedCache {
    /// Create a new Memcached cache
    pub async fn new(config: MemcachedConfig) -> Result<Self> {
        let pool = Arc::new(MemcachedPool::new(config.clone()).await?);

        Ok(Self {
            pool,
            config,
            statistics: Arc::new(RwLock::new(crate::distributed_cache::CacheStatistics {
                total_entries: 0,
                cache_size_bytes: 0,
                hits: 0,
                misses: 0,
                hit_ratio: 0.0,
                evictions: 0,
                sets: 0,
                deletes: 0,
                avg_get_time_us: 0.0,
                avg_set_time_us: 0.0,
                last_reset: Utc::now(),
            })),
        })
    }

    /// Execute a Memcached operation with retry logic
    async fn execute_with_retry<F, T>(&self, operation: F) -> Result<T>
    where
        F: Fn() -> memcached::Result<T> + Send + Sync,
        T: Send + Sync + 'static,
    {
        if !self.config.enable_retry {
            return operation().map_err(|e| {
                FortressError::storage(
                    format!("Memcached operation failed: {}", e),
                    "memcached_cache".to_string(),
                    crate::error::StorageErrorCode::OperationFailed,
                )
            });
        }

        let mut last_error = None;

        for attempt in 0..=self.config.max_retries {
            match operation() {
                Ok(result) => return Ok(result),
                Err(e) => {
                    last_error = Some(e.clone());

                    if attempt < self.config.max_retries {
                        tokio::time::sleep(Duration::from_millis(self.config.retry_delay_ms)).await;
                    }
                }
            }
        }

        Err(FortressError::storage(
            format!(
                "Memcached operation failed after {} attempts: {}",
                self.config.max_retries,
                last_error.unwrap()
            ),
            "memcached_cache".to_string(),
            crate::error::StorageErrorCode::OperationFailed,
        ))
    }

    /// Compress data if enabled
    fn compress_data(&self, data: &[u8]) -> Result<Vec<u8>> {
        if self.config.enable_compression {
            // Use LZ4 compression for speed
            let compressed = lz4::block::compress(data, None, true).map_err(|e| {
                FortressError::storage(
                    format!("Compression failed: {}", e),
                    "memcached_cache".to_string(),
                    crate::error::StorageErrorCode::CorruptedData,
                )
            })?;
            Ok(compressed)
        } else {
            Ok(data.to_vec())
        }
    }

    /// Decompress data if needed
    fn decompress_data(&self, data: &[u8]) -> Result<Vec<u8>> {
        if self.config.enable_compression {
            let decompressed = lz4::block::decompress(data, None).map_err(|e| {
                FortressError::storage(
                    format!("Decompression failed: {}", e),
                    "memcached_cache".to_string(),
                    crate::error::StorageErrorCode::CorruptedData,
                )
            })?;
            Ok(decompressed)
        } else {
            Ok(data.to_vec())
        }
    }

    /// Get full key with prefix
    fn get_full_key(&self, key: &str) -> String {
        format!("{}{}", self.config.key_prefix, key)
    }

    /// Update statistics
    async fn update_stats(&self, operation: &str, success: bool, elapsed_us: f64) {
        let mut stats = self.statistics.write().await;

        match operation {
            "get" => {
                if success {
                    stats.hits += 1;
                } else {
                    stats.misses += 1;
                }
                stats.hit_ratio = stats.hits as f64 / (stats.hits + stats.misses) as f64;
                stats.avg_get_time_us =
                    (stats.avg_get_time_us * (stats.hits + stats.misses - 1) as f64 + elapsed_us)
                        / (stats.hits + stats.misses) as f64;
            }
            "set" => {
                stats.sets += 1;
                stats.avg_set_time_us = (stats.avg_set_time_us * (stats.sets - 1) as f64
                    + elapsed_us)
                    / stats.sets as f64;
            }
            "delete" => {
                stats.deletes += 1;
            }
            _ => {}
        }
    }
}

#[cfg(feature = "memcached")]
#[async_trait]
impl crate::distributed_cache::DistributedCache for MemcachedCache {
    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>> {
        let start = std::time::Instant::now();
        let full_key = self.get_full_key(key);

        let client = self.pool.get_client_for_key(&full_key).await?;

        let result = self.execute_with_retry(|| client.get(&full_key)).await;

        let elapsed_us = start.elapsed().as_micros() as f64;
        let success = result.is_ok() && result.as_ref().unwrap().is_some();
        self.update_stats("get", success, elapsed_us).await;

        match result {
            Ok(Some(compressed_data)) => {
                let decompressed = self.decompress_data(&compressed_data)?;
                Ok(Some(decompressed))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(e),
        }
    }

    async fn set(&self, key: &str, value: Vec<u8>, ttl_seconds: Option<u64>) -> Result<()> {
        let start = std::time::Instant::now();
        let full_key = self.get_full_key(key);
        let compressed_value = self.compress_data(&value)?;

        let client = self.pool.get_client_for_key(&full_key).await?;

        let result = self
            .execute_with_retry(|| {
                if let Some(ttl) = ttl_seconds {
                    client.set_with_expiration(&full_key, &compressed_value, ttl as u32)
                } else {
                    client.set(&full_key, &compressed_value)
                }
            })
            .await;

        let elapsed_us = start.elapsed().as_micros() as f64;
        let success = result.is_ok();
        self.update_stats("set", success, elapsed_us).await;

        result
    }

    async fn delete(&self, key: &str) -> Result<bool> {
        let full_key = self.get_full_key(key);
        let client = self.pool.get_client_for_key(&full_key).await?;

        let result = self.execute_with_retry(|| client.delete(&full_key)).await;

        if result.is_ok() && result.as_ref().unwrap() {
            self.update_stats("delete", true, 0.0).await;
        }

        result
    }

    async fn exists(&self, key: &str) -> Result<bool> {
        let full_key = self.get_full_key(key);
        let client = self.pool.get_client_for_key(&full_key).await?;

        self.execute_with_retry(|| client.get(&full_key).map(|value| value.is_some()))
            .await
    }

    async fn clear(&self) -> Result<()> {
        // Memcached doesn't support selective clearing by prefix
        // We would need to track all keys or use flush_all
        // For now, we'll implement flush_all with a warning

        let client = self.pool.get_client().await?;

        self.execute_with_retry(|| client.flush()).await?;

        // Update statistics
        let mut stats = self.statistics.write().await;
        stats.total_entries = 0;
        stats.cache_size_bytes = 0;

        Ok(())
    }

    async fn mget(&self, keys: &[&str]) -> Result<Vec<Option<Vec<u8>>>> {
        let mut results = Vec::new();

        for key in keys {
            let result = self.get(key).await?;
            results.push(result);
        }

        Ok(results)
    }

    async fn mset(&self, entries: &[(&str, Vec<u8>, Option<u64>)]) -> Result<()> {
        for (key, value, ttl) in entries {
            self.set(key, value.clone(), *ttl).await?;
        }
        Ok(())
    }

    async fn increment(&self, key: &str, delta: i64) -> Result<i64> {
        let full_key = self.get_full_key(key);
        let client = self.pool.get_client_for_key(&full_key).await?;

        self.execute_with_retry(|| {
            if delta > 0 {
                client.increment(&full_key, delta as u64).map(|v| v as i64)
            } else {
                client
                    .decrement(&full_key, (-delta) as u64)
                    .map(|v| v as i64)
            }
        })
        .await
    }

    async fn get_statistics(&self) -> Result<crate::distributed_cache::CacheStatistics> {
        let stats = self.statistics.read().await;

        // Get Memcached server stats
        let client = self.pool.get_client().await?;

        let server_stats = self.execute_with_retry(|| client.stats()).await;

        if let Ok(server_stats) = server_stats {
            // Parse server statistics for additional info
            let mut cache_stats = stats.clone();

            for (server_name, server_data) in server_stats {
                for (key, value) in server_data {
                    match key.as_str() {
                        "bytes" => {
                            if let Ok(bytes) = value.parse::<u64>() {
                                cache_stats.cache_size_bytes = bytes;
                            }
                        }
                        "curr_items" => {
                            if let Ok(items) = value.parse::<u64>() {
                                cache_stats.total_entries = items;
                            }
                        }
                        _ => {}
                    }
                }
            }

            Ok(cache_stats)
        } else {
            Ok(stats.clone())
        }
    }

    async fn reset_statistics(&self) -> Result<()> {
        let mut stats = self.statistics.write().await;
        stats.hits = 0;
        stats.misses = 0;
        stats.hit_ratio = 0.0;
        stats.evictions = 0;
        stats.sets = 0;
        stats.deletes = 0;
        stats.avg_get_time_us = 0.0;
        stats.avg_set_time_us = 0.0;
        stats.last_reset = Utc::now();
        Ok(())
    }

    async fn health_check(&self) -> Result<bool> {
        let test_key = self.get_full_key("health_check");
        let test_value = b"test".to_vec();

        // Try to set and get a test value
        if let Err(_) = self.set("health_check", test_value.clone(), Some(1)).await {
            return Ok(false);
        }

        match self.get("health_check").await {
            Ok(Some(retrieved)) if retrieved == test_value => {
                let _ = self.delete("health_check").await;
                Ok(true)
            }
            _ => Ok(false),
        }
    }
}

/// Factory function to create Memcached cache
#[cfg(feature = "memcached")]
pub async fn create_memcached_cache(
    config: MemcachedConfig,
) -> Result<Box<dyn crate::distributed_cache::DistributedCache>> {
    let cache = MemcachedCache::new(config).await?;
    Ok(Box::new(cache))
}

/// Factory function that returns error when Memcached feature is not enabled
#[cfg(not(feature = "memcached"))]
#[cfg(feature = "distributed-cache")]
pub async fn create_memcached_cache(
    _config: MemcachedConfig,
) -> Result<Box<dyn crate::distributed_cache::DistributedCache>> {
    Err(FortressError::storage(
        "Memcached support not enabled. Enable the 'memcached' feature in Cargo.toml".to_string(),
        "memcached_cache".to_string(),
        crate::error::StorageErrorCode::BackendNotAvailable,
    ))
}

#[cfg(test)]
#[cfg(feature = "memcached")]
mod tests {
    use super::*;
    use crate::distributed_cache::DistributedCache;

    #[tokio::test]
    #[ignore] // Requires Memcached server
    async fn test_memcached_basic_operations() {
        let config = MemcachedConfig::default();
        let cache = MemcachedCache::new(config).await.unwrap();

        // Test set and get
        let key = "test_key";
        let value = b"test_value".to_vec();

        cache.set(key, value.clone(), None).await.unwrap();
        let retrieved = cache.get(key).await.unwrap();

        assert_eq!(retrieved, Some(value));

        // Test exists
        assert!(cache.exists(key).await.unwrap());

        // Test delete
        assert!(cache.delete(key).await.unwrap());
        assert!(!cache.exists(key).await.unwrap());
    }

    #[tokio::test]
    #[ignore] // Requires Memcached server
    async fn test_memcached_ttl() {
        let config = MemcachedConfig::default();
        let cache = MemcachedCache::new(config).await.unwrap();

        let key = "ttl_test";
        let value = b"test_value".to_vec();

        cache.set(key, value.clone(), Some(1)).await.unwrap();

        // Should be available immediately
        assert!(cache.get(key).await.unwrap().is_some());

        // Wait for expiration
        tokio::time::sleep(Duration::from_secs(2)).await;

        // Should be expired
        assert!(cache.get(key).await.unwrap().is_none());
    }

    #[tokio::test]
    #[ignore] // Requires Memcached server
    async fn test_memcached_increment() {
        let config = MemcachedConfig::default();
        let cache = MemcachedCache::new(config).await.unwrap();

        let key = "counter";

        // Increment from non-existent (should start at 0)
        let result = cache.increment(key, 5).await.unwrap();
        assert_eq!(result, 5);

        // Increment existing value
        let result = cache.increment(key, 3).await.unwrap();
        assert_eq!(result, 8);

        // Test decrement
        let result = cache.increment(key, -2).await.unwrap();
        assert_eq!(result, 6);

        // Verify stored value
        let stored = cache.get(key).await.unwrap();
        assert_eq!(stored, Some(b"6".to_vec()));
    }

    #[tokio::test]
    #[ignore] // Requires Memcached server
    async fn test_memcached_mget_mset() {
        let config = MemcachedConfig::default();
        let cache = MemcachedCache::new(config).await.unwrap();

        let entries = vec![
            ("key1", b"value1".to_vec(), None),
            ("key2", b"value2".to_vec(), None),
            ("key3", b"value3".to_vec(), None),
        ];

        cache.mset(&entries).await.unwrap();

        let keys = vec!["key1", "key2", "key3"];
        let results = cache.mget(&keys).await.unwrap();

        assert_eq!(results.len(), 3);
        assert_eq!(results[0], Some(b"value1".to_vec()));
        assert_eq!(results[1], Some(b"value2".to_vec()));
        assert_eq!(results[2], Some(b"value3".to_vec()));
    }

    #[tokio::test]
    #[ignore] // Requires Memcached server
    async fn test_memcached_health_check() {
        let config = MemcachedConfig::default();
        let cache = MemcachedCache::new(config).await.unwrap();

        let healthy = cache.health_check().await.unwrap();
        assert!(healthy);
    }

    #[tokio::test]
    #[ignore] // Requires Memcached server
    async fn test_memcached_consistent_hashing() {
        let config = MemcachedConfig {
            servers: vec!["localhost:11211".to_string(), "localhost:11212".to_string()],
            enable_consistent_hashing: true,
            ..Default::default()
        };

        let cache = MemcachedCache::new(config).await.unwrap();

        // Test that the same key always goes to the same server
        let key = "test_consistent_key";
        let value = b"test_value".to_vec();

        cache.set(key, value.clone(), None).await.unwrap();
        let retrieved1 = cache.get(key).await.unwrap();
        let retrieved2 = cache.get(key).await.unwrap();

        assert_eq!(retrieved1, Some(value.clone()));
        assert_eq!(retrieved2, Some(value));
    }
}
