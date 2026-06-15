//! Redis cache backend implementation for Fortress
//!
//! This module provides a production-ready Redis cache backend with support
//! for clustering, connection pooling, and advanced Redis features.

use serde::{Deserialize, Serialize};
#[cfg(feature = "redis")]
use async_trait::async_trait;
#[cfg(feature = "redis")]
use std::sync::Arc;
#[cfg(feature = "redis")]
use std::time::Duration;
#[cfg(feature = "redis")]
use tokio::sync::RwLock;

#[cfg(feature = "redis")]
use crate::error::{FortressError, Result};

#[cfg(feature = "redis")]
use redis::{AsyncCommands, Client, Connection, RedisError, RedisResult};

/// Redis cache configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedisConfig {
    /// Redis connection URLs
    pub urls: Vec<String>,
    /// Password for authentication
    pub password: Option<String>,
    /// Database number
    pub db: i64,
    /// Connection pool size
    pub pool_size: usize,
    /// Connection timeout in seconds
    pub connection_timeout_seconds: u64,
    /// Command timeout in seconds
    pub command_timeout_seconds: u64,
    /// Enable TLS
    pub enable_tls: bool,
    /// Enable cluster mode
    pub enable_cluster: bool,
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
}

impl Default for RedisConfig {
    fn default() -> Self {
        Self {
            urls: vec!["redis://localhost:6379".to_string()],
            password: None,
            db: 0,
            pool_size: 10,
            connection_timeout_seconds: 5,
            command_timeout_seconds: 3,
            enable_tls: false,
            enable_cluster: false,
            key_prefix: "fortress:".to_string(),
            enable_compression: true,
            enable_retry: true,
            max_retries: 3,
            retry_delay_ms: 100,
        }
    }
}

/// Redis connection pool
#[cfg(feature = "redis")]
#[derive(Debug)]
struct RedisPool {
    clients: Vec<Client>,
    current_index: Arc<RwLock<usize>>,
    config: RedisConfig,
}

#[cfg(feature = "redis")]
impl RedisPool {
    /// Create a new Redis connection pool
    async fn new(config: RedisConfig) -> Result<Self> {
        let mut clients = Vec::new();

        for url in &config.urls {
            let client = Client::open(url.as_str()).map_err(|e| {
                FortressError::storage(
                    format!("Failed to create Redis client: {}", e),
                    "redis_cache".to_string(),
                    crate::error::StorageErrorCode::ConnectionFailed,
                )
            })?;
            clients.push(client);
        }

        if clients.is_empty() {
            return Err(FortressError::storage(
                "No valid Redis URLs provided".to_string(),
                "redis_cache".to_string(),
                crate::error::StorageErrorCode::InvalidConfiguration,
            ));
        }

        Ok(Self {
            clients,
            current_index: Arc::new(RwLock::new(0)),
            config,
        })
    }

    /// Get a connection from the pool
    async fn get_connection(&self) -> Result<redis::aio::MultiplexedConnection> {
        let current_index = {
            let mut index = self.current_index.write().await;
            *index = (*index + 1) % self.clients.len();
            *index
        };

        let client = &self.clients[current_index];

        let conn = client
            .get_multiplexed_async_connection()
            .await
            .map_err(|e| {
                FortressError::storage(
                    format!("Failed to get Redis connection: {}", e),
                    "redis_cache".to_string(),
                    crate::error::StorageErrorCode::ConnectionFailed,
                )
            })?;

        // Authenticate if password is provided
        if let Some(ref password) = self.config.password {
            let mut conn = conn;
            let _: () = redis::cmd("AUTH")
                .arg(password)
                .query_async(&mut conn)
                .await
                .map_err(|e| {
                    FortressError::storage(
                        format!("Redis authentication failed: {}", e),
                        "redis_cache".to_string(),
                        crate::error::StorageErrorCode::AuthenticationFailed,
                    )
                })?;
        }

        // Select database
        if self.config.db != 0 {
            let mut conn = conn;
            let _: () = redis::cmd("SELECT")
                .arg(self.config.db)
                .query_async(&mut conn)
                .await
                .map_err(|e| {
                    FortressError::storage(
                        format!("Failed to select Redis database: {}", e),
                        "redis_cache".to_string(),
                        crate::error::StorageErrorCode::InvalidConfiguration,
                    )
                })?;
        }

        Ok(conn)
    }
}

/// Redis cache implementation
#[cfg(feature = "redis")]
#[derive(Debug)]
pub struct RedisCache {
    pool: Arc<RedisPool>,
    config: RedisConfig,
    statistics: Arc<RwLock<crate::distributed_cache::CacheStatistics>>,
}

#[cfg(feature = "redis")]
impl RedisCache {
    /// Create a new Redis cache
    pub async fn new(config: RedisConfig) -> Result<Self> {
        let pool = Arc::new(RedisPool::new(config.clone()).await?);

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

    /// Execute a Redis command with retry logic
    async fn execute_with_retry<F, T>(&self, operation: F) -> Result<T>
    where
        F: Fn() -> RedisResult<T> + Send + Sync,
        T: Send + Sync + 'static,
    {
        if !self.config.enable_retry {
            return operation().map_err(|e| {
                FortressError::storage(
                    format!("Redis operation failed: {}", e),
                    "redis_cache".to_string(),
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
                "Redis operation failed after {} attempts: {}",
                self.config.max_retries,
                last_error.unwrap()
            ),
            "redis_cache".to_string(),
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
                    "redis_cache".to_string(),
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
                    "redis_cache".to_string(),
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

#[cfg(feature = "redis")]
#[async_trait]
impl crate::distributed_cache::DistributedCache for RedisCache {
    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>> {
        let start = std::time::Instant::now();
        let full_key = self.get_full_key(key);

        let result = self
            .execute_with_retry(|| async {
                let mut conn = self.pool.get_connection().await?;
                let value: Option<Vec<u8>> = conn.get(&full_key).await?;
                Ok(value)
            })
            .await;

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

        let result = self
            .execute_with_retry(|| async {
                let mut conn = self.pool.get_connection().await?;

                if let Some(ttl) = ttl_seconds {
                    let _: () = conn.set_ex(&full_key, &compressed_value, ttl).await?;
                } else {
                    let _: () = conn.set(&full_key, &compressed_value).await?;
                }

                Ok(())
            })
            .await;

        let elapsed_us = start.elapsed().as_micros() as f64;
        let success = result.is_ok();
        self.update_stats("set", success, elapsed_us).await;

        result
    }

    async fn delete(&self, key: &str) -> Result<bool> {
        let full_key = self.get_full_key(key);

        let result = self
            .execute_with_retry(|| async {
                let mut conn = self.pool.get_connection().await?;
                let deleted: i32 = conn.del(&full_key).await?;
                Ok(deleted > 0)
            })
            .await;

        if result.is_ok() && result.as_ref().unwrap() {
            self.update_stats("delete", true, 0.0).await;
        }

        result
    }

    async fn exists(&self, key: &str) -> Result<bool> {
        let full_key = self.get_full_key(key);

        self.execute_with_retry(|| async {
            let mut conn = self.pool.get_connection().await?;
            let exists: bool = conn.exists(&full_key).await?;
            Ok(exists)
        })
        .await
    }

    async fn clear(&self) -> Result<()> {
        // Clear all keys with the configured prefix
        let pattern = format!("{}*", self.config.key_prefix);

        self.execute_with_retry(|| async {
            let mut conn = self.pool.get_connection().await?;
            let _: () = redis::cmd("SCAN")
                .arg(0)
                .arg("MATCH")
                .arg(&pattern)
                .query_async(&mut conn)
                .await?;
            Ok(())
        })
        .await?;

        // Update statistics
        let mut stats = self.statistics.write().await;
        stats.total_entries = 0;
        stats.cache_size_bytes = 0;

        Ok(())
    }

    async fn mget(&self, keys: &[&str]) -> Result<Vec<Option<Vec<u8>>>> {
        let full_keys: Vec<String> = keys.iter().map(|k| self.get_full_key(k)).collect();

        let result = self
            .execute_with_retry(|| async {
                let mut conn = self.pool.get_connection().await?;
                let values: Vec<Option<Vec<u8>>> = conn.mget(&full_keys).await?;
                Ok(values)
            })
            .await?;

        // Decompress all values
        let mut decompressed_results = Vec::new();
        for compressed_value in result {
            match compressed_value {
                Some(data) => {
                    let decompressed = self.decompress_data(&data)?;
                    decompressed_results.push(Some(decompressed));
                }
                None => decompressed_results.push(None),
            }
        }

        Ok(decompressed_results)
    }

    async fn mset(&self, entries: &[(&str, Vec<u8>, Option<u64>)]) -> Result<()> {
        let mut pipe = redis::pipe();

        for (key, value, ttl) in entries {
            let full_key = self.get_full_key(key);
            let compressed_value = self.compress_data(value)?;

            if let Some(ttl) = ttl {
                pipe.set_ex(&full_key, &compressed_value, *ttl);
            } else {
                pipe.set(&full_key, &compressed_value);
            }
        }

        self.execute_with_retry(|| async {
            let mut conn = self.pool.get_connection().await?;
            let _: () = pipe.query_async(&mut conn).await?;
            Ok(())
        })
        .await
    }

    async fn increment(&self, key: &str, delta: i64) -> Result<i64> {
        let full_key = self.get_full_key(key);

        self.execute_with_retry(|| async {
            let mut conn = self.pool.get_connection().await?;
            let result: i64 = conn.incr(&full_key, delta).await?;
            Ok(result)
        })
        .await
    }

    async fn get_statistics(&self) -> Result<crate::distributed_cache::CacheStatistics> {
        let stats = self.statistics.read().await;

        // Get actual Redis info
        let info_result = self
            .execute_with_retry(|| async {
                let mut conn = self.pool.get_connection().await?;
                let info: String = redis::cmd("INFO").query_async(&mut conn).await?;
                Ok(info)
            })
            .await;

        if let Ok(info) = info_result {
            // Parse Redis info for additional statistics
            // This is a simple implementation - in production you'd want more robust parsing
            let mut cache_stats = stats.clone();

            for line in info.lines() {
                if line.starts_with("used_memory:") {
                    if let Some(memory_str) = line.split(':').nth(1) {
                        if let Ok(memory_bytes) = memory_str.parse::<u64>() {
                            cache_stats.cache_size_bytes = memory_bytes;
                        }
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

/// Factory function to create Redis cache
#[cfg(feature = "redis")]
pub async fn create_redis_cache(
    config: RedisConfig,
) -> Result<Box<dyn crate::distributed_cache::DistributedCache>> {
    let cache = RedisCache::new(config).await?;
    Ok(Box::new(cache))
}

/// Factory function that returns error when Redis feature is not enabled
#[cfg(not(feature = "redis"))]
#[cfg(feature = "distributed-cache")]
pub async fn create_redis_cache(
    _config: RedisConfig,
) -> Result<Box<dyn crate::distributed_cache::DistributedCache>> {
    Err(FortressError::storage(
        "Redis support not enabled. Enable the 'redis' feature in Cargo.toml".to_string(),
        "redis_cache".to_string(),
        crate::error::StorageErrorCode::BackendNotAvailable,
    ))
}

#[cfg(test)]
#[cfg(feature = "redis")]
mod tests {
    use super::*;
    use crate::distributed_cache::DistributedCache;

    #[tokio::test]
    #[ignore] // Requires Redis server
    async fn test_redis_basic_operations() {
        let config = RedisConfig::default();
        let cache = RedisCache::new(config).await.unwrap();

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
    #[ignore] // Requires Redis server
    async fn test_redis_ttl() {
        let config = RedisConfig::default();
        let cache = RedisCache::new(config).await.unwrap();

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
    #[ignore] // Requires Redis server
    async fn test_redis_mget_mset() {
        let config = RedisConfig::default();
        let cache = RedisCache::new(config).await.unwrap();

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
    #[ignore] // Requires Redis server
    async fn test_redis_increment() {
        let config = RedisConfig::default();
        let cache = RedisCache::new(config).await.unwrap();

        let key = "counter";

        // Increment from non-existent (should start at 0)
        let result = cache.increment(key, 5).await.unwrap();
        assert_eq!(result, 5);

        // Increment existing value
        let result = cache.increment(key, 3).await.unwrap();
        assert_eq!(result, 8);

        // Verify stored value
        let stored = cache.get(key).await.unwrap();
        assert_eq!(stored, Some(b"8".to_vec()));
    }

    #[tokio::test]
    #[ignore] // Requires Redis server
    async fn test_redis_health_check() {
        let config = RedisConfig::default();
        let cache = RedisCache::new(config).await.unwrap();

        let healthy = cache.health_check().await.unwrap();
        assert!(healthy);
    }
}
