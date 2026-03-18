//! Advanced distributed caching layer for Fortress
//!
//! This module provides high-performance distributed caching with support for
//! Redis, Memcached, and intelligent cache invalidation strategies.

use crate::error::{FortressError, Result};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Cache backend configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CacheBackend {
    /// In-memory cache (for single-node deployments)
    InMemory,
    /// Redis cluster
    Redis { 
        nodes: Vec<String>,
        password: Option<String>,
        db: i64,
    },
    /// Memcached cluster
    Memcached {
        servers: Vec<String>,
    },
    /// Hybrid cache (local + distributed)
    Hybrid {
        local_cache_size: usize,
        distributed_backend: Box<CacheBackend>,
    },
}

/// Cache configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DistributedCacheConfig {
    /// Cache backend type
    pub backend: CacheBackend,
    /// Default TTL for cache entries
    pub default_ttl_seconds: u64,
    /// Maximum cache size (for in-memory)
    pub max_cache_size: usize,
    /// Cache eviction policy
    pub eviction_policy: EvictionPolicy,
    /// Enable compression
    pub enable_compression: bool,
    /// Enable encryption
    pub enable_encryption: bool,
    /// Cache key prefix
    pub key_prefix: String,
    /// Enable metrics collection
    pub enable_metrics: bool,
    /// Connection timeout in seconds
    pub connection_timeout_seconds: u64,
    /// Maximum retry attempts
    pub max_retries: u32,
}

impl Default for DistributedCacheConfig {
    fn default() -> Self {
        Self {
            backend: CacheBackend::InMemory,
            default_ttl_seconds: 3600, // 1 hour
            max_cache_size: 10000,
            eviction_policy: EvictionPolicy::LRU,
            enable_compression: true,
            enable_encryption: false,
            key_prefix: "fortress:".to_string(),
            enable_metrics: true,
            connection_timeout_seconds: 5,
            max_retries: 3,
        }
    }
}

/// Cache eviction policies
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum EvictionPolicy {
    /// Least Recently Used
    LRU,
    /// Least Frequently Used
    LFU,
    /// First In First Out
    FIFO,
    /// Random eviction
    Random,
    /// Time-based expiration only
    TTL,
}

/// Cache entry with metadata
#[derive(Debug, Clone)]
pub struct CacheEntry {
    /// Cache value
    pub value: Vec<u8>,
    /// Creation timestamp
    pub created_at: chrono::DateTime<chrono::Utc>,
    /// Last access timestamp
    pub last_accessed: chrono::DateTime<chrono::Utc>,
    /// Access count
    pub access_count: u64,
    /// TTL in seconds
    pub ttl_seconds: u64,
    /// Entry size in bytes
    pub size_bytes: usize,
    /// Entry metadata
    pub metadata: HashMap<String, String>,
}

/// Cache statistics
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CacheStatistics {
    /// Total number of entries
    pub total_entries: u64,
    /// Cache size in bytes
    pub cache_size_bytes: u64,
    /// Number of hits
    pub hits: u64,
    /// Number of misses
    pub misses: u64,
    /// Hit ratio
    pub hit_ratio: f64,
    /// Number of evictions
    pub evictions: u64,
    /// Number of sets
    pub sets: u64,
    /// Number of deletes
    pub deletes: u64,
    /// Average get time in microseconds
    pub avg_get_time_us: f64,
    /// Average set time in microseconds
    pub avg_set_time_us: f64,
    /// Last reset timestamp
    pub last_reset: chrono::DateTime<chrono::Utc>,
}

/// Trait for distributed cache operations
#[async_trait]
pub trait DistributedCache: Send + Sync + std::fmt::Debug {
    /// Get a value from cache
    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>>;

    /// Set a value in cache with optional TTL
    async fn set(&self, key: &str, value: Vec<u8>, ttl_seconds: Option<u64>) -> Result<()>;

    /// Delete a value from cache
    async fn delete(&self, key: &str) -> Result<bool>;

    /// Check if a key exists
    async fn exists(&self, key: &str) -> Result<bool>;

    /// Clear all cache entries
    async fn clear(&self) -> Result<()>;

    /// Get multiple keys
    async fn mget(&self, keys: &[&str]) -> Result<Vec<Option<Vec<u8>>>>;

    /// Set multiple keys
    async fn mset(&self, entries: &[(&str, Vec<u8>, Option<u64>)]) -> Result<()>;

    /// Increment a numeric value
    async fn increment(&self, key: &str, delta: i64) -> Result<i64>;

    /// Get cache statistics
    async fn get_statistics(&self) -> Result<CacheStatistics>;

    /// Reset statistics
    async fn reset_statistics(&self) -> Result<()>;

    /// Health check
    async fn health_check(&self) -> Result<bool>;
}

/// In-memory cache implementation
#[derive(Debug)]
pub struct InMemoryCache {
    entries: Arc<RwLock<HashMap<String, CacheEntry>>>,
    config: DistributedCacheConfig,
    statistics: Arc<RwLock<CacheStatistics>>,
    access_order: Arc<RwLock<Vec<String>>>, // For LRU
}

impl InMemoryCache {
    /// Create a new in-memory cache
    pub fn new(config: DistributedCacheConfig) -> Self {
        Self {
            entries: Arc::new(RwLock::new(HashMap::new())),
            config,
            statistics: Arc::new(RwLock::new(CacheStatistics {
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
                last_reset: chrono::Utc::now(),
            })),
            access_order: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Evict entries based on the configured policy
    async fn evict_if_needed(&self) -> Result<()> {
        let entries = self.entries.read().await;
        let current_size = entries.len();
        drop(entries);

        if current_size > self.config.max_cache_size {
            match self.config.eviction_policy {
                EvictionPolicy::LRU => self.evict_lru().await?,
                EvictionPolicy::LFU => self.evict_lfu().await?,
                EvictionPolicy::FIFO => self.evict_fifo().await?,
                EvictionPolicy::Random => self.evict_random().await?,
                EvictionPolicy::TTL => self.evict_expired().await?,
            }
        }

        Ok(())
    }

    /// Evict least recently used entries
    async fn evict_lru(&self) -> Result<()> {
        let mut entries = self.entries.write().await;
        let mut access_order = self.access_order.write().await;

        // Remove oldest entries from access order
        while entries.len() > self.config.max_cache_size && !access_order.is_empty() {
            if let Some(oldest_key) = access_order.first() {
                if entries.remove(oldest_key).is_some() {
                    access_order.remove(0);
                    self.update_eviction_stats().await;
                }
            } else {
                break;
            }
        }

        Ok(())
    }

    /// Evict least frequently used entries
    async fn evict_lfu(&self) -> Result<()> {
        let mut entries = self.entries.write().await;

        // Find entry with lowest access count
        if let Some((key_to_remove, _)) = entries.iter()
            .min_by_key(|(_, entry)| entry.access_count) {
            let key = key_to_remove.clone();
            entries.remove(&key);
            self.update_eviction_stats().await;
        }

        Ok(())
    }

    /// Evict first-in entries
    async fn evict_fifo(&self) -> Result<()> {
        let mut entries = self.entries.write().await;

        // Find oldest entry
        if let Some((key_to_remove, _)) = entries.iter()
            .min_by_key(|(_, entry)| entry.created_at) {
            let key = key_to_remove.clone();
            entries.remove(&key);
            self.update_eviction_stats().await;
        }

        Ok(())
    }

    /// Evict random entries
    async fn evict_random(&self) -> Result<()> {
        let mut entries = self.entries.write().await;

        if !entries.is_empty() {
            let keys: Vec<String> = entries.keys().cloned().collect();
            let random_index = rand::random::<usize>() % keys.len();
            let key_to_remove = &keys[random_index];
            entries.remove(key_to_remove);
            self.update_eviction_stats().await;
        }

        Ok(())
    }

    /// Evict expired entries
    async fn evict_expired(&self) -> Result<()> {
        let mut entries = self.entries.write().await;
        let now = chrono::Utc::now();
        let mut keys_to_remove = Vec::new();

        for (key, entry) in entries.iter() {
            let age = now.signed_duration_since(entry.created_at);
            if age.num_seconds() > entry.ttl_seconds as i64 {
                keys_to_remove.push(key.clone());
            }
        }

        for key in keys_to_remove {
            entries.remove(&key);
            self.update_eviction_stats().await;
        }

        Ok(())
    }

    /// Update eviction statistics
    async fn update_eviction_stats(&self) {
        let mut stats = self.statistics.write().await;
        stats.evictions += 1;
    }

    /// Update access order for LRU
    async fn update_access_order(&self, key: &str) {
        let mut access_order = self.access_order.write().await;
        
        // Remove key if it exists
        access_order.retain(|k| k != key);
        // Add key to the end (most recently used)
        access_order.push(key.to_string());
    }

    /// Compress data if enabled
    fn compress_data(&self, data: &[u8]) -> Result<Vec<u8>> {
        if self.config.enable_compression {
            // Use LZ4 compression for speed
            let compressed = lz4::block::compress(data, None, true)
                .map_err(|e| FortressError::storage(
                    format!("Compression failed: {}", e),
                    "distributed_cache".to_string(),
                    crate::error::StorageErrorCode::CorruptedData,
                ))?;
            Ok(compressed)
        } else {
            Ok(data.to_vec())
        }
    }

    /// Decompress data if needed
    fn decompress_data(&self, data: &[u8]) -> Result<Vec<u8>> {
        if self.config.enable_compression {
            let decompressed = lz4::block::decompress(data, None)
                .map_err(|e| FortressError::storage(
                    format!("Decompression failed: {}", e),
                    "distributed_cache".to_string(),
                    crate::error::StorageErrorCode::CorruptedData,
                ))?;
            Ok(decompressed)
        } else {
            Ok(data.to_vec())
        }
    }
}

#[async_trait]
impl DistributedCache for InMemoryCache {
    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>> {
        let start = std::time::Instant::now();
        let full_key = format!("{}{}", self.config.key_prefix, key);

        let mut entries = self.entries.write().await;
        let now = chrono::Utc::now();

        if let Some(entry) = entries.get_mut(&full_key) {
            // Check if expired
            let age = now.signed_duration_since(entry.created_at);
            if age.num_seconds() > entry.ttl_seconds as i64 {
                entries.remove(&full_key);
                drop(entries);
                
                // Update statistics
                let mut stats = self.statistics.write().await;
                stats.misses += 1;
                stats.hit_ratio = stats.hits as f64 / (stats.hits + stats.misses) as f64;
                
                let elapsed = start.elapsed().as_micros() as f64;
                stats.avg_get_time_us = (stats.avg_get_time_us * (stats.hits + stats.misses - 1) as f64 + elapsed) / (stats.hits + stats.misses) as f64;
                
                return Ok(None);
            }

            // Update access information
            entry.last_accessed = now;
            entry.access_count += 1;
            let value = self.decompress_data(&entry.value)?;
            
            drop(entries);
            self.update_access_order(&full_key).await;

            // Update statistics
            let mut stats = self.statistics.write().await;
            stats.hits += 1;
            stats.hit_ratio = stats.hits as f64 / (stats.hits + stats.misses) as f64;
            
            let elapsed = start.elapsed().as_micros() as f64;
            stats.avg_get_time_us = (stats.avg_get_time_us * (stats.hits + stats.misses - 1) as f64 + elapsed) / (stats.hits + stats.misses) as f64;

            Ok(Some(value))
        } else {
            drop(entries);
            
            // Update statistics
            let mut stats = self.statistics.write().await;
            stats.misses += 1;
            stats.hit_ratio = stats.hits as f64 / (stats.hits + stats.misses) as f64;
            
            let elapsed = start.elapsed().as_micros() as f64;
            stats.avg_get_time_us = (stats.avg_get_time_us * (stats.hits + stats.misses - 1) as f64 + elapsed) / (stats.hits + stats.misses) as f64;

            Ok(None)
        }
    }

    async fn set(&self, key: &str, value: Vec<u8>, ttl_seconds: Option<u64>) -> Result<()> {
        let start = std::time::Instant::now();
        let full_key = format!("{}{}", self.config.key_prefix, key);
        let ttl = ttl_seconds.unwrap_or(self.config.default_ttl_seconds);
        let compressed_value = self.compress_data(&value)?;

        let entry = CacheEntry {
            value: compressed_value,
            created_at: chrono::Utc::now(),
            last_accessed: chrono::Utc::now(),
            access_count: 0,
            ttl_seconds: ttl,
            size_bytes: value.len(),
            metadata: HashMap::new(),
        };

        // Evict if needed before adding new entry
        self.evict_if_needed().await?;

        // Add the entry
        {
            let mut entries = self.entries.write().await;
            entries.insert(full_key.clone(), entry);
        }

        self.update_access_order(&full_key).await;

        // Update statistics
        let mut stats = self.statistics.write().await;
        stats.sets += 1;
        stats.total_entries = self.entries.read().await.len() as u64;
        stats.cache_size_bytes = self.entries.read().await
            .values()
            .map(|e| e.size_bytes as u64)
            .sum();
        
        let elapsed = start.elapsed().as_micros() as f64;
        stats.avg_set_time_us = (stats.avg_set_time_us * (stats.sets - 1) as f64 + elapsed) / stats.sets as f64;

        Ok(())
    }

    async fn delete(&self, key: &str) -> Result<bool> {
        let full_key = format!("{}{}", self.config.key_prefix, key);
        
        let mut entries = self.entries.write().await;
        let removed = entries.remove(&full_key).is_some();
        
        if removed {
            // Update statistics
            let mut stats = self.statistics.write().await;
            stats.deletes += 1;
            stats.total_entries = entries.len() as u64;
            stats.cache_size_bytes = entries.values().map(|e| e.size_bytes as u64).sum();
        }

        Ok(removed)
    }

    async fn exists(&self, key: &str) -> Result<bool> {
        let full_key = format!("{}{}", self.config.key_prefix, key);
        let entries = self.entries.read().await;
        Ok(entries.contains_key(&full_key))
    }

    async fn clear(&self) -> Result<()> {
        let mut entries = self.entries.write().await;
        entries.clear();
        
        // Update statistics
        let mut stats = self.statistics.write().await;
        stats.total_entries = 0;
        stats.cache_size_bytes = 0;

        Ok(())
    }

    async fn mget(&self, keys: &[&str]) -> Result<Vec<Option<Vec<u8>>>> {
        let mut results = Vec::new();
        for key in keys {
            results.push(self.get(key).await?);
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
        let current_value = self.get(key).await?;
        
        let current_int = match current_value {
            Some(bytes) => {
                let str_val = String::from_utf8(bytes)
                    .map_err(|_| FortressError::storage(
                        "Cache value is not a valid string".to_string(),
                        "distributed_cache".to_string(),
                        crate::error::StorageErrorCode::CorruptedData,
                    ))?;
                str_val.parse::<i64>()
                    .map_err(|_| FortressError::storage(
                        "Cache value is not a valid integer".to_string(),
                        "distributed_cache".to_string(),
                        crate::error::StorageErrorCode::CorruptedData,
                    ))?
            }
            None => 0,
        };

        let new_value = current_int + delta;
        self.set(key, new_value.to_string().into_bytes(), None).await?;
        
        Ok(new_value)
    }

    async fn get_statistics(&self) -> Result<CacheStatistics> {
        let stats = self.statistics.read().await;
        Ok(stats.clone())
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
        stats.last_reset = chrono::Utc::now();
        Ok(())
    }

    async fn health_check(&self) -> Result<bool> {
        // Try to set and get a test value
        let test_key = "health_check";
        let test_value = b"test".to_vec();
        
        self.set(test_key, test_value.clone(), Some(1)).await?;
        let retrieved = self.get(test_key).await?;
        
        if retrieved.as_ref() == Some(&test_value) {
            self.delete(test_key).await?;
            Ok(true)
        } else {
            Ok(false)
        }
    }
}

/// Redis cache implementation (placeholder for when Redis is added)
#[cfg(feature = "redis")]
#[derive(Debug)]
pub struct RedisCache {
    // Redis client would go here
    config: DistributedCacheConfig,
}

/// Factory function to create cache based on configuration
pub async fn create_distributed_cache(config: DistributedCacheConfig) -> Result<Box<dyn DistributedCache>> {
    match config.backend {
        CacheBackend::InMemory => {
            Ok(Box::new(InMemoryCache::new(config)))
        }
        CacheBackend::Redis { .. } => {
            #[cfg(feature = "redis")]
            {
                // Redis implementation would go here
                Err(FortressError::storage(
                    "Redis cache not yet implemented".to_string(),
                    "distributed_cache".to_string(),
                    crate::error::StorageErrorCode::BackendNotAvailable,
                ))
            }
            #[cfg(not(feature = "redis"))]
            {
                Err(FortressError::storage(
                    "Redis support not enabled. Enable the 'redis' feature.".to_string(),
                    "distributed_cache".to_string(),
                    crate::error::StorageErrorCode::BackendNotAvailable,
                ))
            }
        }
        CacheBackend::Memcached { .. } => {
            Err(FortressError::storage(
                "Memcached cache not yet implemented".to_string(),
                "distributed_cache".to_string(),
                crate::error::StorageErrorCode::BackendNotAvailable,
            ))
        }
        CacheBackend::Hybrid { .. } => {
            Err(FortressError::storage(
                "Hybrid cache not yet implemented".to_string(),
                "distributed_cache".to_string(),
                crate::error::StorageErrorCode::BackendNotAvailable,
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_in_memory_cache_basic_operations() {
        let config = DistributedCacheConfig::default();
        let cache = InMemoryCache::new(config);

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
    async fn test_cache_ttl() {
        let config = DistributedCacheConfig {
            default_ttl_seconds: 1,
            ..Default::default()
        };
        let cache = InMemoryCache::new(config);

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
    async fn test_cache_statistics() {
        let config = DistributedCacheConfig::default();
        let cache = InMemoryCache::new(config);

        let key = "stats_test";
        let value = b"test_value".to_vec();
        
        // Perform operations
        cache.set(key, value.clone(), None).await.unwrap();
        cache.get(key).await.unwrap();
        cache.get(key).await.unwrap();
        cache.get("nonexistent").await.unwrap();
        
        let stats = cache.get_statistics().await.unwrap();
        assert_eq!(stats.sets, 1);
        assert_eq!(stats.hits, 2);
        assert_eq!(stats.misses, 1);
        assert!(stats.hit_ratio > 0.0);
    }

    #[tokio::test]
    async fn test_cache_eviction() {
        let config = DistributedCacheConfig {
            max_cache_size: 2,
            eviction_policy: EvictionPolicy::LRU,
            ..Default::default()
        };
        let cache = InMemoryCache::new(config);

        // Fill cache beyond capacity
        cache.set("key1", b"value1".to_vec(), None).await.unwrap();
        cache.set("key2", b"value2".to_vec(), None).await.unwrap();
        cache.set("key3", b"value3".to_vec(), None).await.unwrap();
        
        // First key should be evicted
        assert!(!cache.exists("key1").await.unwrap());
        assert!(cache.exists("key2").await.unwrap());
        assert!(cache.exists("key3").await.unwrap());
    }

    #[tokio::test]
    async fn test_increment_operation() {
        let config = DistributedCacheConfig::default();
        let cache = InMemoryCache::new(config);

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
}
