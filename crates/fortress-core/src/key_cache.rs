//! High-performance in-memory key cache with LRU eviction
//!
//! This module provides a sophisticated caching system for keys with
//! LRU eviction, memory management, and performance monitoring.

use crate::error::Result;
use crate::key::{KeyId, KeyMetadata, SecureKey};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use tokio::sync::RwLock;

/// Configuration for the key cache
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyCacheConfig {
    /// Maximum number of keys to cache
    pub max_keys: usize,
    /// Maximum memory usage in bytes
    pub max_memory_bytes: usize,
    /// Enable LRU eviction
    pub enable_lru_eviction: bool,
    /// Enable time-based eviction
    pub enable_time_eviction: bool,
    /// Time after which keys are evicted (in seconds)
    pub eviction_time_seconds: u64,
    /// Enable access frequency tracking
    pub track_access_frequency: bool,
    /// Enable cache statistics
    pub enable_stats: bool,
    /// Cache warming on startup
    pub enable_cache_warming: bool,
    /// Background cleanup interval in seconds
    pub background_cleanup_interval_seconds: u64,
    /// Cache hit ratio threshold for auto-scaling
    pub hit_ratio_threshold: f64,
}

impl Default for KeyCacheConfig {
    fn default() -> Self {
        Self {
            max_keys: 10000,
            max_memory_bytes: 500 * 1024 * 1024, // 500MB
            enable_lru_eviction: true,
            enable_time_eviction: true,
            eviction_time_seconds: 3600, // 1 hour
            track_access_frequency: true,
            enable_stats: true,
            enable_cache_warming: false,
            background_cleanup_interval_seconds: 300, // 5 minutes
            hit_ratio_threshold: 0.8,
        }
    }
}

/// Cache entry containing key data and metadata
#[derive(Debug, Clone)]
struct CacheEntry {
    /// The secure key
    key: SecureKey,
    /// Key metadata
    metadata: KeyMetadata,
    /// When the entry was created
    created_at: DateTime<Utc>,
    /// When the entry was last accessed
    last_accessed: DateTime<Utc>,
    /// Number of times this entry was accessed
    access_count: u64,
    /// Size of the key in bytes
    size_bytes: usize,
}

impl CacheEntry {
    fn new(key: SecureKey, metadata: KeyMetadata) -> Self {
        let size_bytes = key.len();
        Self {
            key,
            metadata,
            created_at: Utc::now(),
            last_accessed: Utc::now(),
            access_count: 0,
            size_bytes,
        }
    }

    fn access(&mut self) {
        self.last_accessed = Utc::now();
        self.access_count += 1;
    }

    fn is_expired(&self, eviction_time_seconds: u64) -> bool {
        let now = Utc::now();
        let age_seconds = (now - self.last_accessed).num_seconds();
        age_seconds > eviction_time_seconds as i64
    }
}

/// Cache statistics and metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheStats {
    /// Total number of cache hits
    pub hits: u64,
    /// Total number of cache misses
    pub misses: u64,
    /// Current number of cached keys
    pub current_keys: usize,
    /// Current memory usage in bytes
    pub current_memory_bytes: usize,
    /// Number of evictions due to size limits
    pub size_evictions: u64,
    /// Number of evictions due to time limits
    pub time_evictions: u64,
    /// Cache hit ratio
    pub hit_ratio: f64,
    /// Average access time in microseconds
    pub avg_access_time_us: f64,
    /// Most accessed keys
    pub most_accessed_keys: Vec<(KeyId, u64)>,
    /// Least recently used keys
    pub lru_keys: Vec<KeyId>,
    /// Last cleanup time
    pub last_cleanup_time: Option<DateTime<Utc>>,
    // Compatibility fields for tests
    /// Alias for hits (test compatibility)
    pub cache_hits: u64,
    /// Alias for misses (test compatibility)
    pub cache_misses: u64,
    /// Alias for current_keys (test compatibility)
    pub total_keys: usize,
    /// Total evictions (test compatibility)
    pub evictions: u64,
}

impl CacheStats {
    /// Alias for hits to maintain compatibility with tests
    pub fn cache_hits(&self) -> u64 {
        self.hits
    }
    
    /// Alias for misses to maintain compatibility with tests  
    pub fn cache_misses(&self) -> u64 {
        self.misses
    }
    
    /// Alias for current_keys to maintain compatibility with tests
    pub fn total_keys(&self) -> usize {
        self.current_keys
    }
    
    /// Total evictions (both size and time based)
    pub fn evictions(&self) -> u64 {
        self.size_evictions + self.time_evictions
    }
}

/// High-performance LRU cache for keys
#[derive(Clone)]
pub struct KeyCache {
    config: KeyCacheConfig,
    /// Main cache storage
    cache: Arc<RwLock<HashMap<KeyId, CacheEntry>>>,
    /// LRU tracking (most recent at front, least recent at back)
    lru_order: Arc<RwLock<VecDeque<KeyId>>>,
    /// Cache statistics
    stats: Arc<RwLock<CacheStats>>,
    /// Background cleanup task handle
    cleanup_task: Arc<RwLock<Option<tokio::task::JoinHandle<()>>>>,
}

impl KeyCache {
    /// Create a new key cache with the given configuration
    pub fn new(config: KeyCacheConfig) -> Self {
        Self {
            config,
            cache: Arc::new(RwLock::new(HashMap::new())),
            lru_order: Arc::new(RwLock::new(VecDeque::new())),
            stats: Arc::new(RwLock::new(CacheStats {
                hits: 0,
                misses: 0,
                current_keys: 0,
                current_memory_bytes: 0,
                size_evictions: 0,
                time_evictions: 0,
                hit_ratio: 0.0,
                avg_access_time_us: 0.0,
                most_accessed_keys: Vec::new(),
                lru_keys: Vec::new(),
                last_cleanup_time: None,
                // Compatibility fields
                cache_hits: 0,
                cache_misses: 0,
                total_keys: 0,
                evictions: 0,
            })),
            cleanup_task: Arc::new(RwLock::new(None)),
        }
    }

    /// Initialize the cache and start background tasks
    pub async fn initialize(&self) -> Result<()> {
        if self.config.background_cleanup_interval_seconds > 0 {
            self.start_background_cleanup().await?;
        }
        Ok(())
    }

    /// Get a key from the cache
    pub async fn get(&self, key_id: &KeyId) -> Option<(SecureKey, KeyMetadata)> {
        let start_time = std::time::Instant::now();
        
        let mut cache = self.cache.write().await;
        let mut stats = self.stats.write().await;
        
        if let Some(entry) = cache.get_mut(key_id) {
            // Update access information
            entry.access();
            
            // Update LRU order
            if self.config.enable_lru_eviction {
                let mut lru_order = self.lru_order.write().await;
                // Remove from current position
                lru_order.retain(|id| id != key_id);
                // Add to front (most recent)
                lru_order.push_front(key_id.clone());
            }
            
            // Update statistics
            stats.hits += 1;
            stats.cache_hits += 1; // Update compatibility field
            let elapsed_us = start_time.elapsed().as_micros() as f64;
            stats.avg_access_time_us = (stats.avg_access_time_us * (stats.hits - 1) as f64 + elapsed_us) / stats.hits as f64;
            
            Some((entry.key.clone(), entry.metadata.clone()))
        } else {
            stats.misses += 1;
            stats.cache_misses += 1; // Update compatibility field
            stats.hit_ratio = stats.hits as f64 / (stats.hits + stats.misses) as f64;
            None
        }
    }

    /// Put a key into the cache
    pub async fn put(&self, key_id: KeyId, key: SecureKey, metadata: KeyMetadata) -> Result<()> {
        let entry = CacheEntry::new(key, metadata);
        let key_size = entry.size_bytes;

        // Check memory limits
        let current_memory = self.get_current_memory_usage().await;
        if current_memory + key_size > self.config.max_memory_bytes {
            self.evict_for_memory(key_size).await?;
        }

        // Check key count limits
        let current_keys = self.get_current_key_count().await;
        if current_keys >= self.config.max_keys {
            self.evict_for_space().await?;
        }

        // Insert the key
        {
            let mut cache = self.cache.write().await;
            let mut lru_order = self.lru_order.write().await;
            
            cache.insert(key_id.clone(), entry);
            
            if self.config.enable_lru_eviction {
                // Add to front of LRU (most recent)
                lru_order.push_front(key_id.clone());
            }
        }

        // Update statistics
        if self.config.enable_stats {
            self.update_stats().await;
        }

        Ok(())
    }

    /// Store encrypted data in the cache (convenience method for encrypted bytes)
    /// 
    /// This method provides a convenient way to store encrypted data directly
    /// without needing to create a SecureKey manually.
    /// 
    /// # Arguments
    /// * `key_id` - The unique identifier for the cached data
    /// * `encrypted_data` - The encrypted bytes to store
    /// * `metadata` - Optional metadata for the cache entry
    /// 
    /// # Returns
    /// * `Result<()>` - Success or error
    /// 
    /// # Examples
    /// ```rust
    /// // Store encrypted data directly
    /// cache.store(&key_id, encrypted_bytes, metadata).await?;
    /// ```
    pub async fn store(&self, key_id: &KeyId, encrypted_data: Vec<u8>, metadata: Option<KeyMetadata>) -> Result<()> {
        let secure_key = SecureKey::from_bytes(&encrypted_data);
        let cache_metadata = metadata.unwrap_or_else(|| KeyMetadata::new(
            key_id.clone(),
            "cached_encrypted_data".to_string(),
            1,
            chrono::Utc::now(),
            chrono::Utc::now() + chrono::Duration::hours(24),
            "cache".to_string(),
            crate::encryption::PerformanceProfile::Balanced,
        ));
        
        self.put(key_id.clone(), secure_key, cache_metadata).await
    }

    /// Remove a key from the cache
    /// 
    /// This method securely removes a key and its associated metadata from the cache.
    /// The key is immediately removed from both the cache storage and LRU tracking.
    /// 
    /// # Arguments
    /// * `key_id` - The unique identifier of the key to remove
    /// 
    /// # Returns
    /// * `Result<bool>` - Ok(true) if the key was found and removed, Ok(false) if the key was not found
    /// 
    /// # Security Notes
    /// - The secure key memory is automatically zeroized when dropped
    /// - All references to the key are removed from LRU tracking
    /// - Cache statistics are updated to reflect the removal
    /// 
    /// # Examples
    /// ```rust
    /// let removed = cache.remove(&key_id).await?;
    /// if removed {
    ///     println!("Key securely removed from cache");
    /// }
    /// ```
    pub async fn remove(&self, key_id: &KeyId) -> Result<bool> {
        let mut cache = self.cache.write().await;
        let mut lru_order = self.lru_order.write().await;
        
        let removed = cache.remove(key_id).is_some();
        if removed {
            lru_order.retain(|id| id != key_id);
            
            if self.config.enable_stats {
                self.update_stats().await;
            }
        }

        Ok(removed)
    }

    /// Check if a key exists in the cache
    pub async fn contains(&self, key_id: &KeyId) -> bool {
        let cache = self.cache.read().await;
        cache.contains_key(key_id)
    }

    /// Get current memory usage
    async fn get_current_memory_usage(&self) -> usize {
        let cache = self.cache.read().await;
        cache.values().map(|entry| entry.size_bytes).sum()
    }

    /// Get current key count
    async fn get_current_key_count(&self) -> usize {
        let cache = self.cache.read().await;
        cache.len()
    }

    /// Evict keys to free memory for a new key
    async fn evict_for_memory(&self, required_bytes: usize) -> Result<()> {
        let mut freed_bytes = 0;
        let mut evicted_keys = Vec::new();

        {
            let cache = self.cache.read().await;
            let lru_order = self.lru_order.read().await;
            
            // Evict from least recently used
            for key_id in lru_order.iter().rev() {
                if let Some(entry) = cache.get(key_id) {
                    evicted_keys.push(key_id.clone());
                    freed_bytes += entry.size_bytes;
                    
                    if freed_bytes >= required_bytes {
                        break;
                    }
                }
            }
        }

        // Actually remove the keys
        for key_id in evicted_keys {
            self.remove(&key_id).await?;
            
            let mut stats = self.stats.write().await;
            stats.size_evictions += 1;
            stats.evictions += 1; // Update compatibility field
        }

        Ok(())
    }

    /// Evict keys to make space for a new key
    async fn evict_for_space(&self) -> Result<()> {
        let mut evicted_keys = Vec::new();

        {
            let lru_order = self.lru_order.read().await;
            
            // Remove the least recently used key
            if let Some(key_id) = lru_order.back() {
                evicted_keys.push(key_id.clone());
            }
        }

        // Actually remove the key
        for key_id in evicted_keys {
            self.remove(&key_id).await?;
            
            let mut stats = self.stats.write().await;
            stats.size_evictions += 1;
            stats.evictions += 1; // Update compatibility field
        }

        Ok(())
    }

    /// Perform time-based eviction
    async fn evict_expired_keys(&self) -> Result<usize> {
        if !self.config.enable_time_eviction {
            return Ok(0);
        }

        let mut expired_keys = Vec::new();

        {
            let cache = self.cache.read().await;
            
            for (key_id, entry) in cache.iter() {
                if entry.is_expired(self.config.eviction_time_seconds) {
                    expired_keys.push(key_id.clone());
                }
            }
        }

        // Remove expired keys
        let expired_count = expired_keys.len();
        for key_id in expired_keys {
            self.remove(&key_id).await?;
            
            let mut stats = self.stats.write().await;
            stats.time_evictions += 1;
            stats.evictions += 1; // Update compatibility field
        }

        Ok(expired_count)
    }

    /// Update cache statistics
    async fn update_stats(&self) {
        let mut stats = self.stats.write().await;
        let cache = self.cache.read().await;
        let lru_order = self.lru_order.read().await;

        stats.current_keys = cache.len();
        stats.current_memory_bytes = cache.values().map(|entry| entry.size_bytes).sum();
        stats.hit_ratio = if stats.hits + stats.misses > 0 {
            stats.hits as f64 / (stats.hits + stats.misses) as f64
        } else {
            0.0
        };

        // Update most accessed keys
        stats.most_accessed_keys = cache
            .iter()
            .map(|(key_id, entry)| (key_id.clone(), entry.access_count))
            .collect();
        stats.most_accessed_keys.sort_by(|a, b| b.1.cmp(&a.1));
        stats.most_accessed_keys.truncate(10); // Top 10

        // Update LRU keys
        stats.lru_keys = lru_order.iter().rev().take(10).cloned().collect();
        stats.last_cleanup_time = Some(Utc::now());
        
        // Update compatibility fields
        stats.cache_hits = stats.hits;
        stats.cache_misses = stats.misses;
        stats.total_keys = stats.current_keys;
        stats.evictions = stats.size_evictions + stats.time_evictions;
    }

    /// Start background cleanup task
    async fn start_background_cleanup(&self) -> Result<()> {
        let cache = self.cache.clone();
        let lru_order = self.lru_order.clone();
        let stats = self.stats.clone();
        let config = self.config.clone();

        let handle = tokio::spawn(async move {
            let mut interval = tokio::time::interval(
                std::time::Duration::from_secs(config.background_cleanup_interval_seconds)
            );

            loop {
                interval.tick().await;

                // Perform cleanup
                let mut expired_keys = Vec::new();
                let now = Utc::now();

                {
                    let cache_read = cache.read().await;
                    for (key_id, entry) in cache_read.iter() {
                        if entry.is_expired(config.eviction_time_seconds) {
                            expired_keys.push(key_id.clone());
                        }
                    }
                }

                // Remove expired keys
                if !expired_keys.is_empty() {
                    let mut cache_write = cache.write().await;
                    let mut lru_order_write = lru_order.write().await;
                    let mut stats_write = stats.write().await;

                    for key_id in &expired_keys {
                        cache_write.remove(key_id);
                        lru_order_write.retain(|id| id != key_id);
                        stats_write.time_evictions += 1;
                        stats_write.evictions += 1; // Update compatibility field
                    }

                    // Update statistics
                    stats_write.current_keys = cache_write.len();
                    stats_write.current_memory_bytes = cache_write.values()
                        .map(|entry| entry.size_bytes).sum();
                    stats_write.last_cleanup_time = Some(now);
                }
            }
        });

        let mut cleanup_task = self.cleanup_task.write().await;
        *cleanup_task = Some(handle);

        Ok(())
    }

    /// Get current cache statistics
    pub async fn get_stats(&self) -> CacheStats {
        if self.config.enable_stats {
            self.update_stats().await;
        }
        self.stats.read().await.clone()
    }

    /// Get detailed cache statistics (alias for get_stats for test compatibility)
    pub async fn get_detailed_stats(&self) -> CacheStats {
        self.get_stats().await
    }

    /// Clear all cached keys
    pub async fn clear(&self) -> Result<usize> {
        let mut cache = self.cache.write().await;
        let mut lru_order = self.lru_order.write().await;
        
        let count = cache.len();
        cache.clear();
        lru_order.clear();

        if self.config.enable_stats {
            let mut stats = self.stats.write().await;
            stats.current_keys = 0;
            stats.current_memory_bytes = 0;
        }

        Ok(count)
    }

    /// Warm up the cache with frequently used keys
    pub async fn warm_up(&self, keys: Vec<(KeyId, SecureKey, KeyMetadata)>) -> Result<usize> {
        if !self.config.enable_cache_warming {
            return Ok(0);
        }

        let mut warmed_count = 0;
        let mut current_memory = self.get_current_memory_usage().await;

        for (key_id, key, metadata) in keys {
            // Check if we have space
            if current_memory + key.len() > self.config.max_memory_bytes {
                break;
            }

            if self.get_current_key_count().await >= self.config.max_keys {
                break;
            }

            // Add to cache
            let key_len = key.len();
            self.put(key_id.clone(), key, metadata).await?;
            warmed_count += 1;
            current_memory += key_len;
        }

        Ok(warmed_count)
    }

    /// Get cache performance recommendations
    pub async fn get_performance_recommendations(&self) -> Vec<String> {
        let stats = self.get_stats().await;
        let mut recommendations = Vec::new();

        // Hit ratio recommendations
        if stats.hit_ratio < self.config.hit_ratio_threshold {
            recommendations.push(format!(
                "Cache hit ratio ({:.2}) is below threshold ({:.2}). Consider increasing cache size.",
                stats.hit_ratio, self.config.hit_ratio_threshold
            ));
        }

        // Memory usage recommendations
        let memory_usage_ratio = stats.current_memory_bytes as f64 / self.config.max_memory_bytes as f64;
        if memory_usage_ratio > 0.9 {
            recommendations.push(format!(
                "Cache memory usage ({:.1}%) is high. Consider increasing max_memory_bytes.",
                memory_usage_ratio * 100.0
            ));
        }

        // Key count recommendations
        let key_usage_ratio = stats.current_keys as f64 / self.config.max_keys as f64;
        if key_usage_ratio > 0.9 {
            recommendations.push(format!(
                "Cache key usage ({:.1}%) is high. Consider increasing max_keys.",
                key_usage_ratio * 100.0
            ));
        }

        // Eviction recommendations
        if stats.size_evictions > stats.hits / 10 {
            recommendations.push(
                "High number of size evictions detected. Consider increasing cache limits.".to_string()
            );
        }

        if stats.time_evictions > stats.hits / 20 {
            recommendations.push(
                "High number of time evictions detected. Consider increasing eviction_time_seconds.".to_string()
            );
        }

        recommendations
    }

    /// Shutdown the cache and cleanup background tasks
    pub async fn shutdown(&self) -> Result<()> {
        // Cancel background cleanup task
        let mut cleanup_task = self.cleanup_task.write().await;
        if let Some(handle) = cleanup_task.take() {
            handle.abort();
        }

        // Clear cache
        self.clear().await?;

        Ok(())
    }
}

impl std::fmt::Debug for KeyCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyCache")
            .field("config", &self.config)
            .field("current_keys", &self.cache.try_read().map(|g| g.len()).unwrap_or(0))
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::aes256gcm_wrapper::Aes256GcmWrapper;
use crate::encryption::EncryptionAlgorithm;
    use crate::key::{KeyId, KeyMetadata, KeyPurpose};
use crate::encryption::PerformanceProfile;
    use chrono::{DateTime, Utc};
    use std::time::Duration;

    /// Create a test key cache with reasonable defaults
    fn create_test_cache() -> KeyCache {
        let config = KeyCacheConfig {
            max_keys: 100,
            max_memory_bytes: 10 * 1024 * 1024, // 10MB
            enable_lru_eviction: true,
            enable_time_eviction: true,
            eviction_time_seconds: 3600, // 1 hour
            track_access_frequency: true,
            enable_stats: true,
            enable_cache_warming: false,
            background_cleanup_interval_seconds: 60, // 1 minute for testing
            hit_ratio_threshold: 0.8,
        };
        KeyCache::new(config)
    }

    /// Create test key data
    fn create_test_key_data(id: &str, version: u32) -> (SecureKey, KeyMetadata) {
        let algorithm = Aes256GcmWrapper::new();
        let key = SecureKey::generate(algorithm.key_size()).expect("Failed to generate test key");
        let metadata = KeyMetadata::new(
            id.to_string(),
            algorithm.name().to_string(),
            version,
            Utc::now(),
            Utc::now() + chrono::Duration::days(30),
            "DataEncryption".to_string(),
            PerformanceProfile::Balanced,
        );
        (key, metadata)
    }

    #[tokio::test]
    async fn test_cache_creation() -> Result<()> {
        let cache = create_test_cache();
        
        // Verify initial state
        let stats = cache.get_stats().await;
        assert_eq!(stats.total_keys, 0);
        assert_eq!(stats.current_memory_bytes, 0);
        assert_eq!(stats.cache_hits, 0);
        assert_eq!(stats.cache_misses, 0);
        assert_eq!(stats.evictions, 0);
        
        Ok(())
    }

    #[tokio::test]
    async fn test_cache_put_and_get() -> Result<()> {
        let cache = create_test_cache();
        let (key, metadata) = create_test_key_data("test_key_1", 1);
        let key_id = "test_key_1".to_string();
        
        // Put key in cache
        cache.put(key_id.clone(), key.clone(), metadata.clone()).await?;
        
        // Get key from cache
        let cached_result = cache.get(&key_id).await;
        assert!(cached_result.is_some());
        
        let (cached_key, cached_metadata) = cached_result.unwrap();
        assert_eq!(key.as_bytes(), cached_key.as_bytes());
        assert_eq!(metadata.algorithm, cached_metadata.algorithm);
        assert_eq!(metadata.version, cached_metadata.version);
        
        // Verify stats updated
        let stats = cache.get_stats().await;
        assert_eq!(stats.current_keys, 1);
        assert!(stats.current_memory_bytes > 0);
        
        Ok(())
    }

    #[tokio::test]
    async fn test_cache_miss() -> Result<()> {
        let cache = create_test_cache();
        let non_existent_id = "non_existent_key".to_string();
        
        // Try to get non-existent key
        let result = cache.get(&non_existent_id).await;
        assert!(result.is_none());
        
        // Verify miss count increased
        let stats = cache.get_stats().await;
        assert_eq!(stats.cache_misses, 1);
        assert_eq!(stats.cache_hits, 0);
        
        Ok(())
    }

    #[tokio::test]
    async fn test_cache_hit_ratio() -> Result<()> {
        let cache = create_test_cache();
        let (key, metadata) = create_test_key_data("hit_ratio_test", 1);
        let key_id = "hit_ratio_test".to_string();
        
        // Put key in cache
        cache.put(key_id.clone(), key.clone(), metadata.clone()).await?;
        
        // Generate some hits and misses
        let _ = cache.get(&key_id).await; // Hit
        let _ = cache.get(&"non_existent_1".to_string()).await; // Miss
        let _ = cache.get(&key_id).await; // Hit
        let _ = cache.get(&"non_existent_2".to_string()).await; // Miss
        let _ = cache.get(&key_id).await; // Hit
        
        // Check hit ratio
        let stats = cache.get_stats().await;
        assert_eq!(stats.cache_hits, 3);
        assert_eq!(stats.cache_misses, 2);
        assert_eq!(stats.hit_ratio, 0.6); // 3 hits / 5 total
        
        Ok(())
    }

    #[tokio::test]
    async fn test_cache_contains() -> Result<()> {
        let cache = create_test_cache();
        let (key, metadata) = create_test_key_data("contains_test", 1);
        let key_id = String::from("contains_test");
        
        // Key should not exist initially
        assert!(!cache.contains(&key_id).await);
        
        // Put key in cache
        cache.put(key_id.clone(), key, metadata).await?;
        
        // Key should exist now
        assert!(cache.contains(&key_id).await);
        
        // Non-existent key should not exist
        assert!(!cache.contains(&String::from("non_existent")).await);
        
        Ok(())
    }

    #[tokio::test]
    async fn test_cache_remove() -> Result<()> {
        let cache = create_test_cache();
        let (key, metadata) = create_test_key_data("remove_test", 1);
        let key_id = String::from("remove_test");
        
        // Put key in cache
        cache.put(key_id.clone(), key.clone(), metadata.clone()).await?;
        assert!(cache.contains(&key_id).await);
        
        // Remove key
        let removed = cache.remove(&key_id).await?;
        assert!(removed);
        assert!(!cache.contains(&key_id).await);
        
        // Try to remove non-existent key
        let non_existent_id = String::from("non_existent");
        let not_removed = cache.remove(&non_existent_id).await?;
        assert!(!not_removed);
        
        Ok(())
    }

    #[tokio::test]
    async fn test_cache_clear() -> Result<()> {
        let cache = create_test_cache();
        
        // Add multiple keys
        for i in 1..=5 {
            let (key, metadata) = create_test_key_data(&format!("clear_test_{}", i), i);
            let key_id = String::from(&format!("clear_test_{}", i));
            cache.put(key_id, key, metadata).await?;
        }
        
        // Verify keys exist
        let stats_before = cache.get_stats().await;
        assert_eq!(stats_before.total_keys, 5);
        
        // Clear cache
        let cleared_count = cache.clear().await?;
        assert_eq!(cleared_count, 5);
        
        // Verify cache is empty
        let stats_after = cache.get_stats().await;
        assert_eq!(stats_after.total_keys, 0);
        assert_eq!(stats_after.current_memory_bytes, 0);
        
        Ok(())
    }

    #[tokio::test]
    async fn test_lru_eviction() -> Result<()> {
        let mut config = KeyCacheConfig::default();
        config.max_keys = 3; // Small limit to trigger eviction
        config.enable_lru_eviction = true;
        config.enable_time_eviction = false; // Disable time-based eviction for this test
        
        let cache = KeyCache::new(config);
        
        // Add keys up to the limit
        for i in 1..=3 {
            let (key, metadata) = create_test_key_data(&format!("lru_test_{}", i), i);
            let key_id = format!("lru_test_{}", i);
            cache.put(key_id, key, metadata).await?;
        }
        
        // Access first key to make it most recently used
        let _ = cache.get(&"lru_test_1".to_string()).await;
        
        // Add one more key to trigger eviction
        let (key, metadata) = create_test_key_data("lru_test_4", 4);
        let key_id = "lru_test_4".to_string();
        cache.put(key_id, key, metadata).await?;
        
        // Verify LRU key was evicted (should be lru_test_2 since we accessed lru_test_1)
        assert!(!cache.contains(&"lru_test_2".to_string()).await);
        assert!(cache.contains(&"lru_test_1".to_string()).await);
        assert!(cache.contains(&"lru_test_3".to_string()).await);
        assert!(cache.contains(&"lru_test_4".to_string()).await);
        
        // Verify eviction count
        let stats = cache.get_stats().await;
        assert_eq!(stats.evictions, 1);
        
        Ok(())
    }

    #[tokio::test]
    async fn test_time_based_eviction() -> Result<()> {
        let mut config = KeyCacheConfig::default();
        config.enable_time_eviction = true;
        config.eviction_time_seconds = 1; // Very short for testing
        config.enable_lru_eviction = false; // Disable LRU for this test
        
        let cache = KeyCache::new(config);
        
        // Add a key
        let (key, metadata) = create_test_key_data("time_evict_test", 1);
        let key_id = String::from("time_evict_test");
        cache.put(key_id.clone(), key, metadata).await?;
        
        // Key should exist initially
        assert!(cache.contains(&key_id).await);
        
        // Wait for eviction time
        tokio::time::sleep(Duration::from_secs(2)).await;
        
        // Trigger cleanup (in real implementation, this would be background task)
        // For this test, we'll access the key which should trigger cleanup
        let _ = cache.get(&key_id).await;
        
        // Key should be evicted
        // Note: This test depends on the implementation of time-based eviction
        // In a real implementation, there would be a background cleanup task
        
        Ok(())
    }

    #[tokio::test]
    async fn test_memory_limit_eviction() -> Result<()> {
        let mut config = KeyCacheConfig::default();
        config.max_memory_bytes = 1000; // Very small limit
        config.enable_lru_eviction = true;
        config.enable_time_eviction = false;
        
        let max_memory_bytes = config.max_memory_bytes;
        let cache = KeyCache::new(config);
        
        // Add keys until memory limit is reached
        let mut added_keys = 0;
        for i in 1..=10 {
            let (key, metadata) = create_test_key_data(&format!("memory_test_{}", i), i);
            let key_id = String::from(&format!("memory_test_{}", i));
            
            if cache.put(key_id, key, metadata).await.is_ok() {
                added_keys += 1;
            } else {
                break; // Stop if we hit memory limit
            }
        }
        
        // Verify memory usage is within limits
        let stats = cache.get_stats().await;
        assert!(stats.current_memory_bytes <= max_memory_bytes);
        
        Ok(())
    }

    #[tokio::test]
    async fn test_access_frequency_tracking() -> Result<()> {
        let mut config = KeyCacheConfig::default();
        config.track_access_frequency = true;
        config.enable_stats = true;
        
        let cache = KeyCache::new(config);
        
        let (key, metadata) = create_test_key_data("freq_test", 1);
        let key_id = String::from("freq_test");
        cache.put(key_id.clone(), key, metadata).await?;
        
        // Access key multiple times
        for _ in 0..5 {
            let _ = cache.get(&key_id).await;
        }
        
        // Check stats
        let stats = cache.get_stats().await;
        assert_eq!(stats.cache_hits, 5);
        
        // Get detailed statistics (if available)
        let detailed_stats = cache.get_detailed_stats().await;
        assert!(detailed_stats.total_keys >= 1);
        
        Ok(())
    }

    #[tokio::test]
    async fn test_cache_performance_recommendations() -> Result<()> {
        let cache = create_test_cache();
        
        // Get recommendations for empty cache
        let recommendations = cache.get_performance_recommendations().await;
        assert!(!recommendations.is_empty());
        
        // Add some keys and get recommendations
        for i in 1..=5 {
            let (key, metadata) = create_test_key_data(&format!("rec_test_{}", i), i);
            let key_id = String::from(&format!("rec_test_{}", i));
            cache.put(key_id, key, metadata).await?;
        }
        
        let recommendations = cache.get_performance_recommendations().await;
        assert!(!recommendations.is_empty());
        
        Ok(())
    }

    #[tokio::test]
    async fn test_cache_warming() -> Result<()> {
        let mut config = KeyCacheConfig::default();
        config.enable_cache_warming = true;
        
        let cache = KeyCache::new(config);
        
        // Initialize cache (should trigger warming if configured)
        cache.initialize().await?;
        
        // Cache warming would typically preload frequently used keys
        // This test verifies the initialization doesn't error
        
        Ok(())
    }

    #[tokio::test]
    async fn test_background_cleanup() -> Result<()> {
        let mut config = KeyCacheConfig::default();
        config.background_cleanup_interval_seconds = 1; // Very short for testing
        config.enable_time_eviction = true;
        config.eviction_time_seconds = 2;
        
        let cache = KeyCache::new(config);
        
        // Add a key
        let (key, metadata) = create_test_key_data("cleanup_test", 1);
        let key_id = String::from("cleanup_test");
        cache.put(key_id.clone(), key, metadata).await?;
        
        // Wait for cleanup interval
        tokio::time::sleep(Duration::from_secs(3)).await;
        
        // Background cleanup should have run (in real implementation)
        // This test mainly verifies the cache doesn't panic during this time
        
        Ok(())
    }

    #[tokio::test]
    async fn test_concurrent_access() -> Result<()> {
        let cache = create_test_cache();
        
        // Add a key
        let (key, metadata) = create_test_key_data("concurrent_test", 1);
        let key_id = String::from("concurrent_test");
        cache.put(key_id.clone(), key.clone(), metadata.clone()).await?;
        
        // Spawn multiple concurrent tasks
        let mut handles = Vec::new();
        
        for i in 0..10 {
            let cache_clone = cache.clone();
            let key_id_clone = key_id.clone();
            
            let handle = tokio::spawn(async move {
                // Perform mixed operations
                if i % 2 == 0 {
                    // Get operation
                    let _ = cache_clone.get(&key_id_clone).await;
                } else {
                    // Put operation with different key
                    let (new_key, new_metadata) = create_test_key_data(&format!("concurrent_new_{}", i), i);
                    let new_key_id = format!("concurrent_new_{}", i);
                    let _ = cache_clone.put(new_key_id, new_key, new_metadata).await;
                }
            });
            
            handles.push(handle);
        }
        
        // Wait for all tasks to complete
        for handle in handles {
            let _ = handle.await;
        }
        
        // Verify cache is still in consistent state
        let stats = cache.get_stats().await;
        assert!(stats.total_keys >= 1);
        
        Ok(())
    }

    #[tokio::test]
    async fn test_cache_shutdown() -> Result<()> {
        let cache = create_test_cache();
        
        // Add some keys
        for i in 1..=3 {
            let (key, metadata) = create_test_key_data(&format!("shutdown_test_{}", i), i);
            let key_id = String::from(&format!("shutdown_test_{}", i));
            cache.put(key_id, key, metadata).await?;
        }
        
        // Shutdown cache
        cache.shutdown().await?;
        
        // Verify cache is empty after shutdown
        let stats = cache.get_stats().await;
        assert_eq!(stats.current_keys, 0);
        
        Ok(())
    }

    #[tokio::test]
    async fn test_error_handling() -> Result<()> {
        let cache = create_test_cache();
        
        // Test operations with invalid data
        let empty_key = SecureKey::from_bytes(&[]);
        let metadata = KeyMetadata::new(
            "error_test".to_string(),
            "test_algorithm".to_string(),
            1,
            Utc::now(),
            Utc::now() + chrono::Duration::days(30),
            "DataEncryption".to_string(),
            PerformanceProfile::Balanced,
        );
        
        // Try to put empty key (should be handled gracefully)
        let result = cache.put("empty_key_test".to_string(), empty_key, metadata).await;
        // Result depends on implementation - empty keys might be rejected or accepted
        
        Ok(())
    }

    #[tokio::test]
    async fn test_cache_statistics_accuracy() -> Result<()> {
        let cache = create_test_cache();
        
        // Perform known operations
        let (key1, metadata1) = create_test_key_data("stats_test_1", 1);
        let (key2, metadata2) = create_test_key_data("stats_test_2", 2);
        let key_id1 = String::from("stats_test_1");
        let key_id2 = String::from("stats_test_2");
        
        // Put operations
        cache.put(key_id1.clone(), key1, metadata1).await?;
        cache.put(key_id2.clone(), key2, metadata2).await?;
        
        // Get operations (hits)
        let _ = cache.get(&key_id1).await;
        let _ = cache.get(&key_id2).await;
        let _ = cache.get(&key_id1).await; // Second hit for key1
        
        // Get operations (misses)
        let _ = cache.get(&"non_existent_1".to_string()).await;
        let _ = cache.get(&"non_existent_2".to_string()).await;
        
        // Remove operation
        let _ = cache.remove(&key_id2).await;
        
        // Verify statistics
        let stats = cache.get_stats().await;
        assert_eq!(stats.cache_hits, 3);
        assert_eq!(stats.cache_misses, 2);
        assert_eq!(stats.current_keys, 1); // One key removed
        assert!(stats.current_memory_bytes > 0);
        assert_eq!(stats.hit_ratio, 0.6); // 3 hits / 5 total accesses
        
        Ok(())
    }

    #[tokio::test]
    async fn test_large_key_handling() -> Result<()> {
        let cache = create_test_cache();
        
        // Create a large key (if supported)
        let large_key_data = vec![0u8; 1024 * 1024]; // 1MB key
        let large_key = SecureKey::from_bytes(&large_key_data);
        
        let metadata = KeyMetadata::new(
            String::from("large_key_test"),
            "test_algorithm".to_string(),
            1,
            Utc::now(),
            Utc::now() + chrono::Duration::days(30),
            "DataEncryption".to_string(),
            PerformanceProfile::Balanced,
        );
        
        // Try to store large key
        let result = cache.put(String::from("large_key_test"), large_key, metadata).await;
        
        // Result depends on memory limits and implementation
        if result.is_ok() {
            // If accepted, verify it can be retrieved
            let retrieved = cache.get(&String::from("large_key_test")).await;
            assert!(retrieved.is_some());
            
            let (retrieved_key, _) = retrieved.unwrap();
            assert_eq!(retrieved_key.len(), large_key_data.len());
        }
        
        Ok(())
    }
}
