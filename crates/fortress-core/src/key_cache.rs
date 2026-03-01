//! High-performance in-memory key cache with LRU eviction
//!
//! This module provides a sophisticated caching system for keys with
//! LRU eviction, memory management, and performance monitoring.

use crate::error::{FortressError, Result, KeyErrorCode};
use crate::key::{KeyId, KeyMetadata, SecureKey};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;

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
}

/// High-performance LRU cache for keys
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
            let elapsed_us = start_time.elapsed().as_micros() as f64;
            stats.avg_access_time_us = (stats.avg_access_time_us * (stats.hits - 1) as f64 + elapsed_us) / stats.hits as f64;
            
            Some((entry.key.clone(), entry.metadata.clone()))
        } else {
            stats.misses += 1;
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

    /// Remove a key from the cache
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
