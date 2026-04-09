//! Hybrid cache implementation for Fortress
//!
//! This module provides a multi-tier caching system that combines local
//! in-memory caching with distributed backends for optimal performance.

use crate::error::Result;
use crate::distributed_cache::{DistributedCache, CacheBackend};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::sync::RwLock;
use chrono::{DateTime, Utc};

/// Hybrid cache configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HybridCacheConfig {
    /// Local cache configuration
    pub local_config: crate::distributed_cache::DistributedCacheConfig,
    /// Distributed cache configuration
    pub distributed_config: crate::distributed_cache::DistributedCacheConfig,
    /// Cache coordination strategy
    pub coordination_strategy: CoordinationStrategy,
    /// Write-through strategy
    pub write_strategy: WriteStrategy,
    /// Read repair strategy
    pub read_repair: bool,
    /// Cache warming on startup
    pub enable_cache_warming: bool,
    /// Background sync interval in seconds
    pub background_sync_interval_seconds: u64,
    /// Maximum local cache size
    pub max_local_cache_size: usize,
    /// TTL for local cache entries
    pub local_ttl_seconds: u64,
    /// Enable compression for distributed cache
    pub enable_compression: bool,
    /// Metrics collection
    pub enable_metrics: bool,
}

impl Default for HybridCacheConfig {
    fn default() -> Self {
        Self {
            local_config: crate::distributed_cache::DistributedCacheConfig {
                backend: CacheBackend::InMemory,
                max_cache_size: 10000,
                default_ttl_seconds: 300, // 5 minutes
                ..Default::default()
            },
            distributed_config: crate::distributed_cache::DistributedCacheConfig {
                backend: CacheBackend::InMemory,
                default_ttl_seconds: 3600, // 1 hour
                ..Default::default()
            },
            coordination_strategy: CoordinationStrategy::WriteThrough,
            write_strategy: WriteStrategy::WriteThrough,
            read_repair: true,
            enable_cache_warming: false,
            background_sync_interval_seconds: 60,
            max_local_cache_size: 10000,
            local_ttl_seconds: 300,
            enable_compression: true,
            enable_metrics: true,
        }
    }
}

/// Cache coordination strategies
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum CoordinationStrategy {
    /// Write through - update both caches immediately
    WriteThrough,
    /// Write behind - update local first, async to distributed
    WriteBehind,
    /// Write around - skip local cache, write directly to distributed
    WriteAround,
    /// Refresh ahead - proactively refresh popular keys
    RefreshAhead,
}

/// Write strategies
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum WriteStrategy {
    /// Write through - write to both caches
    WriteThrough,
    /// Write back - write to local, async to distributed
    WriteBack,
    /// Write around - write to distributed only
    WriteAround,
}

/// Cache entry metadata
#[derive(Debug, Clone)]
struct HybridCacheEntry {
    /// Cache value
    value: Vec<u8>,
    /// Creation timestamp
    created_at: DateTime<Utc>,
    /// Last access timestamp
    last_accessed: DateTime<Utc>,
    /// Access count
    access_count: u64,
    /// TTL in seconds
    ttl_seconds: u64,
    /// Whether this entry is dirty (needs sync to distributed)
    is_dirty: bool,
    /// Entry size in bytes
    size_bytes: usize,
    /// Last sync timestamp
    last_sync: Option<DateTime<Utc>>,
}

/// Hybrid cache statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HybridCacheStatistics {
    /// Local cache statistics
    pub local_stats: crate::distributed_cache::CacheStatistics,
    /// Distributed cache statistics
    pub distributed_stats: crate::distributed_cache::CacheStatistics,
    /// Coordination statistics
    pub coordination_stats: CoordinationStats,
    /// Cache hit breakdown
    pub hit_breakdown: HitBreakdown,
    /// Sync statistics
    pub sync_stats: SyncStats,
}

/// Coordination statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoordinationStats {
    /// Total coordinated operations
    pub total_operations: u64,
    /// Write-through operations
    pub write_through_ops: u64,
    /// Write-behind operations
    pub write_behind_ops: u64,
    /// Write-around operations
    pub write_around_ops: u64,
    /// Read repair operations
    pub read_repair_ops: u64,
    /// Cache warming operations
    pub cache_warming_ops: u64,
    /// Background sync operations
    pub background_sync_ops: u64,
}

/// Hit breakdown statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HitBreakdown {
    /// Local cache hits
    pub local_hits: u64,
    /// Distributed cache hits
    pub distributed_hits: u64,
    /// Total misses
    pub total_misses: u64,
    /// Local hit ratio
    pub local_hit_ratio: f64,
    /// Distributed hit ratio
    pub distributed_hit_ratio: f64,
    /// Overall hit ratio
    pub overall_hit_ratio: f64,
}

/// Sync statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncStats {
    /// Successful syncs
    pub successful_syncs: u64,
    /// Failed syncs
    pub failed_syncs: u64,
    /// Pending syncs
    pub pending_syncs: u64,
    /// Average sync time in microseconds
    pub avg_sync_time_us: f64,
    /// Last sync timestamp
    pub last_sync: Option<DateTime<Utc>>,
}

/// Hybrid cache implementation
#[derive(Debug)]
pub struct HybridCache {
    config: HybridCacheConfig,
    /// Local cache
    local_cache: Arc<dyn DistributedCache>,
    /// Distributed cache
    distributed_cache: Arc<dyn DistributedCache>,
    /// Local cache entries metadata
    local_entries: Arc<RwLock<HashMap<String, HybridCacheEntry>>>,
    /// Dirty entries that need sync
    dirty_entries: Arc<RwLock<HashSet<String>>>,
    /// Statistics
    stats: Arc<RwLock<HybridCacheStatistics>>,
    /// Background sync task handle
    sync_task: Arc<RwLock<Option<tokio::task::JoinHandle<()>>>>,
}

impl HybridCache {
    /// Create a new hybrid cache
    pub async fn new(config: HybridCacheConfig) -> Result<Self> {
        // Create local cache
        let local_cache = crate::distributed_cache::create_distributed_cache(config.local_config.clone()).await?;
        let distributed_cache = crate::distributed_cache::create_distributed_cache(config.distributed_config.clone()).await?;
        
        let stats = Arc::new(RwLock::new(HybridCacheStatistics {
            local_stats: crate::distributed_cache::CacheStatistics {
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
            },
            distributed_stats: crate::distributed_cache::CacheStatistics {
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
            },
            coordination_stats: CoordinationStats {
                total_operations: 0,
                write_through_ops: 0,
                write_behind_ops: 0,
                write_around_ops: 0,
                read_repair_ops: 0,
                cache_warming_ops: 0,
                background_sync_ops: 0,
            },
            hit_breakdown: HitBreakdown {
                local_hits: 0,
                distributed_hits: 0,
                total_misses: 0,
                local_hit_ratio: 0.0,
                distributed_hit_ratio: 0.0,
                overall_hit_ratio: 0.0,
            },
            sync_stats: SyncStats {
                successful_syncs: 0,
                failed_syncs: 0,
                pending_syncs: 0,
                avg_sync_time_us: 0.0,
                last_sync: None,
            },
        }));

        let hybrid_cache = Self {
            config,
            local_cache: Arc::from(local_cache),
            distributed_cache: Arc::from(distributed_cache),
            local_entries: Arc::new(RwLock::new(HashMap::new())),
            dirty_entries: Arc::new(RwLock::new(HashSet::new())),
            stats,
            sync_task: Arc::new(RwLock::new(None)),
        };

        // Start background sync task
        hybrid_cache.start_background_sync().await?;

        Ok(hybrid_cache)
    }

    /// Start background sync task
    async fn start_background_sync(&self) -> Result<()> {
        if self.config.background_sync_interval_seconds == 0 {
            return Ok(());
        }

        let local_entries = self.local_entries.clone();
        let dirty_entries = self.dirty_entries.clone();
        let distributed_cache = self.distributed_cache.clone();
        let stats = self.stats.clone();
        let interval_seconds = self.config.background_sync_interval_seconds;

        let handle = tokio::spawn(async move {
            let mut interval = tokio::time::interval(
                std::time::Duration::from_secs(interval_seconds)
            );

            loop {
                interval.tick().await;

                // Sync dirty entries
                let dirty_keys = {
                    let dirty = dirty_entries.read().await;
                    dirty.clone()
                };

                if !dirty_keys.is_empty() {
                    let start_time = std::time::Instant::now();
                    let mut synced_count = 0;
                    let mut failed_count = 0;

                    for key in &dirty_keys {
                        let local_entries_guard = local_entries.read().await;
                        if let Some(entry) = local_entries_guard.get(key) {
                            match distributed_cache.set(key, entry.value.clone(), Some(entry.ttl_seconds)).await {
                                Ok(_) => {
                                    synced_count += 1;
                                }
                                Err(_) => {
                                    failed_count += 1;
                                }
                            }
                        }
                    }

                    // Update statistics
                    {
                        let mut stats_guard = stats.write().await;
                        stats_guard.coordination_stats.background_sync_ops += 1;
                        stats_guard.sync_stats.successful_syncs += synced_count;
                        stats_guard.sync_stats.failed_syncs += failed_count;
                        stats_guard.sync_stats.last_sync = Some(Utc::now());
                        
                        let elapsed_us = start_time.elapsed().as_micros() as f64;
                        stats_guard.sync_stats.avg_sync_time_us = 
                            (stats_guard.sync_stats.avg_sync_time_us * (stats_guard.sync_stats.successful_syncs - 1) as f64 + elapsed_us) 
                            / stats_guard.sync_stats.successful_syncs as f64;
                    }

                    // Clear synced entries from dirty set
                    {
                        let mut dirty = dirty_entries.write().await;
                        for key in &dirty_keys {
                            dirty.remove(key);
                        }
                    }
                }
            }
        });

        let mut sync_task = self.sync_task.write().await;
        *sync_task = Some(handle);

        Ok(())
    }

    /// Update hit breakdown statistics
    async fn update_hit_breakdown(&self, local_hit: bool, distributed_hit: bool) {
        let mut stats = self.stats.write().await;
        
        if local_hit {
            stats.hit_breakdown.local_hits += 1;
        } else if distributed_hit {
            stats.hit_breakdown.distributed_hits += 1;
        } else {
            stats.hit_breakdown.total_misses += 1;
        }

        let total_requests = stats.hit_breakdown.local_hits + stats.hit_breakdown.distributed_hits + stats.hit_breakdown.total_misses;
        
        if total_requests > 0 {
            stats.hit_breakdown.local_hit_ratio = stats.hit_breakdown.local_hits as f64 / total_requests as f64;
            stats.hit_breakdown.distributed_hit_ratio = stats.hit_breakdown.distributed_hits as f64 / total_requests as f64;
            stats.hit_breakdown.overall_hit_ratio = (stats.hit_breakdown.local_hits + stats.hit_breakdown.distributed_hits) as f64 / total_requests as f64;
        }
    }

    /// Check if a local entry is expired
    fn is_entry_expired(&self, entry: &HybridCacheEntry) -> bool {
        let now = Utc::now();
        let age_seconds = (now - entry.created_at).num_seconds();
        age_seconds > entry.ttl_seconds as i64
    }

    /// Clean up expired local entries
    async fn cleanup_expired_entries(&self) -> Result<usize> {
        let mut expired_keys = Vec::new();
        
        {
            let local_entries = self.local_entries.read().await;
            
            for (key, entry) in local_entries.iter() {
                if self.is_entry_expired(entry) {
                    expired_keys.push(key.clone());
                }
            }
        }

        // Remove expired entries
        for key in &expired_keys {
            let _ = self.local_cache.delete(key).await;
            
            let mut local_entries = self.local_entries.write().await;
            local_entries.remove(key);
            
            let mut dirty = self.dirty_entries.write().await;
            dirty.remove(key);
        }

        Ok(expired_keys.len())
    }
}

#[async_trait]
impl DistributedCache for HybridCache {
    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>> {
        // Try local cache first
        match self.local_cache.get(key).await {
            Ok(Some(value)) => {
                // Check if entry is still valid
                let local_entries = self.local_entries.read().await;
                if let Some(entry) = local_entries.get(key) {
                    if !self.is_entry_expired(entry) {
                        self.update_hit_breakdown(true, false).await;
                        return Ok(Some(value));
                    }
                }
                
                // Entry is expired, fall through to distributed cache
            }
            Ok(None) => {
                // Not in local cache, try distributed cache
            }
            Err(_) => {
                // Local cache error, try distributed cache
            }
        }

        // Try distributed cache
        match self.distributed_cache.get(key).await {
            Ok(Some(value)) => {
                // Cache in local for future reads
                let entry = HybridCacheEntry {
                    value: value.clone(),
                    created_at: Utc::now(),
                    last_accessed: Utc::now(),
                    access_count: 1,
                    ttl_seconds: self.config.local_ttl_seconds,
                    is_dirty: false,
                    size_bytes: value.len(),
                    last_sync: Some(Utc::now()),
                };

                {
                    let mut local_entries = self.local_entries.write().await;
                    local_entries.insert(key.to_string(), entry);
                }

                // Store in local cache
                let _ = self.local_cache.set(key, value.clone(), Some(self.config.local_ttl_seconds)).await;

                self.update_hit_breakdown(false, true).await;
                Ok(Some(value))
            }
            Ok(None) => {
                self.update_hit_breakdown(false, false).await;
                Ok(None)
            }
            Err(e) => Err(e),
        }
    }

    async fn set(&self, key: &str, value: Vec<u8>, ttl_seconds: Option<u64>) -> Result<()> {
        let ttl = ttl_seconds.unwrap_or(self.config.local_ttl_seconds);
        
        // Create local entry
        let entry = HybridCacheEntry {
            value: value.clone(),
            created_at: Utc::now(),
            last_accessed: Utc::now(),
            access_count: 0,
            ttl_seconds: ttl,
            is_dirty: false,
            size_bytes: value.len(),
            last_sync: None,
        };

        // Store in local cache
        self.local_cache.set(key, value.clone(), Some(ttl)).await?;

        // Store in local entries metadata
        {
            let mut local_entries = self.local_entries.write().await;
            local_entries.insert(key.to_string(), entry);
        }

        // Handle write strategy
        match self.config.write_strategy {
            WriteStrategy::WriteThrough => {
                // Write to both caches immediately
                self.distributed_cache.set(key, value, ttl_seconds).await?;
                
                let mut stats = self.stats.write().await;
                stats.coordination_stats.write_through_ops += 1;
            }
            WriteStrategy::WriteBack => {
                // Mark as dirty for async sync
                {
                    let mut dirty = self.dirty_entries.write().await;
                    dirty.insert(key.to_string());
                }
                
                let mut local_entries = self.local_entries.write().await;
                if let Some(entry) = local_entries.get_mut(key) {
                    entry.is_dirty = true;
                }
                
                let mut stats = self.stats.write().await;
                stats.coordination_stats.write_behind_ops += 1;
            }
            WriteStrategy::WriteAround => {
                // Write only to distributed cache
                self.distributed_cache.set(key, value, ttl_seconds).await?;
                
                let mut stats = self.stats.write().await;
                stats.coordination_stats.write_around_ops += 1;
            }
        }

        let mut stats = self.stats.write().await;
        stats.coordination_stats.total_operations += 1;

        Ok(())
    }

    async fn delete(&self, key: &str) -> Result<bool> {
        // Delete from local cache
        let local_deleted = self.local_cache.delete(key).await?;
        
        // Delete from local entries metadata
        {
            let mut local_entries = self.local_entries.write().await;
            local_entries.remove(key);
        }
        
        // Remove from dirty entries
        {
            let mut dirty = self.dirty_entries.write().await;
            dirty.remove(key);
        }
        
        // Delete from distributed cache
        let distributed_deleted = self.distributed_cache.delete(key).await?;

        Ok(local_deleted || distributed_deleted)
    }

    async fn exists(&self, key: &str) -> Result<bool> {
        // Check local cache first
        if let Ok(true) = self.local_cache.exists(key).await {
            // Verify entry is not expired
            let local_entries = self.local_entries.read().await;
            if let Some(entry) = local_entries.get(key) {
                if !self.is_entry_expired(entry) {
                    return Ok(true);
                }
            }
        }
        
        // Check distributed cache
        self.distributed_cache.exists(key).await
    }

    async fn clear(&self) -> Result<()> {
        // Clear local cache
        self.local_cache.clear().await?;
        
        // Clear local entries metadata
        {
            let mut local_entries = self.local_entries.write().await;
            local_entries.clear();
        }
        
        // Clear dirty entries
        {
            let mut dirty = self.dirty_entries.write().await;
            dirty.clear();
        }
        
        // Clear distributed cache
        self.distributed_cache.clear().await?;

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
        // For increment, we need to go to distributed cache to ensure consistency
        let result = self.distributed_cache.increment(key, delta).await?;
        
        // Update local cache with new value
        let new_value = result.to_string().into_bytes();
        let _ = self.set(key, new_value, None).await;
        
        Ok(result)
    }

    async fn get_statistics(&self) -> Result<crate::distributed_cache::CacheStatistics> {
        // Update local stats
        let local_stats = self.local_cache.get_statistics().await?;
        
        // Update distributed stats
        let distributed_stats = self.distributed_cache.get_statistics().await?;
        
        // Update our statistics
        {
            let mut stats = self.stats.write().await;
            stats.local_stats = local_stats;
            stats.distributed_stats = distributed_stats;
        }
        
        // Return combined statistics
        let stats = self.stats.read().await;
        Ok(crate::distributed_cache::CacheStatistics {
            total_entries: stats.local_stats.total_entries + stats.distributed_stats.total_entries,
            cache_size_bytes: stats.local_stats.cache_size_bytes + stats.distributed_stats.cache_size_bytes,
            hits: stats.local_stats.hits + stats.distributed_stats.hits,
            misses: stats.local_stats.misses + stats.distributed_stats.misses,
            hit_ratio: if stats.local_stats.hits + stats.local_stats.misses + stats.distributed_stats.hits + stats.distributed_stats.misses > 0 {
                (stats.local_stats.hits + stats.distributed_stats.hits) as f64 / 
                (stats.local_stats.hits + stats.local_stats.misses + stats.distributed_stats.hits + stats.distributed_stats.misses) as f64
            } else {
                0.0
            },
            evictions: stats.local_stats.evictions + stats.distributed_stats.evictions,
            sets: stats.local_stats.sets + stats.distributed_stats.sets,
            deletes: stats.local_stats.deletes + stats.distributed_stats.deletes,
            avg_get_time_us: (stats.local_stats.avg_get_time_us + stats.distributed_stats.avg_get_time_us) / 2.0,
            avg_set_time_us: (stats.local_stats.avg_set_time_us + stats.distributed_stats.avg_set_time_us) / 2.0,
            last_reset: stats.local_stats.last_reset,
        })
    }

    async fn reset_statistics(&self) -> Result<()> {
        self.local_cache.reset_statistics().await?;
        self.distributed_cache.reset_statistics().await?;
        
        let mut stats = self.stats.write().await;
        stats.coordination_stats = CoordinationStats {
            total_operations: 0,
            write_through_ops: 0,
            write_behind_ops: 0,
            write_around_ops: 0,
            read_repair_ops: 0,
            cache_warming_ops: 0,
            background_sync_ops: 0,
        };
        stats.hit_breakdown = HitBreakdown {
            local_hits: 0,
            distributed_hits: 0,
            total_misses: 0,
            local_hit_ratio: 0.0,
            distributed_hit_ratio: 0.0,
            overall_hit_ratio: 0.0,
        };
        stats.sync_stats = SyncStats {
            successful_syncs: 0,
            failed_syncs: 0,
            pending_syncs: 0,
            avg_sync_time_us: 0.0,
            last_sync: None,
        };
        
        Ok(())
    }

    async fn health_check(&self) -> Result<bool> {
        // Check both caches
        let local_healthy = self.local_cache.health_check().await?;
        let distributed_healthy = self.distributed_cache.health_check().await?;
        
        Ok(local_healthy && distributed_healthy)
    }
}

/// Factory function to create hybrid cache
pub async fn create_hybrid_cache(config: HybridCacheConfig) -> Result<Box<dyn DistributedCache>> {
    let cache = HybridCache::new(config).await?;
    Ok(Box::new(cache))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::distributed_cache::DistributedCache;

    #[tokio::test]
    async fn test_hybrid_cache_basic_operations() {
        let config = HybridCacheConfig::default();
        let cache = HybridCache::new(config).await.unwrap();

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
    async fn test_hybrid_cache_write_through() {
        let config = HybridCacheConfig {
            write_strategy: WriteStrategy::WriteThrough,
            ..Default::default()
        };
        
        let cache = HybridCache::new(config).await.unwrap();

        let key = "write_through_test";
        let value = b"test_value".to_vec();
        
        cache.set(key, value.clone(), None).await.unwrap();
        
        // Should be in both caches
        let retrieved = cache.get(key).await.unwrap();
        assert_eq!(retrieved, Some(value));
        
        let stats = cache.get_statistics().await.unwrap();
        assert!(stats.sets > 0);
    }

    #[tokio::test]
    async fn test_hybrid_cache_write_back() {
        let config = HybridCacheConfig {
            write_strategy: WriteStrategy::WriteBack,
            background_sync_interval_seconds: 0, // Disable background sync for test
            ..Default::default()
        };
        
        let cache = HybridCache::new(config).await.unwrap();

        let key = "write_back_test";
        let value = b"test_value".to_vec();
        
        cache.set(key, value.clone(), None).await.unwrap();
        
        // Should be in local cache
        let retrieved = cache.get(key).await.unwrap();
        assert_eq!(retrieved, Some(value));
        
        // Check that it's marked as dirty
        let local_entries = cache.local_entries.read().await;
        if let Some(entry) = local_entries.get(key) {
            assert!(entry.is_dirty);
        }
    }

    #[tokio::test]
    async fn test_hybrid_cache_statistics() {
        let config = HybridCacheConfig::default();
        let cache = HybridCache::new(config).await.unwrap();

        // Perform operations
        cache.set("key1", b"value1".to_vec(), None).await.unwrap();
        cache.get("key1").await.unwrap();
        cache.get("nonexistent").await.unwrap();
        
        let stats = cache.get_statistics().await.unwrap();
        assert!(stats.sets > 0);
        assert!(stats.hits > 0);
        assert!(stats.misses > 0);
        assert!(stats.hit_ratio > 0.0);
    }

    #[tokio::test]
    async fn test_hybrid_cache_health_check() {
        let config = HybridCacheConfig::default();
        let cache = HybridCache::new(config).await.unwrap();

        let healthy = cache.health_check().await.unwrap();
        assert!(healthy);
    }

    #[tokio::test]
    async fn test_hybrid_cache_mget_mset() {
        let config = HybridCacheConfig::default();
        let cache = HybridCache::new(config).await.unwrap();

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
}
