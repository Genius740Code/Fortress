//! High-performance cache implementation for GraphQL queries
//! 
//! Provides LRU caching, intelligent eviction, and comprehensive
//! cache management for query results.

use super::query_executor::{Cache, CacheStats, QueryResult};
use crate::enhanced_error::FortressError;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Serialize, Deserialize};
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use tokio::sync::{RwLock, Mutex};
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CacheEntry {
    value: QueryResult,
    created_at: DateTime<Utc>,
    last_accessed: DateTime<Utc>,
    access_count: u64,
    ttl: Duration,
    size_bytes: usize,
}

#[derive(Debug, Clone)]
pub struct LruCache {
    entries: Arc<RwLock<HashMap<String, CacheEntry>>>,
    access_order: Arc<Mutex<VecDeque<String>>>,
    max_size: usize,
    max_memory_bytes: usize,
    current_memory_bytes: Arc<RwLock<usize>>,
    stats: Arc<RwLock<CacheInternalStats>>,
}

#[derive(Debug, Default)]
struct CacheInternalStats {
    hits: u64,
    misses: u64,
    evictions: u64,
    insertions: u64,
    expirations: u64,
}

impl LruCache {
    pub fn new(max_size: usize, max_memory_bytes: usize) -> Self {
        Self {
            entries: Arc::new(RwLock::new(HashMap::new())),
            access_order: Arc::new(Mutex::new(VecDeque::with_capacity(max_size))),
            max_size,
            max_memory_bytes,
            current_memory_bytes: Arc::new(RwLock::new(0)),
            stats: Arc::new(RwLock::new(CacheInternalStats::default())),
        }
    }

    async fn calculate_entry_size(&self, entry: &QueryResult) -> usize {
        // Estimate size based on serialized data
        serde_json::to_vec(&entry.rows)
            .map(|v| v.len())
            .unwrap_or(1024) // Default estimate if serialization fails
    }

    async fn evict_lru(&self) -> Result<(), FortressError> {
        let mut access_order = self.access_order.lock().await;
        
        if let Some(oldest_key) = access_order.pop_front() {
            drop(access_order); // Release lock before accessing entries
            
            let mut entries = self.entries.write().await;
            if let Some(removed_entry) = entries.remove(&oldest_key) {
                // Update memory usage
                let mut memory_usage = self.current_memory_bytes.write().await;
                *memory_usage = memory_usage.saturating_sub(removed_entry.size_bytes);
                
                // Update stats
                let mut stats = self.stats.write().await;
                stats.evictions += 1;
                
                tracing::debug!("Evicted cache entry: {} (size: {} bytes)", oldest_key, removed_entry.size_bytes);
            }
        }
        
        Ok(())
    }

    async fn evict_expired(&self) -> Result<(), FortressError> {
        let now = Utc::now();
        let mut expired_keys = Vec::new();
        
        // Find expired entries
        {
            let entries = self.entries.read().await;
            for (key, entry) in entries.iter() {
                if now.signed_duration_since(entry.created_at).to_std().unwrap_or(Duration::MAX) > entry.ttl {
                    expired_keys.push(key.clone());
                }
            }
        }
        
        // Remove expired entries
        if !expired_keys.is_empty() {
            let mut entries = self.entries.write().await;
            let mut access_order = self.access_order.lock().await;
            let mut memory_usage = self.current_memory_bytes.write().await;
            let mut stats = self.stats.write().await;
            
            for key in &expired_keys {
                if let Some(removed_entry) = entries.remove(key) {
                    *memory_usage = memory_usage.saturating_sub(removed_entry.size_bytes);
                    access_order.retain(|k| k != key);
                    stats.expirations += 1;
                    
                    tracing::debug!("Expired cache entry: {} (age: {})", key, 
                        now.signed_duration_since(removed_entry.created_at));
                }
            }
        }
        
        Ok(())
    }

    async fn update_access_order(&self, key: &str) {
        let mut access_order = self.access_order.lock().await;
        
        // Remove key from current position
        access_order.retain(|k| k != key);
        
        // Add key to the end (most recently accessed)
        access_order.push_back(key.to_string());
    }

    async fn enforce_memory_limit(&self) -> Result<(), FortressError> {
        let current_memory = *self.current_memory_bytes.read().await;
        
        while current_memory > self.max_memory_bytes {
            self.evict_lru().await?;
            break; // Check again in next iteration
        }
        
        Ok(())
    }

    async fn enforce_size_limit(&self) -> Result<(), FortressError> {
        let entries_count = self.entries.read().await.len();
        
        while entries_count > self.max_size {
            self.evict_lru().await?;
            break; // Check again in next iteration
        }
        
        Ok(())
    }
}

#[async_trait]
impl Cache for LruCache {
    async fn get(&self, key: &str) -> Option<QueryResult> {
        // Clean up expired entries first
        let _ = self.evict_expired().await;
        
        let mut entries = self.entries.write().await;
        
        if let Some(entry) = entries.get_mut(key) {
            let now = Utc::now();
            
            // Check if entry is expired
            if now.signed_duration_since(entry.created_at).to_std().unwrap_or(Duration::MAX) > entry.ttl {
                // Entry expired, remove it
                let removed_entry = entries.remove(key).unwrap();
                let mut memory_usage = self.current_memory_bytes.write().await;
                *memory_usage = memory_usage.saturating_sub(removed_entry.size_bytes);
                
                let mut stats = self.stats.write().await;
                stats.misses += 1;
                stats.expirations += 1;
                
                return None;
            }
            
            // Update access information
            entry.last_accessed = now;
            entry.access_count += 1;
            
            let result = entry.value.clone();
            drop(entries); // Release lock before updating access order
            
            // Update access order
            self.update_access_order(key).await;
            
            // Update stats
            let mut stats = self.stats.write().await;
            stats.hits += 1;
            
            tracing::debug!("Cache hit: {} (access count: {})", key, entry.access_count);
            
            Some(result)
        } else {
            // Update stats
            let mut stats = self.stats.write().await;
            stats.misses += 1;
            
            tracing::debug!("Cache miss: {}", key);
            None
        }
    }

    async fn set(&self, key: &str, value: &QueryResult, ttl: Duration) {
        let now = Utc::now();
        let entry_size = self.calculate_entry_size(value).await;
        
        // Check if we need to evict entries
        if self.entries.read().await.len() >= self.max_size || 
           *self.current_memory_bytes.read().await + entry_size > self.max_memory_bytes {
            let _ = self.evict_lru().await;
        }
        
        // Create new entry
        let entry = CacheEntry {
            value: value.clone(),
            created_at: now,
            last_accessed: now,
            access_count: 1,
            ttl,
            size_bytes: entry_size,
        };
        
        // Insert entry
        {
            let mut entries = self.entries.write().await;
            let mut memory_usage = self.current_memory_bytes.write().await;
            
            // Remove existing entry if present
            if let Some(old_entry) = entries.insert(key.to_string(), entry) {
                *memory_usage = memory_usage.saturating_sub(old_entry.size_bytes);
            }
            
            *memory_usage += entry_size;
        }
        
        // Update access order
        self.update_access_order(key).await;
        
        // Update stats
        let mut stats = self.stats.write().await;
        stats.insertions += 1;
        
        tracing::debug!("Cache set: {} (size: {} bytes, TTL: {:?})", key, entry_size, ttl);
    }

    async fn invalidate(&self, key: &str) {
        let mut entries = self.entries.write().await;
        let mut access_order = self.access_order.lock().await;
        let mut memory_usage = self.current_memory_bytes.write().await;
        
        if let Some(removed_entry) = entries.remove(key) {
            *memory_usage = memory_usage.saturating_sub(removed_entry.size_bytes);
            access_order.retain(|k| k != key);
            
            tracing::debug!("Cache invalidated: {}", key);
        }
    }

    async fn clear(&self) {
        let mut entries = self.entries.write().await;
        let mut access_order = self.access_order.lock().await;
        let mut memory_usage = self.current_memory_bytes.write().await;
        let mut stats = self.stats.write().await;
        
        let cleared_count = entries.len();
        entries.clear();
        access_order.clear();
        *memory_usage = 0;
        
        // Reset stats but keep hit/miss ratios
        stats.evictions += cleared_count as u64;
        
        tracing::info!("Cache cleared: {} entries", cleared_count);
    }

    async fn stats(&self) -> CacheStats {
        let entries = self.entries.read().await;
        let stats = self.stats.read().await;
        let memory_usage = *self.current_memory_bytes.read().await;
        
        CacheStats {
            entries: entries.len() as u64,
            hits: stats.hits,
            misses: stats.misses,
            evictions: stats.evictions,
            memory_usage_bytes: memory_usage as u64,
        }
    }
}

/// Multi-level cache with L1 (memory) and L2 (persistent) caching
pub struct MultiLevelCache {
    l1_cache: Arc<dyn Cache>,
    l2_cache: Option<Arc<dyn Cache>>,
    l1_hit_ratio: Arc<RwLock<f64>>,
    l2_hit_ratio: Arc<RwLock<f64>>,
}

impl MultiLevelCache {
    pub fn new(l1_cache: Arc<dyn Cache>, l2_cache: Option<Arc<dyn Cache>>) -> Self {
        Self {
            l1_cache,
            l2_cache,
            l1_hit_ratio: Arc::new(RwLock::new(0.0)),
            l2_hit_ratio: Arc::new(RwLock::new(0.0)),
        }
    }

    async fn update_hit_ratios(&self, l1_hit: bool, l2_hit: bool) {
        let mut l1_ratio = self.l1_hit_ratio.write().await;
        let mut l2_ratio = self.l2_hit_ratio.write().await;
        
        // Simple exponential moving average
        *l1_ratio = *l1_ratio * 0.9 + if l1_hit { 1.0 } else { 0.0 } * 0.1;
        *l2_ratio = *l2_ratio * 0.9 + if l2_hit { 1.0 } else { 0.0 } * 0.1;
    }
}

#[async_trait]
impl Cache for MultiLevelCache {
    async fn get(&self, key: &str) -> Option<QueryResult> {
        // Try L1 cache first
        if let Some(result) = self.l1_cache.get(key).await {
            self.update_hit_ratios(true, false).await;
            return Some(result);
        }
        
        // Try L2 cache if available
        if let Some(l2_cache) = &self.l2_cache {
            if let Some(result) = l2_cache.get(key).await {
                // Promote to L1 cache
                self.l1_cache.set(key, &result, Duration::from_secs(300)).await;
                self.update_hit_ratios(false, true).await;
                return Some(result);
            }
        }
        
        self.update_hit_ratios(false, false).await;
        None
    }

    async fn set(&self, key: &str, value: &QueryResult, ttl: Duration) {
        // Set in L1 cache
        self.l1_cache.set(key, value, ttl).await;
        
        // Set in L2 cache if available (with longer TTL)
        if let Some(l2_cache) = &self.l2_cache {
            let l2_ttl = ttl * 4; // L2 cache keeps items longer
            l2_cache.set(key, value, l2_ttl).await;
        }
    }

    async fn invalidate(&self, key: &str) {
        self.l1_cache.invalidate(key).await;
        
        if let Some(l2_cache) = &self.l2_cache {
            l2_cache.invalidate(key).await;
        }
    }

    async fn clear(&self) {
        self.l1_cache.clear().await;
        
        if let Some(l2_cache) = &self.l2_cache {
            l2_cache.clear().await;
        }
    }

    async fn stats(&self) -> CacheStats {
        let l1_stats = self.l1_cache.stats().await;
        
        // Combine stats from both levels
        let mut combined_stats = l1_stats;
        
        if let Some(l2_cache) = &self.l2_cache {
            let l2_stats = l2_cache.stats().await;
            combined_stats.entries += l2_stats.entries;
            combined_stats.memory_usage_bytes += l2_stats.memory_usage_bytes;
        }
        
        combined_stats
    }
}

/// Cache warming utility
pub struct CacheWarmer {
    cache: Arc<dyn Cache>,
    query_executor: Arc<super::query_executor::OptimizedQueryExecutor>,
}

impl CacheWarmer {
    pub fn new(
        cache: Arc<dyn Cache>,
        query_executor: Arc<super::query_executor::OptimizedQueryExecutor>,
    ) -> Self {
        Self {
            cache,
            query_executor,
        }
    }

    pub async fn warm_cache(&self, queries: Vec<String>) -> Result<(), FortressError> {
        tracing::info!("Starting cache warming with {} queries", queries.len());
        
        for (i, query) in queries.iter().enumerate() {
            tracing::debug!("Warming cache with query {}/{}: {}", i + 1, queries.len(), 
                query.chars().take(50).collect::<String>());
            
            // Execute query to populate cache
            let _ = self.query_executor.execute_query(
                &async_graphql::Context::new(),
                query.clone(),
                None,
                Some(3600), // 1 hour TTL for warmed queries
            ).await;
            
            // Small delay to prevent overwhelming the system
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        
        tracing::info!("Cache warming completed");
        Ok(())
    }

    pub async fn warm_common_queries(&self) -> Result<(), FortressError> {
        let common_queries = vec![
            "SELECT COUNT(*) FROM users".to_string(),
            "SELECT * FROM users WHERE active = true LIMIT 100".to_string(),
            "SELECT * FROM encryption_keys WHERE status = 'active'".to_string(),
            "SELECT * FROM audit_logs WHERE created_at > NOW() - INTERVAL '1 hour' LIMIT 1000".to_string(),
            "SELECT COUNT(*) FROM database_connections WHERE active = true".to_string(),
        ];
        
        self.warm_cache(common_queries).await
    }
}

/// Cache maintenance utility
pub struct CacheMaintenance {
    cache: Arc<dyn Cache>,
    maintenance_interval: Duration,
}

impl CacheMaintenance {
    pub fn new(cache: Arc<dyn Cache>, maintenance_interval: Duration) -> Self {
        Self {
            cache,
            maintenance_interval,
        }
    }

    pub async fn start_maintenance_task(self) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(self.maintenance_interval);
            
            loop {
                interval.tick().await;
                
                tracing::debug!("Running cache maintenance");
                
                // Clean up expired entries (if cache doesn't do this automatically)
                let stats = self.cache.stats().await;
                
                // Log cache statistics
                tracing::info!("Cache stats: {} entries, {} hits, {} misses, {} evictions, {} MB used",
                    stats.entries,
                    stats.hits,
                    stats.misses,
                    stats.evictions,
                    stats.memory_usage_bytes / (1024 * 1024)
                );
                
                // Trigger cleanup if eviction rate is high
                if stats.evictions > 100 {
                    tracing::warn!("High eviction rate detected, consider increasing cache size");
                }
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[tokio::test]
    async fn test_lru_cache_basic_operations() {
        let cache = LruCache::new(100, 10_000_000); // 100 entries, 10MB limit
        
        let query_result = QueryResult {
            rows: vec![serde_json::json!({"test": "value"})],
            affected_rows: 1,
            execution_time_ms: 10,
            cached: false,
            query_hash: "test_hash".to_string(),
            optimization_applied: None,
        };
        
        // Test set and get
        cache.set("test_key", &query_result, Duration::from_secs(60)).await;
        
        let retrieved = cache.get("test_key").await;
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().rows.len(), 1);
        
        // Test cache miss
        let missed = cache.get("nonexistent_key").await;
        assert!(missed.is_none());
        
        // Test stats
        let stats = cache.stats().await;
        assert_eq!(stats.entries, 1);
        assert_eq!(stats.hits, 1);
        assert_eq!(stats.misses, 1);
    }

    #[tokio::test]
    async fn test_lru_cache_eviction() {
        let cache = LruCache::new(2, 1_000_000); // Small cache to trigger eviction
        
        let query_result = QueryResult {
            rows: vec![serde_json::json!({"test": "value"})],
            affected_rows: 1,
            execution_time_ms: 10,
            cached: false,
            query_hash: "test_hash".to_string(),
            optimization_applied: None,
        };
        
        // Fill cache beyond capacity
        cache.set("key1", &query_result, Duration::from_secs(60)).await;
        cache.set("key2", &query_result, Duration::from_secs(60)).await;
        cache.set("key3", &query_result, Duration::from_secs(60)).await; // Should evict key1
        
        // key1 should be evicted
        let evicted = cache.get("key1").await;
        assert!(evicted.is_none());
        
        // key2 and key3 should still be present
        let present2 = cache.get("key2").await;
        let present3 = cache.get("key3").await;
        assert!(present2.is_some());
        assert!(present3.is_some());
        
        // Check eviction stats
        let stats = cache.stats().await;
        assert_eq!(stats.entries, 2);
        assert_eq!(stats.evictions, 1);
    }

    #[tokio::test]
    async fn test_multi_level_cache() {
        let l1_cache = Arc::new(LruCache::new(10, 1_000_000));
        let l2_cache = Arc::new(LruCache::new(100, 10_000_000));
        let multi_cache = MultiLevelCache::new(l1_cache.clone(), Some(l2_cache.clone()));
        
        let query_result = QueryResult {
            rows: vec![serde_json::json!({"test": "value"})],
            affected_rows: 1,
            execution_time_ms: 10,
            cached: false,
            query_hash: "test_hash".to_string(),
            optimization_applied: None,
        };
        
        // Set in multi-level cache
        multi_cache.set("test_key", &query_result, Duration::from_secs(60)).await;
        
        // Should be in both L1 and L2
        let l1_result = l1_cache.get("test_key").await;
        let l2_result = l2_cache.get("test_key").await;
        assert!(l1_result.is_some());
        assert!(l2_result.is_some());
        
        // Clear L1 and test promotion from L2
        l1_cache.clear().await;
        let promoted = multi_cache.get("test_key").await;
        assert!(promoted.is_some());
        
        // Should be back in L1 after promotion
        let l1_result = l1_cache.get("test_key").await;
        assert!(l1_result.is_some());
    }
}
