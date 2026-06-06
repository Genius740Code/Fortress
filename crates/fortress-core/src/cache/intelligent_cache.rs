//! Intelligent Cache Management with Advanced Strategies
//!
//! This module provides intelligent cache management including:
//! - Adaptive eviction policies
//! - Cache hit ratio optimization
//! - Multi-tier cache strategies
//! - Performance monitoring and auto-tuning

use crate::error::{FortressError, Result};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};
use tokio::sync::{RwLock, Mutex};
use uuid::Uuid;

/// Cache entry with metadata for intelligent management
#[derive(Debug, Clone)]
pub struct IntelligentCacheEntry<T> {
    /// Cache value
    pub value: T,
    /// Creation timestamp
    pub created_at: Instant,
    /// Last access timestamp
    pub last_accessed: Instant,
    /// Access count
    pub access_count: u64,
    /// Size in bytes (if known)
    pub size_bytes: Option<usize>,
    /// Priority score
    pub priority_score: f64,
    /// TTL (time to live)
    pub ttl: Option<Duration>,
    /// Cost to regenerate
    pub regeneration_cost: f64,
}

impl<T> IntelligentCacheEntry<T> {
    /// Create new cache entry
    pub fn new(value: T, size_bytes: Option<usize>, regeneration_cost: f64) -> Self {
        let now = Instant::now();
        Self {
            value,
            created_at: now,
            last_accessed: now,
            access_count: 0,
            size_bytes,
            priority_score: 0.0,
            ttl: None,
            regeneration_cost,
        }
    }

    /// Record access and update metadata
    pub fn record_access(&mut self) {
        self.last_accessed = Instant::now();
        self.access_count += 1;
        self.update_priority_score();
    }

    /// Update priority score based on multiple factors
    fn update_priority_score(&mut self) {
        let now = Instant::now();
        let age = now.duration_since(self.created_at).as_secs() as f64;
        let time_since_access = now.duration_since(self.last_accessed).as_secs() as f64;
        
        // Frequency factor (accesses per second)
        let frequency = if age > 0.0 {
            self.access_count as f64 / age
        } else {
            self.access_count as f64
        };
        
        // Recency factor (more recent accesses get higher score)
        let recency = 1.0 / (1.0 + time_since_access / 3600.0); // Decay over hours
        
        // Cost factor (more expensive to regenerate gets higher priority)
        let cost_factor = self.regeneration_cost.log10().max(0.0);
        
        // Combined priority score
        self.priority_score = frequency * 10.0 + recency * 5.0 + cost_factor * 3.0;
    }

    /// Check if entry has expired
    pub fn is_expired(&self) -> bool {
        if let Some(ttl) = self.ttl {
            self.created_at.elapsed() > ttl
        } else {
            false
        }
    }

    /// Get age in seconds
    pub fn age_seconds(&self) -> f64 {
        self.created_at.elapsed().as_secs() as f64
    }

    /// Get time since last access in seconds
    pub fn time_since_access_seconds(&self) -> f64 {
        self.last_accessed.elapsed().as_secs() as f64
    }
}

/// Eviction policy strategies
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EvictionPolicy {
    /// Least Recently Used
    LRU,
    /// Least Frequently Used
    LFU,
    /// Adaptive (combines multiple factors)
    Adaptive,
    /// Cost-aware (considers regeneration cost)
    CostAware,
    /// Time-aware (considers access patterns over time)
    TimeAware,
}

/// Intelligent cache with adaptive strategies
pub struct IntelligentCache<T: Clone> {
    /// Cache storage
    entries: Arc<RwLock<HashMap<String, IntelligentCacheEntry<T>>>>,
    /// Access order tracking for LRU
    access_order: Arc<RwLock<VecDeque<String>>>,
    /// Eviction policy
    eviction_policy: EvictionPolicy,
    /// Maximum number of entries
    max_entries: usize,
    /// Maximum total size in bytes
    max_size_bytes: Option<usize>,
    /// Current total size
    current_size_bytes: Arc<RwLock<usize>>,
    /// Statistics
    stats: Arc<RwLock<CacheStats>>,
    /// Configuration
    config: IntelligentCacheConfig,
}

/// Configuration for intelligent cache
#[derive(Debug, Clone)]
pub struct IntelligentCacheConfig {
    /// Eviction policy
    pub eviction_policy: EvictionPolicy,
    /// Maximum entries
    pub max_entries: usize,
    /// Maximum size in bytes
    pub max_size_bytes: Option<usize>,
    /// Default TTL
    pub default_ttl: Option<Duration>,
    /// Cleanup interval
    pub cleanup_interval: Duration,
    /// Enable adaptive tuning
    pub enable_adaptive_tuning: bool,
}

impl Default for IntelligentCacheConfig {
    fn default() -> Self {
        Self {
            eviction_policy: EvictionPolicy::Adaptive,
            max_entries: 1000,
            max_size_bytes: Some(100 * 1024 * 1024), // 100MB
            default_ttl: Some(Duration::from_secs(3600)), // 1 hour
            cleanup_interval: Duration::from_secs(300), // 5 minutes
            enable_adaptive_tuning: true,
        }
    }
}

/// Cache performance statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheStats {
    pub total_requests: u64,
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub evictions: u64,
    pub expirations: u64,
    pub current_entries: usize,
    pub current_size_bytes: usize,
    pub average_access_time_ms: f64,
    pub hit_ratio: f64,
    pub memory_efficiency: f64,
}

impl Default for CacheStats {
    fn default() -> Self {
        Self {
            total_requests: 0,
            cache_hits: 0,
            cache_misses: 0,
            evictions: 0,
            expirations: 0,
            current_entries: 0,
            current_size_bytes: 0,
            average_access_time_ms: 0.0,
            hit_ratio: 0.0,
            memory_efficiency: 0.0,
        }
    }
}

impl<T: Clone> IntelligentCache<T> {
    /// Create new intelligent cache
    pub fn new(config: IntelligentCacheConfig) -> Self {
        Self {
            entries: Arc::new(RwLock::new(HashMap::new())),
            access_order: Arc::new(RwLock::new(VecDeque::new())),
            eviction_policy: config.eviction_policy.clone(),
            max_entries: config.max_entries,
            max_size_bytes: config.max_size_bytes,
            current_size_bytes: Arc::new(RwLock::new(0)),
            stats: Arc::new(RwLock::new(CacheStats::default())),
            config,
        }
    }

    /// Get value from cache
    pub async fn get(&self, key: &str) -> Option<T> {
        let start_time = Instant::now();
        
        let mut entries = self.entries.write().await;
        let mut stats = self.stats.write().await;
        
        stats.total_requests += 1;
        
        if let Some(entry) = entries.get_mut(key) {
            if entry.is_expired() {
                // Remove expired entry
                entries.remove(key);
                self.remove_from_access_order(key).await;
                stats.expirations += 1;
                stats.cache_misses += 1;
                self.update_stats(&mut stats).await;
                return None;
            }
            
            // Record access
            entry.record_access();
            self.update_access_order(key).await;
            
            stats.cache_hits += 1;
            self.update_stats(&mut stats).await;
            
            let access_time = start_time.elapsed().as_secs_f64() * 1000.0;
            stats.average_access_time_ms = (stats.average_access_time_ms * (stats.total_requests - 1) as f64 + access_time) / stats.total_requests as f64;
            
            Some(entry.value.clone())
        } else {
            stats.cache_misses += 1;
            self.update_stats(&mut stats).await;
            None
        }
    }

    /// Put value into cache
    pub async fn put(&self, key: &str, value: T, size_bytes: Option<usize>, regeneration_cost: f64) -> Result<()> {
        let mut entry = IntelligentCacheEntry::new(value, size_bytes, regeneration_cost);
        entry.ttl = self.config.default_ttl;
        entry.update_priority_score();
        
        let mut entries = self.entries.write().await;
        let mut current_size = self.current_size_bytes.write().await;
        
        // Check if we need to evict entries
        if entries.len() >= self.max_entries || 
           (self.max_size_bytes.is_some() && *current_size + entry.size_bytes.unwrap_or(0) > self.max_size_bytes.unwrap()) {
            self.evict_entries(&mut entries, &mut current_size).await?;
        }
        
        // Update size accounting
        if let Some(old_entry) = entries.get(key) {
            if let Some(old_size) = old_entry.size_bytes {
                *current_size = current_size.checked_sub(old_size).unwrap_or(0);
            }
        }
        
        if let Some(new_size) = entry.size_bytes {
            *current_size += new_size;
        }
        
        entries.insert(key.to_string(), entry);
        self.update_access_order(key).await;
        
        Ok(())
    }

    /// Remove entry from cache
    pub async fn remove(&self, key: &str) -> Option<T> {
        let mut entries = self.entries.write().await;
        let mut current_size = self.current_size_bytes.write().await;
        
        if let Some(entry) = entries.remove(key) {
            if let Some(size) = entry.size_bytes {
                *current_size = current_size.checked_sub(size).unwrap_or(0);
            }
            self.remove_from_access_order(key).await;
            Some(entry.value)
        } else {
            None
        }
    }

    /// Clear all entries
    pub async fn clear(&self) {
        let mut entries = self.entries.write().await;
        let mut current_size = self.current_size_bytes.write().await;
        let mut access_order = self.access_order.write().await;
        
        entries.clear();
        *current_size = 0;
        access_order.clear();
        
        let mut stats = self.stats.write().await;
        stats.current_entries = 0;
        stats.current_size_bytes = 0;
    }

    /// Evict entries based on policy
    async fn evict_entries(&self, entries: &mut HashMap<String, IntelligentCacheEntry<T>>, current_size: &mut usize) -> Result<()> {
        let mut to_evict = Vec::new();
        
        match self.eviction_policy {
            EvictionPolicy::LRU => {
                // Evict least recently used entries
                let access_order = self.access_order.read().await;
                let mut entries_to_remove = Vec::new();
                
                while (entries.len() >= self.max_entries || 
                       (self.max_size_bytes.is_some() && *current_size > self.max_size_bytes.unwrap())) && 
                      !access_order.is_empty() {
                    if let Some(oldest_key) = access_order.front() {
                        entries_to_remove.push(oldest_key.clone());
                    }
                    // We'll remove from access_order after determining final evictions
                }
                
                to_evict = entries_to_remove;
            }
            
            EvictionPolicy::LFU => {
                // Evict least frequently used entries
                let mut entries_by_frequency: Vec<(String, f64)> = entries
                    .iter()
                    .map(|(key, entry)| {
                        let frequency = if entry.age_seconds() > 0.0 {
                            entry.access_count as f64 / entry.age_seconds()
                        } else {
                            entry.access_count as f64
                        };
                        (key.clone(), frequency)
                    })
                    .collect();
                
                entries_by_frequency.sort_by(|a, b| a.1.partial_cmp(&b.1).unwrap());
                
                let entries_to_remove = entries_by_frequency.len() / 4; // Remove 25%
                to_evict = entries_by_frequency.into_iter()
                    .take(entries_to_remove)
                    .map(|(key, _)| key)
                    .collect();
            }
            
            EvictionPolicy::Adaptive => {
                // Use priority score for adaptive eviction
                let mut entries_by_priority: Vec<(String, f64)> = entries
                    .iter()
                    .map(|(key, entry)| (key.clone(), entry.priority_score))
                    .collect();
                
                entries_by_priority.sort_by(|a, b| a.1.partial_cmp(&b.1).unwrap());
                
                let entries_to_remove = entries.len() / 4; // Remove 25%
                to_evict = entries_by_priority.into_iter()
                    .take(entries_to_remove)
                    .map(|(key, _)| key)
                    .collect();
            }
            
            EvictionPolicy::CostAware => {
                // Evict entries with lowest regeneration cost first
                let mut entries_by_cost: Vec<(String, f64)> = entries
                    .iter()
                    .map(|(key, entry)| (key.clone(), entry.regeneration_cost))
                    .collect();
                
                entries_by_cost.sort_by(|a, b| a.1.partial_cmp(&b.1).unwrap());
                
                let entries_to_remove = entries.len() / 4; // Remove 25%
                to_evict = entries_by_cost.into_iter()
                    .take(entries_to_remove)
                    .map(|(key, _)| key)
                    .collect();
            }
            
            EvictionPolicy::TimeAware => {
                // Evict entries with lowest time-aware score
                let mut entries_by_time_score: Vec<(String, f64)> = entries
                    .iter()
                    .map(|(key, entry)| {
                        let now = Instant::now();
                        let age = now.duration_since(entry.created_at).as_secs() as f64;
                        let time_since_access = entry.time_since_access_seconds();
                        
                        // Higher score for recently accessed and frequently used
                        let time_score = if age > 0.0 {
                            (entry.access_count as f64 / age) * (1.0 / (1.0 + time_since_access / 3600.0))
                        } else {
                            entry.access_count as f64
                        };
                        
                        (key.clone(), time_score)
                    })
                    .collect();
                
                entries_by_time_score.sort_by(|a, b| a.1.partial_cmp(&b.1).unwrap());
                
                let entries_to_remove = entries.len() / 4; // Remove 25%
                to_evict = entries_by_time_score.into_iter()
                    .take(entries_to_remove)
                    .map(|(key, _)| key)
                    .collect();
            }
        }
        
        // Perform eviction
        let mut evicted_count = 0;
        for key in &to_evict {
            if let Some(entry) = entries.remove(key) {
                if let Some(size) = entry.size_bytes {
                    *current_size = current_size.checked_sub(size).unwrap_or(0);
                }
                evicted_count += 1;
                self.remove_from_access_order(key).await;
            }
        }
        
        // Update eviction statistics
        let mut stats = self.stats.write().await;
        stats.evictions += evicted_count as u64;
        
        Ok(())
    }

    /// Update access order for LRU
    async fn update_access_order(&self, key: &str) {
        let mut access_order = self.access_order.write().await;
        
        // Remove key from current position
        access_order.retain(|k| k != key);
        
        // Add to front (most recently used)
        access_order.push_front(key.to_string());
        
        // Limit size of access order tracking
        if access_order.len() > self.max_entries * 2 {
            access_order.truncate(self.max_entries * 2);
        }
    }

    /// Remove from access order
    async fn remove_from_access_order(&self, key: &str) {
        let mut access_order = self.access_order.write().await;
        access_order.retain(|k| k != key);
    }

    /// Update cache statistics
    async fn update_stats(&self, stats: &mut CacheStats) {
        let entries = self.entries.read().await;
        let current_size = self.current_size_bytes.read().await;
        
        stats.current_entries = entries.len();
        stats.current_size_bytes = *current_size;
        
        if stats.total_requests > 0 {
            stats.hit_ratio = stats.cache_hits as f64 / stats.total_requests as f64;
        }
        
        if let Some(max_size) = self.max_size_bytes {
            if max_size > 0 {
                stats.memory_efficiency = stats.current_size_bytes as f64 / max_size as f64;
            }
        }
    }

    /// Get cache statistics
    pub async fn get_stats(&self) -> CacheStats {
        let mut stats = self.stats.write().await;
        self.update_stats(&mut stats).await;
        stats.clone()
    }

    /// Cleanup expired entries
    pub async fn cleanup_expired(&self) -> usize {
        let mut entries = self.entries.write().await;
        let mut current_size = self.current_size_bytes.write().await;
        let mut expired_keys = Vec::new();
        
        for (key, entry) in entries.iter() {
            if entry.is_expired() {
                expired_keys.push(key.clone());
            }
        }
        
        for key in &expired_keys {
            if let Some(entry) = entries.remove(key) {
                if let Some(size) = entry.size_bytes {
                    *current_size = current_size.checked_sub(size).unwrap_or(0);
                }
                self.remove_from_access_order(key).await;
            }
        }
        
        // Update expiration statistics
        let mut stats = self.stats.write().await;
        stats.expirations += expired_keys.len() as u64;
        
        expired_keys.len()
    }

    /// Optimize cache settings based on performance
    pub async fn optimize_settings(&mut self) -> Result<()> {
        if !self.config.enable_adaptive_tuning {
            return Ok(());
        }
        
        let stats = self.get_stats().await;
        
        // Adaptive policy selection based on hit ratio
        if stats.hit_ratio < 0.7 {
            // Low hit ratio - try different eviction policy
            self.eviction_policy = match self.eviction_policy {
                EvictionPolicy::LRU => EvictionPolicy::LFU,
                EvictionPolicy::LFU => EvictionPolicy::Adaptive,
                EvictionPolicy::Adaptive => EvictionPolicy::CostAware,
                EvictionPolicy::CostAware => EvictionPolicy::TimeAware,
                EvictionPolicy::TimeAware => EvictionPolicy::LRU,
            };
            
            tracing::info!("Switched eviction policy to {:?} due to low hit ratio: {:.2}", 
                          self.eviction_policy, stats.hit_ratio);
        }
        
        // Adjust max entries based on memory efficiency
        if stats.memory_efficiency > 0.9 && stats.hit_ratio < 0.8 {
            // High memory usage but low hit ratio - reduce cache size
            self.max_entries = (self.max_entries * 3) / 4;
            tracing::info!("Reduced cache size to {} entries due to low efficiency", self.max_entries);
        } else if stats.memory_efficiency < 0.5 && stats.hit_ratio > 0.9 {
            // Low memory usage and high hit ratio - can increase cache size
            self.max_entries = (self.max_entries * 5) / 4;
            tracing::info!("Increased cache size to {} entries due to high efficiency", self.max_entries);
        }
        
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::time::{sleep, Duration};

    #[tokio::test]
    async fn test_intelligent_cache_basic_operations() {
        let config = IntelligentCacheConfig::default();
        let cache = IntelligentCache::new(config);
        
        // Test put and get
        cache.put("key1", "value1", Some(10), 1.0).await.unwrap();
        assert_eq!(cache.get("key1").await, Some("value1"));
        
        // Test non-existent key
        assert_eq!(cache.get("nonexistent").await, None);
        
        // Test remove
        assert_eq!(cache.remove("key1").await, Some("value1"));
        assert_eq!(cache.get("key1").await, None);
    }

    #[tokio::test]
    async fn test_cache_eviction_policies() {
        let config = IntelligentCacheConfig {
            eviction_policy: EvictionPolicy::LRU,
            max_entries: 2,
            ..Default::default()
        };
        let cache = IntelligentCache::new(config);
        
        // Fill cache beyond capacity
        cache.put("key1", "value1", Some(10), 1.0).await.unwrap();
        cache.put("key2", "value2", Some(10), 1.0).await.unwrap();
        cache.put("key3", "value3", Some(10), 1.0).await.unwrap();
        
        // Should have evicted least recently used
        assert_eq!(cache.get("key1").await, None);
        assert_eq!(cache.get("key2").await, Some("value2"));
        assert_eq!(cache.get("key3").await, Some("value3"));
    }

    #[tokio::test]
    async fn test_cache_expiration() {
        let config = IntelligentCacheConfig {
            default_ttl: Some(Duration::from_millis(100)),
            ..Default::default()
        };
        let cache = IntelligentCache::new(config);
        
        cache.put("key1", "value1", Some(10), 1.0).await.unwrap();
        assert_eq!(cache.get("key1").await, Some("value1"));
        
        // Wait for expiration
        sleep(Duration::from_millis(150)).await;
        assert_eq!(cache.get("key1").await, None);
    }

    #[tokio::test]
    async fn test_cache_statistics() {
        let config = IntelligentCacheConfig::default();
        let cache = IntelligentCache::new(config);
        
        cache.put("key1", "value1", Some(10), 1.0).await.unwrap();
        cache.put("key2", "value2", Some(10), 1.0).await.unwrap();
        
        // Generate some hits and misses
        cache.get("key1").await;
        cache.get("key2").await;
        cache.get("nonexistent").await;
        
        let stats = cache.get_stats().await;
        assert_eq!(stats.total_requests, 3);
        assert_eq!(stats.cache_hits, 2);
        assert_eq!(stats.cache_misses, 1);
        assert!((stats.hit_ratio - 0.666).abs() < 0.01);
    }

    #[tokio::test]
    async fn test_adaptive_optimization() {
        let mut config = IntelligentCacheConfig {
            max_entries: 10,
            enable_adaptive_tuning: true,
            ..Default::default()
        };
        let mut cache = IntelligentCache::new(config.clone());
        
        // Fill cache with low hit ratio scenario
        for i in 0..20 {
            cache.put(&format!("key{}", i), format!("value{}", i), Some(10), 1.0).await.unwrap();
        }
        
        // Generate low hit ratio (mostly misses)
        for i in 0..20 {
            cache.get(&format!("missing{}", i)).await;
        }
        
        // Optimize settings
        cache.optimize_settings().await.unwrap();
        
        // Should have adjusted settings
        let stats = cache.get_stats().await;
        assert!(cache.max_entries < config.max_entries); // Should have reduced size
    }
}
