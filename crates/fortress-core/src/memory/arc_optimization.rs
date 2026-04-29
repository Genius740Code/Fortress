//! Arc Optimization Module
//!
//! This module provides smart pointer optimization to reduce allocations
//! and improve performance through efficient Arc usage patterns.

use std::sync::Arc;
use std::collections::HashMap;
use tokio::sync::RwLock;
use std::sync::atomic::{AtomicU64, Ordering};
use serde::{Serialize, Deserialize};
use crate::error::Result;

/// Arc optimization manager for efficient shared data handling
pub struct ArcOptimizer {
    /// Arc cache for frequently used data
    arc_cache: Arc<RwLock<HashMap<String, Arc<Vec<u8>>>>>,
    /// String Arc cache
    string_cache: Arc<RwLock<HashMap<String, Arc<String>>>>,
    /// Weak reference cache for automatic cleanup
    weak_cache: Arc<RwLock<HashMap<String, std::sync::Weak<Vec<u8>>>>>,
    /// Optimization metrics
    metrics: Arc<RwLock<ArcOptimizationMetrics>>,
    /// Maximum cache size
    max_cache_size: usize,
    /// Cache hit threshold for promotion
    promotion_threshold: u64,
}

/// Arc optimization metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArcOptimizationMetrics {
    /// Total Arc optimizations
    pub total_optimizations: u64,
    /// Cache hits
    pub cache_hits: u64,
    /// Cache misses
    pub cache_misses: u64,
    /// Weak reference cleanups
    pub weak_cleanups: u64,
    /// Memory saved through Arc sharing (in bytes)
    pub memory_saved_bytes: u64,
    /// Current cache size
    pub current_cache_size: usize,
    /// Average Arc reference count
    pub avg_reference_count: f64,
    /// Cache hit rate
    pub cache_hit_rate: f64,
    /// Last updated timestamp
    pub last_updated: chrono::DateTime<chrono::Utc>,
}

impl ArcOptimizer {
    /// Create a new Arc optimizer
    pub fn new() -> Result<Self> {
        Ok(Self {
            arc_cache: Arc::new(RwLock::new(HashMap::new())),
            string_cache: Arc::new(RwLock::new(HashMap::new())),
            weak_cache: Arc::new(RwLock::new(HashMap::new())),
            metrics: Arc::new(RwLock::new(ArcOptimizationMetrics::default())),
            max_cache_size: 10000,
            promotion_threshold: 3,
        })
    }

    /// Create or get an Arc for byte data
    pub async fn get_arc_bytes(&self, key: String, data: Vec<u8>) -> Result<Arc<Vec<u8>>> {
        let _start = std::time::Instant::now();
        
        // Check cache first
        {
            let cache = self.arc_cache.read().await;
            if let Some(arc_data) = cache.get(&key) {
                let mut metrics = self.metrics.write().await;
                metrics.cache_hits += 1;
                metrics.total_optimizations += 1;
                metrics.memory_saved_bytes += data.len() as u64;
                metrics.avg_reference_count = (metrics.avg_reference_count * (metrics.total_optimizations - 1) as f64 
                    + Arc::strong_count(arc_data) as f64) / metrics.total_optimizations as f64;
                return Ok(arc_data.clone());
            }
        }

        // Check weak cache for resurrection
        {
            let mut weak_cache = self.weak_cache.write().await;
            if let Some(weak_data) = weak_cache.get(&key) {
                if let Some(arc_data) = weak_data.upgrade() {
                    // Resurrect from weak cache
                    let mut cache = self.arc_cache.write().await;
                    cache.insert(key.clone(), arc_data.clone());
                    
                    let mut metrics = self.metrics.write().await;
                    metrics.cache_hits += 1;
                    metrics.total_optimizations += 1;
                    metrics.memory_saved_bytes += data.len() as u64;
                    return Ok(arc_data);
                } else {
                    // Clean up dead weak reference
                    weak_cache.remove(&key);
                    let mut metrics = self.metrics.write().await;
                    metrics.weak_cleanups += 1;
                }
            }
        }

        // Create new Arc
        let arc_data = Arc::new(data);

        // Add to cache
        {
            let mut cache = self.arc_cache.write().await;
            cache.insert(key.clone(), arc_data.clone());
            
            // Add to weak cache for potential resurrection
            let mut weak_cache = self.weak_cache.write().await;
            weak_cache.insert(key, Arc::downgrade(&arc_data));
        }

        let mut metrics = self.metrics.write().await;
        metrics.cache_misses += 1;
        metrics.total_optimizations += 1;
        metrics.current_cache_size = self.arc_cache.read().await.len();
        metrics.avg_reference_count = (metrics.avg_reference_count * (metrics.total_optimizations - 1) as f64 
            + 1.0) / metrics.total_optimizations as f64;
        metrics.cache_hit_rate = metrics.cache_hits as f64 / (metrics.cache_hits + metrics.cache_misses) as f64;
        metrics.last_updated = chrono::Utc::now();

        Ok(arc_data)
    }

    /// Create or get an Arc for string data
    pub async fn get_arc_string(&self, key: String, data: String) -> Result<Arc<String>> {
        let _start = std::time::Instant::now();
        
        // Check cache first
        {
            let cache = self.string_cache.read().await;
            if let Some(arc_data) = cache.get(&key) {
                let mut metrics = self.metrics.write().await;
                metrics.cache_hits += 1;
                metrics.total_optimizations += 1;
                metrics.memory_saved_bytes += data.len() as u64;
                metrics.avg_reference_count = (metrics.avg_reference_count * (metrics.total_optimizations - 1) as f64 
                    + Arc::strong_count(arc_data) as f64) / metrics.total_optimizations as f64;
                return Ok(arc_data.clone());
            }
        }

        // Create new Arc
        let arc_data = Arc::new(data);

        // Add to cache
        {
            let mut cache = self.string_cache.write().await;
            cache.insert(key.clone(), arc_data.clone());
        }

        let mut metrics = self.metrics.write().await;
        metrics.cache_misses += 1;
        metrics.total_optimizations += 1;
        metrics.current_cache_size = self.arc_cache.read().await.len();
        metrics.avg_reference_count = (metrics.avg_reference_count * (metrics.total_optimizations - 1) as f64 
            + 1.0) / metrics.total_optimizations as f64;
        metrics.cache_hit_rate = metrics.cache_hits as f64 / (metrics.cache_hits + metrics.cache_misses) as f64;
        metrics.last_updated = chrono::Utc::now();

        Ok(arc_data)
    }

    /// Create a shared Arc from multiple data sources
    pub async fn create_shared_arc<T>(&self, data: T) -> Result<Arc<T>>
    where
        T: Send + Sync + 'static,
    {
        let arc_data = Arc::new(data);
        
        let mut metrics = self.metrics.write().await;
        metrics.total_optimizations += 1;
        metrics.last_updated = chrono::Utc::now();

        Ok(arc_data)
    }

    /// Optimize Arc usage by consolidating duplicate data
    pub async fn consolidate_arcs(&self) -> Result<u64> {
        let mut consolidations = 0u64;
        
        // Consolidate byte Arcs
        {
            let mut cache = self.arc_cache.write().await;
            let mut to_consolidate = Vec::new();
            
            // Find duplicates by comparing data
            let entries: Vec<(String, Arc<Vec<u8>>)> = cache.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
            
            for (i, (key1, data1)) in entries.iter().enumerate() {
                for (key2, data2) in entries.iter().skip(i + 1) {
                    if **data1 == **data2 && key1 != key2 {
                        to_consolidate.push((key2.clone(), data1.clone()));
                        consolidations += 1;
                    }
                }
            }
            
            // Apply consolidations
            for (key, shared_arc) in to_consolidate {
                cache.insert(key, shared_arc);
            }
        }

        // Update metrics
        {
            let mut metrics = self.metrics.write().await;
            metrics.total_optimizations += consolidations;
        }

        Ok(consolidations)
    }

    /// Clean up dead weak references
    pub async fn cleanup_weak_references(&self) -> Result<usize> {
        let mut cleaned = 0;
        
        {
            let mut weak_cache = self.weak_cache.write().await;
            let mut dead_keys = Vec::new();
            
            for (key, weak_ref) in weak_cache.iter() {
                if weak_ref.strong_count() == 0 {
                    dead_keys.push(key.clone());
                }
            }
            
            for key in dead_keys {
                weak_cache.remove(&key);
                cleaned += 1;
            }
        }

        // Update metrics
        {
            let mut metrics = self.metrics.write().await;
            metrics.weak_cleanups += cleaned as u64;
        }

        Ok(cleaned)
    }

    /// Optimize cache size by removing least used entries
    pub async fn optimize_cache_size(&self) -> Result<usize> {
        let mut removed = 0;
        
        // Optimize byte cache
        {
            let mut cache = self.arc_cache.write().await;
            if cache.len() > self.max_cache_size {
                let to_remove = cache.len() - self.max_cache_size;
                let keys_to_remove: Vec<String> = cache.keys().take(to_remove).cloned().collect();
                
                for key in keys_to_remove {
                    cache.remove(&key);
                    removed += 1;
                }
            }
        }

        // Optimize string cache
        {
            let mut cache = self.string_cache.write().await;
            if cache.len() > self.max_cache_size {
                let to_remove = cache.len() - self.max_cache_size;
                let keys_to_remove: Vec<String> = cache.keys().take(to_remove).cloned().collect();
                
                for key in keys_to_remove {
                    cache.remove(&key);
                    removed += 1;
                }
            }
        }

        // Update metrics
        {
            let mut metrics = self.metrics.write().await;
            metrics.current_cache_size = metrics.current_cache_size.saturating_sub(removed);
        }

        Ok(removed)
    }

    /// Get current metrics
    pub async fn get_metrics(&self) -> Result<ArcOptimizationMetrics> {
        let metrics = self.metrics.read().await;
        Ok(metrics.clone())
    }

    /// Get cache statistics
    pub async fn get_cache_stats(&self) -> Result<CacheStats> {
        let byte_cache_size = self.arc_cache.read().await.len();
        let string_cache_size = self.string_cache.read().await.len();
        let weak_cache_size = self.weak_cache.read().await.len();

        Ok(CacheStats {
            byte_cache_size,
            string_cache_size,
            weak_cache_size,
            total_cache_size: byte_cache_size + string_cache_size,
        })
    }

    /// Clear all caches
    pub async fn clear_caches(&self) -> Result<()> {
        self.arc_cache.write().await.clear();
        self.string_cache.write().await.clear();
        self.weak_cache.write().await.clear();

        // Update metrics
        {
            let mut metrics = self.metrics.write().await;
            metrics.current_cache_size = 0;
        }

        Ok(())
    }

    /// Perform optimization cycle
    pub async fn optimize(&self) -> Result<()> {
        // Clean up dead weak references
        self.cleanup_weak_references().await?;
        
        // Optimize cache size
        self.optimize_cache_size().await?;
        
        // Consolidate duplicate Arcs
        self.consolidate_arcs().await?;

        Ok(())
    }

    /// Shutdown the Arc optimizer
    pub async fn shutdown(&self) -> Result<()> {
        self.clear_caches().await?;
        Ok(())
    }
}

/// Cache statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheStats {
    /// Byte cache size
    pub byte_cache_size: usize,
    /// String cache size
    pub string_cache_size: usize,
    /// Weak cache size
    pub weak_cache_size: usize,
    /// Total cache size
    pub total_cache_size: usize,
}

impl Default for ArcOptimizationMetrics {
    fn default() -> Self {
        Self {
            total_optimizations: 0,
            cache_hits: 0,
            cache_misses: 0,
            weak_cleanups: 0,
            memory_saved_bytes: 0,
            current_cache_size: 0,
            avg_reference_count: 0.0,
            cache_hit_rate: 0.0,
            last_updated: chrono::Utc::now(),
        }
    }
}

/// Smart Arc wrapper for enhanced functionality
#[derive(Debug, Clone)]
pub struct SmartArc<T> {
    data: Arc<T>,
    access_count: Arc<AtomicU64>,
    last_access: Arc<std::sync::Mutex<chrono::DateTime<chrono::Utc>>>,
}

impl<T> SmartArc<T> {
    /// Create a new SmartArc
    pub fn new(data: T) -> Self {
        Self {
            data: Arc::new(data),
            access_count: Arc::new(AtomicU64::new(0)),
            last_access: Arc::new(std::sync::Mutex::new(chrono::Utc::now())),
        }
    }

    /// Get reference to the data
    pub fn get(&self) -> &T {
        self.access_count.fetch_add(1, Ordering::Relaxed);
        if let Ok(mut last_access) = self.last_access.lock() {
            *last_access = chrono::Utc::now();
        }
        &self.data
    }

    /// Get the underlying Arc
    pub fn as_arc(&self) -> &Arc<T> {
        &self.data
    }

    /// Get access count
    pub fn access_count(&self) -> u64 {
        self.access_count.load(Ordering::Relaxed)
    }

    /// Get last access time
    pub fn last_access(&self) -> chrono::DateTime<chrono::Utc> {
        self.last_access.lock()
            .map(|time| *time)
            .unwrap_or_else(|_| chrono::Utc::now())
    }

    /// Get strong count
    pub fn strong_count(&self) -> usize {
        Arc::strong_count(&self.data)
    }
}

impl<T> From<T> for SmartArc<T> {
    fn from(data: T) -> Self {
        Self::new(data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_arc_optimizer() {
        let optimizer = ArcOptimizer::new().unwrap();
        
        // Test Arc creation and caching
        let data = vec![1, 2, 3, 4, 5];
        let arc1 = optimizer.get_arc_bytes("test_key".to_string(), data.clone()).await.unwrap();
        let arc2 = optimizer.get_arc_bytes("test_key".to_string(), data).await.unwrap();
        
        // Should be the same Arc (cache hit)
        assert!(Arc::ptr_eq(&arc1, &arc2));
        
        let metrics = optimizer.get_metrics().await.unwrap();
        assert_eq!(metrics.cache_hits, 1);
        assert_eq!(metrics.cache_misses, 1);
    }

    #[tokio::test]
    async fn test_smart_arc() {
        let smart_arc = SmartArc::new(vec![1, 2, 3, 4, 5]);
        
        assert_eq!(smart_arc.access_count(), 0);
        assert_eq!(smart_arc.strong_count(), 1);
        
        // Access the data
        let _data = smart_arc.get();
        assert_eq!(smart_arc.access_count(), 1);
    }

    #[tokio::test]
    async fn test_optimization_cycle() {
        let optimizer = ArcOptimizer::new().unwrap();
        
        // Add some data
        let data = vec![1, 2, 3, 4, 5];
        optimizer.get_arc_bytes("key1".to_string(), data.clone()).await.unwrap();
        optimizer.get_arc_bytes("key2".to_string(), data.clone()).await.unwrap();
        
        // Run optimization
        optimizer.optimize().await.unwrap();
        
        let metrics = optimizer.get_metrics().await.unwrap();
        assert!(metrics.total_optimizations > 0);
    }
}
