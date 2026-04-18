//! Memory Pool Allocator
//!
//! This module provides custom memory pools for frequent allocations
//! to reduce memory fragmentation and improve allocation performance.

use std::sync::Arc;
use std::collections::{VecDeque, HashMap};
use tokio::sync::{RwLock, Mutex};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use serde::{Serialize, Deserialize};
use crate::error::{FortressError, Result};
use super::PoolSizes;

/// Memory pool for objects of a specific size
#[derive(Debug)]
pub struct MemoryPool {
    /// Size of objects in this pool
    object_size: usize,
    /// Maximum number of objects in the pool
    max_objects: usize,
    /// Free objects available for allocation
    free_objects: Arc<Mutex<VecDeque<Vec<u8>>>>,
    /// Total allocations from this pool
    total_allocations: AtomicU64,
    /// Total deallocations to this pool
    total_deallocations: AtomicU64,
    /// Current pool size
    current_size: AtomicUsize,
    /// Pool hits (allocations from pool)
    pool_hits: AtomicU64,
    /// Pool misses (allocations requiring new memory)
    pool_misses: AtomicU64,
}

impl MemoryPool {
    /// Create a new memory pool
    pub fn new(object_size: usize, max_objects: usize) -> Self {
        Self {
            object_size,
            max_objects,
            free_objects: Arc::new(Mutex::new(VecDeque::with_capacity(max_objects))),
            total_allocations: AtomicU64::new(0),
            total_deallocations: AtomicU64::new(0),
            current_size: AtomicUsize::new(0),
            pool_hits: AtomicU64::new(0),
            pool_misses: AtomicU64::new(0),
        }
    }

    /// Allocate memory from the pool
    pub async fn allocate(&self) -> Result<Vec<u8>> {
        self.total_allocations.fetch_add(1, Ordering::Relaxed);

        // Try to get from pool first
        {
            let mut free_objects = self.free_objects.lock().await;
            if let Some(mut object) = free_objects.pop_front() {
                // Clear the memory for security
                object.fill(0);
                self.pool_hits.fetch_add(1, Ordering::Relaxed);
                self.current_size.fetch_sub(1, Ordering::Relaxed);
                return Ok(object);
            }
        }

        // Pool miss - allocate new memory
        self.pool_misses.fetch_add(1, Ordering::Relaxed);
        Ok(vec![0u8; self.object_size])
    }

    /// Deallocate memory back to the pool
    pub async fn deallocate(&self, mut object: Vec<u8>) -> Result<()> {
        self.total_deallocations.fetch_add(1, Ordering::Relaxed);

        // Clear the memory for security
        object.fill(0);

        // Only return to pool if it's the right size and pool isn't full
        if object.len() == self.object_size {
            let mut free_objects = self.free_objects.lock().await;
            if free_objects.len() < self.max_objects {
                free_objects.push_back(object);
                self.current_size.fetch_add(1, Ordering::Relaxed);
            }
        }

        Ok(())
    }

    /// Get pool statistics
    pub fn get_stats(&self) -> MemoryPoolStats {
        MemoryPoolStats {
            object_size: self.object_size,
            max_objects: self.max_objects,
            current_size: self.current_size.load(Ordering::Relaxed),
            total_allocations: self.total_allocations.load(Ordering::Relaxed),
            total_deallocations: self.total_deallocations.load(Ordering::Relaxed),
            pool_hits: self.pool_hits.load(Ordering::Relaxed),
            pool_misses: self.pool_misses.load(Ordering::Relaxed),
            hit_rate: self.calculate_hit_rate(),
        }
    }

    /// Calculate pool hit rate
    fn calculate_hit_rate(&self) -> f64 {
        let hits = self.pool_hits.load(Ordering::Relaxed);
        let misses = self.pool_misses.load(Ordering::Relaxed);
        let total = hits + misses;
        
        if total == 0 {
            0.0
        } else {
            hits as f64 / total as f64
        }
    }

    /// Clear the pool
    pub async fn clear(&self) -> Result<()> {
        let mut free_objects = self.free_objects.lock().await;
        free_objects.clear();
        self.current_size.store(0, Ordering::Relaxed);
        Ok(())
    }

    /// Pre-allocate objects in the pool
    pub async fn preallocate(&self, count: usize) -> Result<()> {
        let mut free_objects = self.free_objects.lock().await;
        let current_len = free_objects.len();
        
        if current_len < self.max_objects {
            let to_allocate = std::cmp::min(count, self.max_objects - current_len);
            for _ in 0..to_allocate {
                free_objects.push_back(vec![0u8; self.object_size]);
            }
            self.current_size.store(free_objects.len(), Ordering::Relaxed);
        }
        
        Ok(())
    }
}

/// Memory pool statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryPoolStats {
    /// Size of objects in this pool
    pub object_size: usize,
    /// Maximum number of objects in the pool
    pub max_objects: usize,
    /// Current number of objects in the pool
    pub current_size: usize,
    /// Total allocations from this pool
    pub total_allocations: u64,
    /// Total deallocations to this pool
    pub total_deallocations: u64,
    /// Pool hits (allocations from pool)
    pub pool_hits: u64,
    /// Pool misses (allocations requiring new memory)
    pub pool_misses: u64,
    /// Pool hit rate (0.0 to 1.0)
    pub hit_rate: f64,
}

/// Pool allocator managing multiple memory pools
pub struct PoolAllocator {
    /// Small object pool (64 bytes)
    small_pool: Arc<MemoryPool>,
    /// Medium object pool (1KB)
    medium_pool: Arc<MemoryPool>,
    /// Large object pool (64KB)
    large_pool: Arc<MemoryPool>,
    /// Custom pools for specific sizes
    custom_pools: Arc<RwLock<HashMap<usize, Arc<MemoryPool>>>>,
    /// Pool configuration
    config: PoolSizes,
    /// Total allocations across all pools
    total_allocations: AtomicU64,
    /// Total deallocations across all pools
    total_deallocations: AtomicU64,
    /// Memory allocated in bytes
    total_memory_allocated: AtomicU64,
    /// Memory deallocated in bytes
    total_memory_deallocated: AtomicU64,
}

impl PoolAllocator {
    /// Create a new pool allocator
    pub fn new(config: PoolSizes) -> Result<Self> {
        let small_pool = Arc::new(MemoryPool::new(
            config.small_pool_size,
            config.small_pool_count,
        ));
        
        let medium_pool = Arc::new(MemoryPool::new(
            config.medium_pool_size,
            config.medium_pool_count,
        ));
        
        let large_pool = Arc::new(MemoryPool::new(
            config.large_pool_size,
            config.large_pool_count,
        ));

        Ok(Self {
            small_pool,
            medium_pool,
            large_pool,
            custom_pools: Arc::new(RwLock::new(HashMap::new())),
            config,
            total_allocations: AtomicU64::new(0),
            total_deallocations: AtomicU64::new(0),
            total_memory_allocated: AtomicU64::new(0),
            total_memory_deallocated: AtomicU64::new(0),
        })
    }

    /// Allocate memory for the specified size
    pub async fn allocate(&self, size: usize) -> Result<Vec<u8>> {
        self.total_allocations.fetch_add(1, Ordering::Relaxed);
        self.total_memory_allocated.fetch_add(size as u64, Ordering::Relaxed);

        // Choose the appropriate pool based on size
        if size <= self.config.small_pool_size {
            Ok(self.small_pool.allocate().await?)
        } else if size <= self.config.medium_pool_size {
            Ok(self.medium_pool.allocate().await?)
        } else if size <= self.config.large_pool_size {
            Ok(self.large_pool.allocate().await?)
        } else {
            // For large allocations, allocate directly
            Ok(vec![0u8; size])
        }
    }

    /// Deallocate memory back to the appropriate pool
    pub async fn deallocate(&self, mut object: Vec<u8>) -> Result<()> {
        let size = object.len();
        self.total_deallocations.fetch_add(1, Ordering::Relaxed);
        self.total_memory_deallocated.fetch_add(size as u64, Ordering::Relaxed);

        // Clear the memory for security
        object.fill(0);

        // Return to appropriate pool
        if size == self.config.small_pool_size {
            self.small_pool.deallocate(object).await?;
        } else if size == self.config.medium_pool_size {
            self.medium_pool.deallocate(object).await?;
        } else if size == self.config.large_pool_size {
            self.large_pool.deallocate(object).await?;
        }
        // For other sizes, just let it drop

        Ok(())
    }

    /// Create a custom pool for a specific size
    pub async fn create_custom_pool(&self, size: usize, max_objects: usize) -> Result<()> {
        let mut custom_pools = self.custom_pools.write().await;
        if !custom_pools.contains_key(&size) {
            let pool = Arc::new(MemoryPool::new(size, max_objects));
            custom_pools.insert(size, pool);
        }
        Ok(())
    }

    /// Allocate from a custom pool
    pub async fn allocate_from_custom_pool(&self, size: usize) -> Result<Vec<u8>> {
        let custom_pools = self.custom_pools.read().await;
        if let Some(pool) = custom_pools.get(&size) {
            pool.allocate().await
        } else {
            Err(FortressError::memory("No custom pool found for size".to_string()))
        }
    }

    /// Get comprehensive metrics
    pub async fn get_metrics(&self) -> Result<PoolAllocatorMetrics> {
        let small_stats = self.small_pool.get_stats();
        let medium_stats = self.medium_pool.get_stats();
        let large_stats = self.large_pool.get_stats();

        let mut custom_stats = Vec::new();
        let custom_pools = self.custom_pools.read().await;
        for (size, pool) in custom_pools.iter() {
            custom_stats.push((*size, pool.get_stats()));
        }

        Ok(PoolAllocatorMetrics {
            small_pool: small_stats,
            medium_pool: medium_stats,
            large_pool: large_stats,
            custom_pools: custom_stats,
            total_allocations: self.total_allocations.load(Ordering::Relaxed),
            total_deallocations: self.total_deallocations.load(Ordering::Relaxed),
            total_memory_allocated: self.total_memory_allocated.load(Ordering::Relaxed),
            total_memory_deallocated: self.total_memory_deallocated.load(Ordering::Relaxed),
            overall_hit_rate: self.calculate_overall_hit_rate(),
            memory_efficiency: self.calculate_memory_efficiency(),
        })
    }

    /// Calculate overall hit rate across all pools
    fn calculate_overall_hit_rate(&self) -> f64 {
        let small_hits = self.small_pool.pool_hits.load(Ordering::Relaxed);
        let medium_hits = self.medium_pool.pool_hits.load(Ordering::Relaxed);
        let large_hits = self.large_pool.pool_hits.load(Ordering::Relaxed);
        
        let small_misses = self.small_pool.pool_misses.load(Ordering::Relaxed);
        let medium_misses = self.medium_pool.pool_misses.load(Ordering::Relaxed);
        let large_misses = self.large_pool.pool_misses.load(Ordering::Relaxed);
        
        let total_hits = small_hits + medium_hits + large_hits;
        let total_misses = small_misses + medium_misses + large_misses;
        let total = total_hits + total_misses;
        
        if total == 0 {
            0.0
        } else {
            total_hits as f64 / total as f64
        }
    }

    /// Calculate memory efficiency
    fn calculate_memory_efficiency(&self) -> f64 {
        let allocated = self.total_memory_allocated.load(Ordering::Relaxed);
        let deallocated = self.total_memory_deallocated.load(Ordering::Relaxed);
        
        if allocated == 0 {
            0.0
        } else {
            deallocated as f64 / allocated as f64
        }
    }

    /// Pre-allocate all pools
    pub async fn preallocate_all(&self) -> Result<()> {
        self.small_pool.preallocate(self.config.small_pool_count / 2).await?;
        self.medium_pool.preallocate(self.config.medium_pool_count / 2).await?;
        self.large_pool.preallocate(self.config.large_pool_count / 2).await?;
        Ok(())
    }

    /// Clear all pools
    pub async fn clear_all(&self) -> Result<()> {
        self.small_pool.clear().await?;
        self.medium_pool.clear().await?;
        self.large_pool.clear().await?;
        
        let custom_pools = self.custom_pools.read().await;
        for pool in custom_pools.values() {
            pool.clear().await?;
        }
        
        Ok(())
    }

    /// Cleanup and optimize pools
    pub async fn cleanup(&self) -> Result<()> {
        // Clear pools that are underutilized
        let small_stats = self.small_pool.get_stats();
        if small_stats.hit_rate < 0.1 && small_stats.current_size > 10 {
            self.small_pool.clear().await?;
        }

        let medium_stats = self.medium_pool.get_stats();
        if medium_stats.hit_rate < 0.1 && medium_stats.current_size > 10 {
            self.medium_pool.clear().await?;
        }

        let large_stats = self.large_pool.get_stats();
        if large_stats.hit_rate < 0.1 && large_stats.current_size > 5 {
            self.large_pool.clear().await?;
        }

        Ok(())
    }

    /// Shutdown the pool allocator
    pub async fn shutdown(&self) -> Result<()> {
        self.clear_all().await?;
        Ok(())
    }
}

/// Pool allocator metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PoolAllocatorMetrics {
    /// Small pool statistics
    pub small_pool: MemoryPoolStats,
    /// Medium pool statistics
    pub medium_pool: MemoryPoolStats,
    /// Large pool statistics
    pub large_pool: MemoryPoolStats,
    /// Custom pool statistics
    pub custom_pools: Vec<(usize, MemoryPoolStats)>,
    /// Total allocations across all pools
    pub total_allocations: u64,
    /// Total deallocations across all pools
    pub total_deallocations: u64,
    /// Total memory allocated in bytes
    pub total_memory_allocated: u64,
    /// Total memory deallocated in bytes
    pub total_memory_deallocated: u64,
    /// Overall hit rate across all pools
    pub overall_hit_rate: f64,
    /// Memory efficiency (0.0 to 1.0)
    pub memory_efficiency: f64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_memory_pool() {
        let pool = MemoryPool::new(64, 10);
        
        // Test allocation
        let obj1 = pool.allocate().await.unwrap();
        assert_eq!(obj1.len(), 64);
        
        let obj2 = pool.allocate().await.unwrap();
        assert_eq!(obj2.len(), 64);
        
        // Test deallocation
        pool.deallocate(obj1).await.unwrap();
        pool.deallocate(obj2).await.unwrap();
        
        // Check stats
        let stats = pool.get_stats();
        assert_eq!(stats.total_allocations, 2);
        assert_eq!(stats.total_deallocations, 2);
    }

    #[tokio::test]
    async fn test_pool_allocator() {
        let config = PoolSizes::default();
        let allocator = PoolAllocator::new(config).unwrap();
        
        // Test small allocation
        let small = allocator.allocate(32).await.unwrap();
        assert_eq!(small.len(), 64); // Should be rounded up to pool size
        
        // Test medium allocation
        let medium = allocator.allocate(512).await.unwrap();
        assert_eq!(medium.len(), 1024); // Should be rounded up to pool size
        
        // Test deallocation
        allocator.deallocate(small).await.unwrap();
        allocator.deallocate(medium).await.unwrap();
        
        // Check metrics
        let metrics = allocator.get_metrics().await.unwrap();
        assert_eq!(metrics.total_allocations, 2);
        assert_eq!(metrics.total_deallocations, 2);
    }

    #[tokio::test]
    async fn test_custom_pool() {
        let config = PoolSizes::default();
        let allocator = PoolAllocator::new(config).unwrap();
        
        // Create custom pool
        allocator.create_custom_pool(128, 5).await.unwrap();
        
        // Allocate from custom pool
        let custom = allocator.allocate_from_custom_pool(128).await.unwrap();
        assert_eq!(custom.len(), 128);
    }
}
