//! Memory Optimization Module
//!
//! This module provides zero-copy architecture and smart memory management
//! for Fortress to optimize performance and reduce memory overhead.

use std::sync::Arc;
use std::collections::HashMap;
use tokio::sync::RwLock;
use serde::{Serialize, Deserialize};

pub mod zero_copy;
pub mod pool_allocator;
pub mod arc_optimization;
pub mod memory_monitor;

pub use zero_copy::ZeroCopyManager;
pub use pool_allocator::PoolAllocator;
pub use arc_optimization::ArcOptimizer;
pub use memory_monitor::MemoryMonitor;

/// Memory optimization configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryOptimizationConfig {
    /// Zero-copy optimization enabled
    pub zero_copy_enabled: bool,
    /// Memory pool allocation enabled
    pub pool_allocation_enabled: bool,
    /// Arc optimization enabled
    pub arc_optimization_enabled: bool,
    /// Memory monitoring enabled
    pub memory_monitoring_enabled: bool,
    /// Maximum memory usage in MB
    pub max_memory_mb: u64,
    /// Memory pool sizes
    pub pool_sizes: PoolSizes,
    /// GC trigger threshold
    pub gc_trigger_threshold: f64,
    /// Memory cleanup interval in seconds
    pub cleanup_interval_seconds: u64,
}

/// Memory pool size configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PoolSizes {
    /// Small object pool size (bytes)
    pub small_pool_size: usize,
    /// Medium object pool size (bytes)
    pub medium_pool_size: usize,
    /// Large object pool size (bytes)
    pub large_pool_size: usize,
    /// Number of small pools
    pub small_pool_count: usize,
    /// Number of medium pools
    pub medium_pool_count: usize,
    /// Number of large pools
    pub large_pool_count: usize,
}

/// Memory optimization metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryOptimizationMetrics {
    /// Total memory allocated
    pub total_allocated_mb: f64,
    /// Total memory freed
    pub total_freed_mb: f64,
    /// Current memory usage
    pub current_usage_mb: f64,
    /// Memory efficiency percentage
    pub memory_efficiency: f64,
    /// Zero-copy operations count
    pub zero_copy_operations: u64,
    /// Pool allocation count
    pub pool_allocations: u64,
    /// Arc optimizations count
    pub arc_optimizations: u64,
    /// GC runs count
    pub gc_runs: u64,
    /// Memory fragmentation percentage
    pub fragmentation_percentage: f64,
    /// Average allocation time in microseconds
    pub avg_allocation_time_us: f64,
    /// Last updated timestamp
    pub last_updated: chrono::DateTime<chrono::Utc>,
}

impl Default for MemoryOptimizationConfig {
    fn default() -> Self {
        Self {
            zero_copy_enabled: true,
            pool_allocation_enabled: true,
            arc_optimization_enabled: true,
            memory_monitoring_enabled: true,
            max_memory_mb: 1024, // 1GB default
            pool_sizes: PoolSizes {
                small_pool_size: 64,    // 64 bytes
                medium_pool_size: 1024,  // 1KB
                large_pool_size: 65536, // 64KB
                small_pool_count: 1000,
                medium_pool_count: 100,
                large_pool_count: 10,
            },
            gc_trigger_threshold: 0.8, // 80%
            cleanup_interval_seconds: 60, // 1 minute
        }
    }
}

impl Default for PoolSizes {
    fn default() -> Self {
        Self {
            small_pool_size: 64,
            medium_pool_size: 1024,
            large_pool_size: 65536,
            small_pool_count: 1000,
            medium_pool_count: 100,
            large_pool_count: 10,
        }
    }
}

impl Default for MemoryOptimizationMetrics {
    fn default() -> Self {
        Self {
            total_allocated_mb: 0.0,
            total_freed_mb: 0.0,
            current_usage_mb: 0.0,
            memory_efficiency: 0.0,
            zero_copy_operations: 0,
            pool_allocations: 0,
            arc_optimizations: 0,
            gc_runs: 0,
            fragmentation_percentage: 0.0,
            avg_allocation_time_us: 0.0,
            last_updated: chrono::Utc::now(),
        }
    }
}

/// Main memory optimization manager
pub struct MemoryOptimizationManager {
    config: MemoryOptimizationConfig,
    zero_copy_manager: Option<Arc<ZeroCopyManager>>,
    pool_allocator: Option<Arc<PoolAllocator>>,
    arc_optimizer: Option<Arc<ArcOptimizer>>,
    memory_monitor: Option<Arc<MemoryMonitor>>,
    metrics: Arc<RwLock<MemoryOptimizationMetrics>>,
}

impl MemoryOptimizationManager {
    /// Create a new memory optimization manager
    pub fn new(config: MemoryOptimizationConfig) -> crate::error::Result<Self> {
        let mut manager = Self {
            zero_copy_manager: None,
            pool_allocator: None,
            arc_optimizer: None,
            memory_monitor: None,
            metrics: Arc::new(RwLock::new(MemoryOptimizationMetrics::default())),
            config,
        };

        // Initialize components based on configuration
        if manager.config.zero_copy_enabled {
            manager.zero_copy_manager = Some(Arc::new(ZeroCopyManager::new()?));
        }

        if manager.config.pool_allocation_enabled {
            manager.pool_allocator = Some(Arc::new(PoolAllocator::new(
                manager.config.pool_sizes.clone()
            )?));
        }

        if manager.config.arc_optimization_enabled {
            manager.arc_optimizer = Some(Arc::new(ArcOptimizer::new()?));
        }

        if manager.config.memory_monitoring_enabled {
            manager.memory_monitor = Some(Arc::new(MemoryMonitor::new(
                manager.config.max_memory_mb,
                manager.config.gc_trigger_threshold,
            )?));
        }

        Ok(manager)
    }

    /// Get current memory metrics
    pub async fn get_metrics(&self) -> crate::error::Result<MemoryOptimizationMetrics> {
        let mut metrics = self.metrics.write().await;
        
        // Update metrics from components
        if let Some(monitor) = &self.memory_monitor {
            let monitor_metrics = monitor.get_metrics().await?;
            metrics.current_usage_mb = monitor_metrics.current_usage_mb;
            metrics.fragmentation_percentage = monitor_metrics.fragmentation_percentage;
        }

        if let Some(allocator) = &self.pool_allocator {
            let allocator_metrics = allocator.get_metrics().await?;
            metrics.pool_allocations = allocator_metrics.total_allocations;
        }

        metrics.last_updated = chrono::Utc::now();
        Ok(metrics.clone())
    }

    /// Perform garbage collection
    pub async fn garbage_collect(&self) -> crate::error::Result<()> {
        // Trigger GC in all components
        if let Some(allocator) = &self.pool_allocator {
            allocator.cleanup().await?;
        }

        if let Some(optimizer) = &self.arc_optimizer {
            optimizer.optimize().await?;
        }

        if let Some(monitor) = &self.memory_monitor {
            monitor.trigger_gc().await?;
        }

        // Update metrics
        let mut metrics = self.metrics.write().await;
        metrics.gc_runs += 1;

        Ok(())
    }

    /// Shutdown the memory optimization manager
    pub async fn shutdown(&self) -> crate::error::Result<()> {
        // Cleanup all components
        if let Some(allocator) = &self.pool_allocator {
            allocator.shutdown().await?;
        }

        if let Some(optimizer) = &self.arc_optimizer {
            optimizer.shutdown().await?;
        }

        if let Some(monitor) = &self.memory_monitor {
            monitor.shutdown().await?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_memory_optimization_config_default() {
        let config = MemoryOptimizationConfig::default();
        assert!(config.zero_copy_enabled);
        assert!(config.pool_allocation_enabled);
        assert!(config.arc_optimization_enabled);
        assert!(config.memory_monitoring_enabled);
        assert_eq!(config.max_memory_mb, 1024);
    }

    #[test]
    fn test_pool_sizes_default() {
        let sizes = PoolSizes::default();
        assert_eq!(sizes.small_pool_size, 64);
        assert_eq!(sizes.medium_pool_size, 1024);
        assert_eq!(sizes.large_pool_size, 65536);
        assert_eq!(sizes.small_pool_count, 1000);
    }

    #[tokio::test]
    async fn test_memory_optimization_manager_creation() {
        let config = MemoryOptimizationConfig::default();
        let manager = MemoryOptimizationManager::new(config);
        assert!(manager.is_ok());
    }
}
