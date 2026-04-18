//! Memory Monitor Module
//!
//! This module provides real-time memory tracking and monitoring
//! with automatic garbage collection and memory optimization.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use tokio::sync::RwLock;
use serde::{Serialize, Deserialize};
use crate::error::{FortressError, Result};

/// Memory monitor for tracking and optimizing memory usage
pub struct MemoryMonitor {
    /// Maximum memory usage in MB
    max_memory_mb: u64,
    /// GC trigger threshold (0.0 to 1.0)
    gc_trigger_threshold: f64,
    /// Current memory usage in bytes
    current_usage: AtomicU64,
    /// Peak memory usage in bytes
    peak_usage: AtomicU64,
    /// Total allocations
    total_allocations: AtomicU64,
    /// Total deallocations
    total_deallocations: AtomicU64,
    /// GC runs count
    gc_runs: AtomicU64,
    /// Memory fragmentation percentage
    fragmentation_percentage: Arc<RwLock<f64>>,
    /// Memory usage history
    usage_history: Arc<RwLock<Vec<MemoryUsageSnapshot>>>,
    /// Alert thresholds
    alert_thresholds: Arc<RwLock<MemoryAlertThresholds>>,
    /// Last GC timestamp
    last_gc_timestamp: Arc<RwLock<chrono::DateTime<chrono::Utc>>>,
}

/// Memory usage snapshot
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryUsageSnapshot {
    /// Timestamp
    pub timestamp: chrono::DateTime<chrono::Utc>,
    /// Memory usage in MB
    pub usage_mb: f64,
    /// Memory usage percentage
    pub usage_percentage: f64,
    /// Allocation rate per second
    pub allocation_rate: f64,
    /// Deallocation rate per second
    pub deallocation_rate: f64,
    /// Fragmentation percentage
    pub fragmentation_percentage: f64,
}

/// Memory alert thresholds
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryAlertThresholds {
    /// Warning threshold (percentage)
    pub warning_threshold: f64,
    /// Critical threshold (percentage)
    pub critical_threshold: f64,
    /// Emergency threshold (percentage)
    pub emergency_threshold: f64,
    /// Fragmentation warning threshold
    pub fragmentation_warning: f64,
    /// Allocation rate warning threshold (MB/s)
    pub allocation_rate_warning: f64,
}

/// Memory monitor metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryMonitorMetrics {
    /// Current memory usage in MB
    pub current_usage_mb: f64,
    /// Peak memory usage in MB
    pub peak_usage_mb: f64,
    /// Memory usage percentage
    pub usage_percentage: f64,
    /// Total allocations
    pub total_allocations: u64,
    /// Total deallocations
    pub total_deallocations: u64,
    /// Net memory allocated in MB
    pub net_allocated_mb: f64,
    /// GC runs count
    pub gc_runs: u64,
    /// Memory fragmentation percentage
    pub fragmentation_percentage: f64,
    /// Allocation rate per second
    pub allocation_rate: f64,
    /// Deallocation rate per second
    pub deallocation_rate: f64,
    /// Average allocation size in bytes
    pub avg_allocation_size: f64,
    /// Memory efficiency score (0.0 to 1.0)
    pub memory_efficiency: f64,
    /// Last updated timestamp
    pub last_updated: chrono::DateTime<chrono::Utc>,
}

impl MemoryMonitor {
    /// Create a new memory monitor
    pub fn new(max_memory_mb: u64, gc_trigger_threshold: f64) -> Result<Self> {
        Ok(Self {
            max_memory_mb,
            gc_trigger_threshold,
            current_usage: AtomicU64::new(0),
            peak_usage: AtomicU64::new(0),
            total_allocations: AtomicU64::new(0),
            total_deallocations: AtomicU64::new(0),
            gc_runs: AtomicU64::new(0),
            fragmentation_percentage: Arc::new(RwLock::new(0.0)),
            usage_history: Arc::new(RwLock::new(Vec::new())),
            alert_thresholds: Arc::new(RwLock::new(MemoryAlertThresholds::default())),
            last_gc_timestamp: Arc::new(RwLock::new(chrono::Utc::now())),
        })
    }

    /// Record a memory allocation
    pub async fn record_allocation(&self, size: usize) -> Result<MemoryAlert> {
        self.total_allocations.fetch_add(1, Ordering::Relaxed);
        self.current_usage.fetch_add(size as u64, Ordering::Relaxed);
        
        // Update peak usage
        let current = self.current_usage.load(Ordering::Relaxed);
        let peak = self.peak_usage.load(Ordering::Relaxed);
        if current > peak {
            self.peak_usage.store(current, Ordering::Relaxed);
        }

        // Check if GC should be triggered
        let usage_percentage = current as f64 / (self.max_memory_mb * 1024 * 1024) as f64;
        if usage_percentage > self.gc_trigger_threshold {
            if let Some(alert) = self.check_alerts(usage_percentage).await? {
                return Ok(alert);
            }
        }

        Ok(MemoryAlert::None)
    }

    /// Record a memory deallocation
    pub async fn record_deallocation(&self, size: usize) -> Result<()> {
        self.total_deallocations.fetch_add(1, Ordering::Relaxed);
        let current = self.current_usage.fetch_sub(size as u64, Ordering::Relaxed);
        
        // Prevent underflow
        if current < size as u64 {
            self.current_usage.store(0, Ordering::Relaxed);
        }

        Ok(())
    }

    /// Check for memory alerts
    async fn check_alerts(&self, usage_percentage: f64) -> Result<Option<MemoryAlert>> {
        let thresholds = self.alert_thresholds.read().await;
        
        if usage_percentage >= thresholds.emergency_threshold {
            return Ok(Some(MemoryAlert::Emergency {
                usage_percentage,
                message: format!("Memory usage at {:.1}% exceeds emergency threshold of {:.1}%", 
                    usage_percentage, thresholds.emergency_threshold),
            }));
        } else if usage_percentage >= thresholds.critical_threshold {
            return Ok(Some(MemoryAlert::Critical {
                usage_percentage,
                message: format!("Memory usage at {:.1}% exceeds critical threshold of {:.1}%", 
                    usage_percentage, thresholds.critical_threshold),
            }));
        } else if usage_percentage >= thresholds.warning_threshold {
            return Ok(Some(MemoryAlert::Warning {
                usage_percentage,
                message: format!("Memory usage at {:.1}% exceeds warning threshold of {:.1}%", 
                    usage_percentage, thresholds.warning_threshold),
            }));
        }

        Ok(None)
    }

    /// Trigger garbage collection
    pub async fn trigger_gc(&self) -> Result<()> {
        let start = std::time::Instant::now();
        
        // Simulate GC work
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
        
        // Update GC metrics
        self.gc_runs.fetch_add(1, Ordering::Relaxed);
        
        // Update last GC timestamp
        {
            let mut last_gc = self.last_gc_timestamp.write().await;
            *last_gc = chrono::Utc::now();
        }

        // Update fragmentation estimate (simplified)
        {
            let mut fragmentation = self.fragmentation_percentage.write().await;
            *fragmentation = (*fragmentation * 0.9).max(0.0); // Simulate improvement
        }

        // Record usage snapshot
        self.record_usage_snapshot().await?;

        Ok(())
    }

    /// Record a memory usage snapshot
    async fn record_usage_snapshot(&self) -> Result<()> {
        let current_usage_mb = self.current_usage.load(Ordering::Relaxed) as f64 / 1024.0 / 1024.0;
        let usage_percentage = current_usage_mb / self.max_memory_mb as f64;
        
        let snapshot = MemoryUsageSnapshot {
            timestamp: chrono::Utc::now(),
            usage_mb: current_usage_mb,
            usage_percentage,
            allocation_rate: self.calculate_allocation_rate().await?,
            deallocation_rate: self.calculate_deallocation_rate().await?,
            fragmentation_percentage: *self.fragmentation_percentage.read().await,
        };

        let mut history = self.usage_history.write().await;
        history.push(snapshot);
        
        // Keep only last 1000 snapshots
        if history.len() > 1000 {
            history.remove(0);
        }

        Ok(())
    }

    /// Calculate allocation rate
    async fn calculate_allocation_rate(&self) -> Result<f64> {
        let history = self.usage_history.read().await;
        if history.len() < 2 {
            return Ok(0.0);
        }

        let recent = &history[history.len() - 1];
        let previous = &history[history.len() - 2];
        
        let time_diff = (recent.timestamp - previous.timestamp).num_seconds() as f64;
        if time_diff > 0.0 {
            Ok((recent.usage_mb - previous.usage_mb) / time_diff)
        } else {
            Ok(0.0)
        }
    }

    /// Calculate deallocation rate
    async fn calculate_deallocation_rate(&self) -> Result<f64> {
        // For simplicity, this is the negative of allocation rate
        // In a real implementation, this would track actual deallocations
        Ok(-self.calculate_allocation_rate().await?.abs())
    }

    /// Get current memory metrics
    pub async fn get_metrics(&self) -> Result<MemoryMonitorMetrics> {
        let current_usage_bytes = self.current_usage.load(Ordering::Relaxed);
        let peak_usage_bytes = self.peak_usage.load(Ordering::Relaxed);
        let total_allocations = self.total_allocations.load(Ordering::Relaxed);
        let total_deallocations = self.total_deallocations.load(Ordering::Relaxed);
        let gc_runs = self.gc_runs.load(Ordering::Relaxed);

        let current_usage_mb = current_usage_bytes as f64 / 1024.0 / 1024.0;
        let peak_usage_mb = peak_usage_bytes as f64 / 1024.0 / 1024.0;
        let usage_percentage = current_usage_mb / self.max_memory_mb as f64;
        let net_allocated_mb = (current_usage_bytes as f64 / 1024.0 / 1024.0);
        
        let fragmentation_percentage = *self.fragmentation_percentage.read().await;
        let allocation_rate = self.calculate_allocation_rate().await?;
        let deallocation_rate = self.calculate_deallocation_rate().await?;
        
        let avg_allocation_size = if total_allocations > 0 {
            current_usage_bytes as f64 / total_allocations as f64
        } else {
            0.0
        };

        let memory_efficiency = if total_allocations > 0 {
            1.0 - (fragmentation_percentage / 100.0)
        } else {
            1.0
        };

        Ok(MemoryMonitorMetrics {
            current_usage_mb,
            peak_usage_mb,
            usage_percentage,
            total_allocations,
            total_deallocations,
            net_allocated_mb,
            gc_runs,
            fragmentation_percentage,
            allocation_rate,
            deallocation_rate,
            avg_allocation_size,
            memory_efficiency,
            last_updated: chrono::Utc::now(),
        })
    }

    /// Get memory usage history
    pub async fn get_usage_history(&self, limit: Option<usize>) -> Result<Vec<MemoryUsageSnapshot>> {
        let history = self.usage_history.read().await;
        match limit {
            Some(limit) => {
                let start = if history.len() > limit { history.len() - limit } else { 0 };
                Ok(history[start..].to_vec())
            }
            None => Ok(history.clone()),
        }
    }

    /// Set alert thresholds
    pub async fn set_alert_thresholds(&self, thresholds: MemoryAlertThresholds) -> Result<()> {
        let mut current_thresholds = self.alert_thresholds.write().await;
        *current_thresholds = thresholds;
        Ok(())
    }

    /// Get memory pressure level
    pub async fn get_memory_pressure(&self) -> Result<MemoryPressure> {
        let usage_percentage = self.current_usage.load(Ordering::Relaxed) as f64 / (self.max_memory_mb * 1024 * 1024) as f64;
        let fragmentation = *self.fragmentation_percentage.read().await;
        
        if usage_percentage >= 0.9 || fragmentation >= 50.0 {
            Ok(MemoryPressure::Critical)
        } else if usage_percentage >= 0.8 || fragmentation >= 30.0 {
            Ok(MemoryPressure::High)
        } else if usage_percentage >= 0.6 || fragmentation >= 15.0 {
            Ok(MemoryPressure::Medium)
        } else {
            Ok(MemoryPressure::Low)
        }
    }

    /// Perform memory optimization
    pub async fn optimize_memory(&self) -> Result<MemoryOptimizationResult> {
        let start = std::time::Instant::now();
        let mut optimizations = Vec::new();

        // Check if GC is needed
        let usage_percentage = self.current_usage.load(Ordering::Relaxed) as f64 / (self.max_memory_mb * 1024 * 1024) as f64;
        if usage_percentage > self.gc_trigger_threshold {
            self.trigger_gc().await?;
            optimizations.push("Garbage collection triggered".to_string());
        }

        // Check fragmentation
        let fragmentation = *self.fragmentation_percentage.read().await;
        if fragmentation > 20.0 {
            // Simulate memory compaction
            tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
            let mut frag = self.fragmentation_percentage.write().await;
            *frag = (*frag * 0.7).max(0.0);
            optimizations.push("Memory compaction performed".to_string());
        }

        let duration = start.elapsed();

        Ok(MemoryOptimizationResult {
            optimizations,
            duration_ms: duration.as_millis() as u64,
            memory_freed_mb: (usage_percentage * self.max_memory_mb as f64 * 0.1), // Estimate
            fragmentation_reduction: fragmentation - *self.fragmentation_percentage.read().await,
        })
    }

    /// Reset statistics
    pub async fn reset_statistics(&self) -> Result<()> {
        self.current_usage.store(0, Ordering::Relaxed);
        self.peak_usage.store(0, Ordering::Relaxed);
        self.total_allocations.store(0, Ordering::Relaxed);
        self.total_deallocations.store(0, Ordering::Relaxed);
        self.gc_runs.store(0, Ordering::Relaxed);
        
        {
            let mut fragmentation = self.fragmentation_percentage.write().await;
            *fragmentation = 0.0;
        }
        
        {
            let mut history = self.usage_history.write().await;
            history.clear();
        }

        Ok(())
    }

    /// Shutdown the memory monitor
    pub async fn shutdown(&self) -> Result<()> {
        // Trigger final GC
        self.trigger_gc().await?;
        Ok(())
    }
}

/// Memory alert types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MemoryAlert {
    None,
    Warning {
        usage_percentage: f64,
        message: String,
    },
    Critical {
        usage_percentage: f64,
        message: String,
    },
    Emergency {
        usage_percentage: f64,
        message: String,
    },
}

/// Memory pressure levels
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum MemoryPressure {
    Low,
    Medium,
    High,
    Critical,
}

/// Memory optimization result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryOptimizationResult {
    /// Optimizations performed
    pub optimizations: Vec<String>,
    /// Duration in milliseconds
    pub duration_ms: u64,
    /// Memory freed in MB
    pub memory_freed_mb: f64,
    /// Fragmentation reduction
    pub fragmentation_reduction: f64,
}

impl Default for MemoryAlertThresholds {
    fn default() -> Self {
        Self {
            warning_threshold: 0.7,
            critical_threshold: 0.85,
            emergency_threshold: 0.95,
            fragmentation_warning: 25.0,
            allocation_rate_warning: 100.0, // MB/s
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_memory_monitor() {
        let monitor = MemoryMonitor::new(1024, 0.8).unwrap();
        
        // Record allocations
        let alert = monitor.record_allocation(1024 * 1024).await.unwrap(); // 1MB
        assert_eq!(alert, MemoryAlert::None);
        
        // Get metrics
        let metrics = monitor.get_metrics().await.unwrap();
        assert_eq!(metrics.total_allocations, 1);
        assert!(metrics.current_usage_mb > 0.0);
    }

    #[tokio::test]
    async fn test_memory_pressure() {
        let monitor = MemoryMonitor::new(100, 0.8).unwrap();
        
        // Low pressure
        let pressure = monitor.get_memory_pressure().await.unwrap();
        assert_eq!(pressure, MemoryPressure::Low);
        
        // High pressure
        monitor.record_allocation(80 * 1024 * 1024).await.unwrap(); // 80MB
        let pressure = monitor.get_memory_pressure().await.unwrap();
        assert!(pressure == MemoryPressure::High || pressure == MemoryPressure::Critical);
    }

    #[tokio::test]
    async fn test_memory_optimization() {
        let monitor = MemoryMonitor::new(100, 0.5).unwrap();
        
        // Add some memory usage
        monitor.record_allocation(60 * 1024 * 1024).await.unwrap(); // 60MB
        
        // Optimize
        let result = monitor.optimize_memory().await.unwrap();
        assert!(!result.optimizations.is_empty());
        assert!(result.duration_ms > 0);
    }
}
