//! Performance metrics collection and monitoring
//!
//! This module provides comprehensive performance metrics for all optimizations
//! including SIMD operations, async operations, and memory management.

use crate::error::FortressError;
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Global performance metrics
pub struct PerformanceMetrics {
    simd_operations: AtomicU64,
    async_operations: AtomicU64,
    memory_allocations: AtomicU64,
    pool_hits: AtomicU64,
    pool_misses: AtomicU64,
    total_encryption_time: AtomicU64, // in microseconds
    total_encryptions: AtomicU64,
    peak_memory_usage: AtomicU64,
    current_memory_usage: AtomicU64,
    cache_hits: AtomicU64,
    cache_misses: AtomicU64,
}

impl PerformanceMetrics {
    /// Create new performance metrics
    pub fn new() -> Self {
        Self {
            simd_operations: AtomicU64::new(0),
            async_operations: AtomicU64::new(0),
            memory_allocations: AtomicU64::new(0),
            pool_hits: AtomicU64::new(0),
            pool_misses: AtomicU64::new(0),
            total_encryption_time: AtomicU64::new(0),
            total_encryptions: AtomicU64::new(0),
            peak_memory_usage: AtomicU64::new(0),
            current_memory_usage: AtomicU64::new(0),
            cache_hits: AtomicU64::new(0),
            cache_misses: AtomicU64::new(0),
        }
    }

    /// Record a SIMD operation
    pub fn record_simd_operation(&self) {
        self.simd_operations.fetch_add(1, Ordering::Relaxed);
    }

    /// Record an async operation
    pub fn record_async_operation(&self) {
        self.async_operations.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a memory allocation
    pub fn record_memory_allocation(&self, size: u64) {
        self.memory_allocations.fetch_add(1, Ordering::Relaxed);
        self.current_memory_usage.fetch_add(size, Ordering::Relaxed);

        // Update peak if necessary
        let current = self.current_memory_usage.load(Ordering::Relaxed);
        let peak = self.peak_memory_usage.load(Ordering::Relaxed);
        if current > peak {
            self.peak_memory_usage.store(current, Ordering::Relaxed);
        }
    }

    /// Record memory deallocation
    pub fn record_memory_deallocation(&self, size: u64) {
        self.current_memory_usage.fetch_sub(size, Ordering::Relaxed);
    }

    /// Record a pool hit
    pub fn record_pool_hit(&self) {
        self.pool_hits.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a pool miss
    pub fn record_pool_miss(&self) {
        self.pool_misses.fetch_add(1, Ordering::Relaxed);
    }

    /// Record encryption operation
    pub fn record_encryption(&self, duration: Duration) {
        let micros = duration.as_micros() as u64;
        self.total_encryption_time
            .fetch_add(micros, Ordering::Relaxed);
        self.total_encryptions.fetch_add(1, Ordering::Relaxed);
    }

    /// Record cache hit
    pub fn record_cache_hit(&self) {
        self.cache_hits.fetch_add(1, Ordering::Relaxed);
    }

    /// Record cache miss
    pub fn record_cache_miss(&self) {
        self.cache_misses.fetch_add(1, Ordering::Relaxed);
    }

    /// Get current metrics
    pub fn get_metrics(&self) -> MetricsSnapshot {
        let total_encryptions = self.total_encryptions.load(Ordering::Relaxed);
        let total_time = self.total_encryption_time.load(Ordering::Relaxed);
        let avg_encryption_time = if total_encryptions > 0 {
            total_time as f64 / total_encryptions as f64
        } else {
            0.0
        };

        let pool_hits = self.pool_hits.load(Ordering::Relaxed);
        let pool_misses = self.pool_misses.load(Ordering::Relaxed);
        let pool_hit_rate = if pool_hits + pool_misses > 0 {
            pool_hits as f64 / (pool_hits + pool_misses) as f64
        } else {
            0.0
        };

        let cache_hits = self.cache_hits.load(Ordering::Relaxed);
        let cache_misses = self.cache_misses.load(Ordering::Relaxed);
        let cache_hit_rate = if cache_hits + cache_misses > 0 {
            cache_hits as f64 / (cache_hits + cache_misses) as f64
        } else {
            0.0
        };

        MetricsSnapshot {
            simd_operations: self.simd_operations.load(Ordering::Relaxed),
            async_operations: self.async_operations.load(Ordering::Relaxed),
            memory_allocations: self.memory_allocations.load(Ordering::Relaxed),
            pool_hits,
            pool_misses,
            pool_hit_rate,
            cache_hits,
            cache_misses,
            cache_hit_rate,
            avg_encryption_time,
            total_encryptions,
            peak_memory_usage: self.peak_memory_usage.load(Ordering::Relaxed),
            current_memory_usage: self.current_memory_usage.load(Ordering::Relaxed),
            throughput_ops_per_sec: self.calculate_throughput(),
            timestamp: Instant::now(),
        }
    }

    /// Calculate operations per second
    fn calculate_throughput(&self) -> f64 {
        let total_ops = self.total_encryptions.load(Ordering::Relaxed);
        let total_time_micros = self.total_encryption_time.load(Ordering::Relaxed);

        if total_time_micros == 0 {
            0.0
        } else {
            (total_ops as f64 * 1_000_000.0) / total_time_micros as f64
        }
    }

    /// Reset all metrics
    pub fn reset(&self) {
        self.simd_operations.store(0, Ordering::Relaxed);
        self.async_operations.store(0, Ordering::Relaxed);
        self.memory_allocations.store(0, Ordering::Relaxed);
        self.pool_hits.store(0, Ordering::Relaxed);
        self.pool_misses.store(0, Ordering::Relaxed);
        self.total_encryption_time.store(0, Ordering::Relaxed);
        self.total_encryptions.store(0, Ordering::Relaxed);
        self.peak_memory_usage.store(0, Ordering::Relaxed);
        self.current_memory_usage.store(0, Ordering::Relaxed);
        self.cache_hits.store(0, Ordering::Relaxed);
        self.cache_misses.store(0, Ordering::Relaxed);
    }
}

/// Metrics snapshot
#[derive(Debug, Clone)]
pub struct MetricsSnapshot {
    pub simd_operations: u64,
    pub async_operations: u64,
    pub memory_allocations: u64,
    pub pool_hits: u64,
    pub pool_misses: u64,
    pub pool_hit_rate: f64,
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub cache_hit_rate: f64,
    pub avg_encryption_time: f64,
    pub total_encryptions: u64,
    pub peak_memory_usage: u64,
    pub current_memory_usage: u64,
    pub throughput_ops_per_sec: f64,
    pub timestamp: Instant,
}

impl MetricsSnapshot {
    /// Get age of snapshot
    pub fn age(&self) -> Duration {
        self.timestamp.elapsed()
    }

    /// Format metrics for display
    pub fn format(&self) -> String {
        format!(
            "Performance Metrics:\n\
             SIMD Operations: {}\n\
             Async Operations: {}\n\
             Memory Allocations: {}\n\
             Pool Hit Rate: {:.2}%\n\
             Cache Hit Rate: {:.2}%\n\
             Avg Encryption Time: {:.2}μs\n\
             Total Encryptions: {}\n\
             Peak Memory: {}MB\n\
             Current Memory: {}MB\n\
             Throughput: {:.2} ops/sec",
            self.simd_operations,
            self.async_operations,
            self.memory_allocations,
            self.pool_hit_rate * 100.0,
            self.cache_hit_rate * 100.0,
            self.avg_encryption_time,
            self.total_encryptions,
            self.peak_memory_usage / (1024 * 1024),
            self.current_memory_usage / (1024 * 1024),
            self.throughput_ops_per_sec
        )
    }
}

/// Performance timer for measuring operation duration
pub struct PerformanceTimer {
    start_time: Instant,
    metrics: Arc<PerformanceMetrics>,
}

impl PerformanceTimer {
    /// Create a new performance timer
    pub fn new(metrics: Arc<PerformanceMetrics>) -> Self {
        Self {
            start_time: Instant::now(),
            metrics,
        }
    }

    /// Finish timing and record the duration
    pub fn finish(self) -> Duration {
        let duration = self.start_time.elapsed();
        self.metrics.record_encryption(duration);
        duration
    }
}

/// Performance profiler for detailed analysis
pub struct PerformanceProfiler {
    operations: Arc<Mutex<HashMap<String, Vec<Duration>>>>,
    start_times: Arc<Mutex<HashMap<String, Instant>>>,
}

impl PerformanceProfiler {
    /// Create a new performance profiler
    pub fn new() -> Self {
        Self {
            operations: Arc::new(Mutex::new(HashMap::new())),
            start_times: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Start profiling an operation
    pub fn start_operation(&self, operation: &str) {
        let mut start_times = self.start_times.lock().unwrap();
        start_times.insert(operation.to_string(), Instant::now());
    }

    /// End profiling an operation
    pub fn end_operation(&self, operation: &str) -> Result<Duration, FortressError> {
        let mut start_times = self.start_times.lock().unwrap();
        let start_time = start_times.remove(operation).ok_or_else(|| {
            FortressError::processor_error(format!("Operation '{}' not started", operation))
        })?;

        let duration = start_time.elapsed();

        let mut operations = self.operations.lock().unwrap();
        operations
            .entry(operation.to_string())
            .or_insert_with(Vec::new)
            .push(duration);

        Ok(duration)
    }

    /// Get profile statistics for an operation
    pub fn get_operation_stats(&self, operation: &str) -> Option<OperationStats> {
        let operations = self.operations.lock().unwrap();
        let durations = operations.get(operation)?;

        if durations.is_empty() {
            return None;
        }

        let total_duration: Duration = durations.iter().sum();
        let avg_duration = total_duration / durations.len() as u32;
        let min_duration = durations.iter().min().unwrap();
        let max_duration = durations.iter().max().unwrap();

        Some(OperationStats {
            name: operation.to_string(),
            count: durations.len(),
            total_duration,
            avg_duration,
            min_duration: *min_duration,
            max_duration: *max_duration,
        })
    }

    /// Get all operation statistics
    pub fn get_all_stats(&self) -> HashMap<String, OperationStats> {
        let operations = self.operations.lock().unwrap();
        let mut stats = HashMap::new();

        for operation_name in operations.keys() {
            if let Some(operation_stats) = self.get_operation_stats(operation_name) {
                stats.insert(operation_name.clone(), operation_stats);
            }
        }

        stats
    }

    /// Clear all profiling data
    pub fn clear(&self) {
        let mut operations = self.operations.lock().unwrap();
        operations.clear();

        let mut start_times = self.start_times.lock().unwrap();
        start_times.clear();
    }
}

/// Operation statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperationStats {
    pub name: String,
    pub count: usize,
    pub total_duration: Duration,
    pub avg_duration: Duration,
    pub min_duration: Duration,
    pub max_duration: Duration,
}

impl OperationStats {
    /// Format statistics for display
    pub fn format(&self) -> String {
        format!(
            "Operation: {}\n\
             Count: {}\n\
             Total: {:?}\n\
             Average: {:?}\n\
             Min: {:?}\n\
             Max: {:?}",
            self.name,
            self.count,
            self.total_duration,
            self.avg_duration,
            self.min_duration,
            self.max_duration
        )
    }
}

/// Global performance metrics instance
static GLOBAL_METRICS: Lazy<Arc<PerformanceMetrics>> =
    Lazy::new(|| Arc::new(PerformanceMetrics::new()));

/// Global performance profiler instance
static GLOBAL_PROFILER: Lazy<Arc<PerformanceProfiler>> =
    Lazy::new(|| Arc::new(PerformanceProfiler::new()));

/// Get global performance metrics
pub fn global_metrics() -> &'static Arc<PerformanceMetrics> {
    &GLOBAL_METRICS
}

/// Get global performance profiler
pub fn global_profiler() -> &'static Arc<PerformanceProfiler> {
    &GLOBAL_PROFILER
}

/// Macro for timing operations
#[macro_export]
macro_rules! time_operation {
    ($metrics:expr, $operation:expr) => {
        let _timer = $crate::performance::metrics::PerformanceTimer::new($metrics);
        $operation
    };
}

/// Macro for profiling operations
#[macro_export]
macro_rules! profile_operation {
    ($profiler:expr, $name:expr, $operation:expr) => {{
        $profiler.start_operation($name);
        let result = $operation;
        let _ = $profiler.end_operation($name);
        result
    }};
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;
    use std::time::Duration;

    #[test]
    fn test_performance_metrics() {
        let metrics = PerformanceMetrics::new();

        metrics.record_simd_operation();
        metrics.record_async_operation();
        metrics.record_memory_allocation(1024);
        metrics.record_pool_hit();
        metrics.record_pool_miss();
        metrics.record_encryption(Duration::from_micros(100));
        metrics.record_cache_hit();
        metrics.record_cache_miss();

        let snapshot = metrics.get_metrics();
        assert_eq!(snapshot.simd_operations, 1);
        assert_eq!(snapshot.async_operations, 1);
        assert_eq!(snapshot.memory_allocations, 1);
        assert_eq!(snapshot.total_encryptions, 1);
        assert!(snapshot.avg_encryption_time > 0.0);
    }

    #[test]
    fn test_performance_timer() {
        let metrics = Arc::new(PerformanceMetrics::new());
        let timer = PerformanceTimer::new(metrics.clone());

        thread::sleep(Duration::from_millis(10));
        let duration = timer.finish();

        assert!(duration >= Duration::from_millis(10));

        let snapshot = metrics.get_metrics();
        assert_eq!(snapshot.total_encryptions, 1);
    }

    #[test]
    fn test_performance_profiler() {
        let profiler = PerformanceProfiler::new();

        profiler.start_operation("test_operation");
        thread::sleep(Duration::from_millis(10));
        let duration = profiler.end_operation("test_operation").unwrap();

        assert!(duration >= Duration::from_millis(10));

        let stats = profiler.get_operation_stats("test_operation").unwrap();
        assert_eq!(stats.name, "test_operation");
        assert_eq!(stats.count, 1);
        assert!(stats.avg_duration >= Duration::from_millis(10));
    }

    #[test]
    fn test_global_metrics() {
        let metrics = global_metrics();
        metrics.record_simd_operation();

        let snapshot = metrics.get_metrics();
        assert!(snapshot.simd_operations > 0);
    }

    #[test]
    fn test_global_profiler() {
        let profiler = global_profiler();

        profiler.start_operation("global_test");
        thread::sleep(Duration::from_millis(5));
        let _ = profiler.end_operation("global_test");

        let stats = profiler.get_operation_stats("global_test");
        assert!(stats.is_some());
    }

    #[test]
    fn test_metrics_snapshot_format() {
        let metrics = PerformanceMetrics::new();
        metrics.record_simd_operation();
        metrics.record_async_operation();
        metrics.record_encryption(Duration::from_micros(100));

        let snapshot = metrics.get_metrics();
        let formatted = snapshot.format();

        assert!(formatted.contains("SIMD Operations: 1"));
        assert!(formatted.contains("Async Operations: 1"));
        assert!(formatted.contains("Avg Encryption Time:"));
    }

    #[test]
    fn test_operation_stats_format() {
        let stats = OperationStats {
            name: "test".to_string(),
            count: 5,
            total_duration: Duration::from_millis(50),
            avg_duration: Duration::from_millis(10),
            min_duration: Duration::from_millis(5),
            max_duration: Duration::from_millis(15),
        };

        let formatted = stats.format();
        assert!(formatted.contains("Operation: test"));
        assert!(formatted.contains("Count: 5"));
    }
}
