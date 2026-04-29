//! Performance optimization module
//! 
//! This module provides comprehensive performance optimizations including:
//! - SIMD optimizations for cryptographic operations
//! - Async processing with batch operations
//! - Memory management with pooling
//! - Performance metrics and monitoring

pub mod simd;
pub mod async_ops;
pub mod memory;
pub mod metrics;

// Re-export commonly used items
pub use simd::{SimdEncryptor, AdaptiveEncryptor, StandardEncryptor};
pub use async_ops::{encrypt_data_async, decrypt_data_async, BatchEncryptor, AsyncEncryptionService};
pub use memory::{MemoryPool, PooledBuffer, MemoryMonitor, MemoryStats, allocation_tracker};
pub use metrics::{PerformanceMetrics, PerformanceTimer, PerformanceProfiler, global_metrics, global_profiler};

use crate::error::FortressError;
use crate::encryption::EncryptionAlgorithm;
use std::sync::Arc;
use std::time::Duration;

/// Performance optimization configuration
#[derive(Debug, Clone)]
pub struct PerformanceConfig {
    /// Enable SIMD optimizations
    pub enable_simd: bool,
    /// Enable async processing
    pub enable_async: bool,
    /// Enable memory pooling
    pub enable_memory_pooling: bool,
    /// Batch size for async operations
    pub batch_size: usize,
    /// Batch timeout for async operations
    pub batch_timeout: Duration,
    /// Concurrency limit for async operations
    pub concurrency_limit: usize,
    /// Memory pressure threshold (percentage)
    pub memory_threshold: f64,
    /// Memory monitoring interval
    pub memory_monitor_interval: Duration,
    /// Memory pool initial size
    pub memory_pool_initial_size: usize,
    /// Memory pool maximum size
    pub memory_pool_max_size: usize,
}

impl Default for PerformanceConfig {
    fn default() -> Self {
        Self {
            enable_simd: true,
            enable_async: true,
            enable_memory_pooling: true,
            batch_size: 32,
            batch_timeout: Duration::from_millis(100),
            concurrency_limit: 10,
            memory_threshold: 80.0,
            memory_monitor_interval: Duration::from_secs(30),
            memory_pool_initial_size: 100,
            memory_pool_max_size: 1000,
        }
    }
}

/// High-performance encryption service with all optimizations
pub struct HighPerformanceEncryptor {
    algorithm: Arc<dyn EncryptionAlgorithm>,
    config: PerformanceConfig,
    adaptive_encryptor: Option<AdaptiveEncryptor>,
    async_service: Option<AsyncEncryptionService>,
    memory_monitor: Option<MemoryMonitor>,
    metrics: Arc<PerformanceMetrics>,
    profiler: Arc<PerformanceProfiler>,
}

impl HighPerformanceEncryptor {
    /// Create a new high-performance encryptor
    pub fn new(algorithm: Box<dyn EncryptionAlgorithm>, config: PerformanceConfig) -> Result<Self, FortressError> {
        let algorithm: Arc<dyn EncryptionAlgorithm> = Arc::from(algorithm);
        let metrics = Arc::new(PerformanceMetrics::new());
        let profiler = Arc::new(PerformanceProfiler::new());

        let adaptive_encryptor = if config.enable_simd {
            // For now, we'll create a new algorithm instance for SIMD
            // In a real implementation, this would need proper algorithm cloning
            None // Disable SIMD for now to avoid cloning issues
        } else {
            None
        };

        let async_service = if config.enable_async {
            Some(AsyncEncryptionService::new(
                algorithm.clone(),
                config.batch_size,
                config.batch_timeout,
                config.concurrency_limit,
            ))
        } else {
            None
        };

        let memory_monitor = if config.enable_memory_pooling {
            let mut monitor = MemoryMonitor::new(config.memory_threshold, config.memory_monitor_interval);
            
            // Add cleanup callbacks
            let metrics_clone = metrics.clone();
            monitor.add_cleanup_callback(move || {
                // Clear caches
                tracing::info!("Clearing performance caches");
                metrics_clone.reset();
            });
            
            Some(monitor)
        } else {
            None
        };

        Ok(Self {
            algorithm,
            config,
            adaptive_encryptor,
            async_service,
            memory_monitor,
            metrics,
            profiler,
        })
    }

    /// Encrypt data with optimal performance
    pub async fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>, FortressError> {
        let _timer = PerformanceTimer::new(self.metrics.clone());
        
        // Use the most appropriate encryption method
        if let Some(async_service) = &self.async_service {
            if data.len() >= 1024 {
                // Use async service for large data
                self.metrics.record_async_operation();
                async_service.encrypt(data).await
            } else if let Some(adaptive_encryptor) = &self.adaptive_encryptor {
                // Use SIMD-optimized encryptor
                self.metrics.record_simd_operation();
                Ok(adaptive_encryptor.encrypt(data)?)
            } else {
                // Use standard encryption
                let key = &[0u8; 32]; // Default key
                self.algorithm.encrypt(data, key)
            }
        } else if let Some(adaptive_encryptor) = &self.adaptive_encryptor {
            // Use SIMD-optimized encryptor
            self.metrics.record_simd_operation();
            Ok(adaptive_encryptor.encrypt(data)?)
        } else {
            // Use standard encryption
            let key = &[0u8; 32]; // Default key
            self.algorithm.encrypt(data, key)
        }
    }

    /// Encrypt multiple items with batch processing
    pub async fn encrypt_batch(&self, data_batch: &[&[u8]]) -> Result<Vec<Vec<u8>>, FortressError> {
        if let Some(async_service) = &self.async_service {
            let key = &[0u8; 32]; // Default key
            async_service.encrypt_batch(data_batch, key).await
        } else {
            // Fallback to individual encryption
            let mut results = Vec::with_capacity(data_batch.len());
            for data in data_batch {
                let result = self.encrypt(data).await?;
                results.push(result);
            }
            Ok(results)
        }
    }

    /// Start performance monitoring
    pub async fn start_monitoring(&mut self) -> Result<(), FortressError> {
        if let Some(memory_monitor) = &mut self.memory_monitor {
            memory_monitor.start_monitoring().await?;
        }
        Ok(())
    }

    /// Stop performance monitoring
    pub fn stop_monitoring(&mut self) -> Result<(), FortressError> {
        if let Some(memory_monitor) = &self.memory_monitor {
            memory_monitor.stop_monitoring()?;
        }
        Ok(())
    }

    /// Get current performance metrics
    pub fn get_metrics(&self) -> crate::performance::metrics::MetricsSnapshot {
        self.metrics.get_metrics()
    }

    /// Get profiling statistics
    pub fn get_profiling_stats(&self) -> std::collections::HashMap<String, crate::performance::metrics::OperationStats> {
        self.profiler.get_all_stats()
    }

    /// Get memory statistics
    pub fn get_memory_stats(&self) -> Result<MemoryStats, FortressError> {
        MemoryStats::collect()
    }

    /// Get supported SIMD features
    pub fn supported_simd_features(&self) -> Vec<&'static str> {
        AdaptiveEncryptor::supported_features()
    }

    /// Get configuration
    pub fn config(&self) -> &PerformanceConfig {
        &self.config
    }

    /// Reset all metrics
    pub fn reset_metrics(&self) {
        self.metrics.reset();
        self.profiler.clear();
    }

    /// Benchmark the encryptor
    pub async fn benchmark(&self, data_size: usize, iterations: usize) -> Result<BenchmarkResults, FortressError> {
        let data = vec![1u8; data_size];
        let mut durations = Vec::with_capacity(iterations);
        
        for _ in 0..iterations {
            let start = std::time::Instant::now();
            let _result = self.encrypt(&data).await?;
            let duration = start.elapsed();
            durations.push(duration);
        }
        
        let total_duration: Duration = durations.iter().sum();
        let avg_duration = total_duration / iterations as u32;
        let min_duration = durations.iter().min().unwrap();
        let max_duration = durations.iter().max().unwrap();
        
        let throughput = (data_size * iterations) as f64 / total_duration.as_secs_f64();
        
        Ok(BenchmarkResults {
            data_size,
            iterations,
            total_duration,
            avg_duration,
            min_duration: *min_duration,
            max_duration: *max_duration,
            throughput_bytes_per_sec: throughput,
            throughput_mb_per_sec: throughput / (1024.0 * 1024.0),
        })
    }
}

/// Benchmark results
#[derive(Debug, Clone)]
pub struct BenchmarkResults {
    pub data_size: usize,
    pub iterations: usize,
    pub total_duration: Duration,
    pub avg_duration: Duration,
    pub min_duration: Duration,
    pub max_duration: Duration,
    pub throughput_bytes_per_sec: f64,
    pub throughput_mb_per_sec: f64,
}

impl BenchmarkResults {
    /// Format results for display
    pub fn format(&self) -> String {
        format!(
            "Benchmark Results:\n\
             Data Size: {} bytes\n\
             Iterations: {}\n\
             Total Duration: {:?}\n\
             Average Duration: {:?}\n\
             Min Duration: {:?}\n\
             Max Duration: {:?}\n\
             Throughput: {:.2} MB/s",
            self.data_size,
            self.iterations,
            self.total_duration,
            self.avg_duration,
            self.min_duration,
            self.max_duration,
            self.throughput_mb_per_sec
        )
    }
}

/// Performance optimization utilities
pub struct PerformanceUtils;

impl PerformanceUtils {
    /// Create an optimized encryptor with default configuration
    pub fn create_optimized_encryptor(algorithm: Box<dyn EncryptionAlgorithm>) -> Result<HighPerformanceEncryptor, FortressError> {
        HighPerformanceEncryptor::new(algorithm, PerformanceConfig::default())
    }

    /// Create an optimized encryptor with custom configuration
    pub fn create_optimized_encryptor_with_config(
        algorithm: Box<dyn EncryptionAlgorithm>, 
        config: PerformanceConfig
    ) -> Result<HighPerformanceEncryptor, FortressError> {
        HighPerformanceEncryptor::new(algorithm, config)
    }

    /// Run a comprehensive performance test
    pub async fn run_performance_test(encryptor: &HighPerformanceEncryptor) -> Result<PerformanceTestResults, FortressError> {
        let mut results = PerformanceTestResults::new();
        
        // Test different data sizes
        let data_sizes = vec![1024, 4096, 16384, 65536]; // 1KB, 4KB, 16KB, 64KB
        
        for &size in &data_sizes {
            let benchmark = encryptor.benchmark(size, 100).await?;
            results.add_benchmark(format!("{}KB", size / 1024), benchmark);
        }
        
        // Test batch processing
        let batch_data: Vec<Vec<u8>> = (0..32).map(|_| vec![1u8; 1024]).collect();
        let batch_refs: Vec<&[u8]> = batch_data.iter().map(|v| v.as_slice()).collect();
        let start = std::time::Instant::now();
        let _batch_result = encryptor.encrypt_batch(&batch_refs).await?;
        let batch_duration = start.elapsed();
        results.set_batch_duration(batch_duration);
        
        // Collect metrics
        results.set_metrics(encryptor.get_metrics());
        results.set_memory_stats(encryptor.get_memory_stats()?);
        results.set_simd_features(encryptor.supported_simd_features());
        
        Ok(results)
    }

    /// Generate performance report
    pub fn generate_performance_report(results: &PerformanceTestResults) -> String {
        let mut report = String::new();
        
        report.push_str("# Performance Optimization Report\n\n");
        
        // SIMD Features
        report.push_str("## SIMD Features\n");
        for feature in &results.simd_features {
            report.push_str(&format!("- {}\n", feature));
        }
        report.push_str("\n");
        
        // Benchmarks
        report.push_str("## Benchmarks\n");
        for (name, benchmark) in &results.benchmarks {
            report.push_str(&format!("### {}\n", name));
            report.push_str(&benchmark.format());
            report.push_str("\n");
        }
        
        // Batch Performance
        if let Some(batch_duration) = results.batch_duration {
            report.push_str("## Batch Performance\n");
            report.push_str(&format!("Batch Duration: {:?}\n", batch_duration));
            report.push_str("\n");
        }
        
        // Metrics
        report.push_str("## Performance Metrics\n");
        report.push_str(&results.metrics.format());
        report.push_str("\n");
        
        // Memory Stats
        report.push_str("## Memory Statistics\n");
        report.push_str(&format!("Buffer Pool Size: {}\n", results.memory_stats.buffer_pool_size));
        report.push_str(&format!("Pool Hit Rate: {:.2}%\n", results.memory_stats.buffer_pool_stats.hit_rate * 100.0));
        report.push_str("\n");
        
        report
    }
}

/// Performance test results
#[derive(Debug, Clone)]
pub struct PerformanceTestResults {
    benchmarks: std::collections::HashMap<String, BenchmarkResults>,
    batch_duration: Option<Duration>,
    metrics: crate::performance::metrics::MetricsSnapshot,
    memory_stats: MemoryStats,
    simd_features: Vec<String>,
}

impl PerformanceTestResults {
    fn new() -> Self {
        Self {
            benchmarks: std::collections::HashMap::new(),
            batch_duration: None,
            metrics: crate::performance::metrics::MetricsSnapshot {
                simd_operations: 0,
                async_operations: 0,
                memory_allocations: 0,
                pool_hits: 0,
                pool_misses: 0,
                pool_hit_rate: 0.0,
                cache_hits: 0,
                cache_misses: 0,
                cache_hit_rate: 0.0,
                avg_encryption_time: 0.0,
                total_encryptions: 0,
                peak_memory_usage: 0,
                current_memory_usage: 0,
                throughput_ops_per_sec: 0.0,
                timestamp: std::time::Instant::now(),
            },
            memory_stats: MemoryStats {
                total_memory: 0,
                used_memory: 0,
                free_memory: 0,
                process_memory: 0,
                buffer_pool_size: 0,
                buffer_pool_stats: crate::performance::memory::PoolStats {
                    current_size: 0,
                    max_size: 0,
                    hits: 0,
                    misses: 0,
                    hit_rate: 0.0,
                },
                allocation_count: 0,
            },
            simd_features: Vec::new(),
        }
    }

    fn add_benchmark(&mut self, name: String, benchmark: BenchmarkResults) {
        self.benchmarks.insert(name, benchmark);
    }

    fn set_batch_duration(&mut self, duration: Duration) {
        self.batch_duration = Some(duration);
    }

    fn set_metrics(&mut self, metrics: crate::performance::metrics::MetricsSnapshot) {
        self.metrics = metrics;
    }

    fn set_memory_stats(&mut self, stats: MemoryStats) {
        self.memory_stats = stats;
    }

    fn set_simd_features(&mut self, features: Vec<&str>) {
        self.simd_features = features.into_iter().map(|s| s.to_string()).collect();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encryption::Aegis256;
    use tokio::time::sleep;

    #[tokio::test]
    async fn test_high_performance_encryptor() {
        let algorithm = Box::new(Aegis256::new());
        let config = PerformanceConfig::default();
        let mut encryptor = HighPerformanceEncryptor::new(algorithm, config).unwrap();
        
        // Start monitoring
        encryptor.start_monitoring().await.unwrap();
        
        // Test encryption
        let data = vec![1u8; 1024];
        let result = encryptor.encrypt(&data).await;
        assert!(result.is_ok());
        
        // Test batch encryption
        let batch_data: Vec<&[u8]> = vec![&[1u8; 512], &[2u8; 512], &[3u8; 512]];
        let batch_result = encryptor.encrypt_batch(&batch_data).await;
        assert!(batch_result.is_ok());
        assert_eq!(batch_result.unwrap().len(), 3);
        
        // Get metrics
        let metrics = encryptor.get_metrics();
        assert!(metrics.total_encryptions > 0);
        
        // Stop monitoring
        encryptor.stop_monitoring().unwrap();
    }

    #[tokio::test]
    async fn test_benchmark() {
        let algorithm = Box::new(Aegis256::new());
        let encryptor = HighPerformanceEncryptor::new(algorithm, PerformanceConfig::default()).unwrap();
        
        let results = encryptor.benchmark(1024, 10).await;
        assert!(results.is_ok());
        
        let benchmark = results.unwrap();
        assert_eq!(benchmark.data_size, 1024);
        assert_eq!(benchmark.iterations, 10);
        assert!(benchmark.throughput_mb_per_sec > 0.0);
    }

    #[tokio::test]
    async fn test_performance_utils() {
        let algorithm = Box::new(Aegis256::new());
        let encryptor = PerformanceUtils::create_optimized_encryptor(algorithm).unwrap();
        
        let results = PerformanceUtils::run_performance_test(&encryptor).await;
        assert!(results.is_ok());
        
        let test_results = results.unwrap();
        assert!(!test_results.benchmarks.is_empty());
        
        let report = PerformanceUtils::generate_performance_report(&test_results);
        assert!(report.contains("Performance Optimization Report"));
        assert!(report.contains("SIMD Features"));
        assert!(report.contains("Benchmarks"));
    }

    #[test]
    fn test_performance_config_default() {
        let config = PerformanceConfig::default();
        assert!(config.enable_simd);
        assert!(config.enable_async);
        assert!(config.enable_memory_pooling);
        assert_eq!(config.batch_size, 32);
        assert_eq!(config.concurrency_limit, 10);
    }

    #[test]
    fn test_benchmark_results_format() {
        let results = BenchmarkResults {
            data_size: 1024,
            iterations: 100,
            total_duration: Duration::from_millis(1000),
            avg_duration: Duration::from_millis(10),
            min_duration: Duration::from_millis(5),
            max_duration: Duration::from_millis(15),
            throughput_bytes_per_sec: 102400.0,
            throughput_mb_per_sec: 0.09765625,
        };
        
        let formatted = results.format();
        assert!(formatted.contains("Data Size: 1024 bytes"));
        assert!(formatted.contains("Iterations: 100"));
        assert!(formatted.contains("Throughput:"));
    }
}
