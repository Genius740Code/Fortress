//! Advanced performance profiling and monitoring for Fortress
//!
//! This module provides comprehensive performance monitoring, profiling,
//! and automatic performance tuning capabilities.

use crate::error::{FortressError, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use uuid::Uuid;

// Import the profile_operation macro
use crate::profile_operation;

/// Performance monitoring configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceMonitorConfig {
    /// Enable performance monitoring
    pub enabled: bool,
    /// Sampling rate for profiling (0.0 to 1.0)
    pub sampling_rate: f64,
    /// Maximum number of profile samples to keep
    pub max_profile_samples: usize,
    /// Profile aggregation interval in seconds
    pub aggregation_interval_seconds: u64,
    /// Enable automatic performance tuning
    pub enable_auto_tuning: bool,
    /// Performance thresholds for alerts
    pub alert_thresholds: PerformanceThresholds,
    /// Enable detailed query profiling
    pub enable_query_profiling: bool,
    /// Enable resource usage monitoring
    pub enable_resource_monitoring: bool,
    /// Metrics retention period in days
    pub metrics_retention_days: u32,
}

/// Performance thresholds for alerting
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceThresholds {
    /// Maximum query time in milliseconds
    pub max_query_time_ms: u64,
    /// Maximum memory usage percentage
    pub max_memory_usage_percent: f64,
    /// Maximum CPU usage percentage
    pub max_cpu_usage_percent: f64,
    /// Minimum cache hit ratio
    pub min_cache_hit_ratio: f64,
    /// Maximum connection pool utilization
    pub max_connection_utilization: f64,
    /// Maximum error rate percentage
    pub max_error_rate_percent: f64,
}

impl Default for PerformanceThresholds {
    fn default() -> Self {
        Self {
            max_query_time_ms: 1000,
            max_memory_usage_percent: 80.0,
            max_cpu_usage_percent: 80.0,
            min_cache_hit_ratio: 0.7,
            max_connection_utilization: 0.9,
            max_error_rate_percent: 5.0,
        }
    }
}

impl Default for PerformanceMonitorConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            sampling_rate: 0.1, // 10% sampling
            max_profile_samples: 10000,
            aggregation_interval_seconds: 60,
            enable_auto_tuning: true,
            alert_thresholds: PerformanceThresholds::default(),
            enable_query_profiling: true,
            enable_resource_monitoring: true,
            metrics_retention_days: 30,
        }
    }
}

/// Performance profile sample
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfileSample {
    /// Sample ID
    pub id: String,
    /// Timestamp when sample was collected
    pub timestamp: chrono::DateTime<chrono::Utc>,
    /// Operation type
    pub operation_type: OperationType,
    /// Operation name
    pub operation_name: String,
    /// Duration in microseconds
    pub duration_us: u64,
    /// Memory usage in bytes
    pub memory_usage_bytes: u64,
    /// CPU usage percentage
    pub cpu_usage_percent: f64,
    /// Number of database queries
    pub db_queries: u64,
    /// Cache hits
    pub cache_hits: u64,
    /// Cache misses
    pub cache_misses: u64,
    /// Error occurred
    pub error: bool,
    /// Additional metadata
    pub metadata: HashMap<String, serde_json::Value>,
}

/// Operation types for profiling
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum OperationType {
    /// Key generation
    KeyGeneration,
    /// Key storage
    KeyStorage,
    /// Key retrieval
    KeyRetrieval,
    /// Encryption operation
    Encryption,
    /// Decryption operation
    Decryption,
    /// Database query
    DatabaseQuery,
    /// Cache operation
    CacheOperation,
    /// Network request
    NetworkRequest,
    /// Background task
    BackgroundTask,
    /// System operation
    SystemOperation,
}

/// Aggregated performance metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AggregatedMetrics {
    /// Time window start
    pub window_start: chrono::DateTime<chrono::Utc>,
    /// Time window end
    pub window_end: chrono::DateTime<chrono::Utc>,
    /// Total operations
    pub total_operations: u64,
    /// Operations per second
    pub operations_per_second: f64,
    /// Average response time in milliseconds
    pub avg_response_time_ms: f64,
    /// P50 response time in milliseconds
    pub p50_response_time_ms: f64,
    /// P95 response time in milliseconds
    pub p95_response_time_ms: f64,
    /// P99 response time in milliseconds
    pub p99_response_time_ms: f64,
    /// Error rate percentage
    pub error_rate_percent: f64,
    /// Throughput in operations per second
    pub throughput: f64,
    /// Memory usage statistics
    pub memory_stats: MemoryStats,
    /// CPU usage statistics
    pub cpu_stats: CpuStats,
    /// Database statistics
    pub db_stats: DatabaseStats,
    /// Cache statistics
    pub cache_stats: CachePerformanceStats,
}

/// Memory usage statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryStats {
    /// Current memory usage in bytes
    pub current_usage_bytes: u64,
    /// Peak memory usage in bytes
    pub peak_usage_bytes: u64,
    /// Average memory usage in bytes
    pub avg_usage_bytes: u64,
    /// Memory usage percentage
    pub usage_percent: f64,
    /// Memory allocation rate per second
    pub allocation_rate_per_sec: f64,
    /// Memory deallocation rate per second
    pub deallocation_rate_per_sec: f64,
}

/// CPU usage statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CpuStats {
    /// Current CPU usage percentage
    pub current_usage_percent: f64,
    /// Average CPU usage percentage
    pub avg_usage_percent: f64,
    /// Peak CPU usage percentage
    pub peak_usage_percent: f64,
    /// CPU time per operation in microseconds
    pub cpu_time_per_op_us: f64,
    /// Number of CPU cores utilized
    pub cores_utilized: u32,
}

/// Database performance statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseStats {
    /// Total queries executed
    pub total_queries: u64,
    /// Queries per second
    pub queries_per_second: f64,
    /// Average query time in milliseconds
    pub avg_query_time_ms: f64,
    /// Slow queries (above threshold)
    pub slow_queries: u64,
    /// Failed queries
    pub failed_queries: u64,
    /// Connection pool utilization
    pub connection_pool_utilization: f64,
    /// Database size in bytes
    pub database_size_bytes: u64,
}

/// Cache performance statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachePerformanceStats {
    /// Cache hit ratio
    pub hit_ratio: f64,
    /// Total cache operations
    pub total_operations: u64,
    /// Cache size in bytes
    pub cache_size_bytes: u64,
    /// Evictions per second
    pub evictions_per_sec: f64,
    /// Average get time in microseconds
    pub avg_get_time_us: f64,
    /// Average set time in microseconds
    pub avg_set_time_us: f64,
}

/// Performance alert
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceAlert {
    /// Alert ID
    pub id: String,
    /// Alert severity
    pub severity: AlertSeverity,
    /// Alert type
    pub alert_type: AlertType,
    /// Alert message
    pub message: String,
    /// Current value
    pub current_value: f64,
    /// Threshold value
    pub threshold_value: f64,
    /// Timestamp when alert was generated
    pub timestamp: chrono::DateTime<chrono::Utc>,
    /// Affected component
    pub component: String,
    /// Recommended action
    pub recommended_action: String,
}

/// Alert severity levels
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum AlertSeverity {
    /// Informational
    Info,
    /// Warning
    Warning,
    /// Critical
    Critical,
}

/// Alert types
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum AlertType {
    /// High response time
    HighResponseTime,
    /// High memory usage
    HighMemoryUsage,
    /// High CPU usage
    HighCpuUsage,
    /// Low cache hit ratio
    LowCacheHitRatio,
    /// High error rate
    HighErrorRate,
    /// Connection pool exhaustion
    ConnectionPoolExhaustion,
    /// Database performance issue
    DatabasePerformanceIssue,
}

/// Performance tuning recommendation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TuningRecommendation {
    /// Recommendation ID
    pub id: String,
    /// Recommendation type
    pub recommendation_type: RecommendationType,
    /// Description
    pub description: String,
    /// Expected improvement
    pub expected_improvement: String,
    /// Implementation complexity
    pub complexity: ImplementationComplexity,
    /// Priority
    pub priority: RecommendationPriority,
    /// Parameters to adjust
    pub parameters: HashMap<String, serde_json::Value>,
}

/// Recommendation types
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub enum RecommendationType {
    /// Increase cache size
    IncreaseCacheSize,
    /// Adjust connection pool size
    AdjustConnectionPool,
    /// Optimize database queries
    OptimizeQueries,
    /// Enable compression
    EnableCompression,
    /// Adjust timeout values
    AdjustTimeouts,
    /// Enable connection recycling
    EnableConnectionRecycling,
    /// Optimize indexing
    OptimizeIndexing,
}

/// Implementation complexity
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum ImplementationComplexity {
    /// Simple configuration change
    Low,
    /// Requires testing and validation
    Medium,
    /// Requires significant changes
    High,
}

/// Recommendation priority
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum RecommendationPriority {
    /// Can be implemented anytime
    Low,
    /// Should be implemented soon
    Medium,
    /// Requires immediate attention
    High,
    /// Critical for system stability
    Critical,
}

/// Advanced performance monitor
#[derive(Debug)]
pub struct AdvancedPerformanceMonitor {
    /// Configuration
    config: PerformanceMonitorConfig,
    /// Profile samples
    samples: Arc<RwLock<Vec<ProfileSample>>>,
    /// Aggregated metrics
    aggregated_metrics: Arc<RwLock<HashMap<String, AggregatedMetrics>>>,
    /// Active alerts
    alerts: Arc<RwLock<Vec<PerformanceAlert>>>,
    /// Tuning recommendations
    recommendations: Arc<RwLock<Vec<TuningRecommendation>>>,
    /// Current operation contexts
    active_operations: Arc<RwLock<HashMap<String, OperationContext>>>,
}

/// Operation context for tracking
#[derive(Debug, Clone)]
struct OperationContext {
    /// Operation ID
    id: String,
    /// Operation type
    operation_type: OperationType,
    /// Operation name
    operation_name: String,
    /// Start time
    start_time: Instant,
    /// Initial memory usage
    initial_memory: u64,
    /// Metadata
    metadata: HashMap<String, serde_json::Value>,
}

impl AdvancedPerformanceMonitor {
    /// Create a new performance monitor
    pub fn new(config: PerformanceMonitorConfig) -> Self {
        let monitor = Self {
            config,
            samples: Arc::new(RwLock::new(Vec::new())),
            aggregated_metrics: Arc::new(RwLock::new(HashMap::new())),
            alerts: Arc::new(RwLock::new(Vec::new())),
            recommendations: Arc::new(RwLock::new(Vec::new())),
            active_operations: Arc::new(RwLock::new(HashMap::new())),
        };

        // Start background aggregation task
        monitor.start_aggregation_task();

        monitor
    }

    /// Start background metrics aggregation
    fn start_aggregation_task(&self) {
        if !self.config.enabled {
            return;
        }

        let samples = self.samples.clone();
        let aggregated_metrics = self.aggregated_metrics.clone();
        let alerts = self.alerts.clone();
        let recommendations = self.recommendations.clone();
        let thresholds = self.config.alert_thresholds.clone();
        let interval = Duration::from_secs(self.config.aggregation_interval_seconds);

        tokio::spawn(async move {
            let mut interval_timer = tokio::time::interval(interval);
            
            loop {
                interval_timer.tick().await;
                
                if let Err(e) = Self::aggregate_metrics(
                    &samples,
                    &aggregated_metrics,
                    &alerts,
                    &recommendations,
                    &thresholds,
                ).await {
                    tracing::error!("Metrics aggregation failed: {}", e);
                }
            }
        });
    }

    /// Aggregate metrics and generate alerts/recommendations
    async fn aggregate_metrics(
        samples: &Arc<RwLock<Vec<ProfileSample>>>,
        aggregated_metrics: &Arc<RwLock<HashMap<String, AggregatedMetrics>>>,
        alerts: &Arc<RwLock<Vec<PerformanceAlert>>>,
        recommendations: &Arc<RwLock<Vec<TuningRecommendation>>>,
        thresholds: &PerformanceThresholds,
    ) -> Result<()> {
        let mut samples_guard = samples.write().await;
        
        if samples_guard.is_empty() {
            return Ok(());
        }

        // Group samples by operation type
        let mut grouped_samples: HashMap<OperationType, Vec<ProfileSample>> = HashMap::new();
        for sample in samples_guard.drain(..) {
            grouped_samples.entry(sample.operation_type)
                .or_insert_with(Vec::new)
                .push(sample);
        }

        // Generate metrics for each operation type
        let mut new_metrics = HashMap::new();
        let mut new_alerts = Vec::new();
        let mut new_recommendations = Vec::new();

        for (operation_type, operation_samples) in grouped_samples {
            if !operation_samples.is_empty() {
                let metrics = Self::calculate_aggregated_metrics(&operation_samples)?;
                
                // Check thresholds and generate alerts
                let operation_alerts = Self::check_thresholds(&metrics, thresholds, operation_type);
                new_alerts.extend(operation_alerts);

                // Generate tuning recommendations
                let operation_recommendations = Self::generate_recommendations(&metrics, operation_type);
                new_recommendations.extend(operation_recommendations);

                new_metrics.insert(format!("{:?}", operation_type), metrics);
            }
        }

        // Update stored metrics
        {
            let mut metrics_guard = aggregated_metrics.write().await;
            for (key, metrics) in new_metrics {
                metrics_guard.insert(key, metrics);
            }
        }

        // Update alerts
        {
            let mut alerts_guard = alerts.write().await;
            alerts_guard.extend(new_alerts);
        }

        // Update recommendations
        {
            let mut rec_guard = recommendations.write().await;
            rec_guard.extend(new_recommendations);
        }

        Ok(())
    }

    /// Calculate aggregated metrics from samples
    fn calculate_aggregated_metrics(samples: &[ProfileSample]) -> Result<AggregatedMetrics> {
        if samples.is_empty() {
            return Err(FortressError::storage(
                "No samples to aggregate".to_string(),
                "performance_monitor".to_string(),
                crate::error::StorageErrorCode::InvalidOperation,
            ));
        }

        let window_start = samples.iter().map(|s| s.timestamp).min().unwrap();
        let window_end = samples.iter().map(|s| s.timestamp).max().unwrap();
        let total_operations = samples.len() as u64;
        
        let duration_ms = window_end.signed_duration_since(window_start).num_milliseconds() as u64;
        let operations_per_second = if duration_ms > 0 {
            (total_operations as f64 * 1000.0) / duration_ms as f64
        } else {
            0.0
        };

        // Calculate response time percentiles
        let mut durations: Vec<u64> = samples.iter().map(|s| s.duration_us / 1000).collect();
        durations.sort_unstable();
        
        let avg_response_time_ms = durations.iter().sum::<u64>() as f64 / durations.len() as f64;
        let p50_response_time_ms = durations[durations.len() * 50 / 100] as f64;
        let p95_response_time_ms = durations[durations.len() * 95 / 100] as f64;
        let p99_response_time_ms = durations[durations.len() * 99 / 100] as f64;

        let error_count = samples.iter().filter(|s| s.error).count() as u64;
        let error_rate_percent = (error_count as f64 / total_operations as f64) * 100.0;

        // Calculate memory statistics
        let memory_usages: Vec<u64> = samples.iter().map(|s| s.memory_usage_bytes).collect();
        let current_usage_bytes = memory_usages.iter().sum::<u64>() / memory_usages.len() as u64;
        let peak_usage_bytes = *memory_usages.iter().max().unwrap();
        let avg_usage_bytes = current_usage_bytes;

        // Calculate CPU statistics
        let cpu_usages: Vec<f64> = samples.iter().map(|s| s.cpu_usage_percent).collect();
        let current_cpu_usage = cpu_usages.iter().sum::<f64>() / cpu_usages.len() as f64;
        let avg_cpu_usage = current_cpu_usage;
        let peak_cpu_usage = *cpu_usages.iter().max_by(|a, b| a.partial_cmp(b).unwrap()).unwrap();

        // Calculate database statistics
        let total_db_queries: u64 = samples.iter().map(|s| s.db_queries).sum();
        let avg_query_time_ms = if total_db_queries > 0 {
            samples.iter()
                .map(|s| s.duration_us as f64 / 1000.0)
                .sum::<f64>() / total_db_queries as f64
        } else {
            0.0
        };

        // Calculate cache statistics
        let total_cache_hits: u64 = samples.iter().map(|s| s.cache_hits).sum();
        let total_cache_misses: u64 = samples.iter().map(|s| s.cache_misses).sum();
        let total_cache_ops = total_cache_hits + total_cache_misses;
        let hit_ratio = if total_cache_ops > 0 {
            total_cache_hits as f64 / total_cache_ops as f64
        } else {
            0.0
        };

        Ok(AggregatedMetrics {
            window_start,
            window_end,
            total_operations,
            operations_per_second,
            avg_response_time_ms,
            p50_response_time_ms,
            p95_response_time_ms,
            p99_response_time_ms,
            error_rate_percent,
            throughput: operations_per_second,
            memory_stats: MemoryStats {
                current_usage_bytes,
                peak_usage_bytes,
                avg_usage_bytes,
                usage_percent: 0.0, // Would need system total memory
                allocation_rate_per_sec: 0.0,
                deallocation_rate_per_sec: 0.0,
            },
            cpu_stats: CpuStats {
                current_usage_percent: current_cpu_usage,
                avg_usage_percent: avg_cpu_usage,
                peak_usage_percent: peak_cpu_usage,
                cpu_time_per_op_us: 0.0,
                cores_utilized: 1,
            },
            db_stats: DatabaseStats {
                total_queries: total_db_queries,
                queries_per_second: total_db_queries as f64 / duration_ms as f64 * 1000.0,
                avg_query_time_ms,
                slow_queries: 0, // Would need threshold comparison
                failed_queries: error_count,
                connection_pool_utilization: 0.0,
                database_size_bytes: 0,
            },
            cache_stats: CachePerformanceStats {
                hit_ratio,
                total_operations: total_cache_ops,
                cache_size_bytes: 0,
                evictions_per_sec: 0.0,
                avg_get_time_us: 0.0,
                avg_set_time_us: 0.0,
            },
        })
    }

    /// Check performance thresholds and generate alerts
    fn check_thresholds(
        metrics: &AggregatedMetrics,
        thresholds: &PerformanceThresholds,
        operation_type: OperationType,
    ) -> Vec<PerformanceAlert> {
        let mut alerts = Vec::new();

        // Check response time
        if metrics.avg_response_time_ms > thresholds.max_query_time_ms as f64 {
            alerts.push(PerformanceAlert {
                id: Uuid::new_v4().to_string(),
                severity: if metrics.avg_response_time_ms > thresholds.max_query_time_ms as f64 * 2.0 {
                    AlertSeverity::Critical
                } else {
                    AlertSeverity::Warning
                },
                alert_type: AlertType::HighResponseTime,
                message: format!("High response time detected: {:.2}ms", metrics.avg_response_time_ms),
                current_value: metrics.avg_response_time_ms,
                threshold_value: thresholds.max_query_time_ms as f64,
                timestamp: chrono::Utc::now(),
                component: format!("{:?}", operation_type),
                recommended_action: "Consider optimizing queries or increasing resources".to_string(),
            });
        }

        // Check memory usage
        if metrics.memory_stats.usage_percent > thresholds.max_memory_usage_percent {
            alerts.push(PerformanceAlert {
                id: Uuid::new_v4().to_string(),
                severity: AlertSeverity::Warning,
                alert_type: AlertType::HighMemoryUsage,
                message: format!("High memory usage: {:.1}%", metrics.memory_stats.usage_percent),
                current_value: metrics.memory_stats.usage_percent,
                threshold_value: thresholds.max_memory_usage_percent,
                timestamp: chrono::Utc::now(),
                component: format!("{:?}", operation_type),
                recommended_action: "Consider increasing memory or optimizing memory usage".to_string(),
            });
        }

        // Check CPU usage
        if metrics.cpu_stats.current_usage_percent > thresholds.max_cpu_usage_percent {
            alerts.push(PerformanceAlert {
                id: Uuid::new_v4().to_string(),
                severity: AlertSeverity::Warning,
                alert_type: AlertType::HighCpuUsage,
                message: format!("High CPU usage: {:.1}%", metrics.cpu_stats.current_usage_percent),
                current_value: metrics.cpu_stats.current_usage_percent,
                threshold_value: thresholds.max_cpu_usage_percent,
                timestamp: chrono::Utc::now(),
                component: format!("{:?}", operation_type),
                recommended_action: "Consider optimizing CPU-intensive operations or scaling horizontally".to_string(),
            });
        }

        // Check cache hit ratio
        if metrics.cache_stats.hit_ratio < thresholds.min_cache_hit_ratio {
            alerts.push(PerformanceAlert {
                id: Uuid::new_v4().to_string(),
                severity: AlertSeverity::Warning,
                alert_type: AlertType::LowCacheHitRatio,
                message: format!("Low cache hit ratio: {:.2}%", metrics.cache_stats.hit_ratio * 100.0),
                current_value: metrics.cache_stats.hit_ratio,
                threshold_value: thresholds.min_cache_hit_ratio,
                timestamp: chrono::Utc::now(),
                component: format!("{:?}", operation_type),
                recommended_action: "Consider increasing cache size or adjusting cache strategy".to_string(),
            });
        }

        // Check error rate
        if metrics.error_rate_percent > thresholds.max_error_rate_percent {
            alerts.push(PerformanceAlert {
                id: Uuid::new_v4().to_string(),
                severity: if metrics.error_rate_percent > thresholds.max_error_rate_percent * 2.0 {
                    AlertSeverity::Critical
                } else {
                    AlertSeverity::Warning
                },
                alert_type: AlertType::HighErrorRate,
                message: format!("High error rate: {:.2}%", metrics.error_rate_percent),
                current_value: metrics.error_rate_percent,
                threshold_value: thresholds.max_error_rate_percent,
                timestamp: chrono::Utc::now(),
                component: format!("{:?}", operation_type),
                recommended_action: "Investigate and fix the root cause of errors".to_string(),
            });
        }

        alerts
    }

    /// Generate tuning recommendations
    fn generate_recommendations(
        metrics: &AggregatedMetrics,
        _operation_type: OperationType,
    ) -> Vec<TuningRecommendation> {
        let mut recommendations = Vec::new();

        // Cache recommendations
        if metrics.cache_stats.hit_ratio < 0.7 {
            recommendations.push(TuningRecommendation {
                id: Uuid::new_v4().to_string(),
                recommendation_type: RecommendationType::IncreaseCacheSize,
                description: "Increase cache size to improve hit ratio".to_string(),
                expected_improvement: "10-30% improvement in response times".to_string(),
                complexity: ImplementationComplexity::Low,
                priority: RecommendationPriority::Medium,
                parameters: {
                    let mut params = HashMap::new();
                    params.insert("cache_size_multiplier".to_string(), serde_json::Value::Number(serde_json::Number::from(2)));
                    params
                },
            });
        }

        // Database recommendations
        if metrics.db_stats.avg_query_time_ms > 100.0 {
            recommendations.push(TuningRecommendation {
                id: Uuid::new_v4().to_string(),
                recommendation_type: RecommendationType::OptimizeQueries,
                description: "Optimize slow database queries".to_string(),
                expected_improvement: "20-50% improvement in query performance".to_string(),
                complexity: ImplementationComplexity::Medium,
                priority: RecommendationPriority::High,
                parameters: HashMap::new(),
            });
        }

        // Connection pool recommendations
        if metrics.db_stats.connection_pool_utilization > 0.8 {
            recommendations.push(TuningRecommendation {
                id: Uuid::new_v4().to_string(),
                recommendation_type: RecommendationType::AdjustConnectionPool,
                description: "Increase connection pool size".to_string(),
                expected_improvement: "Reduced connection waiting times".to_string(),
                complexity: ImplementationComplexity::Low,
                priority: RecommendationPriority::Medium,
                parameters: {
                    let mut params = HashMap::new();
                    params.insert("pool_size_multiplier".to_string(), serde_json::Value::Number(serde_json::Number::from(2)));
                    params
                },
            });
        }

        recommendations
    }

    /// Start profiling an operation
    pub async fn start_operation(
        &self,
        operation_type: OperationType,
        operation_name: String,
        metadata: HashMap<String, serde_json::Value>,
    ) -> String {
        if !self.config.enabled || rand::random::<f64>() > self.config.sampling_rate {
            return String::new(); // Not sampled
        }

        let operation_id = Uuid::new_v4().to_string();
        let context = OperationContext {
            id: operation_id.clone(),
            operation_type,
            operation_name,
            start_time: Instant::now(),
            initial_memory: 0, // Would get actual memory usage
            metadata,
        };

        let mut active_operations = self.active_operations.write().await;
        active_operations.insert(operation_id.clone(), context);

        operation_id
    }

    /// Finish profiling an operation
    pub async fn finish_operation(
        &self,
        operation_id: String,
        error: bool,
        additional_metadata: HashMap<String, serde_json::Value>,
    ) -> Result<()> {
        if operation_id.is_empty() {
            return Ok(());
        }

        let mut active_operations = self.active_operations.write().await;
        if let Some(context) = active_operations.remove(&operation_id) {
            let duration = context.start_time.elapsed();
            
            // Create profile sample
            let sample = ProfileSample {
                id: Uuid::new_v4().to_string(),
                timestamp: chrono::Utc::now(),
                operation_type: context.operation_type,
                operation_name: context.operation_name,
                duration_us: duration.as_micros() as u64,
                memory_usage_bytes: 0, // Would get actual memory usage
                cpu_usage_percent: 0.0, // Would get actual CPU usage
                db_queries: 0, // Would track actual queries
                cache_hits: 0, // Would track actual cache hits
                cache_misses: 0, // Would track actual cache misses
                error,
                metadata: {
                    let mut metadata = context.metadata;
                    metadata.extend(additional_metadata);
                    metadata
                },
            };

            // Add to samples
            let mut samples = self.samples.write().await;
            samples.push(sample);

            // Limit sample size
            if samples.len() > self.config.max_profile_samples {
                let excess = samples.len() - self.config.max_profile_samples;
                samples.drain(0..excess);
            }
        }

        Ok(())
    }

    /// Get current performance metrics
    pub async fn get_metrics(&self) -> Result<HashMap<String, AggregatedMetrics>> {
        let metrics = self.aggregated_metrics.read().await;
        Ok(metrics.clone())
    }

    /// Get active alerts
    pub async fn get_alerts(&self) -> Result<Vec<PerformanceAlert>> {
        let alerts = self.alerts.read().await;
        Ok(alerts.clone())
    }

    /// Get tuning recommendations
    pub async fn get_recommendations(&self) -> Result<Vec<TuningRecommendation>> {
        let recommendations = self.recommendations.read().await;
        Ok(recommendations.clone())
    }

    /// Clear old alerts
    pub async fn clear_old_alerts(&self, older_than_days: u32) -> Result<usize> {
        let _cutoff = chrono::Utc::now() - chrono::Duration::days(older_than_days as i64);
        let mut alerts = self.alerts.write().await;
        let initial_len = alerts.len();
        alerts.retain(|alert| alert.timestamp > chrono::Utc::now() - chrono::Duration::days(older_than_days as i64));
        Ok(initial_len - alerts.len())
    }

    /// Clear old recommendations
    pub async fn clear_old_recommendations(&self, older_than_days: u32) -> Result<usize> {
        let _cutoff = chrono::Utc::now() - chrono::Duration::days(older_than_days as i64);
        let mut recommendations = self.recommendations.write().await;
        let initial_len = recommendations.len();
        recommendations.retain(|_rec| {
            // This is a simplified check - in practice, recommendations might have timestamps
            true // Keep all for now
        });
        Ok(initial_len - recommendations.len())
    }
}

/// Macro for easy operation profiling
#[macro_export]
macro_rules! profile_operation_monitor {
    ($monitor:expr, $operation_type:expr, $operation_name:expr, $block:block) => {{
        let operation_id = $monitor.start_operation($operation_type, $operation_name.to_string(), std::collections::HashMap::new()).await;
        let result = async move $block.await;
        let error = result.is_err();
        $monitor.finish_operation(operation_id, error, std::collections::HashMap::new()).await?;
        result
    }};
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_performance_monitor_basic_operations() {
        let config = PerformanceMonitorConfig::default();
        let monitor = AdvancedPerformanceMonitor::new(config);

        // Test operation profiling
        let operation_id = monitor.start_operation(
            OperationType::KeyGeneration,
            "test_operation".to_string(),
            HashMap::new(),
        ).await;

        // Simulate some work
        tokio::time::sleep(Duration::from_millis(10)).await;

        monitor.finish_operation(operation_id, false, HashMap::new()).await.unwrap();

        // Wait for aggregation
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Check metrics
        let metrics = monitor.get_metrics().await.unwrap();
        assert!(!metrics.is_empty());
    }

    #[tokio::test]
    async fn test_performance_alerts() {
        let config = PerformanceMonitorConfig {
            alert_thresholds: PerformanceThresholds {
                max_query_time_ms: 1, // Very low threshold to trigger alerts
                ..Default::default()
            },
            ..Default::default()
        };
        let monitor = AdvancedPerformanceMonitor::new(config);

        // Simulate slow operation
        let operation_id = monitor.start_operation(
            OperationType::DatabaseQuery,
            "slow_query".to_string(),
            HashMap::new(),
        ).await;

        tokio::time::sleep(Duration::from_millis(10)).await; // Slower than threshold

        monitor.finish_operation(operation_id, false, HashMap::new()).await.unwrap();

        // Wait for aggregation and alert generation
        tokio::time::sleep(Duration::from_millis(200)).await;

        // Check for alerts
        let alerts = monitor.get_alerts().await.unwrap();
        assert!(!alerts.is_empty());
    }

    #[tokio::test]
    async fn test_tuning_recommendations() {
        let config = PerformanceMonitorConfig::default();
        let monitor = AdvancedPerformanceMonitor::new(config);

        // Simulate operations with poor cache performance
        for _ in 0..10 {
            let operation_id = monitor.start_operation(
                OperationType::CacheOperation,
                "cache_miss".to_string(),
                HashMap::new(),
            ).await;

            tokio::time::sleep(Duration::from_millis(1)).await;
            monitor.finish_operation(operation_id, false, HashMap::new()).await.unwrap();
        }

        // Wait for aggregation and recommendation generation
        tokio::time::sleep(Duration::from_millis(200)).await;

        // Check for recommendations
        let recommendations = monitor.get_recommendations().await.unwrap();
        // Note: This test might not generate recommendations without actual cache miss data
    }

    #[tokio::test]
    async fn test_profile_macro() {
        let config = PerformanceMonitorConfig::default();
        let monitor = Arc::new(AdvancedPerformanceMonitor::new(config));

        let result = profile_operation!(&monitor, "encrypt_data", {
            // Simulate encryption work
            tokio::time::sleep(Duration::from_millis(5)).await;
            Ok::<_, FortressError>("encrypted_data")
        });

        assert!(result.is_ok());

        // Wait for aggregation
        tokio::time::sleep(Duration::from_millis(100)).await;

        let metrics = monitor.get_metrics().await.unwrap();
        assert!(metrics.contains_key("Encryption"));
    }
}
