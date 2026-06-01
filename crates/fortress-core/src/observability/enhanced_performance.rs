//! Enhanced performance monitoring with real system metrics integration
//!
//! This module provides comprehensive performance monitoring that combines
//! application-level metrics with system resource monitoring.

use crate::error::Result;
use crate::observability::system_resources::{SystemResourceMonitor, SystemSnapshot};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

/// Enhanced performance monitoring configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnhancedPerformanceConfig {
    /// Enable enhanced performance monitoring
    pub enabled: bool,
    /// Sampling rate for profiling (0.0 to 1.0)
    pub sampling_rate: f64,
    /// Profile aggregation interval in seconds
    pub aggregation_interval_seconds: u64,
    /// Maximum number of profile samples to keep
    pub max_profile_samples: usize,
    /// Enable system resource correlation
    pub enable_system_correlation: bool,
    /// Enable performance anomaly detection
    pub enable_anomaly_detection: bool,
    /// Anomaly detection sensitivity (0.0 to 1.0)
    pub anomaly_sensitivity: f64,
    /// Performance baseline window in minutes
    pub baseline_window_minutes: u64,
    /// Enable automated tuning recommendations
    pub enable_auto_tuning: bool,
    /// Performance alert thresholds
    pub alert_thresholds: EnhancedPerformanceThresholds,
}

/// Enhanced performance thresholds
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnhancedPerformanceThresholds {
    /// Maximum response time in milliseconds
    pub max_response_time_ms: u64,
    /// Minimum throughput in operations per second
    pub min_throughput_ops_per_sec: f64,
    /// Maximum error rate percentage
    pub max_error_rate_percent: f64,
    /// Maximum CPU usage percentage
    pub max_cpu_usage_percent: f64,
    /// Maximum memory usage percentage
    pub max_memory_usage_percent: f64,
    /// Minimum cache hit ratio
    pub min_cache_hit_ratio: f64,
    /// Maximum disk I/O wait percentage
    pub max_disk_io_wait_percent: f64,
    /// Maximum network latency in milliseconds
    pub max_network_latency_ms: u64,
}

impl Default for EnhancedPerformanceThresholds {
    fn default() -> Self {
        Self {
            max_response_time_ms: 1000,
            min_throughput_ops_per_sec: 100.0,
            max_error_rate_percent: 5.0,
            max_cpu_usage_percent: 80.0,
            max_memory_usage_percent: 85.0,
            min_cache_hit_ratio: 0.7,
            max_disk_io_wait_percent: 20.0,
            max_network_latency_ms: 500,
        }
    }
}

impl Default for EnhancedPerformanceConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            sampling_rate: 0.1,
            aggregation_interval_seconds: 60,
            max_profile_samples: 10000,
            enable_system_correlation: true,
            enable_anomaly_detection: true,
            anomaly_sensitivity: 0.7,
            baseline_window_minutes: 30,
            enable_auto_tuning: true,
            alert_thresholds: EnhancedPerformanceThresholds::default(),
        }
    }
}

/// Enhanced performance profile with system correlation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnhancedProfileSample {
    /// Sample ID
    pub id: String,
    /// Timestamp when sample was collected
    pub timestamp: chrono::DateTime<chrono::Utc>,
    /// Operation type
    pub operation_type: String,
    /// Operation name
    pub operation_name: String,
    /// Duration in microseconds
    pub duration_us: u64,
    /// Success status
    pub success: bool,
    /// Error message if any
    pub error_message: Option<String>,
    /// System snapshot at time of operation
    pub system_snapshot: Option<SystemSnapshot>,
    /// Application-specific metrics
    pub application_metrics: HashMap<String, f64>,
    /// Database queries count
    pub db_queries: u64,
    /// Cache hits
    pub cache_hits: u64,
    /// Cache misses
    pub cache_misses: u64,
    /// Network requests count
    pub network_requests: u64,
    /// Additional metadata
    pub metadata: HashMap<String, serde_json::Value>,
}

/// Performance anomaly detection result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceAnomaly {
    /// Anomaly ID
    pub id: String,
    /// Anomaly type
    pub anomaly_type: AnomalyType,
    /// Severity level
    pub severity: AnomalySeverity,
    /// Description
    pub description: String,
    /// Affected operation type
    pub operation_type: String,
    /// Expected value
    pub expected_value: f64,
    /// Actual value
    pub actual_value: f64,
    /// Deviation percentage
    pub deviation_percent: f64,
    /// Timestamp when anomaly was detected
    pub timestamp: chrono::DateTime<chrono::Utc>,
    /// Recommended action
    pub recommended_action: String,
}

/// Anomaly types
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum AnomalyType {
    /// High response time
    HighResponseTime,
    /// Low throughput
    LowThroughput,
    /// High error rate
    HighErrorRate,
    /// High CPU usage
    HighCpuUsage,
    /// High memory usage
    HighMemoryUsage,
    /// Low cache hit ratio
    LowCacheHitRatio,
    /// High disk I/O wait
    HighDiskIOWait,
    /// High network latency
    HighNetworkLatency,
}

/// Anomaly severity levels
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum AnomalySeverity {
    /// Low severity
    Low,
    /// Medium severity
    Medium,
    /// High severity
    High,
    /// Critical severity
    Critical,
}

/// Performance baseline
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceBaseline {
    /// Operation type
    pub operation_type: String,
    /// Baseline period start
    pub baseline_start: chrono::DateTime<chrono::Utc>,
    /// Baseline period end
    pub baseline_end: chrono::DateTime<chrono::Utc>,
    /// Average response time in milliseconds
    pub avg_response_time_ms: f64,
    /// P50 response time in milliseconds
    pub p50_response_time_ms: f64,
    /// P95 response time in milliseconds
    pub p95_response_time_ms: f64,
    /// P99 response time in milliseconds
    pub p99_response_time_ms: f64,
    /// Throughput in operations per second
    pub throughput_ops_per_sec: f64,
    /// Error rate percentage
    pub error_rate_percent: f64,
    /// Average CPU usage percentage
    pub avg_cpu_usage_percent: f64,
    /// Average memory usage percentage
    pub avg_memory_usage_percent: f64,
    /// Sample count used for baseline
    pub sample_count: usize,
}

/// Enhanced performance monitor
#[derive(Debug)]
pub struct EnhancedPerformanceMonitor {
    /// Configuration
    config: EnhancedPerformanceConfig,
    /// System resource monitor
    system_monitor: Arc<SystemResourceMonitor>,
    /// Profile samples
    samples: Arc<RwLock<Vec<EnhancedProfileSample>>>,
    /// Performance baselines
    baselines: Arc<RwLock<HashMap<String, PerformanceBaseline>>>,
    /// Detected anomalies
    anomalies: Arc<RwLock<Vec<PerformanceAnomaly>>>,
    /// Active operation contexts
    active_operations: Arc<RwLock<HashMap<String, OperationContext>>>,
    /// Last baseline update time
    last_baseline_update: Arc<RwLock<chrono::DateTime<chrono::Utc>>>,
}

/// Operation context for enhanced tracking
#[derive(Debug, Clone)]
struct OperationContext {
    /// Operation ID
    id: String,
    /// Operation type
    operation_type: String,
    /// Operation name
    operation_name: String,
    /// Start time
    start_time: Instant,
    /// Initial system snapshot
    initial_system_snapshot: Option<SystemSnapshot>,
    /// Application metrics at start
    initial_metrics: HashMap<String, f64>,
    /// Metadata
    metadata: HashMap<String, serde_json::Value>,
}

impl EnhancedPerformanceMonitor {
    /// Create a new enhanced performance monitor
    pub fn new(
        config: EnhancedPerformanceConfig,
        system_monitor: Arc<SystemResourceMonitor>,
    ) -> Self {
        let monitor = Self {
            config,
            system_monitor,
            samples: Arc::new(RwLock::new(Vec::new())),
            baselines: Arc::new(RwLock::new(HashMap::new())),
            anomalies: Arc::new(RwLock::new(Vec::new())),
            active_operations: Arc::new(RwLock::new(HashMap::new())),
            last_baseline_update: Arc::new(RwLock::new(chrono::Utc::now())),
        };

        // Start background tasks
        monitor.start_background_tasks();
        monitor
    }

    /// Start background monitoring tasks
    fn start_background_tasks(&self) {
        if !self.config.enabled {
            return;
        }

        // Start aggregation task
        self.start_aggregation_task();

        // Start baseline update task
        self.start_baseline_update_task();

        // Start anomaly detection task
        if self.config.enable_anomaly_detection {
            self.start_anomaly_detection_task();
        }
    }

    /// Start profile aggregation task
    fn start_aggregation_task(&self) {
        let samples = self.samples.clone();
        let interval = Duration::from_secs(self.config.aggregation_interval_seconds);

        tokio::spawn(async move {
            let mut interval_timer = tokio::time::interval(interval);

            loop {
                interval_timer.tick().await;

                // Perform aggregation and cleanup
                let mut samples_guard = samples.write().await;
                if samples_guard.len() > 10000 {
                    let excess = samples_guard.len() - 10000;
                    samples_guard.drain(0..excess);
                }
            }
        });
    }

    /// Start baseline update task
    fn start_baseline_update_task(&self) {
        let samples = self.samples.clone();
        let baselines = self.baselines.clone();
        let last_update = self.last_baseline_update.clone();
        let baseline_window = self.config.baseline_window_minutes;
        let interval = Duration::from_secs(300); // Update every 5 minutes

        tokio::spawn(async move {
            let mut interval_timer = tokio::time::interval(interval);

            loop {
                interval_timer.tick().await;

                let now = chrono::Utc::now();
                let cutoff_time = now - chrono::Duration::minutes(baseline_window as i64);

                let samples_guard = samples.read().await;
                let recent_samples: Vec<_> = samples_guard
                    .iter()
                    .filter(|sample| sample.timestamp > cutoff_time)
                    .collect();

                if !recent_samples.is_empty() {
                    let new_baselines = Self::calculate_baselines(&recent_samples);

                    let mut baselines_guard = baselines.write().await;
                    for (operation_type, baseline) in new_baselines {
                        baselines_guard.insert(operation_type, baseline);
                    }

                    let mut last_update_guard = last_update.write().await;
                    *last_update_guard = now;
                }
            }
        });
    }

    /// Start anomaly detection task
    fn start_anomaly_detection_task(&self) {
        let samples = self.samples.clone();
        let baselines = self.baselines.clone();
        let anomalies = self.anomalies.clone();
        let thresholds = self.config.alert_thresholds.clone();
        let sensitivity = self.config.anomaly_sensitivity;
        let interval = Duration::from_secs(60); // Check every minute

        tokio::spawn(async move {
            let mut interval_timer = tokio::time::interval(interval);

            loop {
                interval_timer.tick().await;

                let samples_guard = samples.read().await;
                let baselines_guard = baselines.read().await;

                let recent_samples: Vec<_> = samples_guard
                    .iter()
                    .filter(|sample| {
                        sample.timestamp > chrono::Utc::now() - chrono::Duration::minutes(5)
                    })
                    .collect();

                if !recent_samples.is_empty() {
                    let new_anomalies = Self::detect_anomalies(
                        &recent_samples,
                        &baselines_guard,
                        &thresholds,
                        sensitivity,
                    );

                    if !new_anomalies.is_empty() {
                        let mut anomalies_guard = anomalies.write().await;
                        anomalies_guard.extend(new_anomalies);

                        // Keep only last 1000 anomalies
                        if anomalies_guard.len() > 1000 {
                            let excess = anomalies_guard.len() - 1000;
                            anomalies_guard.drain(0..excess);
                        }
                    }
                }
            }
        });
    }

    /// Start profiling an operation
    pub async fn start_operation(
        &self,
        operation_type: String,
        operation_name: String,
        metadata: HashMap<String, serde_json::Value>,
    ) -> String {
        if !self.config.enabled || rand::random::<f64>() > self.config.sampling_rate {
            return String::new(); // Not sampled
        }

        let operation_id = uuid::Uuid::new_v4().to_string();

        // Get current system snapshot if correlation is enabled
        let initial_system_snapshot = if self.config.enable_system_correlation {
            self.system_monitor.get_current_snapshot().await
        } else {
            None
        };

        let context = OperationContext {
            id: operation_id.clone(),
            operation_type: operation_type.clone(),
            operation_name,
            start_time: Instant::now(),
            initial_system_snapshot,
            initial_metrics: HashMap::new(),
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
        success: bool,
        error_message: Option<String>,
        application_metrics: HashMap<String, f64>,
        additional_metadata: HashMap<String, serde_json::Value>,
    ) -> Result<()> {
        if operation_id.is_empty() {
            return Ok(());
        }

        let mut active_operations = self.active_operations.write().await;
        if let Some(context) = active_operations.remove(&operation_id) {
            let duration = context.start_time.elapsed();

            // Get current system snapshot if correlation is enabled
            let system_snapshot = if self.config.enable_system_correlation {
                self.system_monitor.get_current_snapshot().await
            } else {
                None
            };

            // Create enhanced profile sample
            let sample = EnhancedProfileSample {
                id: uuid::Uuid::new_v4().to_string(),
                timestamp: chrono::Utc::now(),
                operation_type: context.operation_type,
                operation_name: context.operation_name,
                duration_us: duration.as_micros() as u64,
                success,
                error_message,
                system_snapshot,
                application_metrics,
                db_queries: 0, // Would be tracked by instrumentation
                cache_hits: 0,
                cache_misses: 0,
                network_requests: 0,
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

    /// Calculate performance baselines from samples
    fn calculate_baselines(
        samples: &[&EnhancedProfileSample],
    ) -> HashMap<String, PerformanceBaseline> {
        let mut baselines = HashMap::new();
        let mut grouped_samples: HashMap<String, Vec<&EnhancedProfileSample>> = HashMap::new();

        // Group samples by operation type
        for sample in samples {
            grouped_samples
                .entry(sample.operation_type.clone())
                .or_insert_with(Vec::new)
                .push(sample);
        }

        // Calculate baseline for each operation type
        for (operation_type, operation_samples) in grouped_samples {
            if operation_samples.len() < 10 {
                continue; // Need minimum samples for reliable baseline
            }

            let timestamps: Vec<_> = operation_samples.iter().map(|s| s.timestamp).collect();
            let baseline_start = timestamps.iter().min().unwrap();
            let baseline_end = timestamps.iter().max().unwrap();

            // Calculate response time percentiles
            let mut durations: Vec<f64> = operation_samples
                .iter()
                .map(|s| s.duration_us as f64 / 1000.0) // Convert to milliseconds
                .collect();
            durations.sort_by(|a, b| a.partial_cmp(b).unwrap());

            let avg_response_time_ms = durations.iter().sum::<f64>() / durations.len() as f64;
            let p50_response_time_ms = durations[durations.len() * 50 / 100];
            let p95_response_time_ms = durations[durations.len() * 95 / 100];
            let p99_response_time_ms = durations[durations.len() * 99 / 100];

            // Calculate throughput
            let time_window_ms = baseline_end
                .signed_duration_since(*baseline_start)
                .num_milliseconds() as f64;
            let throughput_ops_per_sec = if time_window_ms > 0.0 {
                (operation_samples.len() as f64) / (time_window_ms / 1000.0)
            } else {
                0.0
            };

            // Calculate error rate
            let error_count = operation_samples.iter().filter(|s| !s.success).count();
            let error_rate_percent = (error_count as f64 / operation_samples.len() as f64) * 100.0;

            // Calculate average system resource usage
            let mut cpu_usages = Vec::new();
            let mut memory_usages = Vec::new();

            for sample in &operation_samples {
                if let Some(ref system_snapshot) = sample.system_snapshot {
                    cpu_usages.push(system_snapshot.cpu.overall_usage_percent);
                    memory_usages.push(system_snapshot.memory.usage_percent);
                }
            }

            let avg_cpu_usage_percent = if !cpu_usages.is_empty() {
                cpu_usages.iter().sum::<f64>() / cpu_usages.len() as f64
            } else {
                0.0
            };

            let avg_memory_usage_percent = if !memory_usages.is_empty() {
                memory_usages.iter().sum::<f64>() / memory_usages.len() as f64
            } else {
                0.0
            };

            baselines.insert(
                operation_type.clone(),
                PerformanceBaseline {
                    operation_type: operation_type.clone(),
                    baseline_start: *baseline_start,
                    baseline_end: *baseline_end,
                    avg_response_time_ms,
                    p50_response_time_ms,
                    p95_response_time_ms,
                    p99_response_time_ms,
                    throughput_ops_per_sec,
                    error_rate_percent,
                    avg_cpu_usage_percent,
                    avg_memory_usage_percent,
                    sample_count: operation_samples.len(),
                },
            );
        }

        baselines
    }

    /// Detect performance anomalies
    fn detect_anomalies(
        samples: &[&EnhancedProfileSample],
        baselines: &HashMap<String, PerformanceBaseline>,
        thresholds: &EnhancedPerformanceThresholds,
        sensitivity: f64,
    ) -> Vec<PerformanceAnomaly> {
        let mut anomalies = Vec::new();

        for sample in samples {
            if let Some(baseline) = baselines.get(&sample.operation_type) {
                let response_time_ms = sample.duration_us as f64 / 1000.0;

                // Check for high response time
                if response_time_ms > baseline.p95_response_time_ms * (1.0 + sensitivity) {
                    anomalies.push(PerformanceAnomaly {
                        id: uuid::Uuid::new_v4().to_string(),
                        anomaly_type: AnomalyType::HighResponseTime,
                        severity: Self::calculate_severity(
                            response_time_ms,
                            baseline.p95_response_time_ms,
                            thresholds.max_response_time_ms as f64,
                        ),
                        description: format!(
                            "Response time {}ms is significantly higher than baseline {:.1}ms",
                            response_time_ms, baseline.p95_response_time_ms
                        ),
                        operation_type: sample.operation_type.clone(),
                        expected_value: baseline.p95_response_time_ms,
                        actual_value: response_time_ms,
                        deviation_percent: ((response_time_ms - baseline.p95_response_time_ms)
                            / baseline.p95_response_time_ms)
                            * 100.0,
                        timestamp: sample.timestamp,
                        recommended_action: "Investigate slow operations and consider optimization"
                            .to_string(),
                    });
                }

                // Check system resource anomalies
                if let Some(ref system_snapshot) = sample.system_snapshot {
                    // CPU usage anomaly
                    if system_snapshot.cpu.overall_usage_percent
                        > baseline.avg_cpu_usage_percent * (1.0 + sensitivity)
                    {
                        anomalies.push(PerformanceAnomaly {
                            id: uuid::Uuid::new_v4().to_string(),
                            anomaly_type: AnomalyType::HighCpuUsage,
                            severity: Self::calculate_severity(system_snapshot.cpu.overall_usage_percent, 
                                                            baseline.avg_cpu_usage_percent, thresholds.max_cpu_usage_percent),
                            description: format!("CPU usage {:.1}% is significantly higher than baseline {:.1}%", 
                                            system_snapshot.cpu.overall_usage_percent, baseline.avg_cpu_usage_percent),
                            operation_type: sample.operation_type.clone(),
                            expected_value: baseline.avg_cpu_usage_percent,
                            actual_value: system_snapshot.cpu.overall_usage_percent,
                            deviation_percent: ((system_snapshot.cpu.overall_usage_percent - baseline.avg_cpu_usage_percent) / baseline.avg_cpu_usage_percent) * 100.0,
                            timestamp: sample.timestamp,
                            recommended_action: "Check for CPU-intensive operations or consider scaling".to_string(),
                        });
                    }

                    // Memory usage anomaly
                    if system_snapshot.memory.usage_percent
                        > baseline.avg_memory_usage_percent * (1.0 + sensitivity)
                    {
                        anomalies.push(PerformanceAnomaly {
                            id: uuid::Uuid::new_v4().to_string(),
                            anomaly_type: AnomalyType::HighMemoryUsage,
                            severity: Self::calculate_severity(
                                system_snapshot.memory.usage_percent,
                                baseline.avg_memory_usage_percent,
                                thresholds.max_memory_usage_percent,
                            ),
                            description: format!(
                                "Memory usage {:.1}% is significantly higher than baseline {:.1}%",
                                system_snapshot.memory.usage_percent,
                                baseline.avg_memory_usage_percent
                            ),
                            operation_type: sample.operation_type.clone(),
                            expected_value: baseline.avg_memory_usage_percent,
                            actual_value: system_snapshot.memory.usage_percent,
                            deviation_percent: ((system_snapshot.memory.usage_percent
                                - baseline.avg_memory_usage_percent)
                                / baseline.avg_memory_usage_percent)
                                * 100.0,
                            timestamp: sample.timestamp,
                            recommended_action: "Check for memory leaks or optimize memory usage"
                                .to_string(),
                        });
                    }
                }
            }
        }

        anomalies
    }

    /// Calculate anomaly severity based on deviation and thresholds
    fn calculate_severity(actual: f64, baseline: f64, threshold: f64) -> AnomalySeverity {
        let deviation_ratio = actual / baseline;
        let threshold_ratio = actual / threshold;

        if threshold_ratio > 1.0 {
            AnomalySeverity::Critical
        } else if deviation_ratio > 2.0 {
            AnomalySeverity::High
        } else if deviation_ratio > 1.5 {
            AnomalySeverity::Medium
        } else {
            AnomalySeverity::Low
        }
    }

    /// Get current performance baselines
    pub async fn get_baselines(&self) -> HashMap<String, PerformanceBaseline> {
        let baselines = self.baselines.read().await;
        baselines.clone()
    }

    /// Get detected anomalies
    pub async fn get_anomalies(&self, limit: Option<usize>) -> Vec<PerformanceAnomaly> {
        let anomalies = self.anomalies.read().await;
        match limit {
            Some(limit) => anomalies.iter().rev().take(limit).cloned().collect(),
            None => anomalies.clone(),
        }
    }

    /// Get performance summary
    pub async fn get_performance_summary(&self) -> Result<PerformanceSummary> {
        let samples = self.samples.read().await;
        let baselines = self.baselines.read().await;
        let anomalies = self.anomalies.read().await;

        let total_samples = samples.len();
        let recent_samples: Vec<_> = samples
            .iter()
            .filter(|sample| sample.timestamp > chrono::Utc::now() - chrono::Duration::minutes(60))
            .collect();

        let avg_response_time_ms = if !recent_samples.is_empty() {
            recent_samples
                .iter()
                .map(|s| s.duration_us as f64 / 1000.0)
                .sum::<f64>()
                / recent_samples.len() as f64
        } else {
            0.0
        };

        let error_rate_percent = if !recent_samples.is_empty() {
            let error_count = recent_samples.iter().filter(|s| !s.success).count();
            (error_count as f64 / recent_samples.len() as f64) * 100.0
        } else {
            0.0
        };

        let recent_anomalies = anomalies
            .iter()
            .filter(|anomaly| {
                anomaly.timestamp > chrono::Utc::now() - chrono::Duration::minutes(60)
            })
            .count();

        Ok(PerformanceSummary {
            total_samples,
            recent_samples_count: recent_samples.len(),
            avg_response_time_ms,
            error_rate_percent,
            active_baselines_count: baselines.len(),
            recent_anomalies_count: recent_anomalies,
            last_baseline_update: *self.last_baseline_update.read().await,
        })
    }

    /// Clear old anomalies
    pub async fn clear_old_anomalies(&self, older_than_hours: u32) -> Result<usize> {
        let cutoff = chrono::Utc::now() - chrono::Duration::hours(older_than_hours as i64);
        let mut anomalies = self.anomalies.write().await;
        let initial_len = anomalies.len();
        anomalies.retain(|anomaly| anomaly.timestamp > cutoff);
        Ok(initial_len - anomalies.len())
    }
}

/// Performance summary
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceSummary {
    /// Total number of profile samples
    pub total_samples: usize,
    /// Number of recent samples (last hour)
    pub recent_samples_count: usize,
    /// Average response time in milliseconds
    pub avg_response_time_ms: f64,
    /// Error rate percentage
    pub error_rate_percent: f64,
    /// Number of active baselines
    pub active_baselines_count: usize,
    /// Number of recent anomalies (last hour)
    pub recent_anomalies_count: usize,
    /// Last baseline update time
    pub last_baseline_update: chrono::DateTime<chrono::Utc>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::observability::system_resources::SystemResourceConfig;
    use tokio::time::sleep;

    #[tokio::test]
    async fn test_enhanced_performance_monitor_creation() {
        let config = EnhancedPerformanceConfig::default();
        let system_config = SystemResourceConfig::default();
        let system_monitor = Arc::new(SystemResourceMonitor::new(system_config));

        let monitor = EnhancedPerformanceMonitor::new(config, system_monitor);

        // Test starting an operation
        let operation_id = monitor
            .start_operation(
                "test_operation".to_string(),
                "test_name".to_string(),
                HashMap::new(),
            )
            .await;

        assert!(!operation_id.is_empty());

        // Test finishing the operation
        monitor
            .finish_operation(operation_id, true, None, HashMap::new(), HashMap::new())
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn test_performance_summary() {
        let config = EnhancedPerformanceConfig::default();
        let system_config = SystemResourceConfig::default();
        let system_monitor = Arc::new(SystemResourceMonitor::new(system_config));

        let monitor = EnhancedPerformanceMonitor::new(config, system_monitor);

        // Wait for some data collection
        sleep(Duration::from_millis(100)).await;

        let summary = monitor.get_performance_summary().await.unwrap();
        assert_eq!(summary.total_samples, 0); // No operations performed yet
    }
}
