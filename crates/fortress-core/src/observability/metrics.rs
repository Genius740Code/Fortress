//! Advanced metrics collection system for Fortress
//!
//! Provides comprehensive metrics collection with multiple metric types,
//! aggregation, and export capabilities.

use crate::error::{FortressError, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

/// Advanced metrics configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricsConfig {
    /// Enable metrics collection
    pub enabled: bool,
    /// Collection interval in seconds
    pub collection_interval_seconds: u64,
    /// Retention period in hours
    pub retention_hours: u32,
    /// Export configuration
    pub export: MetricsExportConfig,
    /// Aggregation configuration
    pub aggregation: AggregationConfig,
}

/// Metrics export configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricsExportConfig {
    /// Exporter types
    pub exporters: Vec<MetricsExporter>,
    /// Export interval in seconds
    pub interval_seconds: u64,
    /// Export timeout in seconds
    pub timeout_seconds: u64,
}

/// Metrics exporter types
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum MetricsExporter {
    /// Prometheus exporter
    Prometheus,
    /// OpenTelemetry exporter
    OpenTelemetry,
    /// StatsD exporter
    StatsD,
    /// InfluxDB exporter
    InfluxDB,
    /// JSON file exporter
    JsonFile,
    /// Console exporter
    Console,
}

/// Aggregation configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AggregationConfig {
    /// Enable aggregation
    pub enabled: bool,
    /// Aggregation window in seconds
    pub window_seconds: u64,
    /// Percentiles to calculate
    pub percentiles: Vec<f64>,
    /// Enable histogram calculation
    pub enable_histograms: bool,
    /// Histogram buckets
    pub histogram_buckets: Vec<f64>,
}

impl Default for MetricsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            collection_interval_seconds: 10,
            retention_hours: 24,
            export: MetricsExportConfig::default(),
            aggregation: AggregationConfig::default(),
        }
    }
}

impl Default for MetricsExportConfig {
    fn default() -> Self {
        Self {
            exporters: vec![MetricsExporter::Console],
            interval_seconds: 30,
            timeout_seconds: 10,
        }
    }
}

impl Default for AggregationConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            window_seconds: 60,
            percentiles: vec![0.5, 0.95, 0.99],
            enable_histograms: true,
            histogram_buckets: vec![
                0.1, 0.5, 1.0, 2.5, 5.0, 10.0, 25.0, 50.0, 100.0, 250.0, 500.0, 1000.0,
            ],
        }
    }
}

/// Metric types
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum MetricType {
    /// Counter metric (monotonically increasing)
    Counter,
    /// Gauge metric (can go up and down)
    Gauge,
    /// Histogram metric (distribution of values)
    Histogram,
    /// Summary metric (similar to histogram with configurable quantiles)
    Summary,
}

/// Metric value
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MetricValue {
    /// Counter value
    Counter(u64),
    /// Gauge value
    Gauge(f64),
    /// Histogram value
    Histogram(HistogramValue),
    /// Summary value
    Summary(SummaryValue),
}

/// Histogram metric value
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HistogramValue {
    /// Total count of observations
    pub count: u64,
    /// Sum of all observations
    pub sum: f64,
    /// Bucket counts
    pub buckets: HashMap<String, u64>,
}

/// Summary metric value
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SummaryValue {
    /// Total count of observations
    pub count: u64,
    /// Sum of all observations
    pub sum: f64,
    /// Quantile values
    pub quantiles: HashMap<String, f64>,
}

/// Metric definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricDefinition {
    /// Metric name
    pub name: String,
    /// Metric type
    pub metric_type: MetricType,
    /// Description
    pub description: String,
    /// Labels
    pub labels: HashMap<String, String>,
    /// Unit
    pub unit: Option<String>,
}

/// Metric data point
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricDataPoint {
    /// Metric definition
    pub definition: MetricDefinition,
    /// Value
    pub value: MetricValue,
    /// Timestamp
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

/// Metrics summary
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricsSummary {
    /// Total metrics count
    pub total_metrics: usize,
    /// Metrics by type
    pub metrics_by_type: HashMap<MetricType, usize>,
    /// Collection rate (metrics per second)
    pub collection_rate: f64,
    /// Memory usage in bytes
    pub memory_usage_bytes: u64,
    /// Last collection time
    pub last_collection_time: chrono::DateTime<chrono::Utc>,
}

/// Advanced metrics collector
#[derive(Debug)]
pub struct AdvancedMetricsCollector {
    /// Configuration
    config: MetricsConfig,
    /// Metric registry
    registry: Arc<RwLock<MetricRegistry>>,
    /// Collection start time
    start_time: Instant,
    /// Collection statistics
    stats: Arc<RwLock<CollectionStats>>,
}

/// Metric registry
#[derive(Debug, Default)]
pub struct MetricRegistry {
    /// Metric definitions
    definitions: HashMap<String, MetricDefinition>,
    /// Metric values
    values: HashMap<String, Arc<MetricStorage>>,
    /// Time series data
    time_series: HashMap<String, Vec<MetricDataPoint>>,
}

/// Metric storage for different metric types
#[derive(Debug)]
enum MetricStorage {
    Counter(AtomicU64),
    Gauge(tokio::sync::RwLock<f64>),
    Histogram(tokio::sync::RwLock<HistogramStorage>),
    Summary(tokio::sync::RwLock<SummaryStorage>),
}

/// Histogram storage
#[derive(Debug, Default)]
struct HistogramStorage {
    count: u64,
    sum: f64,
    buckets: HashMap<String, u64>,
    observations: Vec<f64>,
}

/// Summary storage
#[derive(Debug, Default)]
struct SummaryStorage {
    count: u64,
    sum: f64,
    observations: Vec<f64>,
    quantiles: Vec<f64>,
}

/// Collection statistics
#[derive(Debug, Default)]
struct CollectionStats {
    total_collections: u64,
    total_metrics_collected: u64,
    last_collection_time: Option<chrono::DateTime<chrono::Utc>>,
    collection_errors: u64,
}

impl AdvancedMetricsCollector {
    /// Create a new advanced metrics collector
    pub fn new(config: MetricsConfig) -> Result<Self> {
        Ok(Self {
            config,
            registry: Arc::new(RwLock::new(MetricRegistry::default())),
            start_time: Instant::now(),
            stats: Arc::new(RwLock::new(CollectionStats::default())),
        })
    }

    /// Register a new metric
    pub async fn register_metric(&self, definition: MetricDefinition) -> Result<()> {
        if !self.config.enabled {
            return Ok(());
        }

        let mut registry = self.registry.write().await;
        
        // Check if metric already exists
        if registry.definitions.contains_key(&definition.name) {
            return Err(FortressError::validation(
                format!("Metric '{}' already registered", definition.name),
                None,
                None,
            ));
        }

        // Create metric storage based on type
        let storage = match definition.metric_type {
            MetricType::Counter => MetricStorage::Counter(AtomicU64::new(0)),
            MetricType::Gauge => MetricStorage::Gauge(tokio::sync::RwLock::new(0.0)),
            MetricType::Histogram => {
                let buckets = self.config.aggregation.histogram_buckets
                    .iter()
                    .enumerate()
                    .map(|(i, &bound)| (format!("le_{}", bound), 0))
                    .collect();
                MetricStorage::Histogram(tokio::sync::RwLock::new(HistogramStorage {
                    buckets,
                    ..Default::default()
                }))
            }
            MetricType::Summary => MetricStorage::Summary(tokio::sync::RwLock::new(SummaryStorage {
                quantiles: self.config.aggregation.percentiles.clone(),
                ..Default::default()
            })),
        };

        registry.definitions.insert(definition.name.clone(), definition.clone());
        registry.values.insert(definition.name, Arc::new(storage));

        Ok(())
    }

    /// Record a counter metric
    pub async fn record_counter(&self, name: &str, value: u64, labels: HashMap<String, String>) -> Result<()> {
        if !self.config.enabled {
            return Ok(());
        }

        let full_name = self.format_metric_name(name, &labels);
        let registry = self.registry.read().await;
        
        if let Some(storage) = registry.values.get(&full_name) {
            if let MetricStorage::Counter(counter) = storage.as_ref() {
                counter.fetch_add(value, Ordering::Relaxed);
                self.record_time_series(&full_name, MetricValue::Counter(value)).await;
            }
        }

        Ok(())
    }

    /// Set a gauge metric
    pub async fn set_gauge(&self, name: &str, value: f64, labels: HashMap<String, String>) -> Result<()> {
        if !self.config.enabled {
            return Ok(());
        }

        let full_name = self.format_metric_name(name, &labels);
        let registry = self.registry.read().await;
        
        if let Some(storage) = registry.values.get(&full_name) {
            if let MetricStorage::Gauge(gauge) = storage.as_ref() {
                let mut gauge_val = gauge.write().await;
                *gauge_val = value;
                self.record_time_series(&full_name, MetricValue::Gauge(value)).await;
            }
        }

        Ok(())
    }

    /// Record a histogram observation
    pub async fn record_histogram(&self, name: &str, value: f64, labels: HashMap<String, String>) -> Result<()> {
        if !self.config.enabled {
            return Ok(());
        }

        let full_name = self.format_metric_name(name, &labels);
        let registry = self.registry.read().await;
        
        if let Some(storage) = registry.values.get(&full_name) {
            if let MetricStorage::Histogram(hist) = storage.as_ref() {
                let mut histogram = hist.write().await;
                histogram.count += 1;
                histogram.sum += value;
                histogram.observations.push(value);

                // Update buckets
                for bucket_bound in &self.config.aggregation.histogram_buckets {
                    if value <= *bucket_bound {
                        let bucket_key = format!("le_{}", bucket_bound);
                        *histogram.buckets.entry(bucket_key).or_insert(0) += 1;
                    }
                }

                // Keep observations limited
                if histogram.observations.len() > 10000 {
                    histogram.observations.drain(0..5000);
                }

                let histogram_value = MetricValue::Histogram(HistogramValue {
                    count: histogram.count,
                    sum: histogram.sum,
                    buckets: histogram.buckets.clone(),
                });
                self.record_time_series(&full_name, histogram_value).await;
            }
        }

        Ok(())
    }

    /// Record a summary observation
    pub async fn record_summary(&self, name: &str, value: f64, labels: HashMap<String, String>) -> Result<()> {
        if !self.config.enabled {
            return Ok(());
        }

        let full_name = self.format_metric_name(name, &labels);
        let registry = self.registry.read().await;
        
        if let Some(storage) = registry.values.get(&full_name) {
            if let MetricStorage::Summary(summary) = storage.as_ref() {
                let mut sum = summary.write().await;
                sum.count += 1;
                sum.sum += value;
                sum.observations.push(value);

                // Keep observations limited
                if sum.observations.len() > 10000 {
                    sum.observations.drain(0..5000);
                }

                // Calculate quantiles
                let mut quantiles = HashMap::new();
                if !sum.observations.is_empty() {
                    let mut sorted = sum.observations.clone();
                    sorted.sort_by(|a, b| a.partial_cmp(b).unwrap());
                    
                    for &quantile in &sum.quantiles {
                        let index = ((quantile * (sorted.len() - 1) as f64) as usize).min(sorted.len() - 1);
                        quantiles.insert(format!("{:.2}", quantile), sorted[index]);
                    }
                }

                let summary_value = MetricValue::Summary(SummaryValue {
                    count: sum.count,
                    sum: sum.sum,
                    quantiles,
                });
                self.record_time_series(&full_name, summary_value).await;
            }
        }

        Ok(())
    }

    /// Get metric value
    pub async fn get_metric(&self, name: &str, labels: HashMap<String, String>) -> Result<Option<MetricValue>> {
        if !self.config.enabled {
            return Ok(None);
        }

        let full_name = self.format_metric_name(name, &labels);
        let registry = self.registry.read().await;
        
        if let Some(storage) = registry.values.get(&full_name) {
            let value = match storage.as_ref() {
                MetricStorage::Counter(counter) => MetricValue::Counter(counter.load(Ordering::Relaxed)),
                MetricStorage::Gauge(gauge) => MetricValue::Gauge(*gauge.read().await),
                MetricStorage::Histogram(hist) => {
                    let histogram = hist.read().await;
                    MetricValue::Histogram(HistogramValue {
                        count: histogram.count,
                        sum: histogram.sum,
                        buckets: histogram.buckets.clone(),
                    })
                }
                MetricStorage::Summary(summary) => {
                    let sum = summary.read().await;
                    let mut quantiles = HashMap::new();
                    if !sum.observations.is_empty() {
                        let mut sorted = sum.observations.clone();
                        sorted.sort_by(|a, b| a.partial_cmp(b).unwrap());
                        
                        for &quantile in &sum.quantiles {
                            let index = ((quantile * (sorted.len() - 1) as f64) as usize).min(sorted.len() - 1);
                            quantiles.insert(format!("{:.2}", quantile), sorted[index]);
                        }
                    }
                    MetricValue::Summary(SummaryValue {
                        count: sum.count,
                        sum: sum.sum,
                        quantiles,
                    })
                }
            };
            Ok(Some(value))
        } else {
            Ok(None)
        }
    }

    /// Get all metrics
    pub async fn get_all_metrics(&self) -> Result<HashMap<String, (MetricDefinition, MetricValue)>> {
        if !self.config.enabled {
            return Ok(HashMap::new());
        }

        let registry = self.registry.read().await;
        let mut metrics = HashMap::new();

        for (name, definition) in &registry.definitions {
            if let Some(storage) = registry.values.get(name) {
                let value = match storage.as_ref() {
                    MetricStorage::Counter(counter) => MetricValue::Counter(counter.load(Ordering::Relaxed)),
                    MetricStorage::Gauge(gauge) => MetricValue::Gauge(*gauge.read().await),
                    MetricStorage::Histogram(hist) => {
                        let histogram = hist.read().await;
                        MetricValue::Histogram(HistogramValue {
                            count: histogram.count,
                            sum: histogram.sum,
                            buckets: histogram.buckets.clone(),
                        })
                    }
                    MetricStorage::Summary(summary) => {
                        let sum = summary.read().await;
                        let mut quantiles = HashMap::new();
                        if !sum.observations.is_empty() {
                            let mut sorted = sum.observations.clone();
                            sorted.sort_by(|a, b| a.partial_cmp(b).unwrap());
                            
                            for &quantile in &sum.quantiles {
                                let index = ((quantile * (sorted.len() - 1) as f64) as usize).min(sorted.len() - 1);
                                quantiles.insert(format!("{:.2}", quantile), sorted[index]);
                            }
                        }
                        MetricValue::Summary(SummaryValue {
                            count: sum.count,
                            sum: sum.sum,
                            quantiles,
                        })
                    }
                };
                metrics.insert(name.clone(), (definition.clone(), value));
            }
        }

        Ok(metrics)
    }

    /// Get metrics summary
    pub async fn get_summary(&self) -> MetricsSummary {
        let registry = self.registry.read().await;
        let stats = self.stats.read().await;

        let total_metrics = registry.definitions.len();
        let mut metrics_by_type = HashMap::new();
        
        for definition in registry.definitions.values() {
            *metrics_by_type.entry(definition.metric_type).or_insert(0) += 1;
        }

        let collection_rate = if let Some(last_time) = stats.last_collection_time {
            let duration = chrono::Utc::now() - last_time;
            if duration.num_seconds() > 0 {
                stats.total_metrics_collected as f64 / duration.num_seconds() as f64
            } else {
                0.0
            }
        } else {
            0.0
        };

        MetricsSummary {
            total_metrics,
            metrics_by_type,
            collection_rate,
            memory_usage_bytes: self.estimate_memory_usage().await,
            last_collection_time: stats.last_collection_time.unwrap_or_else(|| chrono::Utc::now()),
        }
    }

    /// Export metrics in Prometheus format
    pub async fn export_prometheus(&self) -> Result<String> {
        if !self.config.enabled {
            return Ok(String::new());
        }

        let metrics = self.get_all_metrics().await?;
        let mut output = Vec::new();

        for (name, (definition, value)) in metrics {
            // Add HELP and TYPE comments
            output.push(format!("# HELP {} {}", name, definition.description));
            output.push(format!("# TYPE {} {}", name, self.metric_type_to_prometheus(definition.metric_type)));

            match value {
                MetricValue::Counter(val) => {
                    output.push(format!("{} {}", name, val));
                }
                MetricValue::Gauge(val) => {
                    output.push(format!("{} {}", name, val));
                }
                MetricValue::Histogram(hist) => {
                    output.push(format!("{}_count {}", name, hist.count));
                    output.push(format!("{}_sum {}", name, hist.sum));
                    for (bucket, count) in hist.buckets {
                        output.push(format!("{}_bucket{{le=\"{}\"}} {}", name, bucket.trim_start_matches("le_"), count));
                    }
                }
                MetricValue::Summary(summary) => {
                    output.push(format!("{}_count {}", name, summary.count));
                    output.push(format!("{}_sum {}", name, summary.sum));
                    for (quantile, value) in summary.quantiles {
                        output.push(format!("{}{{quantile=\"{}\"}} {}", name, quantile, value));
                    }
                }
            }
        }

        Ok(output.join("\n"))
    }

    /// Start the metrics collector
    pub async fn start(&self) -> Result<()> {
        if !self.config.enabled {
            return Ok(());
        }

        // Start background collection task
        self.start_collection_task().await;

        tracing::info!("Advanced metrics collector started");
        Ok(())
    }

    /// Shutdown the metrics collector
    pub async fn shutdown(&self) -> Result<()> {
        if self.config.enabled {
            tracing::info!("Advanced metrics collector shutdown");
        }
        Ok(())
    }

    /// Format metric name with labels
    fn format_metric_name(&self, name: &str, labels: &HashMap<String, String>) -> String {
        if labels.is_empty() {
            name.to_string()
        } else {
            let label_str: Vec<String> = labels
                .iter()
                .map(|(k, v)| format!("{}=\"{}\"", k, v))
                .collect();
            format!("{{{}}}", label_str.join(","))
        }
    }

    /// Record time series data
    async fn record_time_series(&self, name: &str, value: MetricValue) {
        let mut registry = self.registry.write().await;
        let data_point = MetricDataPoint {
            definition: registry.definitions.get(name).cloned().unwrap_or_else(|| MetricDefinition {
                name: name.to_string(),
                metric_type: MetricType::Counter,
                description: "Auto-generated metric".to_string(),
                labels: HashMap::new(),
                unit: None,
            }),
            value,
            timestamp: chrono::Utc::now(),
        };

        registry.time_series.entry(name.to_string()).or_insert_with(Vec::new).push(data_point);

        // Limit time series data
        let time_series = registry.time_series.get_mut(name).unwrap();
        if time_series.len() > 1000 {
            time_series.drain(0..500);
        }
    }

    /// Start background collection task
    async fn start_collection_task(&self) {
        let registry = self.registry.clone();
        let stats = self.stats.clone();
        let interval = Duration::from_secs(self.config.collection_interval_seconds);

        tokio::spawn(async move {
            let mut timer = tokio::time::interval(interval);
            
            loop {
                timer.tick().await;
                
                // Update collection statistics
                let mut stats_guard = stats.write().await;
                stats_guard.total_collections += 1;
                stats_guard.last_collection_time = Some(chrono::Utc::now());
                
                // Count total metrics
                let registry_guard = registry.read().await;
                stats_guard.total_metrics_collected += registry_guard.definitions.len() as u64;
            }
        });
    }

    /// Estimate memory usage
    async fn estimate_memory_usage(&self) -> u64 {
        let registry = self.registry.read().await;
        let mut total_size = 0u64;

        // Estimate size of definitions
        for definition in registry.definitions.values() {
            total_size += definition.name.len() as u64;
            total_size += definition.description.len() as u64;
            total_size += (definition.labels.len() * 50) as u64; // Rough estimate
        }

        // Estimate size of time series data
        for time_series in registry.time_series.values() {
            total_size += (time_series.len() * 200) as u64; // Rough estimate per data point
        }

        total_size
    }

    /// Convert metric type to Prometheus type
    fn metric_type_to_prometheus(&self, metric_type: MetricType) -> &'static str {
        match metric_type {
            MetricType::Counter => "counter",
            MetricType::Gauge => "gauge",
            MetricType::Histogram => "histogram",
            MetricType::Summary => "summary",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_metrics_collector_creation() {
        let config = MetricsConfig::default();
        let collector = AdvancedMetricsCollector::new(config);
        assert!(collector.is_ok());
    }

    #[tokio::test]
    async fn test_counter_metric() {
        let config = MetricsConfig::default();
        let collector = AdvancedMetricsCollector::new(config).unwrap();

        let definition = MetricDefinition {
            name: "test_counter".to_string(),
            metric_type: MetricType::Counter,
            description: "Test counter".to_string(),
            labels: HashMap::new(),
            unit: Some("count".to_string()),
        };

        collector.register_metric(definition).await.unwrap();
        collector.record_counter("test_counter", 5, HashMap::new()).await.unwrap();

        let value = collector.get_metric("test_counter", HashMap::new()).await.unwrap();
        assert!(matches!(value, Some(MetricValue::Counter(5))));
    }

    #[tokio::test]
    async fn test_gauge_metric() {
        let config = MetricsConfig::default();
        let collector = AdvancedMetricsCollector::new(config).unwrap();

        let definition = MetricDefinition {
            name: "test_gauge".to_string(),
            metric_type: MetricType::Gauge,
            description: "Test gauge".to_string(),
            labels: HashMap::new(),
            unit: Some("bytes".to_string()),
        };

        collector.register_metric(definition).await.unwrap();
        collector.set_gauge("test_gauge", 42.5, HashMap::new()).await.unwrap();

        let value = collector.get_metric("test_gauge", HashMap::new()).await.unwrap();
        assert!(matches!(value, Some(MetricValue::Gauge(42.5))));
    }

    #[tokio::test]
    async fn test_prometheus_export() {
        let config = MetricsConfig::default();
        let collector = AdvancedMetricsCollector::new(config).unwrap();

        let definition = MetricDefinition {
            name: "test_counter".to_string(),
            metric_type: MetricType::Counter,
            description: "Test counter".to_string(),
            labels: HashMap::new(),
            unit: None,
        };

        collector.register_metric(definition).await.unwrap();
        collector.record_counter("test_counter", 10, HashMap::new()).await.unwrap();

        let prometheus_output = collector.export_prometheus().await.unwrap();
        assert!(prometheus_output.contains("test_counter"));
        assert!(prometheus_output.contains("# HELP"));
        assert!(prometheus_output.contains("# TYPE"));
    }
}
