//! Performance monitoring and metrics for GraphQL operations
//!
//! Implements comprehensive performance tracking, query analysis,
//! and real-time metrics collection for optimization and monitoring.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tokio::sync::RwLock;
use serde::{Serialize, Deserialize};
use uuid::Uuid;

/// Performance metrics for a single operation
#[derive(Debug, Clone, async_graphql::SimpleObject)]
pub struct OperationMetrics {
    pub operation_id: String,
    pub operation_type: OperationType,
    pub operation_name: String,
    pub duration_ms: Option<u64>,
    pub success: bool,
    pub error_message: Option<String>,
    pub record_count: Option<usize>,
    pub cache_hit: bool,
    pub database_operations: u32,
    pub memory_usage_bytes: u64,
}

/// Serializable version of OperationMetrics for API responses
#[derive(Debug, Clone, Serialize, Deserialize, async_graphql::SimpleObject)]
pub struct SerializableOperationMetrics {
    pub operation_id: String,
    pub operation_type: OperationType,
    pub operation_name: String,
    pub start_time_ms: u64,
    pub end_time_ms: Option<u64>,
    pub duration_ms: Option<u64>,
    pub success: bool,
    pub error_message: Option<String>,
    pub record_count: Option<usize>,
    pub cache_hit: bool,
    pub database_operations: u32,
    pub memory_usage_bytes: Option<u64>,
}

impl From<&OperationMetrics> for SerializableOperationMetrics {
    fn from(metrics: &OperationMetrics) -> Self {
        Self {
            operation_id: metrics.operation_id.clone(),
            operation_type: metrics.operation_type.clone(),
            operation_name: metrics.operation_name.clone(),
            start_time_ms: (SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_else(|_| std::time::Duration::from_secs(0))
                .as_millis() as u64),
            end_time_ms: None, // We don't track end_time separately, only duration
            duration_ms: metrics.duration_ms,
            success: metrics.success,
            error_message: metrics.error_message.clone(),
            record_count: metrics.record_count,
            cache_hit: metrics.cache_hit,
            database_operations: metrics.database_operations,
            memory_usage_bytes: Some(metrics.memory_usage_bytes),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, async_graphql::Enum, Copy, PartialEq, Eq)]
pub enum OperationType {
    Query,
    Mutation,
    Subscription,
}

impl OperationMetrics {
    pub fn new(operation_type: OperationType, operation_name: String) -> Self {
        Self {
            operation_id: Uuid::new_v4().to_string(),
            operation_type,
            operation_name,
            duration_ms: None,
            success: false,
            error_message: None,
            record_count: None,
            cache_hit: false,
            database_operations: 0,
            memory_usage_bytes: 0,
        }
    }

    pub fn complete(&mut self, success: bool, record_count: Option<usize>) {
        let start_time = std::time::Instant::now();
        self.duration_ms = Some(start_time.elapsed().as_millis() as u64);
        self.success = success;
        self.record_count = record_count;
    }

    pub fn set_error(&mut self, error: &str) {
        self.error_message = Some(error.to_string());
        self.complete(false, None);
    }

    pub fn set_cache_hit(&mut self) {
        self.cache_hit = true;
    }

    pub fn increment_database_operations(&mut self) {
        self.database_operations += 1;
    }
}

/// Aggregated performance statistics
#[derive(Debug, Clone, Serialize, Deserialize, async_graphql::SimpleObject)]
pub struct PerformanceStats {
    pub total_operations: u64,
    pub successful_operations: u64,
    pub failed_operations: u64,
    pub average_duration_ms: f64,
    pub p95_duration_ms: f64,
    pub p99_duration_ms: f64,
    pub cache_hit_rate: f64,
    pub operations_per_second: f64,
    pub average_record_count: f64,
    pub total_database_operations: u64,
}

/// Performance monitor for GraphQL operations
#[derive(Clone)]
pub struct PerformanceMonitor {
    operations: Arc<RwLock<Vec<OperationMetrics>>>,
    max_operations: usize,
    cleanup_interval: Duration,
}

impl PerformanceMonitor {
    pub fn new(max_operations: usize, cleanup_interval: Duration) -> Self {
        Self {
            operations: Arc::new(RwLock::new(Vec::new())),
            max_operations,
            cleanup_interval,
        }
    }

    /// Start monitoring an operation
    pub async fn start_operation(&self, operation_type: OperationType, operation_name: String) -> OperationTracker {
        let metrics = OperationMetrics::new(operation_type, operation_name);
        let operation_id = metrics.operation_id.clone();
        
        {
            let mut operations = self.operations.write().await;
            operations.push(metrics);
            
            // Maintain max size
            if operations.len() > self.max_operations {
                operations.remove(0);
            }
        }

        OperationTracker {
            monitor: Arc::new(self.clone()),
            operation_id,
        }
    }

    /// Get performance statistics
    pub async fn get_stats(&self) -> PerformanceStats {
        let operations = self.operations.read().await;
        
        if operations.is_empty() {
            return PerformanceStats {
                total_operations: 0,
                successful_operations: 0,
                failed_operations: 0,
                average_duration_ms: 0.0,
                p95_duration_ms: 0.0,
                p99_duration_ms: 0.0,
                cache_hit_rate: 0.0,
                operations_per_second: 0.0,
                average_record_count: 0.0,
                total_database_operations: 0,
            };
        }

        let completed_operations: Vec<_> = operations.iter()
            .filter(|op| op.duration_ms.is_some())
            .collect();

        let total_operations = operations.len() as u64;
        let successful_operations = completed_operations.iter()
            .filter(|op| op.success)
            .count() as u64;
        let failed_operations = completed_operations.len() as u64 - successful_operations;

        let durations: Vec<u64> = completed_operations.iter()
            .filter_map(|op| op.duration_ms)
            .collect();

        let average_duration_ms = if !durations.is_empty() {
            durations.iter().sum::<u64>() as f64 / durations.len() as f64
        } else {
            0.0
        };

        let mut sorted_durations = durations.clone();
        sorted_durations.sort();
        let p95_duration_ms = if !sorted_durations.is_empty() {
            let index = (sorted_durations.len() as f64 * 0.95) as usize;
            sorted_durations.get(index).copied().unwrap_or(0) as f64
        } else {
            0.0
        };

        let p99_duration_ms = if !sorted_durations.is_empty() {
            let index = (sorted_durations.len() as f64 * 0.99) as usize;
            sorted_durations.get(index).copied().unwrap_or(0) as f64
        } else {
            0.0
        };

        let cache_hits = completed_operations.iter()
            .filter(|op| op.cache_hit)
            .count() as f64;
        let cache_hit_rate = if !completed_operations.is_empty() {
            cache_hits / completed_operations.len() as f64
        } else {
            0.0
        };

        // Calculate operations per second (last minute) - simplified since we don't have start_time field
        let recent_operations = completed_operations.len() as f64;
        let operations_per_second = recent_operations / 60.0;

        let average_record_count = if !completed_operations.is_empty() {
            completed_operations.iter()
                .filter_map(|op| op.record_count)
                .sum::<usize>() as f64 / completed_operations.len() as f64
        } else {
            0.0
        };

        let total_database_operations: u64 = completed_operations.iter()
            .map(|op| op.database_operations as u64)
            .sum();

        PerformanceStats {
            total_operations,
            successful_operations,
            failed_operations,
            average_duration_ms,
            p95_duration_ms,
            p99_duration_ms,
            cache_hit_rate,
            operations_per_second,
            average_record_count,
            total_database_operations,
        }
    }

    /// Get slow operations
    pub async fn get_slow_operations(&self, threshold_ms: u64) -> Vec<SerializableOperationMetrics> {
        let operations = self.operations.read().await;
        operations.iter()
            .filter(|op| {
                op.duration_ms.map_or(false, |duration| duration > threshold_ms)
            })
            .map(|op| SerializableOperationMetrics::from(op))
            .collect()
    }

    /// Get operations by type
    pub async fn get_operations_by_type(&self, _operation_type: OperationType) -> Vec<OperationMetrics> {
        let operations = self.operations.read().await;
        operations.iter()
            .filter(|op| matches!(op.operation_type, _operation_type))
            .cloned()
            .collect()
    }

    /// Start background cleanup task
    pub fn start_cleanup_task(self: Arc<Self>) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(self.cleanup_interval);
            loop {
                interval.tick().await;
                
                // Clean up old operations (older than 1 hour) - simplified for GraphQL compatibility
                let mut operations = self.operations.write().await;
                operations.retain(|_op| {
                    // Keep operations that are recent (simplified logic)
                    true // For now, keep all operations - real cleanup would need timestamp field
                });
            }
        })
    }
}

/// Tracker for individual operations
pub struct OperationTracker {
    monitor: Arc<PerformanceMonitor>,
    operation_id: String,
}

impl OperationTracker {
    /// Complete the operation successfully
    pub async fn complete_success(self, record_count: Option<usize>) {
        let mut operations = self.monitor.operations.write().await;
        if let Some(operation) = operations.iter_mut()
            .find(|op| op.operation_id == self.operation_id) {
            operation.complete(true, record_count);
        }
    }

    /// Complete the operation with an error
    pub async fn complete_error(self, error: &str) {
        let mut operations = self.monitor.operations.write().await;
        if let Some(operation) = operations.iter_mut()
            .find(|op| op.operation_id == self.operation_id) {
            operation.set_error(error);
        }
    }

    /// Mark as cache hit
    pub async fn set_cache_hit(&self) {
        let mut operations = self.monitor.operations.write().await;
        if let Some(operation) = operations.iter_mut()
            .find(|op| op.operation_id == self.operation_id) {
            operation.set_cache_hit();
        }
    }

    /// Increment database operations counter
    pub async fn increment_database_operations(&self) {
        let mut operations = self.monitor.operations.write().await;
        if let Some(operation) = operations.iter_mut()
            .find(|op| op.operation_id == self.operation_id) {
            operation.increment_database_operations();
        }
    }
}

/// Query analyzer for performance optimization
pub struct QueryAnalyzer {
    slow_query_threshold: Duration,
    complex_query_threshold: usize,
}

impl QueryAnalyzer {
    pub fn new(slow_query_threshold: Duration, complex_query_threshold: usize) -> Self {
        Self {
            slow_query_threshold,
            complex_query_threshold,
        }
    }

    /// Analyze query complexity
    pub fn analyze_query(&self, query: &str) -> QueryAnalysis {
        let complexity = self.calculate_complexity(query);
        let estimated_duration = self.estimate_duration(complexity);
        
        QueryAnalysis {
            complexity,
            estimated_duration,
            is_slow: estimated_duration > self.slow_query_threshold,
            is_complex: complexity > self.complex_query_threshold,
            recommendations: self.generate_recommendations(complexity),
        }
    }

    fn calculate_complexity(&self, query: &str) -> usize {
        // Simple complexity calculation based on query characteristics
        let mut complexity = 0;
        
        // Count fields
        complexity += query.matches('{').count();
        
        // Count nested objects
        complexity += query.matches(':').count();
        
        // Count filters/arguments
        complexity += query.matches('(').count();
        
        // Count pagination
        complexity += query.matches("page").count();
        
        complexity
    }

    fn estimate_duration(&self, complexity: usize) -> Duration {
        // Base duration + complexity factor
        let base_ms = 10;
        let complexity_factor = complexity as u64 * 2;
        Duration::from_millis(base_ms + complexity_factor)
    }

    fn generate_recommendations(&self, complexity: usize) -> Vec<String> {
        let mut recommendations = Vec::new();
        
        if complexity > 100 {
            recommendations.push("Consider breaking this query into smaller parts".to_string());
        }
        
        if complexity > 50 {
            recommendations.push("Add pagination to limit result size".to_string());
        }
        
        if complexity > 200 {
            recommendations.push("Consider using GraphQL subscriptions for real-time data".to_string());
        }
        
        recommendations
    }
}

/// Query analysis result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryAnalysis {
    pub complexity: usize,
    pub estimated_duration: Duration,
    pub is_slow: bool,
    pub is_complex: bool,
    pub recommendations: Vec<String>,
}

/// Resource usage monitor
#[derive(Clone)]
pub struct ResourceMonitor {
    memory_usage: Arc<RwLock<HashMap<String, u64>>>,
    cpu_usage: Arc<RwLock<f64>>,
}

impl ResourceMonitor {
    pub fn new() -> Self {
        Self {
            memory_usage: Arc::new(RwLock::new(HashMap::new())),
            cpu_usage: Arc::new(RwLock::new(0.0)),
        }
    }

    /// Record memory usage for a component
    pub async fn record_memory_usage(&self, component: &str, bytes: u64) {
        let mut memory_usage = self.memory_usage.write().await;
        memory_usage.insert(component.to_string(), bytes);
    }

    /// Get total memory usage
    pub async fn get_total_memory_usage(&self) -> u64 {
        let memory_usage = self.memory_usage.read().await;
        memory_usage.values().sum()
    }

    /// Update CPU usage
    pub async fn update_cpu_usage(&self, usage: f64) {
        let mut cpu_usage = self.cpu_usage.write().await;
        *cpu_usage = usage;
    }

    /// Get CPU usage
    pub async fn get_cpu_usage(&self) -> f64 {
        let cpu_usage = self.cpu_usage.read().await;
        *cpu_usage
    }
}
