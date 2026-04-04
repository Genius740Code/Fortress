//! Metrics collection and export system
//!
//! This module provides comprehensive metrics collection for the Fortress server,
//! including HTTP request metrics, performance metrics, and custom business metrics.

use crate::models::MetricsResponse;
use chrono::Utc;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tracing::info;
use axum::extract::State;

/// Metrics collector for the Fortress server
#[derive(Clone)]
pub struct MetricsCollector {
    /// Internal metrics storage
    internal_metrics: Arc<RwLock<InternalMetrics>>,
    /// Collection start time
    start_time: Instant,
}

/// Internal metrics storage
#[derive(Debug, Default)]
struct InternalMetrics {
    /// HTTP request counts by method and path
    http_requests: HashMap<String, u64>,
    /// HTTP response times by method and path
    http_response_times: HashMap<String, Vec<Duration>>,
    /// HTTP status codes
    http_status_codes: HashMap<u16, u64>,
    /// Active connections
    active_connections: u64,
    /// Total connections processed
    total_connections: u64,
    /// Data stored (bytes)
    data_stored_bytes: u64,
    /// Data retrieved (bytes)
    data_retrieved_bytes: u64,
    /// Encryption operations
    encryption_operations: u64,
    /// Decryption operations
    decryption_operations: u64,
    /// Authentication attempts
    auth_attempts: u64,
    /// Authentication failures
    auth_failures: u64,
    /// Rate limit violations
    rate_limit_violations: u64,
    /// Error counts by type
    errors: HashMap<String, u64>,
}

impl MetricsCollector {
    /// Create a new metrics collector
    pub fn new() -> Self {
        Self {
            internal_metrics: Arc::new(RwLock::new(InternalMetrics::default())),
            start_time: Instant::now(),
        }
    }

    /// Record HTTP request
    pub async fn record_http_request(&self, method: &str, path: &str, status: u16, response_time: Duration) {
        let mut metrics = self.internal_metrics.write().await;
        
        let key = format!("{} {}", method, path);
        *metrics.http_requests.entry(key.clone()).or_insert(0) += 1;
        
        let response_times = metrics.http_response_times.entry(key).or_insert_with(Vec::new);
        response_times.push(response_time);
        
        // Keep only last 1000 response times per endpoint
        if response_times.len() > 1000 {
            response_times.drain(0..response_times.len() - 1000);
        }
        
        *metrics.http_status_codes.entry(status).or_insert(0) += 1;
    }

    /// Increment active connections
    pub async fn increment_active_connections(&self) {
        let mut metrics = self.internal_metrics.write().await;
        metrics.active_connections += 1;
        metrics.total_connections += 1;
    }

    /// Decrement active connections
    pub async fn decrement_active_connections(&self) {
        let mut metrics = self.internal_metrics.write().await;
        if metrics.active_connections > 0 {
            metrics.active_connections -= 1;
        }
    }

    /// Record data storage
    pub async fn record_data_stored(&self, bytes: u64) {
        let mut metrics = self.internal_metrics.write().await;
        metrics.data_stored_bytes += bytes;
    }

    /// Record data retrieval
    pub async fn record_data_retrieved(&self, bytes: u64) {
        let mut metrics = self.internal_metrics.write().await;
        metrics.data_retrieved_bytes += bytes;
    }

    /// Record encryption operation
    pub async fn record_encryption_operation(&self) {
        let mut metrics = self.internal_metrics.write().await;
        metrics.encryption_operations += 1;
    }

    /// Record decryption operation
    pub async fn record_decryption_operation(&self) {
        let mut metrics = self.internal_metrics.write().await;
        metrics.decryption_operations += 1;
    }

    /// Record authentication attempt
    pub async fn record_auth_attempt(&self) {
        let mut metrics = self.internal_metrics.write().await;
        metrics.auth_attempts += 1;
    }

    /// Record authentication failure
    pub async fn record_auth_failure(&self) {
        let mut metrics = self.internal_metrics.write().await;
        metrics.auth_failures += 1;
    }

    /// Record rate limit violation
    pub async fn record_rate_limit_violation(&self) {
        let mut metrics = self.internal_metrics.write().await;
        metrics.rate_limit_violations += 1;
    }

    /// Record error
    pub async fn record_error(&self, error_type: &str) {
        let mut metrics = self.internal_metrics.write().await;
        *metrics.errors.entry(error_type.to_string()).or_insert(0) += 1;
    }

    /// Get current metrics as JSON
    pub async fn get_metrics(&self) -> MetricsResponse {
        let metrics = self.internal_metrics.read().await;
        
        let mut metrics_map = HashMap::new();
        
        // Basic server metrics
        metrics_map.insert("uptime_seconds".to_string(), json!(self.start_time.elapsed().as_secs()));
        metrics_map.insert("active_connections".to_string(), json!(metrics.active_connections));
        metrics_map.insert("total_connections".to_string(), json!(metrics.total_connections));
        
        // Data metrics
        metrics_map.insert("data_stored_bytes".to_string(), json!(metrics.data_stored_bytes));
        metrics_map.insert("data_retrieved_bytes".to_string(), json!(metrics.data_retrieved_bytes));
        
        // Operation metrics
        metrics_map.insert("encryption_operations".to_string(), json!(metrics.encryption_operations));
        metrics_map.insert("decryption_operations".to_string(), json!(metrics.decryption_operations));
        
        // Security metrics
        metrics_map.insert("auth_attempts".to_string(), json!(metrics.auth_attempts));
        metrics_map.insert("auth_failures".to_string(), json!(metrics.auth_failures));
        metrics_map.insert("rate_limit_violations".to_string(), json!(metrics.rate_limit_violations));
        
        // HTTP metrics
        let mut http_metrics = HashMap::new();
        for (endpoint, count) in &metrics.http_requests {
            http_metrics.insert(endpoint.clone(), json!(count));
        }
        metrics_map.insert("http_requests".to_string(), json!(http_metrics));
        
        // Response time metrics
        let mut response_time_metrics = HashMap::new();
        for (endpoint, times) in &metrics.http_response_times {
            if !times.is_empty() {
                let total: Duration = times.iter().sum();
                let avg = total / times.len() as u32;
                let min = times.iter().min().unwrap();
                let max = times.iter().max().unwrap();
                
                let stats = json!({
                    "count": times.len(),
                    "avg_ms": avg.as_millis(),
                    "min_ms": min.as_millis(),
                    "max_ms": max.as_millis(),
                });
                
                response_time_metrics.insert(endpoint.clone(), stats);
            }
        }
        metrics_map.insert("response_times".to_string(), json!(response_time_metrics));
        
        // Status code metrics
        let mut status_code_metrics = HashMap::new();
        for (status, count) in &metrics.http_status_codes {
            status_code_metrics.insert(status.to_string(), json!(count));
        }
        metrics_map.insert("status_codes".to_string(), json!(status_code_metrics));
        
        // Error metrics
        let mut error_metrics = HashMap::new();
        for (error_type, count) in &metrics.errors {
            error_metrics.insert(error_type.clone(), json!(count));
        }
        metrics_map.insert("errors".to_string(), json!(error_metrics));
        
        MetricsResponse {
            metrics: metrics_map,
            timestamp: Utc::now(),
        }
    }

    /// Get metrics in Prometheus format
    pub async fn get_prometheus_metrics(&self) -> Result<String, Box<dyn std::error::Error>> {
        let metrics = self.internal_metrics.read().await;
        
        let mut prometheus_metrics = Vec::new();
        
        // Server metrics
        prometheus_metrics.push(format!(
            "# HELP fortress_uptime_seconds Server uptime in seconds\n\
             # TYPE fortress_uptime_seconds counter\n\
             fortress_uptime_seconds {}",
            self.start_time.elapsed().as_secs()
        ));
        
        prometheus_metrics.push(format!(
            "# HELP fortress_active_connections Current active connections\n\
             # TYPE fortress_active_connections gauge\n\
             fortress_active_connections {}",
            metrics.active_connections
        ));
        
        prometheus_metrics.push(format!(
            "# HELP fortress_total_connections Total connections processed\n\
             # TYPE fortress_total_connections counter\n\
             fortress_total_connections {}",
            metrics.total_connections
        ));
        
        // Data metrics
        prometheus_metrics.push(format!(
            "# HELP fortress_data_stored_bytes Total data stored in bytes\n\
             # TYPE fortress_data_stored_bytes counter\n\
             fortress_data_stored_bytes {}",
            metrics.data_stored_bytes
        ));
        
        prometheus_metrics.push(format!(
            "# HELP fortress_data_retrieved_bytes Total data retrieved in bytes\n\
             # TYPE fortress_data_retrieved_bytes counter\n\
             fortress_data_retrieved_bytes {}",
            metrics.data_retrieved_bytes
        ));
        
        // Operation metrics
        prometheus_metrics.push(format!(
            "# HELP fortress_encryption_operations Total encryption operations\n\
             # TYPE fortress_encryption_operations counter\n\
             fortress_encryption_operations {}",
            metrics.encryption_operations
        ));
        
        prometheus_metrics.push(format!(
            "# HELP fortress_decryption_operations Total decryption operations\n\
             # TYPE fortress_decryption_operations counter\n\
             fortress_decryption_operations {}",
            metrics.decryption_operations
        ));
        
        // Security metrics
        prometheus_metrics.push(format!(
            "# HELP fortress_auth_attempts Total authentication attempts\n\
             # TYPE fortress_auth_attempts counter\n\
             fortress_auth_attempts {}",
            metrics.auth_attempts
        ));
        
        prometheus_metrics.push(format!(
            "# HELP fortress_auth_failures Total authentication failures\n\
             # TYPE fortress_auth_failures counter\n\
             fortress_auth_failures {}",
            metrics.auth_failures
        ));
        
        prometheus_metrics.push(format!(
            "# HELP fortress_rate_limit_violations Total rate limit violations\n\
             # TYPE fortress_rate_limit_violations counter\n\
             fortress_rate_limit_violations {}",
            metrics.rate_limit_violations
        ));
        
        // HTTP request metrics
        prometheus_metrics.push(
            "# HELP fortress_http_requests_total Total HTTP requests\n\
             # TYPE fortress_http_requests_total counter\n\
             fortress_http_requests_total".to_string()
        );
        
        for (endpoint, count) in &metrics.http_requests {
            prometheus_metrics.push(format!(
                "fortress_http_requests_total{{endpoint=\"{}\"}} {}",
                endpoint.replace("\"", "\\\""),
                count
            ));
        }
        
        // Response time metrics
        prometheus_metrics.push(
            "# HELP fortress_response_time_ms HTTP response time in milliseconds\n\
             # TYPE fortress_response_time_ms histogram".to_string()
        );
        
        for (endpoint, times) in &metrics.http_response_times {
            if !times.is_empty() {
                let avg = times.iter().sum::<Duration>() / times.len() as u32;
                prometheus_metrics.push(format!(
                    "fortress_response_time_ms{{endpoint=\"{}\"}} {}",
                    endpoint.replace("\"", "\\\""),
                    avg.as_millis()
                ));
            }
        }
        
        // Status code metrics
        prometheus_metrics.push(
            "# HELP fortress_http_status_codes HTTP status codes\n\
             # TYPE fortress_http_status_codes counter".to_string()
        );
        
        for (status, count) in &metrics.http_status_codes {
            prometheus_metrics.push(format!(
                "fortress_http_status_codes{{status=\"{}\"}} {}",
                status,
                count
            ));
        }
        
        // Error metrics
        prometheus_metrics.push(
            "# HELP fortress_errors_total Total errors by type\n\
             # TYPE fortress_errors_total counter".to_string()
        );
        
        for (error_type, count) in &metrics.errors {
            prometheus_metrics.push(format!(
                "fortress_errors_total{{error_type=\"{}\"}} {}",
                error_type.replace("\"", "\\\""),
                count
            ));
        }
        
        Ok(prometheus_metrics.join("\n\n"))
    }

    /// Reset all metrics
    pub async fn reset_metrics(&self) {
        let mut metrics = self.internal_metrics.write().await;
        *metrics = InternalMetrics::default();
        info!("All metrics have been reset");
    }

    /// Get specific metric value
    pub async fn get_metric(&self, metric_name: &str) -> Option<Value> {
        let metrics = self.internal_metrics.read().await;
        
        match metric_name {
            "uptime_seconds" => Some(json!(self.start_time.elapsed().as_secs())),
            "active_connections" => Some(json!(metrics.active_connections)),
            "total_connections" => Some(json!(metrics.total_connections)),
            "data_stored_bytes" => Some(json!(metrics.data_stored_bytes)),
            "data_retrieved_bytes" => Some(json!(metrics.data_retrieved_bytes)),
            "encryption_operations" => Some(json!(metrics.encryption_operations)),
            "decryption_operations" => Some(json!(metrics.decryption_operations)),
            "auth_attempts" => Some(json!(metrics.auth_attempts)),
            "auth_failures" => Some(json!(metrics.auth_failures)),
            "rate_limit_violations" => Some(json!(metrics.rate_limit_violations)),
            _ => None,
        }
    }
}

impl Default for MetricsCollector {
    fn default() -> Self {
        Self::new()
    }
}

/// Metrics middleware for recording HTTP metrics
pub async fn metrics_middleware(
    State(metrics_collector): State<Arc<MetricsCollector>>,
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let start = Instant::now();
    let method = request.method().clone();
    let path = request.uri().path().to_string();
    
    metrics_collector.increment_active_connections().await;
    
    let response = next.run(request).await;
    
    let duration = start.elapsed();
    let status = response.status().as_u16();
    
    metrics_collector.record_http_request(&method.to_string(), &path, status, duration).await;
    metrics_collector.decrement_active_connections().await;
    
    // Record errors
    if response.status().is_server_error() {
        metrics_collector.record_error("server_error").await;
    } else if response.status().is_client_error() {
        metrics_collector.record_error("client_error").await;
    }
    
    response
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test]
    async fn test_metrics_collector_creation() {
        let collector = MetricsCollector::new();
        let metrics = collector.get_metrics().await;
        
        assert!(metrics.metrics.contains_key("uptime_seconds"));
        assert!(metrics.metrics.contains_key("active_connections"));
    }

    #[tokio::test]
    async fn test_http_request_recording() {
        let collector = MetricsCollector::new();
        
        collector.record_http_request("GET", "/test", 200, Duration::from_millis(100)).await;
        collector.record_http_request("POST", "/data", 201, Duration::from_millis(150)).await;
        
        let metrics = collector.get_metrics().await;
        
        assert_eq!(metrics.metrics["http_requests"]["GET /test"], 1);
        assert_eq!(metrics.metrics["http_requests"]["POST /data"], 1);
        assert_eq!(metrics.metrics["status_codes"]["200"], 1);
        assert_eq!(metrics.metrics["status_codes"]["201"], 1);
    }

    #[tokio::test]
    async fn test_connection_tracking() {
        let collector = MetricsCollector::new();
        
        collector.increment_active_connections().await;
        collector.increment_active_connections().await;
        
        let metrics = collector.get_metrics().await;
        assert_eq!(metrics.metrics["active_connections"], 2);
        assert_eq!(metrics.metrics["total_connections"], 2);
        
        collector.decrement_active_connections().await;
        let metrics = collector.get_metrics().await;
        assert_eq!(metrics.metrics["active_connections"], 1);
        assert_eq!(metrics.metrics["total_connections"], 2);
    }

    #[tokio::test]
    async fn test_data_metrics() {
        let collector = MetricsCollector::new();
        
        collector.record_data_stored(1024).await;
        collector.record_data_retrieved(512).await;
        
        let metrics = collector.get_metrics().await;
        assert_eq!(metrics.metrics["data_stored_bytes"], 1024);
        assert_eq!(metrics.metrics["data_retrieved_bytes"], 512);
    }

    #[tokio::test]
    async fn test_security_metrics() {
        let collector = MetricsCollector::new();
        
        collector.record_auth_attempt().await;
        collector.record_auth_attempt().await;
        collector.record_auth_failure().await;
        collector.record_rate_limit_violation().await;
        
        let metrics = collector.get_metrics().await;
        assert_eq!(metrics.metrics["auth_attempts"], 2);
        assert_eq!(metrics.metrics["auth_failures"], 1);
        assert_eq!(metrics.metrics["rate_limit_violations"], 1);
    }

    #[tokio::test]
    async fn test_prometheus_format() {
        let collector = MetricsCollector::new();
        
        collector.record_http_request("GET", "/test", 200, Duration::from_millis(100)).await;
        
        let prometheus_output = collector.get_prometheus_metrics().await.unwrap();
        
        assert!(prometheus_output.contains("fortress_uptime_seconds"));
        assert!(prometheus_output.contains("fortress_http_requests_total"));
        assert!(prometheus_output.contains("HELP"));
        assert!(prometheus_output.contains("TYPE"));
    }

    #[tokio::test]
    async fn test_metrics_reset() {
        let collector = MetricsCollector::new();
        
        collector.record_auth_attempt().await;
        collector.record_data_stored(1024).await;
        
        let metrics_before = collector.get_metrics().await;
        assert_eq!(metrics_before.metrics["auth_attempts"], 1);
        
        collector.reset_metrics().await;
        
        let metrics_after = collector.get_metrics().await;
        assert_eq!(metrics_after.metrics["auth_attempts"], 0);
        assert_eq!(metrics_after.metrics["data_stored_bytes"], 0);
    }
}
