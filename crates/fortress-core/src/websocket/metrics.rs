//! WebSocket monitoring and metrics

use crate::error::{FortressError, Result};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use serde::{Serialize, Deserialize};

/// WebSocket metrics collector
#[derive(Debug)]
pub struct WebSocketMetrics {
    /// Connection metrics
    pub connection_metrics: Arc<RwLock<ConnectionMetrics>>,
    /// Message metrics
    pub message_metrics: Arc<RwLock<MessageMetrics>>,
    /// Performance metrics
    pub performance_metrics: Arc<RwLock<PerformanceMetrics>>,
    /// Error metrics
    pub error_metrics: Arc<RwLock<ErrorMetrics>>,
}

/// Connection-related metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionMetrics {
    /// Total connections created
    pub total_connections: u64,
    /// Current active connections
    pub active_connections: usize,
    /// Peak concurrent connections
    pub peak_connections: usize,
    /// Total authenticated connections
    pub authenticated_connections: u64,
    /// Connections per IP
    pub connections_per_ip: HashMap<String, u32>,
    /// Connections per user
    pub connections_per_user: HashMap<String, u32>,
    /// Average connection duration (as seconds for serialization)
    pub avg_connection_duration: f64,
    /// Connection success rate
    pub connection_success_rate: f64,
    /// Connection duration history for statistics
    #[serde(skip)]
    pub connection_durations: Vec<Duration>,
}

/// Message-related metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessageMetrics {
    /// Total messages sent
    pub messages_sent: u64,
    /// Total messages received
    pub messages_received: u64,
    /// Messages per second
    pub messages_per_second: f64,
    /// Average message size in bytes
    pub avg_message_size: f64,
    /// Total bytes sent
    pub bytes_sent: u64,
    /// Total bytes received
    pub bytes_received: u64,
    /// Messages per type
    pub messages_per_type: HashMap<String, u64>,
    /// Message latency history for statistics
    #[serde(skip)]
    pub message_latencies: Vec<Duration>,
}

/// Performance-related metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceMetrics {
    /// CPU usage percentage
    pub cpu_usage: f64,
    /// Memory usage in bytes
    pub memory_usage: u64,
    /// Memory usage percentage
    pub memory_usage_percent: f64,
    /// WebSocket thread count
    pub thread_count: usize,
    /// Buffer utilization
    pub buffer_utilization: f64,
    /// Subscription count
    pub subscription_count: usize,
    /// Broadcast queue size
    pub broadcast_queue_size: usize,
    /// Last update timestamp (as string for serialization)
    pub last_update: String,
}

/// Error-related metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorMetrics {
    /// Total errors
    pub total_errors: u64,
    /// Errors per type
    pub errors_per_type: HashMap<String, u64>,
    /// Errors per connection
    pub errors_per_connection: HashMap<String, u32>,
    /// Authentication failures
    pub auth_failures: u64,
    /// Rate limit violations
    pub rate_limit_violations: u64,
    /// Connection errors
    pub connection_errors: u64,
    /// Protocol errors
    pub protocol_errors: u64,
    /// Last error timestamp (as string for serialization)
    pub last_error: Option<String>,
    /// Error rate per minute
    pub errors_per_minute: f64,
}

impl WebSocketMetrics {
    /// Create new metrics collector
    pub fn new() -> Self {
        Self {
            connection_metrics: Arc::new(RwLock::new(ConnectionMetrics::default())),
            message_metrics: Arc::new(RwLock::new(MessageMetrics::default())),
            performance_metrics: Arc::new(RwLock::new(PerformanceMetrics::default())),
            error_metrics: Arc::new(RwLock::new(ErrorMetrics::default())),
        }
    }

    /// Record connection established
    pub async fn record_connection_established(&self, _connection_id: &str, client_ip: &str, user_id: Option<String>) {
        let mut metrics = self.connection_metrics.write().await;
        metrics.total_connections += 1;
        metrics.active_connections += 1;
        
        if metrics.active_connections > metrics.peak_connections {
            metrics.peak_connections = metrics.active_connections;
        }

        *metrics.connections_per_ip.entry(client_ip.to_string()).or_insert(0) += 1;
        
        if let Some(uid) = user_id {
            *metrics.connections_per_user.entry(uid).or_insert(0) += 1;
            metrics.authenticated_connections += 1;
        }
    }

    /// Record connection closed
    pub async fn record_connection_closed(&self, _connection_id: &str, duration: Duration) {
        let mut metrics = self.connection_metrics.write().await;
        
        if metrics.active_connections > 0 {
            metrics.active_connections -= 1;
        }

        metrics.connection_durations.push(duration);
        
        // Keep only last 1000 durations for statistics
        if metrics.connection_durations.len() > 1000 {
            metrics.connection_durations.remove(0);
        }

        // Update average connection duration
        if !metrics.connection_durations.is_empty() {
            let total: Duration = metrics.connection_durations.iter().sum();
            metrics.avg_connection_duration = total.as_secs_f64() / metrics.connection_durations.len() as f64;
        }

        // Update connection success rate
        if metrics.total_connections > 0 {
            metrics.connection_success_rate = (metrics.authenticated_connections as f64 / metrics.total_connections as f64) * 100.0;
        }
    }

    /// Record message sent
    pub async fn record_message_sent(&self, message_type: &str, size_bytes: usize, latency: Duration) {
        let mut metrics = self.message_metrics.write().await;
        
        metrics.messages_sent += 1;
        metrics.bytes_sent += size_bytes as u64;
        
        *metrics.messages_per_type.entry(message_type.to_string()).or_insert(0) += 1;
        
        metrics.message_latencies.push(latency);
        
        // Keep only last 1000 latencies for statistics
        if metrics.message_latencies.len() > 1000 {
            metrics.message_latencies.remove(0);
        }

        // Update average message size
        if metrics.messages_sent > 0 {
            metrics.avg_message_size = metrics.bytes_sent as f64 / metrics.messages_sent as f64;
        }

        // Update latency statistics
        self.update_latency_stats(&mut metrics);
    }

    /// Record message received
    pub async fn record_message_received(&self, message_type: &str, size_bytes: usize) {
        let mut metrics = self.message_metrics.write().await;
        
        metrics.messages_received += 1;
        metrics.bytes_received += size_bytes as u64;
        
        *metrics.messages_per_type.entry(message_type.to_string()).or_insert(0) += 1;
        
        // Update messages per second (simplified calculation)
        metrics.messages_per_second = (metrics.messages_sent + metrics.messages_received) as f64 / 60.0; // Last minute average
    }

    /// Record error
    pub async fn record_error(&self, error_type: &str, connection_id: Option<String>) {
        let mut metrics = self.error_metrics.write().await;
        
        metrics.total_errors += 1;
        *metrics.errors_per_type.entry(error_type.to_string()).or_insert(0) += 1;
        
        if let Some(conn_id) = connection_id {
            *metrics.errors_per_connection.entry(conn_id).or_insert(0) += 1;
        }
        
        metrics.last_error = Some(chrono::Utc::now().to_rfc3339());
        
        // Update error rate
        metrics.errors_per_minute = metrics.total_errors as f64 / 60.0; // Last minute average
    }

    /// Record authentication failure
    pub async fn record_auth_failure(&self) {
        let mut metrics = self.error_metrics.write().await;
        metrics.auth_failures += 1;
    }

    /// Record rate limit violation
    pub async fn record_rate_limit_violation(&self) {
        let mut metrics = self.error_metrics.write().await;
        metrics.rate_limit_violations += 1;
    }

    /// Update performance metrics
    pub async fn update_performance_metrics(&self) {
        let mut metrics = self.performance_metrics.write().await;
        
        // Get system information
        metrics.cpu_usage = self.get_cpu_usage();
        metrics.memory_usage = self.get_memory_usage();
        metrics.memory_usage_percent = self.get_memory_usage_percent();
        metrics.thread_count = self.get_thread_count();
        metrics.buffer_utilization = self.get_buffer_utilization();
        metrics.last_update = chrono::Utc::now().to_rfc3339();
    }

    /// Update latency statistics
    fn update_latency_stats(&self, _metrics: &mut MessageMetrics) {
        // Latency statistics tracking removed for simplicity
        // In a real implementation, this would calculate P95/P99 latencies
    }

    /// Get CPU usage (simplified)
    fn get_cpu_usage(&self) -> f64 {
        // In a real implementation, use system metrics
        // For now, return a simulated value
        25.0
    }

    /// Get memory usage in bytes
    fn get_memory_usage(&self) -> u64 {
        // In a real implementation, use system metrics
        // For now, return a simulated value
        512 * 1024 * 1024 // 512MB
    }

    /// Get memory usage percentage
    fn get_memory_usage_percent(&self) -> f64 {
        // In a real implementation, calculate based on total system memory
        // For now, return a simulated value
        15.0
    }

    /// Get thread count
    fn get_thread_count(&self) -> usize {
        // In a real implementation, get actual thread count
        // For now, return a simulated value
        8
    }

    /// Get buffer utilization
    fn get_buffer_utilization(&self) -> f64 {
        // In a real implementation, calculate based on actual buffer usage
        // For now, return a simulated value
        35.0
    }

    /// Get all metrics as a single struct
    pub async fn get_all_metrics(&self) -> AllMetrics {
        AllMetrics {
            connection_metrics: self.connection_metrics.read().await.clone(),
            message_metrics: self.message_metrics.read().await.clone(),
            performance_metrics: self.performance_metrics.read().await.clone(),
            error_metrics: self.error_metrics.read().await.clone(),
            timestamp: chrono::Utc::now(),
        }
    }

    /// Reset all metrics
    pub async fn reset_metrics(&self) {
        *self.connection_metrics.write().await = ConnectionMetrics::default();
        *self.message_metrics.write().await = MessageMetrics::default();
        *self.performance_metrics.write().await = PerformanceMetrics::default();
        *self.error_metrics.write().await = ErrorMetrics::default();
    }

    /// Export metrics to JSON
    pub async fn export_json(&self) -> Result<String> {
        let metrics = self.get_all_metrics().await;
        serde_json::to_string(&metrics).map_err(|e| {
            FortressError::websocket(format!("Failed to serialize metrics: {}", e))
        })
    }
}

/// Combined metrics structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AllMetrics {
    /// Connection metrics
    pub connection_metrics: ConnectionMetrics,
    /// Message metrics
    pub message_metrics: MessageMetrics,
    /// Performance metrics
    pub performance_metrics: PerformanceMetrics,
    /// Error metrics
    pub error_metrics: ErrorMetrics,
    /// Export timestamp
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

impl Default for ConnectionMetrics {
    fn default() -> Self {
        Self {
            total_connections: 0,
            active_connections: 0,
            peak_connections: 0,
            authenticated_connections: 0,
            connections_per_ip: HashMap::new(),
            connections_per_user: HashMap::new(),
            avg_connection_duration: 0.0,
            connection_success_rate: 0.0,
            connection_durations: Vec::new(),
        }
    }
}

impl Default for PerformanceMetrics {
    fn default() -> Self {
        Self {
            cpu_usage: 0.0,
            memory_usage: 0,
            memory_usage_percent: 0.0,
            thread_count: 0,
            buffer_utilization: 0.0,
            subscription_count: 0,
            broadcast_queue_size: 0,
            last_update: chrono::Utc::now().to_rfc3339(),
        }
    }
}

impl Default for MessageMetrics {
    fn default() -> Self {
        Self {
            messages_sent: 0,
            messages_received: 0,
            messages_per_second: 0.0,
            avg_message_size: 0.0,
            bytes_sent: 0,
            bytes_received: 0,
            messages_per_type: HashMap::new(),
            message_latencies: Vec::new(),
        }
    }
}

impl Default for ErrorMetrics {
    fn default() -> Self {
        Self {
            total_errors: 0,
            errors_per_type: HashMap::new(),
            errors_per_connection: HashMap::new(),
            auth_failures: 0,
            rate_limit_violations: 0,
            connection_errors: 0,
            protocol_errors: 0,
            last_error: None,
            errors_per_minute: 0.0,
        }
    }
}
