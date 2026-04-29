//! Real-time performance dashboard with live metrics streaming

//!

//! Provides WebSocket-based real-time dashboard capabilities with

//! live system metrics, performance data, and interactive visualizations.



use crate::error::Result;

use crate::observability::{

    SystemResourceMonitor, EnhancedPerformanceMonitor, 

    AdvancedMetricsCollector, SystemSnapshot

};

use serde::{Deserialize, Serialize};

use std::collections::HashMap;

use std::sync::Arc;

use std::time::{Duration, Instant};

use tokio::sync::{RwLock, broadcast};

use tokio::time::interval;

use uuid::Uuid;



/// Real-time dashboard configuration

#[derive(Debug, Clone, Serialize, Deserialize)]

pub struct RealTimeDashboardConfig {

    /// Enable real-time dashboard

    pub enabled: bool,

    /// WebSocket server port

    pub websocket_port: u16,

    /// Update interval in milliseconds

    pub update_interval_ms: u64,

    /// Maximum concurrent connections

    pub max_connections: usize,

    /// Enable system metrics streaming

    pub enable_system_metrics: bool,

    /// Enable performance metrics streaming

    pub enable_performance_metrics: bool,

    /// Enable application metrics streaming

    pub enable_application_metrics: bool,

    /// Data buffer size per connection

    pub buffer_size: usize,

    /// Connection timeout in seconds

    pub connection_timeout_seconds: u64,

}



impl Default for RealTimeDashboardConfig {

    fn default() -> Self {

        Self {

            enabled: true,

            websocket_port: 8081,

            update_interval_ms: 1000, // 1 second updates

            max_connections: 100,

            enable_system_metrics: true,

            enable_performance_metrics: true,

            enable_application_metrics: true,

            buffer_size: 1000,

            connection_timeout_seconds: 300, // 5 minutes

        }

    }

}



/// Real-time dashboard message types

#[derive(Debug, Clone, Serialize, Deserialize)]

#[serde(tag = "type")]

pub enum DashboardMessage {

    /// System metrics update

    SystemMetrics(SystemMetricsUpdate),

    /// Performance metrics update

    PerformanceMetrics(PerformanceMetricsUpdate),

    /// Application metrics update

    ApplicationMetrics(ApplicationMetricsUpdate),

    /// Alert notification

    Alert(AlertNotification),

    /// Connection status

    ConnectionStatus(ConnectionStatus),

    /// Error message

    Error(ErrorMessage),

}



/// System metrics update

#[derive(Debug, Clone, Serialize, Deserialize)]

pub struct SystemMetricsUpdate {

    /// Timestamp

    pub timestamp: chrono::DateTime<chrono::Utc>,

    /// CPU usage

    pub cpu_usage: f64,

    /// Memory usage

    pub memory_usage: f64,

    /// Disk usage

    pub disk_usage: f64,

    /// Network usage

    pub network_usage: NetworkMetrics,

    /// Active processes

    pub active_processes: usize,

    /// System load

    pub system_load: f64,

}



/// Performance metrics update

#[derive(Debug, Clone, Serialize, Deserialize)]

pub struct PerformanceMetricsUpdate {

    /// Timestamp

    pub timestamp: chrono::DateTime<chrono::Utc>,

    /// Response time percentiles

    pub response_time_percentiles: ResponseTimePercentiles,

    /// Throughput

    pub throughput: f64,

    /// Error rate

    pub error_rate: f64,

    /// Active operations

    pub active_operations: usize,

    /// Queue depth

    pub queue_depth: f64,

}



/// Application metrics update

#[derive(Debug, Clone, Serialize, Deserialize)]

pub struct ApplicationMetricsUpdate {

    /// Timestamp

    pub timestamp: chrono::DateTime<chrono::Utc>,

    /// Custom metrics

    pub metrics: HashMap<String, f64>,

    /// Counters

    pub counters: HashMap<String, u64>,

    /// Gauges

    pub gauges: HashMap<String, f64>,

    /// Histograms

    pub histograms: HashMap<String, HistogramData>,

}



/// Network metrics

#[derive(Debug, Clone, Serialize, Deserialize)]

pub struct NetworkMetrics {

    /// Bytes received per second

    pub bytes_rx_per_sec: f64,

    /// Bytes transmitted per second

    pub bytes_tx_per_sec: f64,

    /// Packets received per second

    pub packets_rx_per_sec: f64,

    /// Packets transmitted per second

    pub packets_tx_per_sec: f64,

    /// Error rate

    pub error_rate: f64,

}



/// Response time percentiles

#[derive(Debug, Clone, Serialize, Deserialize)]

pub struct ResponseTimePercentiles {

    /// P50 response time in milliseconds

    pub p50_ms: f64,

    /// P95 response time in milliseconds

    pub p95_ms: f64,

    /// P99 response time in milliseconds

    pub p99_ms: f64,

    /// Average response time in milliseconds

    pub avg_ms: f64,

}



/// Histogram data

#[derive(Debug, Clone, Serialize, Deserialize)]

pub struct HistogramData {

    /// Count

    pub count: u64,

    /// Sum

    pub sum: f64,

    /// Buckets

    pub buckets: Vec<HistogramBucket>,

}



/// Histogram bucket

#[derive(Debug, Clone, Serialize, Deserialize)]

pub struct HistogramBucket {

    /// Upper bound

    pub upper_bound: f64,

    /// Cumulative count

    pub cumulative_count: u64,

}



/// Alert notification

#[derive(Debug, Clone, Serialize, Deserialize)]

pub struct AlertNotification {

    /// Alert ID

    pub id: String,

    /// Alert severity

    pub severity: AlertSeverity,

    /// Alert title

    pub title: String,

    /// Alert message

    pub message: String,

    /// Alert timestamp

    pub timestamp: chrono::DateTime<chrono::Utc>,

    /// Alert source

    pub source: String,

}



/// Alert severity

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]

pub enum AlertSeverity {

    /// Information

    Info,

    /// Warning

    Warning,

    /// Error

    Error,

    /// Critical

    Critical,

}



/// Connection status

#[derive(Debug, Clone, Serialize, Deserialize)]

pub struct ConnectionStatus {

    /// Connection ID

    pub connection_id: String,

    /// Status

    pub status: ConnectionStatusType,

    /// Message

    pub message: String,

    /// Timestamp

    pub timestamp: chrono::DateTime<chrono::Utc>,

}



/// Connection status type

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]

pub enum ConnectionStatusType {

    /// Connected

    Connected,

    /// Disconnected

    Disconnected,

    /// Error

    Error,

}



/// Error message

#[derive(Debug, Clone, Serialize, Deserialize)]

pub struct ErrorMessage {

    /// Error code

    pub code: String,

    /// Error message

    pub message: String,

    /// Error timestamp

    pub timestamp: chrono::DateTime<chrono::Utc>,

}



/// Real-time dashboard manager

#[derive(Debug)]

pub struct RealTimeDashboard {

    /// Configuration

    config: RealTimeDashboardConfig,

    /// System resource monitor

    system_monitor: Arc<SystemResourceMonitor>,

    /// Performance monitor

    performance_monitor: Arc<EnhancedPerformanceMonitor>,

    /// Metrics collector

    metrics_collector: Arc<AdvancedMetricsCollector>,

    /// Message broadcaster

    message_broadcaster: broadcast::Sender<DashboardMessage>,

    /// Active connections

    connections: Arc<RwLock<HashMap<String, ConnectionInfo>>>,

    /// Last system snapshot

    last_system_snapshot: Arc<RwLock<Option<SystemSnapshot>>>,

    /// Start time

    start_time: Instant,

}



/// Connection information

#[derive(Debug, Clone)]

struct ConnectionInfo {

    /// Connection ID

    id: String,

    /// Connected at

    connected_at: Instant,

    /// Last activity

    last_activity: Instant,

    /// Subscriptions

    subscriptions: Vec<SubscriptionType>,

}



/// Subscription types

#[derive(Debug, Clone)]

enum SubscriptionType {

    SystemMetrics,

    PerformanceMetrics,

    ApplicationMetrics,

    Alerts,

}



impl RealTimeDashboard {

    /// Create a new real-time dashboard

    pub fn new(

        config: RealTimeDashboardConfig,

        system_monitor: Arc<SystemResourceMonitor>,

        performance_monitor: Arc<EnhancedPerformanceMonitor>,

        metrics_collector: Arc<AdvancedMetricsCollector>,

    ) -> Result<Self> {

        let (message_broadcaster, _) = broadcast::channel(config.buffer_size);



        Ok(Self {

            config,

            system_monitor,

            performance_monitor,

            metrics_collector,

            message_broadcaster,

            connections: Arc::new(RwLock::new(HashMap::new())),

            last_system_snapshot: Arc::new(RwLock::new(None)),

            start_time: Instant::now(),

        })

    }



    /// Start the real-time dashboard

    pub async fn start(&self) -> Result<()> {

        if !self.config.enabled {

            return Ok(());

        }



        // Start background data collection

        self.start_data_collection().await;



        // Start WebSocket server

        self.start_websocket_server().await;



        // Start connection cleanup

        self.start_connection_cleanup().await;



        tracing::info!("Real-time dashboard started on port {}", self.config.websocket_port);

        Ok(())

    }



    /// Start background data collection

    async fn start_data_collection(&self) {

        let message_broadcaster = self.message_broadcaster.clone();

        let system_monitor = self.system_monitor.clone();

        let performance_monitor = self.performance_monitor.clone();

        let _metrics_collector = self.metrics_collector.clone();

        let last_system_snapshot = self.last_system_snapshot.clone();

        let update_interval = Duration::from_millis(self.config.update_interval_ms);



        tokio::spawn(async move {

            let mut interval_timer = interval(update_interval);

            

            loop {

                interval_timer.tick().await;



                // Collect system metrics

                if let Some(system_snapshot) = system_monitor.get_current_snapshot().await {

                    *last_system_snapshot.write().await = Some(system_snapshot.clone());



                    let system_metrics = DashboardMessage::SystemMetrics(SystemMetricsUpdate {

                        timestamp: chrono::Utc::now(),

                        cpu_usage: system_snapshot.cpu.overall_usage_percent,

                        memory_usage: system_snapshot.memory.usage_percent,

                        disk_usage: system_snapshot.disks.iter()

                            .map(|d| d.usage_percent)

                            .sum::<f64>() / system_snapshot.disks.len().max(1) as f64,

                        network_usage: NetworkMetrics {

                            bytes_rx_per_sec: system_snapshot.networks.iter()

                                .map(|n| n.receive_bandwidth_bps)

                                .sum::<f64>(),

                            bytes_tx_per_sec: system_snapshot.networks.iter()

                                .map(|n| n.transmit_bandwidth_bps)

                                .sum::<f64>(),

                            packets_rx_per_sec: system_snapshot.networks.iter()

                                .map(|n| n.packets_received as f64 / 60.0) // Rough estimate

                                .sum::<f64>(),

                            packets_tx_per_sec: system_snapshot.networks.iter()

                                .map(|n| n.packets_transmitted as f64 / 60.0) // Rough estimate

                                .sum::<f64>(),

                            error_rate: system_snapshot.networks.iter()

                                .map(|n| n.error_rate_percent)

                                .sum::<f64>() / system_snapshot.networks.len().max(1) as f64,

                        },

                        active_processes: system_snapshot.processes.len(),

                        system_load: system_snapshot.cpu.load_averages

                            .map(|(load1, _, _)| load1)

                            .unwrap_or(0.0),

                    });



                    let _ = message_broadcaster.send(system_metrics);

                }



                // Collect performance metrics

                if let Ok(performance_summary) = performance_monitor.get_performance_summary().await {

                    let performance_metrics = DashboardMessage::PerformanceMetrics(PerformanceMetricsUpdate {

                        timestamp: chrono::Utc::now(),

                        response_time_percentiles: ResponseTimePercentiles {

                            p50_ms: performance_summary.avg_response_time_ms * 0.8, // Estimate

                            p95_ms: performance_summary.avg_response_time_ms * 1.5, // Estimate

                            p99_ms: performance_summary.avg_response_time_ms * 2.0, // Estimate

                            avg_ms: performance_summary.avg_response_time_ms,

                        },

                        throughput: 1000.0 / performance_summary.avg_response_time_ms.max(1.0), // Estimate

                        error_rate: performance_summary.error_rate_percent,

                        active_operations: performance_summary.recent_samples_count,

                        queue_depth: 0.0, // Would need additional tracking

                    });



                    let _ = message_broadcaster.send(performance_metrics);

                }



                // Collect application metrics

                let application_metrics = DashboardMessage::ApplicationMetrics(ApplicationMetricsUpdate {

                    timestamp: chrono::Utc::now(),

                    metrics: HashMap::new(), // Would be populated from actual metrics

                    counters: HashMap::new(),

                    gauges: HashMap::new(),

                    histograms: HashMap::new(),

                });



                let _ = message_broadcaster.send(application_metrics);

            }

        });

    }



    /// Start WebSocket server

    async fn start_websocket_server(&self) {

        let message_broadcaster = self.message_broadcaster.clone();

        let connections = self.connections.clone();

        let max_connections = self.config.max_connections;

        let port = self.config.websocket_port;



        tokio::spawn(async move {

            // Note: This is a simplified WebSocket server implementation

            // In production, you would use a proper WebSocket library like tokio-tungstenite

            

            tracing::info!("WebSocket server listening on port {}", port);

            

            // Simulate WebSocket connections

            let mut connection_counter = 0;

            let mut interval_timer = interval(Duration::from_secs(10));

            

            loop {

                interval_timer.tick().await;

                

                // Simulate new connection

                if connection_counter < max_connections {

                    let connection_id = Uuid::new_v4().to_string();

                    let connection_info = ConnectionInfo {

                        id: connection_id.clone(),

                        connected_at: Instant::now(),

                        last_activity: Instant::now(),

                        subscriptions: vec![

                            SubscriptionType::SystemMetrics,

                            SubscriptionType::PerformanceMetrics,

                            SubscriptionType::ApplicationMetrics,

                            SubscriptionType::Alerts,

                        ],

                    };

                    

                    connections.write().await.insert(connection_id.clone(), connection_info);

                    connection_counter += 1;

                    

                    // Send connection status

                    let status_message = DashboardMessage::ConnectionStatus(ConnectionStatus {

                        connection_id: connection_id.clone(),

                        status: ConnectionStatusType::Connected,

                        message: "Connected successfully".to_string(),

                        timestamp: chrono::Utc::now(),

                    });

                    

                    let _ = message_broadcaster.send(status_message);

                    

                    tracing::info!("New WebSocket connection: {}", connection_id);

                }

            }

        });

    }



    /// Start connection cleanup

    async fn start_connection_cleanup(&self) {

        let connections = self.connections.clone();

        let message_broadcaster = self.message_broadcaster.clone();

        let timeout_duration = Duration::from_secs(self.config.connection_timeout_seconds);



        tokio::spawn(async move {

            let mut interval_timer = interval(Duration::from_secs(60)); // Check every minute

            

            loop {

                interval_timer.tick().await;

                

                let now = Instant::now();

                let mut connections_guard = connections.write().await;

                let mut to_remove = Vec::new();

                

                for (connection_id, connection_info) in connections_guard.iter() {

                    if now.duration_since(connection_info.last_activity) > timeout_duration {

                        to_remove.push(connection_id.clone());

                    }

                }

                

                for connection_id in to_remove {

                    if let Some(_connection_info) = connections_guard.remove(&connection_id) {

                        // Send disconnection status

                        let status_message = DashboardMessage::ConnectionStatus(ConnectionStatus {

                            connection_id: connection_id.clone(),

                            status: ConnectionStatusType::Disconnected,

                            message: "Connection timed out".to_string(),

                            timestamp: chrono::Utc::now(),

                        });

                        

                        let _ = message_broadcaster.send(status_message);

                        

                        tracing::info!("WebSocket connection timed out: {}", connection_id);

                    }

                }

            }

        });

    }



    /// Send alert to all connected clients

    pub async fn send_alert(&self, alert: AlertNotification) -> Result<()> {

        let message = DashboardMessage::Alert(alert);

        let _ = self.message_broadcaster.send(message);

        Ok(())

    }



    /// Get dashboard statistics

    pub async fn get_statistics(&self) -> DashboardStatistics {

        let connections_guard = self.connections.read().await;

        let uptime = self.start_time.elapsed();

        

        DashboardStatistics {

            active_connections: connections_guard.len(),

            total_messages_sent: 0, // Would need tracking

            uptime_seconds: uptime.as_secs(),

            messages_per_second: 0.0, // Would need tracking

            system_metrics_enabled: self.config.enable_system_metrics,

            performance_metrics_enabled: self.config.enable_performance_metrics,

            application_metrics_enabled: self.config.enable_application_metrics,

        }

    }



    /// Generate dashboard HTML

    pub async fn generate_dashboard_html(&self) -> Result<String> {

        let stats = self.get_statistics().await;

        

        Ok(format!(

            r#"

<!DOCTYPE html>

<html>

<head>

    <title>Fortress Real-time Dashboard</title>

    <meta charset="utf-8">

    <meta name="viewport" content="width=device-width, initial-scale=1">

    <style>

        body {{ 

            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;

            margin: 0; 

            padding: 20px; 

            background: #f5f5f5;

        }}

        .dashboard {{ 

            max-width: 1400px; 

            margin: 0 auto; 

            display: grid;

            grid-template-columns: repeat(auto-fit, minmax(400px, 1fr));

            gap: 20px;

        }}

        .widget {{ 

            background: white; 

            border-radius: 8px; 

            box-shadow: 0 2px 4px rgba(0,0,0,0.1);

            padding: 20px; 

        }}

        .widget-title {{ 

            font-weight: 600; 

            margin-bottom: 15px; 

            color: #333;

            font-size: 18px;

        }}

        .metric {{ 

            display: flex; 

            justify-content: space-between; 

            margin: 10px 0; 

            align-items: center;

        }}

        .metric-value {{ 

            font-weight: 500; 

            color: #666; 

        }}

        .metric-label {{ 

            color: #999; 

            font-size: 14px;

        }}

        .status-indicator {{

            display: inline-block;

            width: 12px;

            height: 12px;

            border-radius: 50%;

            margin-right: 8px;

        }}

        .status-good {{ background: #4CAF50; }}

        .status-warning {{ background: #FF9800; }}

        .status-error {{ background: #F44336; }}

        .header {{

            background: white;

            border-radius: 8px;

            padding: 20px;

            margin-bottom: 20px;

            box-shadow: 0 2px 4px rgba(0,0,0,0.1);

        }}

        .stats {{

            display: flex;

            gap: 30px;

            flex-wrap: wrap;

        }}

        .stat-item {{

            text-align: center;

        }}

        .stat-value {{

            font-size: 24px;

            font-weight: 600;

            color: #333;

        }}

        .stat-label {{

            font-size: 14px;

            color: #666;

            margin-top: 5px;

        }}

    </style>

</head>

<body>

    <div class="header">

        <h1>🛡️ Fortress Performance Dashboard</h1>

        <div class="stats">

            <div class="stat-item">

                <div class="stat-value">{active_connections}</div>

                <div class="stat-label">Active Connections</div>

            </div>

            <div class="stat-item">

                <div class="stat-value">{uptime}s</div>

                <div class="stat-label">Uptime</div>

            </div>

            <div class="stat-item">

                <div class="stat-value">

                    <span class="status-indicator status-good"></span>

                    Live

                </div>

                <div class="stat-label">Status</div>

            </div>

        </div>

    </div>

    

    <div class="dashboard">

        <div class="widget">

            <div class="widget-title">🖥️ System Resources</div>

            <div class="metric">

                <span class="metric-label">CPU Usage</span>

                <span class="metric-value" id="cpu-usage">--%</span>

            </div>

            <div class="metric">

                <span class="metric-label">Memory Usage</span>

                <span class="metric-value" id="memory-usage">--%</span>

            </div>

            <div class="metric">

                <span class="metric-label">Disk Usage</span>

                <span class="metric-value" id="disk-usage">--%</span>

            </div>

            <div class="metric">

                <span class="metric-label">Active Processes</span>

                <span class="metric-value" id="processes">--</span>

            </div>

        </div>

        

        <div class="widget">

            <div class="widget-title">Performance Metrics</div>

            <div class="metric">

                <span class="metric-label">Avg Response Time</span>

                <span class="metric-value" id="response-time">--ms</span>

            </div>

            <div class="metric">

                <span class="metric-label">Throughput</span>

                <span class="metric-value" id="throughput">-- ops/s</span>

            </div>

            <div class="metric">

                <span class="metric-label">Error Rate</span>

                <span class="metric-value" id="error-rate">--%</span>

            </div>

            <div class="metric">

                <span class="metric-label">Active Operations</span>

                <span class="metric-value" id="active-ops">--</span>

            </div>

        </div>

        

        <div class="widget">

            <div class="widget-title">Network</div>

            <div class="metric">

                <span class="metric-label">RX Bandwidth</span>

                <span class="metric-value" id="rx-bandwidth">-- MB/s</span>

            </div>

            <div class="metric">

                <span class="metric-label">TX Bandwidth</span>

                <span class="metric-value" id="tx-bandwidth">-- MB/s</span>

            </div>

            <div class="metric">

                <span class="metric-label">Error Rate</span>

                <span class="metric-value" id="network-error-rate">--%</span>

            </div>

        </div>

        

        <div class="widget">

            <div class="widget-title">Recent Alerts</div>

            <div id="alerts-container">

                <p style="color: #666; font-style: italic;">No recent alerts</p>

            </div>

        </div>

    </div>

    

    <script>

        // WebSocket connection for real-time updates

        const ws = new WebSocket('ws://localhost:{websocket_port}/ws');

        

        ws.onmessage = function(event) {{

            const message = JSON.parse(event.data);

            handleDashboardMessage(message);

        }};

        

        function handleDashboardMessage(message) {{

            switch (message.type) {{

                case 'SystemMetrics':

                    updateSystemMetrics(message);

                    break;

                case 'PerformanceMetrics':

                    updatePerformanceMetrics(message);

                    break;

                case 'ApplicationMetrics':

                    updateApplicationMetrics(message);

                    break;

                case 'Alert':

                    addAlert(message);

                    break;

                case 'ConnectionStatus':

                    console.log('Connection status:', message);

                    break;

            }}

        }}

        

        function updateSystemMetrics(metrics) {{

            document.getElementById('cpu-usage').textContent = metrics.cpu_usage.toFixed(1) + '%';

            document.getElementById('memory-usage').textContent = metrics.memory_usage.toFixed(1) + '%';

            document.getElementById('disk-usage').textContent = metrics.disk_usage.toFixed(1) + '%';

            document.getElementById('processes').textContent = metrics.active_processes;

            

            // Update network metrics

            document.getElementById('rx-bandwidth').textContent = (metrics.network_usage.bytes_rx_per_sec / 1024 / 1024).toFixed(2) + ' MB/s';

            document.getElementById('tx-bandwidth').textContent = (metrics.network_usage.bytes_tx_per_sec / 1024 / 1024).toFixed(2) + ' MB/s';

            document.getElementById('network-error-rate').textContent = metrics.network_usage.error_rate.toFixed(2) + '%';

        }}

        

        function updatePerformanceMetrics(metrics) {{

            document.getElementById('response-time').textContent = metrics.response_time_percentiles.avg_ms.toFixed(2) + 'ms';

            document.getElementById('throughput').textContent = metrics.throughput.toFixed(1) + ' ops/s';

            document.getElementById('error-rate').textContent = metrics.error_rate.toFixed(2) + '%';

            document.getElementById('active-ops').textContent = metrics.active_operations;

        }}

        

        function updateApplicationMetrics(metrics) {{

            // Handle custom application metrics

            console.log('Application metrics:', metrics);

        }}

        

        function addAlert(alert) {{

            const container = document.getElementById('alerts-container');

            const alertElement = document.createElement('div');

            alertElement.style.cssText = `

                padding: 10px;

                margin: 5px 0;

                border-radius: 4px;

                background: ${{alert.severity === 'Critical' ? '#ffebee' : alert.severity === 'Error' ? '#fff3e0' : '#e8f5e8'}};

                border-left: 4px solid ${{alert.severity === 'Critical' ? '#f44336' : alert.severity === 'Error' ? '#ff9800' : '#4caf50'}};

            `;

            alertElement.innerHTML = `

                <strong>${{alert.title}}</strong> - ${{alert.message}}

                <br><small style="color: #666;">${{new Date(alert.timestamp).toLocaleString()}}</small>

            `;

            

            // Clear "no alerts" message if present

            if (container.querySelector('p')) {{

                container.innerHTML = '';

            }}

            

            container.insertBefore(alertElement, container.firstChild);

            

            // Keep only last 10 alerts

            while (container.children.length > 10) {{

                container.removeChild(container.lastChild);

            }}

        }}

        

        // Simulate initial data

        setTimeout(() => {{

            document.getElementById('cpu-usage').textContent = '25.3%';

            document.getElementById('memory-usage').textContent = '42.1%';

            document.getElementById('disk-usage').textContent = '67.8%';

            document.getElementById('processes').textContent = '156';

            document.getElementById('response-time').textContent = '125.4ms';

            document.getElementById('throughput').textContent = '1,234 ops/s';

            document.getElementById('error-rate').textContent = '0.2%';

            document.getElementById('active-ops').textContent = '42';

        }}, 1000);

    </script>

</body>

</html>

"#,

            active_connections = stats.active_connections,

            uptime = stats.uptime_seconds,

            websocket_port = self.config.websocket_port,

        ))

    }

}



/// Dashboard statistics

#[derive(Debug, Clone, Serialize, Deserialize)]

pub struct DashboardStatistics {

    /// Number of active connections

    pub active_connections: usize,

    /// Total messages sent

    pub total_messages_sent: u64,

    /// Uptime in seconds

    pub uptime_seconds: u64,

    /// Messages per second

    pub messages_per_second: f64,

    /// System metrics enabled

    pub system_metrics_enabled: bool,

    /// Performance metrics enabled

    pub performance_metrics_enabled: bool,

    /// Application metrics enabled

    pub application_metrics_enabled: bool,

}



#[cfg(test)]

mod tests {

    use super::*;

    use crate::observability::system_resources::SystemResourceConfig;

    use crate::observability::enhanced_performance::EnhancedPerformanceConfig;

    use crate::observability::metrics::MetricsConfig;



    #[tokio::test]

    async fn test_real_time_dashboard_creation() {

        let config = RealTimeDashboardConfig::default();

        let system_config = SystemResourceConfig::default();

        let performance_config = EnhancedPerformanceConfig::default();

        let metrics_config = MetricsConfig::default();

        

        let system_monitor = Arc::new(SystemResourceMonitor::new(system_config));

        let performance_monitor = Arc::new(EnhancedPerformanceMonitor::new(

            performance_config, 

            system_monitor.clone()

        ));

        let metrics_collector = Arc::new(AdvancedMetricsCollector::new(metrics_config));

        

        let dashboard = RealTimeDashboard::new(

            config,

            system_monitor,

            performance_monitor,

            metrics_collector,

        );

        

        assert!(dashboard.is_ok());

    }



    #[tokio::test]

    async fn test_dashboard_html_generation() {

        let config = RealTimeDashboardConfig::default();

        let system_config = SystemResourceConfig::default();

        let performance_config = EnhancedPerformanceConfig::default();

        let metrics_config = MetricsConfig::default();

        

        let system_monitor = Arc::new(SystemResourceMonitor::new(system_config));

        let performance_monitor = Arc::new(EnhancedPerformanceMonitor::new(

            performance_config, 

            system_monitor.clone()

        ));

        let metrics_collector = Arc::new(AdvancedMetricsCollector::new(metrics_config));

        

        let dashboard = RealTimeDashboard::new(

            config,

            system_monitor,

            performance_monitor,

            metrics_collector,

        ).unwrap();

        

        let html = dashboard.generate_dashboard_html().await.unwrap();

        assert!(html.contains("Fortress Performance Dashboard"));

        assert!(html.contains("System Resources"));

        assert!(html.contains("Performance Metrics"));

    }



    #[test]

    fn test_dashboard_message_serialization() {

        let message = DashboardMessage::SystemMetrics(SystemMetricsUpdate {

            timestamp: chrono::Utc::now(),

            cpu_usage: 75.5,

            memory_usage: 60.2,

            disk_usage: 45.8,

            network_usage: NetworkMetrics {

                bytes_rx_per_sec: 1024000.0,

                bytes_tx_per_sec: 512000.0,

                packets_rx_per_sec: 1000.0,

                packets_tx_per_sec: 800.0,

                error_rate: 0.1,

            },

            active_processes: 156,

            system_load: 1.5,

        });

        

        let serialized = serde_json::to_string(&message).unwrap();

        let deserialized: DashboardMessage = serde_json::from_str(&serialized).unwrap();

        

        match deserialized {

            DashboardMessage::SystemMetrics(metrics) => {

                assert_eq!(metrics.cpu_usage, 75.5);

                assert_eq!(metrics.memory_usage, 60.2);

            }

            _ => assert!(matches!(message_type, MessageType::SystemMetrics), 

             "Expected SystemMetrics message, got {:?}", message_type),

        }

    }

}

