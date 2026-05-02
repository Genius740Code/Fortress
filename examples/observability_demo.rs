//! Advanced Observability Demo for Fortress
//!
//! This example demonstrates the comprehensive observability capabilities
//! of Fortress including distributed tracing, metrics collection, health checks,
//! alerting, and dashboard management.

use fortress_core::prelude::*;
use fortress_core::observability::*;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use ::tracing::{info, warn, error, debug, trace};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize the observability system
    println!("Initializing Fortress Observability System...");
    
    // Create comprehensive observability configuration
    let observability_config = create_observability_config();
    
    // Create the observability manager
    let observability_manager = ObservabilityManager::new(observability_config)?;
    
    // Start all observability components
    observability_manager.start().await?;
    
    // Set up mock metrics provider for alerts
    let metrics_provider = Arc::new(MockMetricsProvider::new());
    
    // Register some health checks
    register_health_checks(&observability_manager.health_checker()).await?;
    
    // Register alert rules
    register_alert_rules(&observability_manager.alert_manager(), metrics_provider.clone()).await?;
    
    // Create a sample dashboard
    create_sample_dashboard(&observability_manager.dashboard_manager()).await?;
    
    // Run the demo
    run_demo(&observability_manager, metrics_provider).await?;
    
    // Shutdown gracefully
    observability_manager.shutdown().await?;
    
    println!("✓ Observability demo completed successfully");
    Ok(())
}

/// Create comprehensive observability configuration
fn create_observability_config() -> ObservabilityConfig {
    ObservabilityConfig {
        tracing: TraceConfig {
            enabled: true,
            service_name: "fortress-observability-demo".to_string(),
            service_version: "0.1.0".to_string(),
            sampling: SamplingConfig {
                strategy: SamplingStrategy::TraceIdRatio,
                ratio: 1.0, // Sample all traces for demo
                spans_per_second: 1000,
            },
            export: ExportConfig {
                exporter_type: ExporterType::Console,
                endpoint: None,
                export_interval_seconds: 5,
                export_timeout_seconds: 10,
                batch_config: BatchConfig::default(),
            },
            span_limits: SpanLimits::default(),
        },
        metrics: metrics::MetricsConfig {
            enabled: true,
            collection_interval_seconds: 10,
            retention_hours: 24,
            export: metrics::MetricsExportConfig {
                exporters: vec![metrics::MetricsExporter::Console],
                interval_seconds: 30,
                timeout_seconds: 10,
            },
            aggregation: metrics::AggregationConfig::default(),
        },
        logging: LogConfig {
            enabled: true,
            level: LogLevel::Info,
            format: LogFormat::Json,
            output: LogOutputConfig {
                targets: vec![LogOutputTarget {
                    id: "console".to_string(),
                    target_type: LogOutputType::Console,
                    config: HashMap::new(),
                    enabled: true,
                    levels: vec![LogLevel::Info, LogLevel::Warn, LogLevel::Error],
                }],
                buffer: LogBufferConfig::default(),
                rotation: LogRotationConfig::default(),
            },
            filtering: LogFilteringConfig::default(),
            sampling: LogSamplingConfig::default(),
            context: LogContextConfig::default(),
        },
        health: HealthConfig {
            enabled: true,
            check_interval_seconds: 30,
            check_timeout_seconds: 10,
            failure_threshold: 3,
            components: HashMap::new(),
        },
        alerts: AlertConfig {
            enabled: true,
            evaluation_interval_seconds: 60,
            max_active_alerts: 100,
            retention_hours: 168,
            notifications: NotificationConfig::default(),
            escalation: EscalationConfig::default(),
        },
        dashboard: DashboardConfig {
            enabled: true,
            refresh_interval_seconds: 30,
            max_dashboards: 10,
            widgets: WidgetConfig::default(),
            theme: ThemeConfig::default(),
            export: DashboardExportConfig::default(),
        },
    }
}

/// Register health checks
async fn register_health_checks(health_checker: &HealthChecker) -> Result<(), Box<dyn std::error::Error>> {
    // Database health check
    let db_config = ComponentHealthConfig {
        enabled: true,
        check_interval_seconds: 30,
        timeout_seconds: 10,
        failure_threshold: 3,
        thresholds: {
            let mut thresholds = HashMap::new();
            thresholds.insert("max_response_time_ms".to_string(), 1000.0);
            thresholds.insert("max_connection_usage".to_string(), 0.8);
            thresholds
        },
    };
    
    health_checker.register_check(Box::new(DatabaseHealthCheck::new("database".to_string(), db_config))).await?;
    
    // Memory health check
    let memory_config = ComponentHealthConfig {
        enabled: true,
        check_interval_seconds: 60,
        timeout_seconds: 5,
        failure_threshold: 3,
        thresholds: {
            let mut thresholds = HashMap::new();
            thresholds.insert("max_usage_percent".to_string(), 85.0);
            thresholds
        },
    };
    
    health_checker.register_check(Box::new(MemoryHealthCheck::new("memory".to_string(), memory_config))).await?;
    
    println!("✓ Health checks registered");
    Ok(())
}

/// Register alert rules
async fn register_alert_rules(alert_manager: &AlertManager, metrics_provider: Arc<MockMetricsProvider>) -> Result<(), Box<dyn std::error::Error>> {
    // High CPU usage alert
    let cpu_alert_rule = AlertRule {
        id: "high_cpu_usage".to_string(),
        name: "High CPU Usage".to_string(),
        description: "Alert when CPU usage exceeds 80%".to_string(),
        enabled: true,
        condition: AlertCondition::Threshold {
            metric: "cpu_usage".to_string(),
            operator: ComparisonOperator::GreaterThan,
            threshold: 80.0,
            duration_seconds: 300,
        },
        severity: AlertSeverity::Warning,
        notification_channels: vec!["console".to_string()],
        cooldown_seconds: 300,
        metadata: {
            let mut metadata = HashMap::new();
            metadata.insert("category".to_string(), "performance".to_string());
            metadata.insert("impact".to_string(), "medium".to_string());
            metadata
        },
    };
    
    alert_manager.add_rule(cpu_alert_rule).await?;
    
    // High memory usage alert
    let memory_alert_rule = AlertRule {
        id: "high_memory_usage".to_string(),
        name: "High Memory Usage".to_string(),
        description: "Alert when memory usage exceeds 90%".to_string(),
        enabled: true,
        condition: AlertCondition::Threshold {
            metric: "memory_usage".to_string(),
            operator: ComparisonOperator::GreaterThan,
            threshold: 90.0,
            duration_seconds: 300,
        },
        severity: AlertSeverity::Critical,
        notification_channels: vec!["console".to_string()],
        cooldown_seconds: 300,
        metadata: {
            let mut metadata = HashMap::new();
            metadata.insert("category".to_string(), "performance".to_string());
            metadata.insert("impact".to_string(), "high".to_string());
            metadata
        },
    };
    
    alert_manager.add_rule(memory_alert_rule).await?;
    
    // Database connection alert
    let db_alert_rule = AlertRule {
        id: "database_connections".to_string(),
        name: "Database Connection Pool Exhaustion".to_string(),
        description: "Alert when database connection pool usage exceeds 85%".to_string(),
        enabled: true,
        condition: AlertCondition::Threshold {
            metric: "db_connection_usage".to_string(),
            operator: ComparisonOperator::GreaterThan,
            threshold: 85.0,
            duration_seconds: 60,
        },
        severity: AlertSeverity::Error,
        notification_channels: vec!["console".to_string()],
        cooldown_seconds: 180,
        metadata: {
            let mut metadata = HashMap::new();
            metadata.insert("category".to_string(), "database".to_string());
            metadata.insert("impact".to_string(), "high".to_string());
            metadata
        },
    };
    
    alert_manager.add_rule(db_alert_rule).await?;
    
    println!("✓ Alert rules registered");
    Ok(())
}

/// Create a sample dashboard
async fn create_sample_dashboard(dashboard_manager: &DashboardManager) -> Result<(), Box<dyn std::error::Error>> {
    // Create dashboard
    let dashboard = Dashboard {
        id: "fortress-overview".to_string(),
        name: "Fortress System Overview".to_string(),
        description: "Comprehensive overview of Fortress system health and performance".to_string(),
        tags: vec!["overview".to_string(), "system".to_string()],
        widgets: create_sample_widgets(),
        layout: DashboardLayout {
            layout_type: LayoutType::Grid,
            grid: GridConfig {
                columns: 12,
                rows: 8,
                gap: 16,
            },
            widget_positions: create_widget_positions(),
        },
        config: DashboardConfig::default(),
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
        owner: "observability-demo".to_string(),
        permissions: DashboardPermissions {
            public: true,
            allowed_users: Vec::new(),
            allowed_roles: Vec::new(),
        },
    };
    
    dashboard_manager.create_dashboard(dashboard).await?;
    
    println!("✓ Sample dashboard created");
    Ok(())
}

/// Create sample widgets for the dashboard
fn create_sample_widgets() -> Vec<Widget> {
    vec![
        // CPU Usage Widget
        Widget {
            id: "cpu_usage".to_string(),
            widget_type: WidgetType::GaugeChart,
            title: "CPU Usage".to_string(),
            config: WidgetConfigData {
                config: {
                    let mut config = HashMap::new();
                    config.insert("min".to_string(), serde_json::Value::Number(0.into()));
                    config.insert("max".to_string(), serde_json::Value::Number(100.into()));
                    config.insert("unit".to_string(), serde_json::Value::String("%".to_string()));
                    config
                },
                visualization: VisualizationConfig {
                    chart_type: Some(ChartType::Area),
                    color_scheme: Some("blue".to_string()),
                    axes: None,
                    legend: Some(LegendConfig {
                        show: false,
                        position: LegendPosition::Bottom,
                    }),
                },
            },
            data_source: DataSource {
                source_type: DataSourceType::Metrics,
                config: HashMap::new(),
                query: "cpu_usage".to_string(),
                refresh_interval_seconds: 30,
            },
            position: WidgetPosition { x: 0, y: 0, width: 4, height: 2 },
            size: WidgetSize { width: 4, height: 2 },
            refresh_interval_seconds: 30,
            enabled: true,
        },
        
        // Memory Usage Widget
        Widget {
            id: "memory_usage".to_string(),
            widget_type: WidgetType::GaugeChart,
            title: "Memory Usage".to_string(),
            config: WidgetConfigData {
                config: {
                    let mut config = HashMap::new();
                    config.insert("min".to_string(), serde_json::Value::Number(0.into()));
                    config.insert("max".to_string(), serde_json::Value::Number(100.into()));
                    config.insert("unit".to_string(), serde_json::Value::String("%".to_string()));
                    config
                },
                visualization: VisualizationConfig {
                    chart_type: Some(ChartType::Area),
                    color_scheme: Some("green".to_string()),
                    axes: None,
                    legend: None,
                },
            },
            data_source: DataSource {
                source_type: DataSourceType::Metrics,
                config: HashMap::new(),
                query: "memory_usage".to_string(),
                refresh_interval_seconds: 30,
            },
            position: WidgetPosition { x: 4, y: 0, width: 4, height: 2 },
            size: WidgetSize { width: 4, height: 2 },
            refresh_interval_seconds: 30,
            enabled: true,
        },
        
        // System Health Widget
        Widget {
            id: "system_health".to_string(),
            widget_type: WidgetType::HealthStatus,
            title: "System Health".to_string(),
            config: WidgetConfigData {
                config: HashMap::new(),
                visualization: VisualizationConfig {
                    chart_type: None,
                    color_scheme: None,
                    axes: None,
                    legend: None,
                },
            },
            data_source: DataSource {
                source_type: DataSourceType::Health,
                config: HashMap::new(),
                query: "overall_health".to_string(),
                refresh_interval_seconds: 60,
            },
            position: WidgetPosition { x: 8, y: 0, width: 4, height: 2 },
            size: WidgetSize { width: 4, height: 2 },
            refresh_interval_seconds: 60,
            enabled: true,
        },
        
        // Active Alerts Widget
        Widget {
            id: "active_alerts".to_string(),
            widget_type: WidgetType::AlertList,
            title: "Active Alerts".to_string(),
            config: WidgetConfigData {
                config: {
                    let mut config = HashMap::new();
                    config.insert("max_items".to_string(), serde_json::Value::Number(10.into()));
                    config
                },
                visualization: VisualizationConfig {
                    chart_type: None,
                    color_scheme: None,
                    axes: None,
                    legend: None,
                },
            },
            data_source: DataSource {
                source_type: DataSourceType::Alerts,
                config: HashMap::new(),
                query: "active_alerts".to_string(),
                refresh_interval_seconds: 30,
            },
            position: WidgetPosition { x: 0, y: 2, width: 6, height: 3 },
            size: WidgetSize { width: 6, height: 3 },
            refresh_interval_seconds: 30,
            enabled: true,
        },
        
        // Response Time Widget
        Widget {
            id: "response_time".to_string(),
            widget_type: WidgetType::TimeSeriesChart,
            title: "Response Time".to_string(),
            config: WidgetConfigData {
                config: {
                    let mut config = HashMap::new();
                    config.insert("time_range".to_string(), serde_json::Value::String("1h".to_string()));
                    config.insert("unit".to_string(), serde_json::Value::String("ms".to_string()));
                    config
                },
                visualization: VisualizationConfig {
                    chart_type: Some(ChartType::Line),
                    color_scheme: Some("orange".to_string()),
                    axes: Some(AxisConfig {
                        x_axis: Some(Axis {
                            label: "Time".to_string(),
                            axis_type: AxisType::Time,
                            min: None,
                            max: None,
                        }),
                        y_axis: Some(Axis {
                            label: "Response Time (ms)".to_string(),
                            axis_type: AxisType::Linear,
                            min: Some(0.0),
                            max: None,
                        }),
                    }),
                    legend: Some(LegendConfig {
                        show: true,
                        position: LegendPosition::Bottom,
                    }),
                },
            },
            data_source: DataSource {
                source_type: DataSourceType::Metrics,
                config: HashMap::new(),
                query: "response_time".to_string(),
                refresh_interval_seconds: 30,
            },
            position: WidgetPosition { x: 6, y: 2, width: 6, height: 3 },
            size: WidgetSize { width: 6, height: 3 },
            refresh_interval_seconds: 30,
            enabled: true,
        },
    ]
}

/// Create widget positions for the dashboard layout
fn create_widget_positions() -> HashMap<String, WidgetPosition> {
    let mut positions = HashMap::new();
    
    positions.insert("cpu_usage".to_string(), WidgetPosition { x: 0, y: 0, width: 4, height: 2 });
    positions.insert("memory_usage".to_string(), WidgetPosition { x: 4, y: 0, width: 4, height: 2 });
    positions.insert("system_health".to_string(), WidgetPosition { x: 8, y: 0, width: 4, height: 2 });
    positions.insert("active_alerts".to_string(), WidgetPosition { x: 0, y: 2, width: 6, height: 3 });
    positions.insert("response_time".to_string(), WidgetPosition { x: 6, y: 2, width: 6, height: 3 });
    
    positions
}

/// Run the observability demo
async fn run_demo(
    observability_manager: &ObservabilityManager,
    metrics_provider: Arc<MockMetricsProvider>,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("\nStarting observability demo...\n");
    
    // Demo duration in seconds
    let demo_duration = 120;
    let start_time = std::time::Instant::now();
    
    while start_time.elapsed().as_secs() < demo_duration {
        // Simulate system metrics
        simulate_system_metrics(&metrics_provider).await;
        
        // Demonstrate distributed tracing
        demonstrate_tracing(&observability_manager.tracer()).await?;
        
        // Demonstrate metrics collection
        demonstrate_metrics(&observability_manager.metrics()).await?;
        
        // Demonstrate structured logging
        demonstrate_logging(&observability_manager.logger()).await?;
        
        // Show system status
        show_system_status(&observability_manager).await?;
        
        // Wait before next iteration
        tokio::time::sleep(Duration::from_secs(10)).await;
    }
    
    println!("\nFinal observability summary:");
    print_final_summary(&observability_manager).await?;
    
    Ok(())
}

/// Simulate system metrics
async fn simulate_system_metrics(metrics_provider: &MockMetricsProvider) {
    // Simulate varying CPU usage
    let cpu_usage = 50.0 + (rand::random::<f64>() * 40.0); // 50-90%
    metrics_provider.set_metric("cpu_usage", cpu_usage).await;
    
    // Simulate varying memory usage
    let memory_usage = 60.0 + (rand::random::<f64>() * 30.0); // 60-90%
    metrics_provider.set_metric("memory_usage", memory_usage).await;
    
    // Simulate database connection usage
    let db_usage = 70.0 + (rand::random::<f64>() * 20.0); // 70-90%
    metrics_provider.set_metric("db_connection_usage", db_usage).await;
    
    // Simulate response time
    let response_time = 50.0 + (rand::random::<f64>() * 150.0); // 50-200ms
    metrics_provider.set_metric("response_time", response_time).await;
}

/// Demonstrate distributed tracing
async fn demonstrate_tracing(tracer: &ObservabilityTracer) -> Result<(), Box<dyn std::error::Error>> {
    // Start a parent span
    let parent_context = tracer
        .start_span("database_operation", None, {
            let mut metadata = HashMap::new();
            metadata.insert("operation".to_string(), "query".to_string());
            metadata.insert("table".to_string(), "users".to_string());
            metadata
        })
        .await?;
    
    // Simulate some work
    tokio::time::sleep(Duration::from_millis(100)).await;
    
    // Start a child span
    let child_context = tracer
        .start_span("cache_lookup", Some(&parent_context), {
            let mut metadata = HashMap::new();
            metadata.insert("cache_key".to_string(), "user_123".to_string());
            metadata
        })
        .await?;
    
    tokio::time::sleep(Duration::from_millis(50)).await;
    
    // Finish child span
    tracer.finish_span(&child_context, Some("cache_hit"), None).await?;
    
    // Finish parent span
    tracer.finish_span(&parent_context, Some("success"), None).await?;
    
    Ok(())
}

/// Demonstrate metrics collection
async fn demonstrate_metrics(metrics: &AdvancedMetricsCollector) -> Result<(), Box<dyn std::error::Error>> {
    // Register some metrics if not already registered
    let counter_def = MetricDefinition {
        name: "requests_total".to_string(),
        metric_type: MetricType::Counter,
        description: "Total number of requests".to_string(),
        labels: HashMap::new(),
        unit: Some("count".to_string()),
    };
    
    let gauge_def = MetricDefinition {
        name: "active_connections".to_string(),
        metric_type: MetricType::Gauge,
        description: "Number of active connections".to_string(),
        labels: HashMap::new(),
        unit: Some("count".to_string()),
    };
    
    let histogram_def = MetricDefinition {
        name: "request_duration".to_string(),
        metric_type: MetricType::Histogram,
        description: "Request duration histogram".to_string(),
        labels: HashMap::new(),
        unit: Some("ms".to_string()),
    };
    
    // Register metrics (ignore errors if already registered)
    let _ = metrics.register_metric(counter_def).await;
    let _ = metrics.register_metric(gauge_def).await;
    let _ = metrics.register_metric(histogram_def).await;
    
    // Record some metrics
    let mut labels = HashMap::new();
    labels.insert("method".to_string(), "GET".to_string());
    labels.insert("endpoint".to_string(), "/api/users".to_string());
    
    metrics.record_counter("requests_total", 1, labels.clone()).await?;
    metrics.set_gauge("active_connections", 42.0, HashMap::new()).await?;
    metrics.record_histogram("request_duration", 125.5, labels).await?;
    
    Ok(())
}

/// Demonstrate structured logging
async fn demonstrate_logging(logger: &StructuredLogger) -> Result<(), Box<dyn std::error::Error>> {
    // Add some context
    logger.add_global_context("demo_run", "observability_demo").await?;
    logger.add_global_context("version", "0.1.0").await?;
    
    // Log some structured events
    ::tracing::info!(
        user_id = "user_123",
        action = "login",
        ip_address = "192.168.1.100",
        "User successfully authenticated"
    );
    
    ::tracing::warn!(
        component = "database",
        query_time_ms = 1500,
        threshold_ms = 1000,
        "Slow database query detected"
    );
    
    ::tracing::error!(
        error_code = "DB_CONNECTION_FAILED",
        retry_count = 3,
        component = "database",
        "Failed to connect to database after retries"
    );
    
    Ok(())
}

/// Show system status
async fn show_system_status(observability_manager: &ObservabilityManager) -> Result<(), Box<dyn std::error::Error>> {
    let status = observability_manager.get_system_status().await;
    
    println!("📈 System Status:");
    println!("  Health: {:?}", status.health.status);
    println!("  Active Alerts: {}", status.active_alerts_count);
    println!("  Total Metrics: {}", status.metrics_summary.total_metrics);
    println!("  Collection Rate: {:.2} metrics/sec", status.metrics_summary.collection_rate);
    println!("  Uptime: {:?}", status.uptime);
    println!();
    
    Ok(())
}

/// Print final summary
async fn print_final_summary(observability_manager: &ObservabilityManager) -> Result<(), Box<dyn std::error::Error>> {
    // Get final metrics summary
    let metrics_summary = observability_manager.metrics().get_summary().await;
    
    println!("Metrics Summary:");
    println!("  Total Metrics: {}", metrics_summary.total_metrics);
    println!("  Collection Rate: {:.2} metrics/sec", metrics_summary.collection_rate);
    println!("  Memory Usage: {} bytes", metrics_summary.memory_usage_bytes);
    
    // Get final health status
    let health_status = observability_manager.health_checker().get_overall_health().await;
    
    println!("\nHealth Status:");
    println!("  Overall Status: {:?}", health_status.status);
    println!("  Total Components: {}", health_status.total_components);
    println!("  Healthy: {}", health_status.healthy_components);
    println!("  Warning: {}", health_status.warning_components);
    println!("  Unhealthy: {}", health_status.unhealthy_components);
    println!("  Uptime: {:.1}%", health_status.uptime_percentage);
    
    // Get active alerts
    let active_alerts = observability_manager.alert_manager().get_active_alerts().await;
    
    println!("\nActive Alerts: {}", active_alerts.len());
    for alert in active_alerts.iter().take(5) {
        println!("  [{}] {}: {}", alert.severity, alert.title, alert.message);
    }
    
    // Get dashboard info
    let dashboards = observability_manager.dashboard_manager().list_dashboards().await;
    
    println!("\nDashboards: {}", dashboards.len());
    for dashboard in &dashboards {
        println!("  - {} ({} widgets)", dashboard.name, dashboard.widgets.len());
    }
    
    println!();
    Ok(())
}

/// Mock metrics provider implementation
struct MockMetricsProvider {
    metrics: Arc<RwLock<HashMap<String, f64>>>,
}

impl MockMetricsProvider {
    fn new() -> Self {
        Self {
            metrics: Arc::new(RwLock::new(HashMap::new())),
        }
    }
    
    async fn set_metric(&self, name: &str, value: f64) {
        let mut metrics = self.metrics.write().await;
        metrics.insert(name.to_string(), value);
    }
}

#[async_trait::async_trait]
impl MetricsProvider for MockMetricsProvider {
    async fn get_metric(&self, name: &str) -> Result<Option<f64>> {
        let metrics = self.metrics.read().await;
        Ok(metrics.get(name).copied())
    }
}

/// Mock data provider for dashboard widgets
struct MockDashboardDataProvider {
    provider_type: DataSourceType,
}

impl MockDashboardDataProvider {
    fn new(provider_type: DataSourceType) -> Self {
        Self { provider_type }
    }
}

#[async_trait::async_trait]
impl DataProvider for MockDashboardDataProvider {
    async fn get_data(&self, widget: &Widget) -> Result<WidgetData> {
        let data = match self.provider_type {
            DataSourceType::Metrics => {
                WidgetDataContent::Metric(rand::random::<f64>() * 100.0)
            }
            DataSourceType::Health => {
                let mut components = HashMap::new();
                components.insert("database".to_string(), ComponentHealthInfo {
                    name: "database".to_string(),
                    status: "healthy".to_string(),
                    last_check: chrono::Utc::now(),
                    response_time_ms: 50,
                });
                
                WidgetDataContent::HealthStatus(HealthInfo {
                    status: "healthy".to_string(),
                    components,
                })
            }
            DataSourceType::Alerts => {
                let alerts = vec![
                    AlertInfo {
                        id: "alert_1".to_string(),
                        title: "High CPU Usage".to_string(),
                        severity: "warning".to_string(),
                        status: "active".to_string(),
                        created_at: chrono::Utc::now(),
                    },
                ];
                WidgetDataContent::AlertList(alerts)
            }
            _ => WidgetDataContent::Text("Mock data".to_string()),
        };

        Ok(WidgetData {
            widget_id: widget.id.clone(),
            timestamp: chrono::Utc::now(),
            data,
            metadata: HashMap::new(),
        })
    }
}
