# Fortress Observability Guide

## Overview

Fortress provides a comprehensive observability system that includes distributed tracing, metrics collection, structured logging, health monitoring, alerting, and dashboard management. This guide covers how to set up, configure, and use these features effectively.

## Table of Contents

1. [Architecture](#architecture)
2. [Distributed Tracing](#distributed-tracing)
3. [Metrics Collection](#metrics-collection)
4. [Structured Logging](#structured-logging)
5. [Health Monitoring](#health-monitoring)
6. [Alert Management](#alert-management)
7. [Dashboard Management](#dashboard-management)
8. [Configuration](#configuration)
9. [Examples](#examples)
10. [Best Practices](#best-practices)

## Architecture

The Fortress observability system is built around a modular architecture that allows you to use components independently or as part of an integrated solution:

```
┌─────────────────────────────────────────────────────────────┐
│                    Observability Manager                     │
├─────────────────┬─────────────────┬─────────────────────────┤
│   Tracing       │    Metrics      │      Logging            │
│                 │                 │                        │
│ • OpenTelemetry │ • Counters      │ • Structured logs      │
│ • Span Context  │ • Gauges        │ • JSON format         │
│ • Propagation   │ • Histograms    │ • Multiple outputs     │
│ • Sampling      │ • Summaries     │ • Context enrichment   │
└─────────────────┴─────────────────┴─────────────────────────┘
├─────────────────┬─────────────────┬─────────────────────────┤
│   Health        │    Alerts       │      Dashboards         │
│                 │                 │                        │
│ • Component     │ • Rules         │ • Custom widgets       │
│ • Thresholds    │ • Notifications │ • Real-time data       │
│ • Status        │ • Escalation    │ • Export capabilities   │
└─────────────────┴─────────────────┴─────────────────────────┘
```

## Distributed Tracing

### Overview

Distributed tracing allows you to track requests as they flow through your system, providing visibility into performance bottlenecks and dependencies.

### Key Features

- **OpenTelemetry Compatibility**: Full OpenTelemetry support for interoperability
- **Span Propagation**: Automatic context propagation across service boundaries
- **Sampling**: Configurable sampling strategies to control overhead
- **Export**: Multiple export targets (Jaeger, Zipkin, OTLP, Console)

### Basic Usage

```rust
use fortress_core::observability::*;

// Create tracer configuration
let trace_config = TraceConfig {
    enabled: true,
    service_name: "my-fortress-service".to_string(),
    service_version: "1.0.0".to_string(),
    sampling: SamplingConfig {
        strategy: SamplingStrategy::TraceIdRatio,
        ratio: 0.1, // 10% sampling
        spans_per_second: 1000,
    },
    export: ExportConfig {
        exporter_type: ExporterType::Jaeger,
        endpoint: Some("http://jaeger:14268/api/traces".to_string()),
        export_interval_seconds: 5,
        export_timeout_seconds: 10,
        batch_config: BatchConfig::default(),
    },
    span_limits: SpanLimits::default(),
};

// Create tracer
let tracer = ObservabilityTracer::new(trace_config)?;
tracer.start().await?;

// Start a span
let parent_context = tracer
    .start_span("database_operation", None, {
        let mut metadata = HashMap::new();
        metadata.insert("operation".to_string(), "query".to_string());
        metadata.insert("table".to_string(), "users".to_string());
        metadata
    })
    .await?;

// Do some work...

// Finish the span
tracer.finish_span(&parent_context, Some("success"), None).await?;
```

### Manual Span Management

```rust
// Start a span with parent context
let child_context = tracer
    .start_span("cache_lookup", Some(&parent_context), {
        let mut metadata = HashMap::new();
        metadata.insert("cache_key".to_string(), "user_123".to_string());
        metadata
    })
    .await?;

// Add events to the span
tracer.add_span_event(&child_context, "cache_hit", {
    let mut attributes = HashMap::new();
    attributes.insert("hit_rate".to_string(), "0.95".to_string());
    attributes
}).await?;

// Finish the span
tracer.finish_span(&child_context, Some("cache_hit"), None).await?;
```

### Context Propagation

```rust
// Extract context from incoming headers
let headers = HashMap::from([
    ("traceparent".to_string(), "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01".to_string()),
]);

let context = tracer.extract_context(&headers)?;
if let Some(ctx) = context {
    // Use the extracted context for child spans
    let child_span = tracer.start_span("process_request", Some(&ctx), HashMap::new()).await?;
    // ...
}

// Inject context into outgoing headers
let mut outgoing_headers = HashMap::new();
tracer.inject_context(&context.unwrap(), &mut outgoing_headers)?;
```

## Metrics Collection

### Overview

The metrics system provides comprehensive collection of counters, gauges, histograms, and summaries with configurable aggregation and export capabilities.

### Metric Types

1. **Counters**: Monotonically increasing values
2. **Gauges**: Values that can go up and down
3. **Histograms**: Distribution of values with configurable buckets
4. **Summaries**: Similar to histograms with configurable quantiles

### Basic Usage

```rust
use fortress_core::observability::*;

// Create metrics configuration
let metrics_config = metrics::MetricsConfig {
    enabled: true,
    collection_interval_seconds: 10,
    retention_hours: 24,
    export: metrics::MetricsExportConfig {
        exporters: vec![
            metrics::MetricsExporter::Prometheus,
            metrics::MetricsExporter::OpenTelemetry,
        ],
        interval_seconds: 30,
        timeout_seconds: 10,
    },
    aggregation: metrics::AggregationConfig::default(),
};

// Create metrics collector
let metrics = AdvancedMetricsCollector::new(metrics_config)?;
metrics.start().await?;

// Register metrics
let counter_def = MetricDefinition {
    name: "requests_total".to_string(),
    metric_type: MetricType::Counter,
    description: "Total number of HTTP requests".to_string(),
    labels: HashMap::new(),
    unit: Some("count".to_string()),
};

let gauge_def = MetricDefinition {
    name: "active_connections".to_string(),
    metric_type: MetricType::Gauge,
    description: "Number of active database connections".to_string(),
    labels: HashMap::new(),
    unit: Some("count".to_string()),
};

let histogram_def = MetricDefinition {
    name: "request_duration_ms".to_string(),
    metric_type: MetricType::Histogram,
    description: "Request duration in milliseconds".to_string(),
    labels: HashMap::new(),
    unit: Some("ms".to_string()),
};

metrics.register_metric(counter_def).await?;
metrics.register_metric(gauge_def).await?;
metrics.register_metric(histogram_def).await?;

// Record metrics
let mut labels = HashMap::new();
labels.insert("method".to_string(), "GET".to_string());
labels.insert("endpoint".to_string(), "/api/users".to_string());

metrics.record_counter("requests_total", 1, labels.clone()).await?;
metrics.set_gauge("active_connections", 42.0, HashMap::new()).await?;
metrics.record_histogram("request_duration_ms", 125.5, labels).await?;
```

### Prometheus Export

```rust
// Export metrics in Prometheus format
let prometheus_output = metrics.export_prometheus().await?;
println!("{}", prometheus_output);
```

### Custom Metrics with Labels

```rust
// Record metrics with different label combinations
let mut success_labels = HashMap::new();
success_labels.insert("status".to_string(), "success".to_string());
success_labels.insert("method".to_string(), "POST".to_string());

let mut error_labels = HashMap::new();
error_labels.insert("status".to_string(), "error".to_string());
error_labels.insert("method".to_string(), "POST".to_string());

metrics.record_counter("http_requests_total", 1, success_labels).await?;
metrics.record_counter("http_requests_total", 1, error_labels).await?;
```

## Structured Logging

### Overview

Structured logging provides consistent, machine-readable log output with context enrichment and multiple output formats.

### Key Features

- **Multiple Formats**: JSON, compact JSON, pretty, plain text
- **Context Enrichment**: Automatic and manual context fields
- **Multiple Outputs**: Console, file, network, Elasticsearch, Loki
- **Filtering**: Module-level and target-level filtering
- **Sampling**: Configurable sampling for high-volume scenarios

### Basic Usage

```rust
use fortress_core::observability::*;

// Create logging configuration
let log_config = LogConfig {
    enabled: true,
    level: LogLevel::Info,
    format: LogFormat::Json,
    output: LogOutputConfig {
        targets: vec![
            LogOutputTarget {
                id: "console".to_string(),
                target_type: LogOutputType::Console,
                config: HashMap::new(),
                enabled: true,
                levels: vec![LogLevel::Info, LogLevel::Warn, LogLevel::Error],
            },
            LogOutputTarget {
                id: "file".to_string(),
                target_type: LogOutputType::File,
                config: {
                    let mut config = HashMap::new();
                    config.insert("path".to_string(), "/var/log/fortress/app.log".to_string());
                    config
                },
                enabled: true,
                levels: vec![LogLevel::Debug, LogLevel::Info, LogLevel::Warn, LogLevel::Error],
            },
        ],
        buffer: LogBufferConfig::default(),
        rotation: LogRotationConfig {
            enabled: true,
            max_file_size_bytes: 100 * 1024 * 1024, // 100MB
            max_files: 10,
            schedule: RotationSchedule::Size,
        },
    },
    filtering: LogFilteringConfig::default(),
    sampling: LogSamplingConfig::default(),
    context: LogContextConfig::default(),
};

// Create and initialize logger
let logger = StructuredLogger::new(log_config);
logger.init()?;
logger.start().await?;

// Add global context
logger.add_global_context("service_version", "1.0.0").await?;
logger.add_global_context("environment", "production").await?;

// Log structured events
tracing::info!(
    user_id = "user_123",
    action = "login",
    ip_address = "192.168.1.100",
    "User successfully authenticated"
);

tracing::warn!(
    component = "database",
    query_time_ms = 1500,
    threshold_ms = 1000,
    "Slow database query detected"
);

tracing::error!(
    error_code = "DB_CONNECTION_FAILED",
    retry_count = 3,
    component = "database",
    "Failed to connect to database after retries"
);
```

### Custom Log Macros

```rust
use fortress_core::{log_structured, log_error, log_performance};

// Structured logging with context
log_structured!(
    level: LogLevel::Info,
    message: "User action completed",
    user_id = "user_123",
    action = "profile_update",
    duration_ms = 250
);

// Error logging with context
log_error!(
    &fortress_error,
    component = "encryption",
    operation = "key_generation",
    key_id = "key_456"
);

// Performance logging
log_performance!(
    "database_query",
    query_duration,
    table = "users",
    query_type = "SELECT",
    rows_returned = 42
);
```

## Health Monitoring

### Overview

Health monitoring provides comprehensive health checks for all system components with configurable thresholds and automatic status reporting.

### Key Features

- **Component Health**: Individual health checks for each component
- **Thresholds**: Configurable thresholds for different metrics
- **Status Reporting**: Overall system health aggregation
- **Failure Detection**: Configurable failure thresholds and recovery

### Basic Usage

```rust
use fortress_core::observability::*;

// Create health checker configuration
let health_config = HealthConfig {
    enabled: true,
    check_interval_seconds: 30,
    check_timeout_seconds: 10,
    failure_threshold: 3,
    components: HashMap::new(),
};

// Create health checker
let health_checker = HealthChecker::new(health_config);

// Register health checks
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

// Start health checking
health_checker.start().await?;

// Get health status
let overall_health = health_checker.get_overall_health().await;
println!("Overall health: {:?}", overall_health.status);

let component_health = health_checker.get_component_health("database").await?;
if let Some(health) = component_health {
    println!("Database health: {:?}", health.status);
    println!("Response time: {:?}", health.response_time_ms);
}
```

### Custom Health Checks

```rust
use fortress_core::observability::*;
use async_trait::async_trait;

pub struct CustomHealthCheck {
    name: String,
    config: ComponentHealthConfig,
}

impl CustomHealthCheck {
    pub fn new(name: String, config: ComponentHealthConfig) -> Self {
        Self { name, config }
    }
}

#[async_trait::async_trait]
impl HealthCheck for CustomHealthCheck {
    fn name(&self) -> &str {
        &self.name
    }

    async fn check(&self) -> HealthCheckResult {
        let start_time = std::time::Instant::now();
        
        // Perform your custom health check logic here
        let is_healthy = perform_custom_check().await;
        let response_time = start_time.elapsed().as_millis() as u64;
        
        if is_healthy {
            HealthCheckResult::healthy(response_time)
        } else {
            HealthCheckResult::unhealthy(response_time, "Custom check failed".to_string())
        }
    }

    fn config(&self) -> &ComponentHealthConfig {
        &self.config
    }
}

async fn perform_custom_check() -> bool {
    // Implement your custom health check logic
    true
}
```

## Alert Management

### Overview

The alert system provides comprehensive alerting with configurable rules, multiple notification channels, and escalation policies.

### Key Features

- **Flexible Rules**: Threshold, composite, and custom alert conditions
- **Multiple Channels**: Email, Slack, PagerDuty, webhooks, SMS, console
- **Escalation**: Configurable escalation policies and timing
- **Rate Limiting**: Prevent alert fatigue with configurable rate limits

### Basic Usage

```rust
use fortress_core::observability::*;

// Create alert configuration
let alert_config = AlertConfig {
    enabled: true,
    evaluation_interval_seconds: 60,
    max_active_alerts: 100,
    retention_hours: 168,
    notifications: NotificationConfig {
        enabled: true,
        channels: vec![
            NotificationChannel {
                id: "console".to_string(),
                name: "Console".to_string(),
                channel_type: ChannelType::Console,
                config: HashMap::new(),
                enabled: true,
            },
            NotificationChannel {
                id: "slack".to_string(),
                name: "Slack".to_string(),
                channel_type: ChannelType::Slack,
                config: {
                    let mut config = HashMap::new();
                    config.insert("webhook_url".to_string(), "https://hooks.slack.com/...".to_string());
                    config.insert("channel".to_string(), "#alerts".to_string());
                    config
                },
                enabled: true,
            },
        ],
        rate_limit: RateLimitConfig::default(),
        retry: RetryConfig::default(),
    },
    escalation: EscalationConfig::default(),
};

// Create alert manager with metrics provider
let metrics_provider = Arc::new(MockMetricsProvider::new());
let alert_manager = AlertManager::new(alert_config, metrics_provider);

// Register alert rules
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
    notification_channels: vec!["console".to_string(), "slack".to_string()],
    cooldown_seconds: 300,
    metadata: {
        let mut metadata = HashMap::new();
        metadata.insert("category".to_string(), "performance".to_string());
        metadata.insert("impact".to_string(), "medium".to_string());
        metadata
    },
};

alert_manager.add_rule(cpu_alert_rule).await?;

// Start alert manager
alert_manager.start().await?;

// Monitor alerts
let active_alerts = alert_manager.get_active_alerts().await;
for alert in active_alerts {
    println!("Alert: {} - {}", alert.title, alert.message);
}
```

### Alert Conditions

```rust
// Threshold condition
let threshold_condition = AlertCondition::Threshold {
    metric: "error_rate".to_string(),
    operator: ComparisonOperator::GreaterThan,
    threshold: 5.0,
    duration_seconds: 300,
};

// Composite condition (AND)
let composite_condition = AlertCondition::Composite {
    operator: LogicalOperator::And,
    conditions: vec![
        AlertCondition::Threshold {
            metric: "cpu_usage".to_string(),
            operator: ComparisonOperator::GreaterThan,
            threshold: 80.0,
            duration_seconds: 300,
        },
        AlertCondition::Threshold {
            metric: "memory_usage".to_string(),
            operator: ComparisonOperator::GreaterThan,
            threshold: 85.0,
            duration_seconds: 300,
        },
    ],
};

// Custom condition
let custom_condition = AlertCondition::Custom {
    expression: "cpu_usage > 80 AND memory_usage > 85".to_string(),
    parameters: HashMap::new(),
};
```

### Alert Management

```rust
// Acknowledge an alert
alert_manager.acknowledge_alert("alert_id", "admin_user").await?;

// Resolve an alert
alert_manager.resolve_alert("alert_id").await?;

// Suppress an alert
alert_manager.suppress_alert("alert_id").await?;
```

## Dashboard Management

### Overview

The dashboard system provides comprehensive visualization capabilities with custom widgets, real-time data, and export functionality.

### Key Features

- **Custom Widgets**: Multiple widget types (charts, gauges, tables, alerts)
- **Real-time Data**: Automatic data refresh and caching
- **Flexible Layouts**: Grid, free-form, and tabbed layouts
- **Export Capabilities**: JSON, CSV, HTML, PNG, PDF export

### Basic Usage

```rust
use fortress_core::observability::*;

// Create dashboard configuration
let dashboard_config = DashboardConfig {
    enabled: true,
    refresh_interval_seconds: 30,
    max_dashboards: 50,
    widgets: WidgetConfig::default(),
    theme: ThemeConfig::default(),
    export: DashboardExportConfig::default(),
};

// Create dashboard manager
let mut dashboard_manager = DashboardManager::new(dashboard_config);

// Register data providers
dashboard_manager.register_data_provider(
    DataSourceType::Metrics,
    Box::new(MockDashboardDataProvider::new(DataSourceType::Metrics))
);

// Create dashboard
let dashboard = Dashboard {
    id: "system-overview".to_string(),
    name: "System Overview".to_string(),
    description: "Comprehensive system monitoring dashboard".to_string(),
    tags: vec!["overview".to_string(), "system".to_string()],
    widgets: create_dashboard_widgets(),
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
    owner: "admin".to_string(),
    permissions: DashboardPermissions {
        public: true,
        allowed_users: Vec::new(),
        allowed_roles: Vec::new(),
    },
};

dashboard_manager.create_dashboard(dashboard).await?;

// Start dashboard manager
dashboard_manager.start().await?;

// Refresh dashboard data
let widget_data = dashboard_manager.refresh_dashboard("system-overview").await?;
for data in widget_data {
    println!("Widget {} updated at {}", data.widget_id, data.timestamp);
}
```

### Widget Types

```rust
// Gauge widget for single metrics
let gauge_widget = Widget {
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
            legend: None,
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
};

// Time series widget for trends
let timeseries_widget = Widget {
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
};
```

## Configuration

### Complete Observability Configuration

```rust
use fortress_core::observability::*;

let observability_config = ObservabilityConfig {
    tracing: TraceConfig {
        enabled: true,
        service_name: "fortress-service".to_string(),
        service_version: "1.0.0".to_string(),
        sampling: SamplingConfig {
            strategy: SamplingStrategy::TraceIdRatio,
            ratio: 0.1,
            spans_per_second: 1000,
        },
        export: ExportConfig {
            exporter_type: ExporterType::Jaeger,
            endpoint: Some("http://jaeger:14268/api/traces".to_string()),
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
            exporters: vec![
                metrics::MetricsExporter::Prometheus,
                metrics::MetricsExporter::OpenTelemetry,
            ],
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
            targets: vec![
                LogOutputTarget {
                    id: "console".to_string(),
                    target_type: LogOutputType::Console,
                    config: HashMap::new(),
                    enabled: true,
                    levels: vec![LogLevel::Info, LogLevel::Warn, LogLevel::Error],
                },
            ],
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
        max_dashboards: 50,
        widgets: WidgetConfig::default(),
        theme: ThemeConfig::default(),
        export: DashboardExportConfig::default(),
    },
};

// Create and start observability manager
let observability_manager = ObservabilityManager::new(observability_config)?;
observability_manager.start().await?;
```

## Examples

### Complete Observability Setup

```rust
use fortress_core::observability::*;
use std::collections::HashMap;
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create observability configuration
    let config = create_observability_config();
    
    // Create observability manager
    let manager = ObservabilityManager::new(config)?;
    
    // Start all components
    manager.start().await?;
    
    // Set up health checks
    setup_health_checks(&manager.health_checker()).await?;
    
    // Set up alerts
    setup_alerts(&manager.alert_manager()).await?;
    
    // Set up dashboards
    setup_dashboards(&manager.dashboard_manager()).await?;
    
    // Run application
    run_application(&manager).await?;
    
    // Shutdown
    manager.shutdown().await?;
    
    Ok(())
}

fn create_observability_config() -> ObservabilityConfig {
    // Return your configuration
    ObservabilityConfig::default()
}

async fn setup_health_checks(health_checker: &HealthChecker) -> Result<()> {
    // Set up your health checks
    Ok(())
}

async fn setup_alerts(alert_manager: &AlertManager) -> Result<()> {
    // Set up your alert rules
    Ok(())
}

async fn setup_dashboards(dashboard_manager: &DashboardManager) -> Result<()> {
    // Set up your dashboards
    Ok(())
}

async fn run_application(manager: &ObservabilityManager) -> Result<()> {
    // Your application logic with observability
    Ok(())
}
```

### Custom Metrics Provider

```rust
use fortress_core::observability::*;
use async_trait::async_trait;

pub struct CustomMetricsProvider {
    // Your implementation
}

#[async_trait::async_trait]
impl MetricsProvider for CustomMetricsProvider {
    async fn get_metric(&self, name: &str) -> Result<Option<f64>> {
        // Implement your metric collection logic
        match name {
            "custom_metric" => Ok(Some(42.0)),
            _ => Ok(None),
        }
    }
}
```

### Custom Health Check

```rust
use fortress_core::observability::*;
use async_trait::async_trait;

pub struct CustomHealthCheck {
    name: String,
    config: ComponentHealthConfig,
}

#[async_trait::async_trait]
impl HealthCheck for CustomHealthCheck {
    fn name(&self) -> &str {
        &self.name
    }

    async fn check(&self) -> HealthCheckResult {
        let start_time = std::time::Instant::now();
        
        // Your custom health check logic
        let is_healthy = check_custom_component().await;
        let response_time = start_time.elapsed().as_millis() as u64;
        
        if is_healthy {
            HealthCheckResult::healthy(response_time)
        } else {
            HealthCheckResult::unhealthy(response_time, "Component unhealthy".to_string())
        }
    }

    fn config(&self) -> &ComponentHealthConfig {
        &self.config
    }
}

async fn check_custom_component() -> bool {
    // Your implementation
    true
}
```

## Best Practices

### 1. Sampling Strategy

- **Development**: Use 100% sampling for debugging
- **Staging**: Use 10-50% sampling for performance testing
- **Production**: Use 1-10% sampling to minimize overhead

### 2. Metric Naming

- Use consistent naming conventions
- Include units in metric names (e.g., `duration_ms`, `size_bytes`)
- Use labels for dimensions rather than creating separate metrics

### 3. Alert Thresholds

- Set thresholds based on SLA requirements
- Use multiple severity levels for different impact levels
- Implement cooldown periods to prevent alert fatigue

### 4. Dashboard Design

- Group related metrics together
- Use appropriate chart types for different data
- Keep dashboards focused and avoid information overload

### 5. Performance Considerations

- Monitor observability overhead
- Use sampling for high-volume scenarios
- Configure appropriate retention periods

### 6. Security

- Secure sensitive information in logs and traces
- Use authentication for dashboard access
- Implement proper access controls for alert management

## Troubleshooting

### Common Issues

1. **High Memory Usage**: Reduce retention periods or sampling rates
2. **Missing Metrics**: Check metric registration and data providers
3. **Alert Fatigue**: Adjust thresholds and cooldown periods
4. **Slow Dashboards**: Optimize widget refresh intervals

### Debug Mode

Enable debug logging for troubleshooting:

```rust
let log_config = LogConfig {
    level: LogLevel::Debug,
    // ... other config
};
```

### Performance Monitoring

Monitor the observability system itself:

```rust
// Get system status
let status = observability_manager.get_system_status().await;
println!("Observability system status: {:?}", status);
```

## Integration Examples

### Prometheus Integration

```rust
// Export metrics endpoint
use axum::{Router, response::Json};

async fn metrics_endpoint(State(metrics): State<Arc<AdvancedMetricsCollector>>) -> Result<String, StatusCode> {
    match metrics.export_prometheus().await {
        Ok(output) => Ok(output),
        Err(_) => Err(StatusCode::INTERNAL_SERVER_ERROR),
    }
}

let app = Router::new()
    .route("/metrics", axum::routing::get(metrics_endpoint))
    .with_state(metrics);
```

### Jaeger Integration

```rust
let trace_config = TraceConfig {
    export: ExportConfig {
        exporter_type: ExporterType::Jaeger,
        endpoint: Some("http://jaeger:14268/api/traces".to_string()),
        // ... other config
    },
    // ... other config
};
```

### Elasticsearch Integration

```rust
let log_config = LogConfig {
    output: LogOutputConfig {
        targets: vec![
            LogOutputTarget {
                id: "elasticsearch".to_string(),
                target_type: LogOutputType::Elasticsearch,
                config: {
                    let mut config = HashMap::new();
                    config.insert("url".to_string(), "http://elasticsearch:9200".to_string());
                    config.insert("index".to_string(), "fortress-logs".to_string());
                    config
                },
                enabled: true,
                levels: vec![LogLevel::Info, LogLevel::Warn, LogLevel::Error],
            },
        ],
        // ... other config
    },
    // ... other config
};
```

This comprehensive observability guide provides everything you need to implement effective monitoring, tracing, and alerting in your Fortress applications.
