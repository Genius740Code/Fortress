//! Advanced observability module for Fortress
//!
//! This module provides comprehensive observability capabilities including
//! distributed tracing, advanced metrics, structured logging, and monitoring
//! dashboards integration.

pub mod alerts;
pub mod dashboard;
pub mod enhanced_performance;
pub mod health;
pub mod logging;
pub mod metrics;
pub mod realtime_dashboard;
pub mod system_resources;
pub mod tracing;

pub use alerts::{AlertManager, AlertRule, NotificationChannel};
pub use dashboard::{DashboardConfig, DashboardManager, Widget};
pub use enhanced_performance::{
    EnhancedPerformanceConfig, EnhancedPerformanceMonitor, PerformanceAnomaly, PerformanceBaseline,
};
pub use health::{ComponentHealth, HealthChecker, HealthStatus};
pub use logging::{LogConfig, LogFormat, StructuredLogger};
pub use metrics::{AdvancedMetricsCollector, MetricRegistry, MetricType};
pub use realtime_dashboard::{
    DashboardMessage, DashboardStatistics, RealTimeDashboard, RealTimeDashboardConfig,
};
pub use system_resources::{
    ResourceAlert, SystemResourceConfig, SystemResourceMonitor, SystemSnapshot,
};
pub use tracing::{ObservabilityTracer, SpanContext, TraceConfig};

use serde::{Deserialize, Serialize};
use std::sync::Arc;
#[cfg(feature = "observability")]
use tracing::{debug, error, info, warn};

/// Comprehensive observability configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObservabilityConfig {
    /// Tracing configuration
    pub tracing: TraceConfig,
    /// Metrics configuration
    pub metrics: metrics::MetricsConfig,
    /// Logging configuration
    pub logging: LogConfig,
    /// Health check configuration
    pub health: health::HealthConfig,
    /// Alert configuration
    pub alerts: alerts::AlertConfig,
    /// Dashboard configuration
    pub dashboard: DashboardConfig,
    /// System resource monitoring configuration
    pub system_resources: SystemResourceConfig,
}

impl Default for ObservabilityConfig {
    fn default() -> Self {
        Self {
            tracing: TraceConfig::default(),
            metrics: metrics::MetricsConfig::default(),
            logging: LogConfig::default(),
            health: health::HealthConfig::default(),
            alerts: alerts::AlertConfig::default(),
            dashboard: DashboardConfig::default(),
            system_resources: SystemResourceConfig::default(),
        }
    }
}

/// Main observability manager that coordinates all monitoring components
pub struct ObservabilityManager {
    /// Configuration
    config: ObservabilityConfig,
    /// Distributed tracer
    tracer: ObservabilityTracer,
    /// Metrics collector
    metrics: AdvancedMetricsCollector,
    /// Structured logger
    logger: StructuredLogger,
    /// Health checker
    health_checker: HealthChecker,
    /// Alert manager
    alert_manager: AlertManager,
    /// Dashboard manager
    dashboard_manager: DashboardManager,
    /// System resource monitor
    system_resource_monitor: SystemResourceMonitor,
}

impl std::fmt::Debug for ObservabilityManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ObservabilityManager")
            .field("config", &self.config)
            .finish()
    }
}

impl ObservabilityManager {
    /// Create a new observability manager with the given configuration
    pub fn new(config: ObservabilityConfig) -> Result<Self, Box<dyn std::error::Error>> {
        let tracer = ObservabilityTracer::new(config.tracing.clone())?;
        let metrics = AdvancedMetricsCollector::new(config.metrics.clone())?;
        let logger = StructuredLogger::new(config.logging.clone());
        let health_checker = HealthChecker::new(config.health.clone());

        // Create a mock metrics provider for alerts
        let mock_provider = Arc::new(crate::observability::alerts::MockMetricsProvider::new());
        let alert_manager = AlertManager::new(config.alerts.clone(), mock_provider);
        let dashboard_manager = DashboardManager::new(config.dashboard.clone());
        let system_resource_monitor = SystemResourceMonitor::new(config.system_resources.clone());

        Ok(Self {
            config,
            tracer,
            metrics,
            logger,
            health_checker,
            alert_manager,
            dashboard_manager,
            system_resource_monitor,
        })
    }

    /// Get the distributed tracer
    pub fn tracer(&self) -> &ObservabilityTracer {
        &self.tracer
    }

    /// Get the metrics collector
    pub fn metrics(&self) -> &AdvancedMetricsCollector {
        &self.metrics
    }

    /// Get the structured logger
    pub fn logger(&self) -> &StructuredLogger {
        &self.logger
    }

    /// Get the health checker
    pub fn health_checker(&self) -> &HealthChecker {
        &self.health_checker
    }

    /// Get the alert manager
    pub fn alert_manager(&self) -> &AlertManager {
        &self.alert_manager
    }

    /// Get dashboard manager
    pub fn dashboard_manager(&self) -> &DashboardManager {
        &self.dashboard_manager
    }

    /// Get system resource monitor
    pub fn system_resource_monitor(&self) -> &SystemResourceMonitor {
        &self.system_resource_monitor
    }

    /// Start all observability components
    pub async fn start(&self) -> Result<(), Box<dyn std::error::Error>> {
        // Start tracing
        self.tracer.start().await?;

        // Start metrics collection
        self.metrics.start().await?;

        // Start logging
        self.logger.start().await?;

        // Start health checks
        self.health_checker.start().await?;

        // Start alert manager
        self.alert_manager.start().await?;

        // Start dashboard manager
        self.dashboard_manager.start().await?;

        #[cfg(feature = "observability")]
        info!("Observability system started successfully");
        Ok(())
    }

    /// Stop all observability components
    pub async fn shutdown(&self) -> Result<(), Box<dyn std::error::Error>> {
        #[cfg(feature = "observability")]
        info!("Shutting down observability system");

        // Stop in reverse order
        self.dashboard_manager.shutdown().await?;
        self.alert_manager.shutdown().await?;
        self.health_checker.shutdown().await?;
        self.logger.shutdown().await?;
        self.metrics.shutdown().await?;
        self.tracer.shutdown().await?;

        #[cfg(feature = "observability")]
        info!("Observability system shutdown complete");
        Ok(())
    }

    /// Get comprehensive system status
    pub async fn get_system_status(&self) -> SystemStatus {
        let health_status = self.health_checker.get_overall_health().await;
        let active_alerts = self.alert_manager.get_active_alerts().await;
        let metrics_summary = self.metrics.get_summary().await;

        SystemStatus {
            health: health_status,
            active_alerts_count: active_alerts.len(),
            metrics_summary,
            uptime: self.get_uptime().await,
            timestamp: chrono::Utc::now(),
        }
    }

    /// Get system uptime
    async fn get_uptime(&self) -> std::time::Duration {
        // This would be tracked from startup time
        std::time::Duration::from_secs(0) // Placeholder
    }
}

/// System status overview
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemStatus {
    /// Overall health status
    pub health: health::OverallHealth,
    /// Number of active alerts
    pub active_alerts_count: usize,
    /// Metrics summary
    pub metrics_summary: metrics::MetricsSummary,
    /// System uptime
    pub uptime: std::time::Duration,
    /// Status timestamp
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_observability_config_default() {
        let config = ObservabilityConfig::default();
        assert!(config.tracing.enabled);
        assert!(config.metrics.enabled);
        assert!(config.logging.enabled);
    }

    #[tokio::test]
    async fn test_observability_manager_creation() {
        let config = ObservabilityConfig::default();
        let manager = ObservabilityManager::new(config);
        assert!(manager.is_ok());
    }
}
