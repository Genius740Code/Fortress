//! Health check system for Fortress
//!
//! Provides comprehensive health monitoring for all system components
//! with configurable checks, thresholds, and reporting.

use crate::error::{FortressError, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

/// Health check configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthConfig {
    /// Enable health checks
    pub enabled: bool,
    /// Check interval in seconds
    pub check_interval_seconds: u64,
    /// Timeout for individual checks in seconds
    pub check_timeout_seconds: u64,
    /// Number of consecutive failures before marking as unhealthy
    pub failure_threshold: u32,
    /// Component-specific configurations
    pub components: HashMap<String, ComponentHealthConfig>,
}

/// Component health configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComponentHealthConfig {
    /// Enable checks for this component
    pub enabled: bool,
    /// Check interval in seconds
    pub check_interval_seconds: u64,
    /// Timeout in seconds
    pub timeout_seconds: u64,
    /// Failure threshold
    pub failure_threshold: u32,
    /// Custom thresholds
    pub thresholds: HashMap<String, f64>,
}

impl Default for HealthConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            check_interval_seconds: 30,
            check_timeout_seconds: 10,
            failure_threshold: 3,
            components: HashMap::new(),
        }
    }
}

impl Default for ComponentHealthConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            check_interval_seconds: 30,
            timeout_seconds: 10,
            failure_threshold: 3,
            thresholds: HashMap::new(),
        }
    }
}

/// Health status levels
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum HealthStatus {
    /// Component is healthy
    Healthy,
    /// Component has warnings but is functional
    Warning,
    /// Component is unhealthy
    Unhealthy,
    /// Component status is unknown
    Unknown,
}

/// Component health information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComponentHealth {
    /// Component name
    pub name: String,
    /// Current health status
    pub status: HealthStatus,
    /// Last check timestamp
    pub last_check: chrono::DateTime<chrono::Utc>,
    /// Last successful check timestamp
    pub last_success: Option<chrono::DateTime<chrono::Utc>>,
    /// Last error message
    pub last_error: Option<String>,
    /// Consecutive failures
    pub consecutive_failures: u32,
    /// Total checks performed
    pub total_checks: u32,
    /// Response time in milliseconds
    pub response_time_ms: Option<u64>,
    /// Additional metrics
    pub metrics: HashMap<String, f64>,
    /// Health check details
    pub details: HashMap<String, String>,
}

/// Overall health status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OverallHealth {
    /// Overall status
    pub status: HealthStatus,
    /// Total components
    pub total_components: usize,
    /// Healthy components
    pub healthy_components: usize,
    /// Warning components
    pub warning_components: usize,
    /// Unhealthy components
    pub unhealthy_components: usize,
    /// Unknown components
    pub unknown_components: usize,
    /// Overall uptime percentage
    pub uptime_percentage: f64,
    /// Last check timestamp
    pub last_check: chrono::DateTime<chrono::Utc>,
    /// Component health details
    pub components: HashMap<String, ComponentHealth>,
}

/// Health check trait
#[async_trait::async_trait]
pub trait HealthCheck: Send + Sync {
    /// Get the name of this health check
    fn name(&self) -> &str;

    /// Perform the health check
    async fn check(&self) -> HealthCheckResult;

    /// Get the component configuration
    fn config(&self) -> &ComponentHealthConfig;
}

/// Health check result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthCheckResult {
    /// Status of the check
    pub status: HealthStatus,
    /// Response time in milliseconds
    pub response_time_ms: u64,
    /// Error message if any
    pub error: Option<String>,
    /// Additional metrics
    pub metrics: HashMap<String, f64>,
    /// Additional details
    pub details: HashMap<String, String>,
}

impl HealthCheckResult {
    /// Create a successful health check result
    pub fn healthy(response_time_ms: u64) -> Self {
        Self {
            status: HealthStatus::Healthy,
            response_time_ms,
            error: None,
            metrics: HashMap::new(),
            details: HashMap::new(),
        }
    }

    /// Create a warning health check result
    pub fn warning(response_time_ms: u64, message: String) -> Self {
        Self {
            status: HealthStatus::Warning,
            response_time_ms,
            error: Some(message),
            metrics: HashMap::new(),
            details: HashMap::new(),
        }
    }

    /// Create an unhealthy health check result
    pub fn unhealthy(response_time_ms: u64, error: String) -> Self {
        Self {
            status: HealthStatus::Unhealthy,
            response_time_ms,
            error: Some(error),
            metrics: HashMap::new(),
            details: HashMap::new(),
        }
    }
}

/// Health checker that manages all component health checks
pub struct HealthChecker {
    /// Configuration
    config: HealthConfig,
    /// Registered health checks
    health_checks: Arc<RwLock<HashMap<String, Box<dyn HealthCheck>>>>,
    /// Component health status
    component_health: Arc<RwLock<HashMap<String, ComponentHealth>>>,
    /// Overall health status
    overall_health: Arc<RwLock<OverallHealth>>,
    /// Start time
    start_time: Instant,
}

impl HealthChecker {
    /// Create a new health checker
    pub fn new(config: HealthConfig) -> Self {
        Self {
            config,
            health_checks: Arc::new(RwLock::new(HashMap::new())),
            component_health: Arc::new(RwLock::new(HashMap::new())),
            overall_health: Arc::new(RwLock::new(OverallHealth::default())),
            start_time: Instant::now(),
        }
    }

    /// Register a health check
    pub async fn register_check(&self, check: Box<dyn HealthCheck>) -> Result<()> {
        if !self.config.enabled {
            return Ok(());
        }

        let name = check.name().to_string();
        let mut health_checks = self.health_checks.write().await;

        if health_checks.contains_key(&name) {
            return Err(FortressError::validation(
                format!("Health check '{}' already registered", name),
                None,
                None,
            ));
        }

        health_checks.insert(name.clone(), check);

        // Initialize component health
        let mut component_health = self.component_health.write().await;
        component_health.insert(name.clone(), ComponentHealth::new(name.clone()));

        tracing::info!("Registered health check: {}", name.clone());
        Ok(())
    }

    /// Unregister a health check
    pub async fn unregister_check(&self, name: &str) -> Result<()> {
        let mut health_checks = self.health_checks.write().await;
        health_checks.remove(name).ok_or_else(|| {
            FortressError::validation(format!("Health check '{}' not found", name), None, None)
        })?;

        let mut component_health = self.component_health.write().await;
        component_health.remove(name);

        tracing::info!("Unregistered health check: {}", name);
        Ok(())
    }

    /// Perform health check for a specific component
    pub async fn check_component(&self, name: &str) -> Result<HealthCheckResult> {
        let health_checks = self.health_checks.read().await;

        let check = health_checks.get(name).ok_or_else(|| {
            FortressError::validation(format!("Health check '{}' not found", name), None, None)
        })?;

        let start_time = Instant::now();
        let result = tokio::time::timeout(
            Duration::from_secs(check.config().timeout_seconds),
            check.check(),
        )
        .await;

        let response_time_ms = start_time.elapsed().as_millis() as u64;

        let result = match result {
            Ok(result) => result,
            Err(e) => HealthCheckResult::unhealthy(response_time_ms, e.to_string()),
        };

        // Update component health
        self.update_component_health(name, &result).await;

        Ok(result)
    }

    /// Perform health checks for all components
    pub async fn check_all_components(&self) -> Result<HashMap<String, HealthCheckResult>> {
        let health_checks = self.health_checks.read().await;
        let mut results = HashMap::new();

        for name in health_checks.keys() {
            match self.check_component(name).await {
                Ok(result) => {
                    results.insert(name.clone(), result);
                }
                Err(e) => {
                    tracing::error!("Health check failed for {}: {}", name, e);
                    results.insert(name.clone(), HealthCheckResult::unhealthy(0, e.to_string()));
                }
            }
        }

        // Update overall health
        self.update_overall_health(&results).await;

        Ok(results)
    }

    /// Get component health
    pub async fn get_component_health(&self, name: &str) -> Result<Option<ComponentHealth>> {
        let component_health = self.component_health.read().await;
        Ok(component_health.get(name).cloned())
    }

    /// Get overall health
    pub async fn get_overall_health(&self) -> OverallHealth {
        let overall_health = self.overall_health.read().await;
        overall_health.clone()
    }

    /// Get all component health
    pub async fn get_all_component_health(&self) -> HashMap<String, ComponentHealth> {
        let component_health = self.component_health.read().await;
        component_health.clone()
    }

    /// Start the health checker
    pub async fn start(&self) -> Result<()> {
        if !self.config.enabled {
            return Ok(());
        }

        // Start background health check task
        self.start_health_check_task().await;

        tracing::info!("Health checker started");
        Ok(())
    }

    /// Shutdown the health checker
    pub async fn shutdown(&self) -> Result<()> {
        if self.config.enabled {
            tracing::info!("Health checker shutdown");
        }
        Ok(())
    }

    /// Update component health based on check result
    async fn update_component_health(&self, name: &str, result: &HealthCheckResult) {
        let mut component_health = self.component_health.write().await;

        if let Some(component) = component_health.get_mut(name) {
            component.last_check = chrono::Utc::now();
            component.response_time_ms = Some(result.response_time_ms);
            component.metrics = result.metrics.clone();
            component.details = result.details.clone();

            match result.status {
                HealthStatus::Healthy => {
                    component.status = HealthStatus::Healthy;
                    component.last_success = Some(chrono::Utc::now());
                    component.consecutive_failures = 0;
                    component.last_error = None;
                }
                HealthStatus::Warning => {
                    component.status = HealthStatus::Warning;
                    component.consecutive_failures = 0;
                    component.last_error = result.error.clone();
                }
                HealthStatus::Unhealthy => {
                    component.consecutive_failures += 1;
                    component.last_error = result.error.clone();

                    // Check if we should mark as unhealthy
                    let health_checks = self.health_checks.read().await;
                    if let Some(check) = health_checks.get(name) {
                        if component.consecutive_failures >= check.config().failure_threshold {
                            component.status = HealthStatus::Unhealthy;
                        }
                    }
                }
                HealthStatus::Unknown => {
                    component.status = HealthStatus::Unknown;
                    component.last_error = result.error.clone();
                }
            }

            component.total_checks += 1;
        }
    }

    /// Update overall health based on component results
    async fn update_overall_health(&self, results: &HashMap<String, HealthCheckResult>) {
        let component_health = self.component_health.read().await;
        let mut overall = OverallHealth {
            status: HealthStatus::Healthy,
            total_components: results.len(),
            healthy_components: 0,
            warning_components: 0,
            unhealthy_components: 0,
            unknown_components: 0,
            uptime_percentage: self.calculate_uptime_percentage().await,
            last_check: chrono::Utc::now(),
            components: component_health.clone(),
        };

        for result in results.values() {
            match result.status {
                HealthStatus::Healthy => overall.healthy_components += 1,
                HealthStatus::Warning => overall.warning_components += 1,
                HealthStatus::Unhealthy => overall.unhealthy_components += 1,
                HealthStatus::Unknown => overall.unknown_components += 1,
            }
        }

        // Determine overall status
        overall.status = if overall.unhealthy_components > 0 {
            HealthStatus::Unhealthy
        } else if overall.warning_components > 0 {
            HealthStatus::Warning
        } else if overall.unknown_components > 0 {
            HealthStatus::Unknown
        } else {
            HealthStatus::Healthy
        };

        let mut overall_health = self.overall_health.write().await;
        *overall_health = overall;
    }

    /// Calculate uptime percentage
    async fn calculate_uptime_percentage(&self) -> f64 {
        let component_health = self.component_health.read().await;

        if component_health.is_empty() {
            return 100.0;
        }

        let total_checks: u32 = component_health.values().map(|c| c.total_checks).sum();
        let successful_checks: u32 = component_health
            .values()
            .map(|c| c.total_checks - c.consecutive_failures)
            .sum();

        if total_checks == 0 {
            100.0
        } else {
            (successful_checks as f64 / total_checks as f64) * 100.0
        }
    }

    /// Start background health check task
    async fn start_health_check_task(&self) {
        let health_checker = self.clone();
        let interval = Duration::from_secs(self.config.check_interval_seconds);

        tokio::spawn(async move {
            let mut timer = tokio::time::interval(interval);

            loop {
                timer.tick().await;

                if let Err(e) = health_checker.check_all_components().await {
                    tracing::error!("Health check failed: {}", e);
                }
            }
        });
    }
}

impl Clone for HealthChecker {
    fn clone(&self) -> Self {
        Self {
            config: self.config.clone(),
            health_checks: self.health_checks.clone(),
            component_health: self.component_health.clone(),
            overall_health: self.overall_health.clone(),
            start_time: self.start_time,
        }
    }
}

impl Default for OverallHealth {
    fn default() -> Self {
        Self {
            status: HealthStatus::Unknown,
            total_components: 0,
            healthy_components: 0,
            warning_components: 0,
            unhealthy_components: 0,
            unknown_components: 0,
            uptime_percentage: 0.0,
            last_check: chrono::Utc::now(),
            components: HashMap::new(),
        }
    }
}

impl ComponentHealth {
    /// Create a new component health
    pub fn new(name: String) -> Self {
        Self {
            name,
            status: HealthStatus::Unknown,
            last_check: chrono::Utc::now(),
            last_success: None,
            last_error: None,
            consecutive_failures: 0,
            total_checks: 0,
            response_time_ms: None,
            metrics: HashMap::new(),
            details: HashMap::new(),
        }
    }

    /// Check if component is healthy
    pub fn is_healthy(&self) -> bool {
        self.status == HealthStatus::Healthy
    }

    /// Check if component has warnings
    pub fn has_warnings(&self) -> bool {
        self.status == HealthStatus::Warning
    }

    /// Check if component is unhealthy
    pub fn is_unhealthy(&self) -> bool {
        self.status == HealthStatus::Unhealthy
    }

    /// Get uptime percentage for this component
    pub fn uptime_percentage(&self) -> f64 {
        if self.total_checks == 0 {
            0.0
        } else {
            ((self.total_checks - self.consecutive_failures) as f64 / self.total_checks as f64)
                * 100.0
        }
    }
}

/// Database health check implementation
pub struct DatabaseHealthCheck {
    name: String,
    config: ComponentHealthConfig,
    // Database connection would be injected here
}

impl DatabaseHealthCheck {
    pub fn new(name: String, config: ComponentHealthConfig) -> Self {
        Self { name, config }
    }
}

#[async_trait::async_trait]
impl HealthCheck for DatabaseHealthCheck {
    fn name(&self) -> &str {
        &self.name
    }

    async fn check(&self) -> HealthCheckResult {
        let start_time = Instant::now();

        // Simulate database health check
        // In a real implementation, this would query the database
        tokio::time::sleep(Duration::from_millis(50)).await;

        let response_time = start_time.elapsed().as_millis() as u64;

        // Simulate occasional failures
        if rand::random::<f32>() < 0.05 {
            return HealthCheckResult::unhealthy(
                response_time,
                "Database connection failed".to_string(),
            );
        }

        let mut metrics = HashMap::new();
        metrics.insert("connection_pool_size".to_string(), 10.0);
        metrics.insert("active_connections".to_string(), 3.0);

        HealthCheckResult::healthy(response_time)
    }

    fn config(&self) -> &ComponentHealthConfig {
        &self.config
    }
}

/// Memory health check implementation
pub struct MemoryHealthCheck {
    name: String,
    config: ComponentHealthConfig,
}

impl MemoryHealthCheck {
    pub fn new(name: String, config: ComponentHealthConfig) -> Self {
        Self { name, config }
    }
}

#[async_trait::async_trait]
impl HealthCheck for MemoryHealthCheck {
    fn name(&self) -> &str {
        &self.name
    }

    async fn check(&self) -> HealthCheckResult {
        let start_time = Instant::now();

        // Get memory usage
        let memory_usage = self.get_memory_usage().await;
        let response_time = start_time.elapsed().as_millis() as u64;

        let threshold = self
            .config
            .thresholds
            .get("max_usage_percent")
            .unwrap_or(&80.0);

        let mut metrics = HashMap::new();
        metrics.insert("usage_percent".to_string(), memory_usage);

        if memory_usage > *threshold {
            HealthCheckResult::warning(
                response_time,
                format!("High memory usage: {:.1}%", memory_usage),
            )
        } else {
            HealthCheckResult::healthy(response_time)
        }
    }

    fn config(&self) -> &ComponentHealthConfig {
        &self.config
    }
}

impl MemoryHealthCheck {
    async fn get_memory_usage(&self) -> f64 {
        // Simulate memory usage check
        // In a real implementation, this would use system APIs
        rand::random::<f64>() * 100.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_health_checker_creation() {
        let config = HealthConfig::default();
        let checker = HealthChecker::new(config);
        assert_eq!(checker.config.check_interval_seconds, 30);
    }

    #[tokio::test]
    async fn test_component_health() {
        let health = ComponentHealth::new("test".to_string());
        assert_eq!(health.name, "test");
        assert_eq!(health.status, HealthStatus::Unknown);
        assert_eq!(health.uptime_percentage(), 0.0);
    }

    #[tokio::test]
    async fn test_database_health_check() {
        let config = ComponentHealthConfig::default();
        let check = DatabaseHealthCheck::new("database".to_string(), config);

        let result = check.check().await;
        assert!(matches!(
            result.status,
            HealthStatus::Healthy | HealthStatus::Unhealthy
        ));
        assert!(result.response_time_ms > 0);
    }

    #[tokio::test]
    async fn test_register_health_check() {
        let config = HealthConfig::default();
        let checker = HealthChecker::new(config);

        let db_config = ComponentHealthConfig::default();
        let db_check = DatabaseHealthCheck::new("database".to_string(), db_config);

        checker.register_check(Box::new(db_check)).await.unwrap();

        let result = checker.check_component("database").await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_overall_health() {
        let config = HealthConfig::default();
        let checker = HealthChecker::new(config);

        let overall = checker.get_overall_health().await;
        assert_eq!(overall.status, HealthStatus::Unknown);
        assert_eq!(overall.total_components, 0);
    }
}
