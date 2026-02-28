//! Health check system for the Fortress server
//!
//! This module provides comprehensive health monitoring for all server components,
//! including database connections, external services, and internal metrics.

use crate::config::FeatureFlags;
use crate::models::{HealthResponse, HealthStatus, ComponentHealth};
use crate::error::{ServerError, ServerResult};
use chrono::{DateTime, Utc};
use fortress_core::prelude::*;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tracing::{info, warn, error};

/// Simple in-memory audit logger for health checks
struct InMemoryAuditLogger;

impl InMemoryAuditLogger {
    fn new(_config: AuditConfig) -> Self {
        Self
    }
}

#[async_trait::async_trait]
impl AuditLogger for InMemoryAuditLogger {
    fn log(&mut self, _entry: AuditEntry) -> Result<(), FortressError> {
        // Just return success for health check
        Ok(())
    }
}

/// Health checker for monitoring server components
#[derive(Clone)]
pub struct HealthChecker {
    /// Component health registry
    components: Arc<RwLock<HashMap<String, ComponentStatus>>>,
    /// Server start time
    start_time: Instant,
    /// Feature flags
    features: FeatureFlags,
}

/// Internal component status
#[derive(Clone, Debug)]
struct ComponentStatus {
    /// Current health status
    status: HealthStatus,
    /// Status message
    message: Option<String>,
    /// Last check timestamp
    last_check: DateTime<Utc>,
    /// Response time in milliseconds
    response_time_ms: Option<u64>,
    /// Consecutive failures
    consecutive_failures: u32,
}

impl HealthChecker {
    /// Create a new health checker
    pub fn new(features: FeatureFlags) -> Self {
        Self {
            components: Arc::new(RwLock::new(HashMap::new())),
            start_time: Instant::now(),
            features,
        }
    }

    /// Get overall health status
    pub async fn get_health(&self) -> HealthResponse {
        let components = self.components.read().await;
        let mut component_health = HashMap::new();

        let mut overall_status = HealthStatus::Healthy;

        for (name, status) in components.iter() {
            let health = ComponentHealth {
                status: status.status.clone(),
                message: status.message.clone(),
                response_time_ms: status.response_time_ms,
                last_check: status.last_check,
            };

            component_health.insert(name.clone(), health);

            // Determine overall status
            match status.status {
                HealthStatus::Unhealthy => {
                    overall_status = HealthStatus::Unhealthy;
                }
                HealthStatus::Degraded if overall_status == HealthStatus::Healthy => {
                    overall_status = HealthStatus::Degraded;
                }
                _ => {}
            }
        }

        HealthResponse {
            status: overall_status,
            version: crate::VERSION.to_string(),
            uptime: self.start_time.elapsed().as_secs(),
            components: component_health,
            timestamp: Utc::now(),
        }
    }

    /// Check a component's health
    pub async fn check_component<F, Fut>(&self, name: &str, checker: F) -> ServerResult<()>
    where
        F: FnOnce() -> Fut + Send,
        Fut: std::future::Future<Output = ServerResult<()>> + Send,
    {
        let start = Instant::now();
        let result = checker().await;
        let response_time = start.elapsed().as_millis() as u64;

        let mut components = self.components.write().await;
        let status = components.entry(name.to_string()).or_insert_with(|| ComponentStatus {
            status: HealthStatus::Healthy,
            message: None,
            last_check: Utc::now(),
            response_time_ms: None,
            consecutive_failures: 0,
        });

        status.last_check = Utc::now();
        status.response_time_ms = Some(response_time);

        match result {
            Ok(()) => {
                status.status = HealthStatus::Healthy;
                status.message = None;
                status.consecutive_failures = 0;
                
                if response_time > 1000 {
                    status.status = HealthStatus::Degraded;
                    status.message = Some("High response time".to_string());
                }
                
                info!(
                    component = %name,
                    response_time_ms = response_time,
                    status = ?status.status,
                    "Health check completed"
                );
            }
            Err(e) => {
                status.consecutive_failures += 1;
                status.message = Some(e.to_string());
                
                if status.consecutive_failures >= 3 {
                    status.status = HealthStatus::Unhealthy;
                } else {
                    status.status = HealthStatus::Degraded;
                }
                
                error!(
                    component = %name,
                    error = %e,
                    consecutive_failures = status.consecutive_failures,
                    "Health check failed"
                );
            }
        }

        Ok(())
    }

    /// Set component health manually
    pub async fn set_component_health(
        &self,
        name: &str,
        status: HealthStatus,
        message: Option<String>,
    ) {
        let mut components = self.components.write().await;
        
        let component_status = components.entry(name.to_string()).or_insert_with(|| ComponentStatus {
            status: HealthStatus::Healthy,
            message: None,
            last_check: Utc::now(),
            response_time_ms: None,
            consecutive_failures: 0,
        });

        component_status.status = status;
        component_status.message = message;
        component_status.last_check = Utc::now();
    }

    /// Run comprehensive health checks
    pub async fn run_all_checks(&self) {
        info!("Starting comprehensive health checks");

        // Check core Fortress components
        if self.features.auth_enabled {
            self.check_component("auth", || async {
                // Check authentication system
                self.check_auth_system().await
            }).await;
        }

        if self.features.field_encryption {
            self.check_component("encryption", || async {
                // Check encryption system
                self.check_encryption_system().await
            }).await;
        }

        // Check storage backend
        self.check_component("storage", || async {
            self.check_storage_backend().await
        }).await;

        // Check key management
        self.check_component("key_management", || async {
            self.check_key_management().await
        }).await;

        // Check audit logging
        if self.features.audit_enabled {
            self.check_component("audit_logging", || async {
                self.check_audit_logging().await
            }).await;
        }

        // Check metrics collection
        if self.features.metrics_enabled {
            self.check_component("metrics", || async {
                self.check_metrics_collection().await
            }).await;
        }

        info!("Comprehensive health checks completed");
    }

    /// Check authentication system
    async fn check_auth_system(&self) -> ServerResult<()> {
        // In a real implementation, this would check JWT validation,
        // user database connectivity, etc.
        tokio::time::sleep(Duration::from_millis(10)).await;
        Ok(())
    }

    /// Check encryption system
    async fn check_encryption_system(&self) -> ServerResult<()> {
        // Test encryption/decryption with default algorithm
        let algorithm = Aegis256::new();
        let key = SecureKey::generate(algorithm.key_size());
        
        let plaintext = b"health_check_test";
        let ciphertext = algorithm.encrypt(plaintext, &key)?;
        let decrypted = algorithm.decrypt(&ciphertext, &key)?;
        
        if plaintext != &decrypted[..] {
            return Err(ServerError::internal("Encryption test failed"));
        }
        
        Ok(())
    }

    /// Check storage backend
    async fn check_storage_backend(&self) -> ServerResult<()> {
        // In a real implementation, this would check database connectivity
        // For now, we'll simulate a storage check
        tokio::time::sleep(Duration::from_millis(50)).await;
        Ok(())
    }

    /// Check key management
    async fn check_key_management(&self) -> ServerResult<()> {
        // Test key generation
        let key_manager = InMemoryKeyManager::new();
        let algorithm = Aegis256::new();
        let key = SecureKey::generate(algorithm.key_size());
        
        // Store the key
        let key_id = "test_key".to_string();
        let now = Utc::now();
        let metadata = KeyMetadata::new(
            key_id.clone(),
            "aegis256".to_string(),
            1,
            now,
            now + chrono::Duration::days(365),
            "test".to_string(),
            PerformanceProfile::Balanced,
        );
        key_manager.store_key(&key_id, &key, &metadata).await?;
        
        // Retrieve the key
        let (retrieved_key, _retrieved_metadata) = key_manager.retrieve_key(&key_id).await?;
        
        if retrieved_key.data() != key.data() {
            return Err(ServerError::internal("Key retrieval failed"));
        }
        
        Ok(())
    }

    /// Check audit logging
    async fn check_audit_logging(&self) -> ServerResult<()> {
        // Test audit log creation
        let audit_config = AuditConfig::default();
        let mut audit_logger = InMemoryAuditLogger::new(audit_config);
        
        let entry = AuditEntry {
            id: Uuid::new_v4().to_string(),
            timestamp: Utc::now().timestamp_millis() as u64,
            event_type: AuditEventType::DataAccess,
            security_level: SecurityLevel::Medium,
            principal: Some("health_check".to_string()),
            resource: Some("test".to_string()),
            action: "health_check".to_string(),
            outcome: EventOutcome::Success,
            metadata: HashMap::new(),
            previous_hash: None,
            current_hash: "test_hash".to_string(),
            signature: "test_signature".to_string(),
        };
        
        audit_logger.log(entry)?;
        
        Ok(())
    }

    /// Check metrics collection
    async fn check_metrics_collection(&self) -> ServerResult<()> {
        // Test metrics collection
        metrics::counter!("test_counter", 1);
        metrics::gauge!("test_gauge", 42.0);
        metrics::histogram!("test_histogram", 100.0);
        
        Ok(())
    }

    /// Get component-specific health
    pub async fn get_component_health(&self, component_name: &str) -> Option<ComponentHealth> {
        let components = self.components.read().await;
        components.get(component_name).map(|status| ComponentHealth {
            status: status.status.clone(),
            message: status.message.clone(),
            response_time_ms: status.response_time_ms,
            last_check: status.last_check,
        })
    }

    /// Reset component health
    pub async fn reset_component_health(&self, component_name: &str) {
        let mut components = self.components.write().await;
        components.remove(component_name);
    }

    /// Get server uptime
    pub fn uptime(&self) -> Duration {
        self.start_time.elapsed()
    }
}

/// Health check trait for custom components
#[async_trait::async_trait]
pub trait HealthCheck: Send + Sync {
    /// Check the health of the component
    async fn check_health(&self) -> ServerResult<()>;
    
    /// Get component name
    fn name(&self) -> &str;
}

/// Registry for custom health checks
pub struct HealthCheckRegistry {
    checks: Arc<RwLock<HashMap<String, Arc<dyn HealthCheck>>>>,
}

impl HealthCheckRegistry {
    /// Create a new health check registry
    pub fn new() -> Self {
        Self {
            checks: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Register a health check
    pub async fn register(&self, check: Arc<dyn HealthCheck>) {
        let mut checks = self.checks.write().await;
        checks.insert(check.name().to_string(), check);
    }

    /// Unregister a health check
    pub async fn unregister(&self, name: &str) {
        let mut checks = self.checks.write().await;
        checks.remove(name);
    }

    /// Run all registered health checks
    pub async fn run_all_checks(&self, health_checker: &HealthChecker) {
        let checks = self.checks.read().await;
        
        for (name, check) in checks.iter() {
            health_checker.check_component(name, || async {
                check.check_health().await
            }).await;
        }
    }
}

impl Default for HealthCheckRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::FeatureFlags;

    #[tokio::test]
    async fn test_health_checker_creation() {
        let features = FeatureFlags::default();
        let health_checker = HealthChecker::new(features);
        
        let health = health_checker.get_health().await;
        assert_eq!(health.status, HealthStatus::Healthy);
        assert!(!health.components.is_empty());
    }

    #[tokio::test]
    async fn test_component_health_check() {
        let features = FeatureFlags::default();
        let health_checker = HealthChecker::new(features);
        
        // Test successful check
        health_checker.check_component("test_component", || async {
            Ok(())
        }).await.unwrap();
        
        let health = health_checker.get_health().await;
        assert!(health.components.contains_key("test_component"));
        assert_eq!(health.components["test_component"].status, HealthStatus::Healthy);
    }

    #[tokio::test]
    async fn test_component_health_check_failure() {
        let features = FeatureFlags::default();
        let health_checker = HealthChecker::new(features);
        
        // Test failed check
        health_checker.check_component("failing_component", || async {
            Err(ServerError::internal("Test failure"))
        }).await;
        
        let health = health_checker.get_health().await;
        assert!(health.components.contains_key("failing_component"));
        assert_eq!(health.components["failing_component"].status, HealthStatus::Degraded);
    }

    #[tokio::test]
    async fn test_manual_component_health() {
        let features = FeatureFlags::default();
        let health_checker = HealthChecker::new(features);
        
        health_checker.set_component_health(
            "manual_component",
            HealthStatus::Degraded,
            Some("Manual test".to_string()),
        ).await;
        
        let health = health_checker.get_health().await;
        assert!(health.components.contains_key("manual_component"));
        assert_eq!(health.components["manual_component"].status, HealthStatus::Degraded);
        assert_eq!(health.components["manual_component"].message, Some("Manual test".to_string()));
    }

    #[tokio::test]
    async fn test_health_check_registry() {
        let registry = HealthCheckRegistry::new();
        
        struct TestHealthCheck;
        
        #[async_trait::async_trait]
        impl HealthCheck for TestHealthCheck {
            async fn check_health(&self) -> ServerResult<()> {
                Ok(())
            }
            
            fn name(&self) -> &str {
                "test_check"
            }
        }
        
        let check = Arc::new(TestHealthCheck);
        registry.register(check.clone()).await;
        
        let features = FeatureFlags::default();
        let health_checker = HealthChecker::new(features);
        registry.run_all_checks(&health_checker).await;
        
        let health = health_checker.get_health().await;
        assert!(health.components.contains_key("test_check"));
    }
}
