//! Security Monitoring and Alerting System
//! 
//! Provides real-time security metrics collection, analysis, and alerting.
//! This module monitors security events, detects threats, and triggers alerts
//! for anomalous activity.

use crate::error::FortressError;
use crate::security_audit::{SecurityAuditEvent, SecurityEventType, SecurityEventResult};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use tokio::sync::{Mutex, RwLock};
use tokio::time::interval;

#[cfg(feature = "performance-optimization")]
use dashmap::DashMap;
#[cfg(feature = "performance-optimization")]
use parking_lot::{RwLock as ParkingLotRwLock, Mutex as ParkingLotMutex};
#[cfg(feature = "performance-optimization")]
use crossbeam::queue::SegQueue;

/// Security alert severity levels
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AlertSeverity {
    Low,
    Medium,
    High,
    Critical,
}

/// Security alert types
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum AlertType {
    BruteForceAttack,
    SuspiciousActivity,
    UnauthorizedAccess,
    DataBreach,
    SystemCompromise,
    PolicyViolation,
    AnomalousBehavior,
    PerformanceIssue,
}

/// Security alert
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityAlert {
    /// Alert ID
    pub id: String,
    /// Alert timestamp
    pub timestamp: DateTime<Utc>,
    /// Alert severity
    pub severity: AlertSeverity,
    /// Alert type
    pub alert_type: AlertType,
    /// Alert title
    pub title: String,
    /// Alert description
    pub description: String,
    /// Source IP address
    pub source_ip: Option<String>,
    /// User ID (if applicable)
    pub user_id: Option<String>,
    /// Resource involved
    pub resource: Option<String>,
    /// Alert metadata
    pub metadata: HashMap<String, String>,
    /// Alert status
    pub status: AlertStatus,
    /// Events that triggered this alert
    pub related_events: Vec<String>,
}

/// Alert status
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum AlertStatus {
    Active,
    Acknowledged,
    Resolved,
    Suppressed,
}

/// Security metrics
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SecurityMetrics {
    /// Total authentication attempts
    pub authentication_attempts: u64,
    /// Failed authentication attempts
    pub failed_authentications: u64,
    /// Total authorization checks
    pub authorization_checks: u64,
    /// Failed authorization checks
    pub failed_authorizations: u64,
    /// Suspicious activities detected
    pub suspicious_activities: u64,
    /// Blocked requests
    pub blocked_requests: u64,
    /// Data access events
    pub data_access_events: u64,
    /// Configuration changes
    pub configuration_changes: u64,
    /// Security policy violations
    pub policy_violations: u64,
    /// Threat detections
    pub threat_detections: u64,
    /// Active alerts by severity
    pub active_alerts: HashMap<AlertSeverity, u64>,
    /// Average response time
    pub avg_response_time_ms: f64,
    /// Peak concurrent requests
    pub peak_concurrent_requests: u32,
    /// Current concurrent requests
    pub current_concurrent_requests: u32,
}

/// Anomaly detection configuration
#[derive(Debug, Clone)]
pub struct AnomalyDetectionConfig {
    /// Enable anomaly detection
    pub enabled: bool,
    /// Failed authentication threshold per minute
    pub failed_auth_threshold_per_minute: u32,
    /// Failed authorization threshold per minute
    pub failed_authz_threshold_per_minute: u32,
    /// Suspicious activity threshold per minute
    pub suspicious_activity_threshold_per_minute: u32,
    /// Concurrent requests threshold
    pub concurrent_requests_threshold: u32,
    /// Response time threshold in milliseconds
    pub response_time_threshold_ms: f64,
    /// Alert cooldown period in minutes
    pub alert_cooldown_minutes: u32,
    /// Enable ML-based behavioral analysis
    pub enable_ml_detection: bool,
    /// ML model confidence threshold
    pub ml_confidence_threshold: f64,
    /// Behavioral pattern window size (hours)
    pub behavior_window_hours: u32,
}

impl Default for AnomalyDetectionConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            failed_auth_threshold_per_minute: 10,
            failed_authz_threshold_per_minute: 20,
            suspicious_activity_threshold_per_minute: 5,
            concurrent_requests_threshold: 1000,
            response_time_threshold_ms: 5000.0,
            alert_cooldown_minutes: 5,
            enable_ml_detection: true,
            ml_confidence_threshold: 0.8,
            behavior_window_hours: 24,
        }
    }
}

/// Security monitoring configuration
#[derive(Debug, Clone)]
pub struct SecurityMonitoringConfig {
    /// Metrics retention period in hours
    pub metrics_retention_hours: u32,
    /// Alert retention period in hours
    pub alert_retention_hours: u32,
    /// Anomaly detection configuration
    pub anomaly_detection: AnomalyDetectionConfig,
    /// Enable real-time monitoring
    pub real_time_monitoring: bool,
    /// Monitoring interval in seconds
    pub monitoring_interval_seconds: u32,
}

impl Default for SecurityMonitoringConfig {
    fn default() -> Self {
        Self {
            metrics_retention_hours: 24,
            alert_retention_hours: 168, // 7 days
            anomaly_detection: AnomalyDetectionConfig::default(),
            real_time_monitoring: true,
            monitoring_interval_seconds: 30,
        }
    }
}

/// Security monitoring system
pub struct SecurityMonitoringSystem {
    /// Current metrics
    #[cfg(not(feature = "performance-optimization"))]
    metrics: Arc<RwLock<SecurityMetrics>>,
    #[cfg(feature = "performance-optimization")]
    metrics: Arc<ParkingLotRwLock<SecurityMetrics>>,
    /// Historical metrics (time series)
    #[cfg(not(feature = "performance-optimization"))]
    historical_metrics: Arc<Mutex<VecDeque<(DateTime<Utc>, SecurityMetrics)>>>,
    #[cfg(feature = "performance-optimization")]
    historical_metrics: Arc<ParkingLotMutex<VecDeque<(DateTime<Utc>, SecurityMetrics)>>>,
    /// Active alerts
    #[cfg(not(feature = "performance-optimization"))]
    active_alerts: Arc<Mutex<Vec<SecurityAlert>>>,
    #[cfg(feature = "performance-optimization")]
    active_alerts: Arc<SegQueue<SecurityAlert>>,
    /// Alert history
    #[cfg(not(feature = "performance-optimization"))]
    alert_history: Arc<Mutex<VecDeque<SecurityAlert>>>,
    #[cfg(feature = "performance-optimization")]
    alert_history: Arc<ParkingLotMutex<VecDeque<SecurityAlert>>>,
    /// Event counters for anomaly detection
    #[cfg(not(feature = "performance-optimization"))]
    event_counters: Arc<Mutex<HashMap<String, VecDeque<DateTime<Utc>>>>>,
    #[cfg(feature = "performance-optimization")]
    event_counters: Arc<DashMap<String, VecDeque<DateTime<Utc>>>>,
    /// Configuration
    config: SecurityMonitoringConfig,
    /// Alert callback
    alert_callback: Option<Box<dyn Fn(SecurityAlert) + Send + Sync>>,
    /// ML-based behavioral patterns
    #[cfg(feature = "performance-optimization")]
    behavior_patterns: Arc<DashMap<String, Vec<f64>>>,
}

impl SecurityMonitoringSystem {
    /// Create new security monitoring system
    pub fn new(config: SecurityMonitoringConfig) -> Self {
        #[cfg(not(feature = "performance-optimization"))]
        {
            Self {
                metrics: Arc::new(RwLock::new(SecurityMetrics::default())),
                historical_metrics: Arc::new(Mutex::new(VecDeque::new())),
                active_alerts: Arc::new(Mutex::new(Vec::new())),
                alert_history: Arc::new(Mutex::new(VecDeque::new())),
                event_counters: Arc::new(Mutex::new(HashMap::new())),
                config,
                alert_callback: None,
            }
        }
        #[cfg(feature = "performance-optimization")]
        {
            Self {
                metrics: Arc::new(ParkingLotRwLock::new(SecurityMetrics::default())),
                historical_metrics: Arc::new(ParkingLotMutex::new(VecDeque::new())),
                active_alerts: Arc::new(SegQueue::new()),
                alert_history: Arc::new(ParkingLotMutex::new(VecDeque::new())),
                event_counters: Arc::new(DashMap::new()),
                config,
                alert_callback: None,
                behavior_patterns: Arc::new(DashMap::new()),
            }
        }
    }

    /// Create with default configuration
    pub fn default() -> Self {
        Self::new(SecurityMonitoringConfig::default())
    }

    /// Set alert callback
    pub fn with_alert_callback<F>(mut self, callback: F) -> Self
    where
        F: Fn(SecurityAlert) + Send + Sync + 'static,
    {
        self.alert_callback = Some(Box::new(callback));
        self
    }

    /// Start monitoring system
    pub async fn start(&self) -> Result<(), FortressError> {
        if !self.config.real_time_monitoring {
            return Ok(());
        }

        let system = self.clone();
        tokio::spawn(async move {
            let mut interval = interval(
                std::time::Duration::from_secs(system.config.monitoring_interval_seconds as u64),
            );

            loop {
                interval.tick().await;
                if let Err(e) = system.perform_monitoring_cycle().await {
                    tracing::error!("Error in monitoring cycle: {}", e);
                }
            }
        });

        tracing::info!("Security monitoring system started");
        Ok(())
    }

    /// Process a security event
    pub async fn process_security_event(&self, event: &SecurityAuditEvent) -> Result<(), FortressError> {
        // Update metrics
        self.update_metrics(event).await?;

        // Check for anomalies
        if self.config.anomaly_detection.enabled {
            self.check_for_anomalies(event).await?;
        }

        // Record event for time series analysis
        self.record_event_for_analysis(event).await;

        Ok(())
    }

    /// Update security metrics
    async fn update_metrics(&self, event: &SecurityAuditEvent) -> Result<(), FortressError> {
        let mut metrics = self.metrics.write().await;

        match event.event_type {
            SecurityEventType::Authentication => {
                metrics.authentication_attempts += 1;
                if event.result == SecurityEventResult::Failure {
                    metrics.failed_authentications += 1;
                }
            }
            SecurityEventType::Authorization => {
                metrics.authorization_checks += 1;
                if event.result == SecurityEventResult::Failure {
                    metrics.failed_authorizations += 1;
                }
            }
            SecurityEventType::DataAccess => {
                metrics.data_access_events += 1;
            }
            SecurityEventType::ConfigurationChange => {
                metrics.configuration_changes += 1;
            }
            SecurityEventType::SecurityPolicyViolation => {
                metrics.policy_violations += 1;
            }
            SecurityEventType::ThreatDetection => {
                metrics.threat_detections += 1;
            }
            _ => {}
        }

        if matches!(event.result, SecurityEventResult::Blocked) {
            metrics.blocked_requests += 1;
        }

        Ok(())
    }

    /// Check for anomalies and trigger alerts
    async fn check_for_anomalies(&self, event: &SecurityAuditEvent) -> Result<(), FortressError> {
        let now = Utc::now();
        let config = &self.config.anomaly_detection;

        // Check for brute force attacks
        if event.event_type == SecurityEventType::Authentication && event.result == SecurityEventResult::Failure {
            if self.is_brute_force_attack(event, &now, config.failed_auth_threshold_per_minute).await? {
                self.create_alert(
                    AlertType::BruteForceAttack,
                    AlertSeverity::High,
                    "Potential brute force attack detected",
                    format!(
                        "Multiple failed authentication attempts from {}",
                        event.ip_address.as_deref().unwrap_or("unknown")
                    ),
                    event,
                ).await?;
            }
        }

        // Check for suspicious activity patterns
        if self.is_suspicious_activity_pattern(&now, config.suspicious_activity_threshold_per_minute).await? {
            self.create_alert(
                AlertType::SuspiciousActivity,
                AlertSeverity::Medium,
                "Suspicious activity pattern detected",
                "Elevated level of suspicious activities detected".to_string(),
                event,
            ).await?;
        }

        // Check for authorization failures
        if event.event_type == SecurityEventType::Authorization && event.result == SecurityEventResult::Failure {
            if self.is_authorization_abuse(event, &now, config.failed_authz_threshold_per_minute).await? {
                self.create_alert(
                    AlertType::UnauthorizedAccess,
                    AlertSeverity::High,
                    "Potential authorization abuse detected",
                    "Multiple failed authorization attempts detected".to_string(),
                    event,
                ).await?;
            }
        }

        Ok(())
    }

    /// Check for brute force attack pattern
    async fn is_brute_force_attack(
        &self,
        event: &SecurityAuditEvent,
        now: &DateTime<Utc>,
        threshold: u32,
    ) -> Result<bool, FortressError> {
        let ip = event.ip_address.clone().unwrap_or_else(|| "unknown".to_string());
        let key = format!("auth_fail_{}", ip);

        let mut counters = self.event_counters.lock().await;
        let events = counters.entry(key).or_insert_with(VecDeque::new);

        // Add current event
        events.push_back(*now);

        // Remove events older than 1 minute
        let one_minute_ago = *now - Duration::minutes(1);
        while let Some(&front_time) = events.front() {
            if front_time < one_minute_ago {
                events.pop_front();
            } else {
                break;
            }
        }

        Ok(events.len() >= threshold as usize)
    }

    /// Check for suspicious activity pattern
    async fn is_suspicious_activity_pattern(
        &self,
        now: &DateTime<Utc>,
        threshold: u32,
    ) -> Result<bool, FortressError> {
        let key = "suspicious_activity".to_string();

        let mut counters = self.event_counters.lock().await;
        let events = counters.entry(key).or_insert_with(VecDeque::new);

        // Add current event
        events.push_back(*now);

        // Remove events older than 1 minute
        let one_minute_ago = *now - Duration::minutes(1);
        while let Some(&front_time) = events.front() {
            if front_time < one_minute_ago {
                events.pop_front();
            } else {
                break;
            }
        }

        Ok(events.len() >= threshold as usize)
    }

    /// Check for authorization abuse
    async fn is_authorization_abuse(
        &self,
        event: &SecurityAuditEvent,
        now: &DateTime<Utc>,
        threshold: u32,
    ) -> Result<bool, FortressError> {
        let ip = event.ip_address.clone().unwrap_or_else(|| "unknown".to_string());
        let key = format!("authz_fail_{}", ip);

        let mut counters = self.event_counters.lock().await;
        let events = counters.entry(key).or_insert_with(VecDeque::new);

        // Add current event
        events.push_back(*now);

        // Remove events older than 1 minute
        let one_minute_ago = *now - Duration::minutes(1);
        while let Some(&front_time) = events.front() {
            if front_time < one_minute_ago {
                events.pop_front();
            } else {
                break;
            }
        }

        Ok(events.len() >= threshold as usize)
    }

    /// Create and trigger an alert
    async fn create_alert(
        &self,
        alert_type: AlertType,
        severity: AlertSeverity,
        title: &str,
        description: String,
        related_event: &SecurityAuditEvent,
    ) -> Result<(), FortressError> {
        // Check cooldown period
        if self.is_alert_in_cooldown(&alert_type, severity.clone()).await? {
            return Ok(());
        }

        let alert = SecurityAlert {
            id: uuid::Uuid::new_v4().to_string(),
            timestamp: Utc::now(),
            severity,
            alert_type,
            title: title.to_string(),
            description,
            source_ip: related_event.ip_address.clone(),
            user_id: related_event.user_id.clone(),
            resource: related_event.resource.clone(),
            metadata: related_event.metadata.clone(),
            status: AlertStatus::Active,
            related_events: vec![related_event.request_id.clone().unwrap_or_default()],
        };

        // Add to active alerts
        let mut active_alerts = self.active_alerts.lock().await;
        active_alerts.push(alert.clone());

        // Add to alert history
        let mut alert_history = self.alert_history.lock().await;
        alert_history.push_back(alert.clone());

        // Trim alert history
        let retention_duration = Duration::hours(self.config.alert_retention_hours as i64);
        let cutoff_time = Utc::now() - retention_duration;
        while let Some(front_alert) = alert_history.front() {
            if front_alert.timestamp < cutoff_time {
                alert_history.pop_front();
            } else {
                break;
            }
        }

        // Trigger alert callback
        if let Some(ref callback) = self.alert_callback {
            callback(alert.clone());
        }

        // Log alert
        tracing::warn!(
            target: "security_alert",
            alert_id = %alert.id,
            alert_type = ?alert.alert_type,
            severity = ?alert.severity,
            title = %alert.title,
            "Security alert triggered"
        );

        Ok(())
    }

    /// Check if alert is in cooldown period
    async fn is_alert_in_cooldown(&self, alert_type: &AlertType, severity: AlertSeverity) -> Result<bool, FortressError> {
        let active_alerts = self.active_alerts.lock().await;
        let cooldown_duration = Duration::minutes(self.config.anomaly_detection.alert_cooldown_minutes as i64);
        let cutoff_time = Utc::now() - cooldown_duration;

        for alert in active_alerts.iter() {
            if alert.alert_type == *alert_type
                && alert.severity == severity
                && alert.timestamp > cutoff_time
                && alert.status == AlertStatus::Active
            {
                return Ok(true);
            }
        }

        Ok(false)
    }

    /// Record event for time series analysis
    async fn record_event_for_analysis(&self, _event: &SecurityAuditEvent) {
        // This would be used for more sophisticated analysis
        // For now, we just track basic event patterns
    }

    /// Perform monitoring cycle
    async fn perform_monitoring_cycle(&self) -> Result<(), FortressError> {
        // Update historical metrics
        self.update_historical_metrics().await?;

        // Clean up old data
        self.cleanup_old_data().await?;

        // Check system health
        self.check_system_health().await?;

        Ok(())
    }

    /// Update historical metrics
    async fn update_historical_metrics(&self) -> Result<(), FortressError> {
        let metrics = self.metrics.read().await.clone();
        let mut historical = self.historical_metrics.lock().await;

        historical.push_back((Utc::now(), metrics));

        // Trim historical data
        let retention_duration = Duration::hours(self.config.metrics_retention_hours as i64);
        let cutoff_time = Utc::now() - retention_duration;

        while let Some(&(timestamp, _)) = historical.front() {
            if timestamp < cutoff_time {
                historical.pop_front();
            } else {
                break;
            }
        }

        Ok(())
    }

    /// Clean up old data
    async fn cleanup_old_data(&self) -> Result<(), FortressError> {
        let mut counters = self.event_counters.lock().await;
        let cutoff_time = Utc::now() - Duration::minutes(5); // Keep 5 minutes of data

        for events in counters.values_mut() {
            while let Some(&front_time) = events.front() {
                if front_time < cutoff_time {
                    events.pop_front();
                } else {
                    break;
                }
            }
        }

        Ok(())
    }

    /// Check system health
    async fn check_system_health(&self) -> Result<(), FortressError> {
        let metrics = self.metrics.read().await;

        // Check for performance issues
        if metrics.avg_response_time_ms > self.config.anomaly_detection.response_time_threshold_ms {
            self.create_alert(
                AlertType::PerformanceIssue,
                AlertSeverity::Medium,
                "High response time detected",
                format!(
                    "Average response time is {:.2}ms, exceeding threshold of {:.2}ms",
                    metrics.avg_response_time_ms,
                    self.config.anomaly_detection.response_time_threshold_ms
                ),
                &SecurityAuditEvent::new(
                    SecurityEventType::SystemEvent,
                    "performance_check".to_string(),
                    SecurityEventResult::Warning,
                ),
            ).await?;
        }

        Ok(())
    }

    /// Get current metrics
    pub async fn get_metrics(&self) -> SecurityMetrics {
        self.metrics.read().await.clone()
    }

    /// Get active alerts
    pub async fn get_active_alerts(&self) -> Vec<SecurityAlert> {
        self.active_alerts.lock().await.clone()
    }

    /// Get alert history
    pub async fn get_alert_history(&self, limit: Option<usize>) -> Vec<SecurityAlert> {
        let history = self.alert_history.lock().await;
        if let Some(limit) = limit {
            history.iter().rev().take(limit).cloned().collect()
        } else {
            history.iter().rev().cloned().collect()
        }
    }

    /// Acknowledge an alert
    pub async fn acknowledge_alert(&self, alert_id: &str) -> Result<(), FortressError> {
        let mut active_alerts = self.active_alerts.lock().await;
        
        for alert in active_alerts.iter_mut() {
            if alert.id == alert_id {
                alert.status = AlertStatus::Acknowledged;
                tracing::info!(target: "security_alert", alert_id = %alert_id, "Alert acknowledged");
                return Ok(());
            }
        }

        Err(FortressError::validation("Alert not found", None, None))
    }

    /// Resolve an alert
    pub async fn resolve_alert(&self, alert_id: &str) -> Result<(), FortressError> {
        let mut active_alerts = self.active_alerts.lock().await;
        
        for i in 0..active_alerts.len() {
            if active_alerts[i].id == alert_id {
                let mut alert = active_alerts.remove(i);
                alert.status = AlertStatus::Resolved;
                
                // Add to history
                let mut history = self.alert_history.lock().await;
                history.push_back(alert);
                
                tracing::info!(target: "security_alert", alert_id = %alert_id, "Alert resolved");
                return Ok(());
            }
        }

        Err(FortressError::validation("Alert not found", None, None))
    }

    /// Update performance metrics
    pub async fn update_performance_metrics(&self, response_time_ms: f64, concurrent_requests: u32) {
        let mut metrics = self.metrics.write().await;
        
        // Update average response time (simple moving average)
        metrics.avg_response_time_ms = (metrics.avg_response_time_ms + response_time_ms) / 2.0;
        
        // Update concurrent requests
        metrics.current_concurrent_requests = concurrent_requests;
        if concurrent_requests > metrics.peak_concurrent_requests {
            metrics.peak_concurrent_requests = concurrent_requests;
        }
    }

    /// Get security dashboard data
    pub async fn get_dashboard_data(&self) -> SecurityDashboard {
        let metrics = self.get_metrics().await;
        let active_alerts = self.get_active_alerts().await;
        let recent_alerts = self.get_alert_history(Some(10)).await;

        SecurityDashboard {
            metrics: metrics.clone(),
            active_alerts_count: active_alerts.len() as u32,
            active_alerts_by_severity: self.count_alerts_by_severity(&active_alerts),
            recent_alerts,
            system_health: self.calculate_system_health(&metrics).await,
        }
    }

    /// Count alerts by severity
    fn count_alerts_by_severity(&self, alerts: &[SecurityAlert]) -> HashMap<AlertSeverity, u64> {
        let mut counts = HashMap::new();
        for alert in alerts {
            *counts.entry(alert.severity.clone()).or_insert(0) += 1;
        }
        counts
    }

    /// Calculate system health score
    async fn calculate_system_health(&self, metrics: &SecurityMetrics) -> SystemHealth {
        let mut score = 100.0;

        // Deduct for failed authentications
        if metrics.authentication_attempts > 0 {
            let fail_rate = metrics.failed_authentications as f64 / metrics.authentication_attempts as f64;
            score -= fail_rate * 20.0;
        }

        // Deduct for failed authorizations
        if metrics.authorization_checks > 0 {
            let fail_rate = metrics.failed_authorizations as f64 / metrics.authorization_checks as f64;
            score -= fail_rate * 15.0;
        }

        // Deduct for suspicious activities
        score -= (metrics.suspicious_activities as f64 / 10.0).min(20.0);

        // Deduct for policy violations
        score -= (metrics.policy_violations as f64 / 5.0).min(15.0);

        // Deduct for performance issues
        if metrics.avg_response_time_ms > 1000.0 {
            score -= (metrics.avg_response_time_ms - 1000.0) / 100.0;
        }

        score = score.max(0.0).min(100.0);

        let status = match score {
            90.0..=100.0 => HealthStatus::Excellent,
            75.0..=89.9 => HealthStatus::Good,
            60.0..=74.9 => HealthStatus::Fair,
            40.0..=59.9 => HealthStatus::Poor,
            0.0..=39.9 => HealthStatus::Critical,
            _ => HealthStatus::Poor, // Default for unexpected values
        };

        SystemHealth {
            score,
            status,
            issues: self.identify_health_issues(metrics).await,
        }
    }

    /// Identify health issues
    async fn identify_health_issues(&self, metrics: &SecurityMetrics) -> Vec<String> {
        let mut issues = Vec::new();

        if metrics.failed_authentications > 10 {
            issues.push("High number of failed authentications".to_string());
        }

        if metrics.failed_authorizations > 20 {
            issues.push("High number of failed authorizations".to_string());
        }

        if metrics.suspicious_activities > 5 {
            issues.push("Suspicious activities detected".to_string());
        }

        if metrics.policy_violations > 3 {
            issues.push("Security policy violations".to_string());
        }

        if metrics.avg_response_time_ms > 2000.0 {
            issues.push("High response times".to_string());
        }

        issues
    }
}

impl Clone for SecurityMonitoringSystem {
    fn clone(&self) -> Self {
        Self {
            metrics: self.metrics.clone(),
            historical_metrics: self.historical_metrics.clone(),
            active_alerts: self.active_alerts.clone(),
            alert_history: self.alert_history.clone(),
            event_counters: self.event_counters.clone(),
            config: self.config.clone(),
            alert_callback: None, // Callbacks are not cloned
        }
    }
}

/// Security dashboard data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityDashboard {
    pub metrics: SecurityMetrics,
    pub active_alerts_count: u32,
    pub active_alerts_by_severity: HashMap<AlertSeverity, u64>,
    pub recent_alerts: Vec<SecurityAlert>,
    pub system_health: SystemHealth,
}

/// System health information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemHealth {
    pub score: f64,
    pub status: HealthStatus,
    pub issues: Vec<String>,
}

/// Health status
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum HealthStatus {
    Excellent,
    Good,
    Fair,
    Poor,
    Critical,
}

/// Global security monitoring instance
static GLOBAL_MONITORING_SYSTEM: std::sync::OnceLock<Arc<SecurityMonitoringSystem>> = std::sync::OnceLock::new();

/// Initialize global security monitoring system
pub fn init_security_monitoring(config: SecurityMonitoringConfig) -> Result<(), FortressError> {
    let system = Arc::new(SecurityMonitoringSystem::new(config));
    GLOBAL_MONITORING_SYSTEM
        .set(system)
        .map_err(|_| FortressError::configuration(
            "Security monitoring system already initialized".to_string(),
            None,
            crate::error::ConfigurationErrorCode::InvalidFormat,
        ))?;
    Ok(())
}

/// Get global security monitoring system
pub fn get_security_monitoring() -> Option<Arc<SecurityMonitoringSystem>> {
    GLOBAL_MONITORING_SYSTEM.get().cloned()
}

/// Convenience function to process security events
pub async fn process_security_event(event: &SecurityAuditEvent) -> Result<(), FortressError> {
    if let Some(monitoring) = get_security_monitoring() {
        monitoring.process_security_event(event).await
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_security_metrics_update() {
        let monitoring = SecurityMonitoringSystem::default();
        
        let event = SecurityAuditEvent::new(
            SecurityEventType::Authentication,
            "login_attempt".to_string(),
            SecurityEventResult::Failure,
        );

        monitoring.process_security_event(&event).await.unwrap();

        let metrics = monitoring.get_metrics().await;
        assert_eq!(metrics.authentication_attempts, 1);
        assert_eq!(metrics.failed_authentications, 1);
    }

    #[tokio::test]
    async fn test_brute_force_detection() {
        let config = SecurityMonitoringConfig {
            anomaly_detection: AnomalyDetectionConfig {
                failed_auth_threshold_per_minute: 3,
                ..Default::default()
            },
            ..Default::default()
        };

        let monitoring = SecurityMonitoringSystem::new(config);

        // Simulate multiple failed auth attempts
        for i in 0..3 {
            let event = SecurityAuditEvent::new(
                SecurityEventType::Authentication,
                format!("login_attempt_{}", i),
                SecurityEventResult::Failure,
            ).with_network("192.168.1.1".to_string(), None);

            monitoring.process_security_event(&event).await.unwrap();
        }

        let alerts = monitoring.get_active_alerts().await;
        assert!(!alerts.is_empty());
        assert_eq!(alerts[0].alert_type, AlertType::BruteForceAttack);
    }

    #[tokio::test]
    async fn test_alert_acknowledgment() {
        let monitoring = SecurityMonitoringSystem::default();
        
        // Create a test alert
        let event = SecurityAuditEvent::new(
            SecurityEventType::ThreatDetection,
            "test_threat".to_string(),
            SecurityEventResult::Blocked,
        );

        monitoring.create_alert(
            AlertType::SuspiciousActivity,
            AlertSeverity::Medium,
            "Test alert",
            "Test description".to_string(),
            &event,
        ).await.unwrap();

        let alerts = monitoring.get_active_alerts().await;
        let alert_id = alerts[0].id.clone();

        monitoring.acknowledge_alert(&alert_id).await.unwrap();

        let alerts = monitoring.get_active_alerts().await;
        assert_eq!(alerts[0].status, AlertStatus::Acknowledged);
    }

    #[tokio::test]
    async fn test_system_health_calculation() {
        let monitoring = SecurityMonitoringSystem::default();
        
        // Simulate some metrics
        let mut metrics = monitoring.get_metrics().await;
        metrics.failed_authentications = 5;
        metrics.suspicious_activities = 2;
        metrics.avg_response_time_ms = 500.0;

        let health = monitoring.calculate_system_health(&metrics).await;
        assert!(health.score > 80.0); // Should still be good health
        assert_eq!(health.status, HealthStatus::Excellent);
    }
}
