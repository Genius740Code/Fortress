//! Security Audit Logging Module
//!
//! Provides comprehensive security audit logging for all security events.
//! This module tracks authentication attempts, authorization decisions,
//! and other security-relevant events for compliance and monitoring.

use crate::error::FortressError;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;

/// Security event types for categorization
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum SecurityEventType {
    Authentication,
    Authorization,
    DataAccess,
    ConfigurationChange,
    SecurityPolicyViolation,
    SystemEvent,
    ThreatDetection,
    Compliance,
}

/// Security event results
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum SecurityEventResult {
    Success,
    Failure,
    Blocked,
    Warning,
    Error,
}

/// Risk score levels (0-100)
pub type RiskScore = u8;

/// Comprehensive security audit event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityAuditEvent {
    /// Event timestamp in UTC
    pub timestamp: DateTime<Utc>,
    /// Type of security event
    pub event_type: SecurityEventType,
    /// User identifier (if applicable)
    pub user_id: Option<String>,
    /// IP address of the source
    pub ip_address: Option<String>,
    /// User agent string
    pub user_agent: Option<String>,
    /// Resource being accessed
    pub resource: Option<String>,
    /// Action being performed
    pub action: String,
    /// Result of the security check
    pub result: SecurityEventResult,
    /// Risk score (0-100, higher = more risky)
    pub risk_score: RiskScore,
    /// Additional metadata
    pub metadata: HashMap<String, String>,
    /// Session identifier (if applicable)
    pub session_id: Option<String>,
    /// Request ID for tracing
    pub request_id: Option<String>,
}

impl SecurityAuditEvent {
    /// Create a new security audit event
    pub fn new(event_type: SecurityEventType, action: String, result: SecurityEventResult) -> Self {
        Self {
            timestamp: Utc::now(),
            event_type,
            user_id: None,
            ip_address: None,
            user_agent: None,
            resource: None,
            action,
            result,
            risk_score: 0,
            metadata: HashMap::new(),
            session_id: None,
            request_id: None,
        }
    }

    /// Set user context
    pub fn with_user(mut self, user_id: String) -> Self {
        self.user_id = Some(user_id);
        self
    }

    /// Set network context
    pub fn with_network(mut self, ip_address: String, user_agent: Option<String>) -> Self {
        self.ip_address = Some(ip_address);
        self.user_agent = user_agent;
        self
    }

    /// Set resource context
    pub fn with_resource(mut self, resource: String) -> Self {
        self.resource = Some(resource);
        self
    }

    /// Set risk score
    pub fn with_risk_score(mut self, risk_score: RiskScore) -> Self {
        self.risk_score = risk_score;
        self
    }

    /// Add metadata
    pub fn with_metadata(mut self, key: String, value: String) -> Self {
        self.metadata.insert(key, value);
        self
    }

    /// Set session context
    pub fn with_session(mut self, session_id: String) -> Self {
        self.session_id = Some(session_id);
        self
    }

    /// Set request ID
    pub fn with_request_id(mut self, request_id: String) -> Self {
        self.request_id = Some(request_id);
        self
    }

    /// Calculate risk score based on event characteristics
    pub fn calculate_risk_score(&mut self) -> &mut Self {
        let mut score = 0u8;

        // Base score by event type
        match self.event_type {
            SecurityEventType::Authentication => score += 10,
            SecurityEventType::Authorization => score += 15,
            SecurityEventType::DataAccess => score += 20,
            SecurityEventType::ConfigurationChange => score += 25,
            SecurityEventType::SecurityPolicyViolation => score += 40,
            SecurityEventType::SystemEvent => score += 5,
            SecurityEventType::ThreatDetection => score += 50,
            SecurityEventType::Compliance => score += 10,
        }

        // Adjust by result
        match self.result {
            SecurityEventResult::Success => score += 0,
            SecurityEventResult::Failure => score += 20,
            SecurityEventResult::Blocked => score += 30,
            SecurityEventResult::Warning => score += 10,
            SecurityEventResult::Error => score += 15,
        }

        // Adjust by context
        if self.ip_address.is_some() {
            score += 5;
        }

        if self.user_id.is_none() && self.event_type != SecurityEventType::SystemEvent {
            score += 15; // Anonymous access is riskier
        }

        // Cap at 100
        self.risk_score = std::cmp::min(score, 100);
        self
    }
}

/// Security audit logger configuration
#[derive(Debug, Clone)]
pub struct SecurityLoggerConfig {
    /// Maximum number of events to keep in memory
    pub max_events: usize,
    /// Events to retain when rotating
    pub retention_count: usize,
    /// Whether to log to console
    pub console_logging: bool,
    /// Risk score threshold for alerts
    pub alert_threshold: RiskScore,
}

impl Default for SecurityLoggerConfig {
    fn default() -> Self {
        Self {
            max_events: 10000,
            retention_count: 5000,
            console_logging: true,
            alert_threshold: 70,
        }
    }
}

/// Comprehensive security audit logger
pub struct SecurityLogger {
    /// In-memory audit log
    audit_log: Arc<Mutex<Vec<SecurityAuditEvent>>>,
    /// Logger configuration
    config: SecurityLoggerConfig,
    /// Alert callback function
    alert_callback: Option<Box<dyn Fn(&SecurityAuditEvent) + Send + Sync>>,
}

impl SecurityLogger {
    /// Create a new security logger
    pub fn new(config: SecurityLoggerConfig) -> Self {
        Self {
            audit_log: Arc::new(Mutex::new(Vec::with_capacity(config.max_events))),
            config,
            alert_callback: None,
        }
    }

    /// Create with default configuration
    pub fn default() -> Self {
        Self::new(SecurityLoggerConfig::default())
    }

    /// Set alert callback
    pub fn with_alert_callback<F>(mut self, callback: F) -> Self
    where
        F: Fn(&SecurityAuditEvent) + Send + Sync + 'static,
    {
        self.alert_callback = Some(Box::new(callback));
        self
    }

    /// Log a security event
    pub async fn log_security_event(
        &self,
        mut event: SecurityAuditEvent,
    ) -> Result<(), FortressError> {
        // Calculate risk score if not set
        if event.risk_score == 0 {
            event.calculate_risk_score();
        }

        // Log to structured logger
        if self.config.console_logging {
            self.log_to_console(&event).await;
        }

        // Check for alerts
        if event.risk_score >= self.config.alert_threshold {
            self.trigger_alert(&event).await;
        }

        // Store in audit log
        let mut audit_log = self.audit_log.lock().await;
        audit_log.push(event);

        // Rotate if needed
        if audit_log.len() > self.config.max_events {
            audit_log.drain(0..self.config.retention_count);
        }

        Ok(())
    }

    /// Log to console with structured format
    async fn log_to_console(&self, event: &SecurityAuditEvent) {
        tracing::info!(
            target: "security_audit",
            timestamp = %event.timestamp,
            event_type = ?event.event_type,
            user_id = ?event.user_id,
            ip_address = ?event.ip_address,
            resource = ?event.resource,
            action = %event.action,
            result = ?event.result,
            risk_score = event.risk_score,
            session_id = ?event.session_id,
            request_id = ?event.request_id,
            "Security event"
        );
    }

    /// Trigger alert for high-risk events
    async fn trigger_alert(&self, event: &SecurityAuditEvent) {
        tracing::warn!(
            target: "security_alert",
            timestamp = %event.timestamp,
            event_type = ?event.event_type,
            user_id = ?event.user_id,
            ip_address = ?event.ip_address,
            action = %event.action,
            risk_score = event.risk_score,
            "HIGH RISK SECURITY EVENT"
        );

        if let Some(ref callback) = self.alert_callback {
            callback(event);
        }
    }

    /// Get audit events with pagination
    pub async fn get_events(
        &self,
        page: u32,
        page_size: u32,
    ) -> Result<Vec<SecurityAuditEvent>, FortressError> {
        let audit_log = self.audit_log.lock().await;
        let start = (page.saturating_sub(1) * page_size) as usize;
        let end = std::cmp::min(start + page_size as usize, audit_log.len());

        if start >= audit_log.len() {
            return Ok(Vec::new());
        }

        Ok(audit_log[start..end].to_vec())
    }

    /// Get events by user ID
    pub async fn get_events_by_user(
        &self,
        user_id: &str,
    ) -> Result<Vec<SecurityAuditEvent>, FortressError> {
        let audit_log = self.audit_log.lock().await;
        Ok(audit_log
            .iter()
            .filter(|event| event.user_id.as_ref().map_or(false, |uid| uid == user_id))
            .cloned()
            .collect())
    }

    /// Get events by risk score threshold
    pub async fn get_high_risk_events(
        &self,
        min_risk_score: RiskScore,
    ) -> Result<Vec<SecurityAuditEvent>, FortressError> {
        let audit_log = self.audit_log.lock().await;
        Ok(audit_log
            .iter()
            .filter(|event| event.risk_score >= min_risk_score)
            .cloned()
            .collect())
    }

    /// Get events by time range
    pub async fn get_events_by_time_range(
        &self,
        start: DateTime<Utc>,
        end: DateTime<Utc>,
    ) -> Result<Vec<SecurityAuditEvent>, FortressError> {
        let audit_log = self.audit_log.lock().await;
        Ok(audit_log
            .iter()
            .filter(|event| event.timestamp >= start && event.timestamp <= end)
            .cloned()
            .collect())
    }

    /// Get security statistics
    pub async fn get_security_stats(&self) -> Result<SecurityStats, FortressError> {
        let audit_log = self.audit_log.lock().await;

        let mut stats = SecurityStats::default();

        for event in audit_log.iter() {
            stats.total_events += 1;

            // Count by event type
            match event.event_type {
                SecurityEventType::Authentication => stats.authentication_events += 1,
                SecurityEventType::Authorization => stats.authorization_events += 1,
                SecurityEventType::DataAccess => stats.data_access_events += 1,
                SecurityEventType::ConfigurationChange => stats.config_changes += 1,
                SecurityEventType::SecurityPolicyViolation => stats.policy_violations += 1,
                SecurityEventType::SystemEvent => stats.system_events += 1,
                SecurityEventType::ThreatDetection => stats.threats_detected += 1,
                SecurityEventType::Compliance => stats.compliance_events += 1,
            }

            // Count by result
            match event.result {
                SecurityEventResult::Success => stats.successful_events += 1,
                SecurityEventResult::Failure => stats.failed_events += 1,
                SecurityEventResult::Blocked => stats.blocked_events += 1,
                SecurityEventResult::Warning => stats.warnings += 1,
                SecurityEventResult::Error => stats.errors += 1,
            }

            // Risk score statistics
            if event.risk_score >= 80 {
                stats.critical_risk_events += 1;
            } else if event.risk_score >= 60 {
                stats.high_risk_events += 1;
            } else if event.risk_score >= 40 {
                stats.medium_risk_events += 1;
            } else {
                stats.low_risk_events += 1;
            }
        }

        Ok(stats)
    }

    /// Clear audit log
    pub async fn clear_log(&self) -> Result<(), FortressError> {
        let mut audit_log = self.audit_log.lock().await;
        audit_log.clear();
        Ok(())
    }
}

/// Security statistics
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SecurityStats {
    pub total_events: u64,
    pub authentication_events: u64,
    pub authorization_events: u64,
    pub data_access_events: u64,
    pub config_changes: u64,
    pub policy_violations: u64,
    pub system_events: u64,
    pub threats_detected: u64,
    pub compliance_events: u64,
    pub successful_events: u64,
    pub failed_events: u64,
    pub blocked_events: u64,
    pub warnings: u64,
    pub errors: u64,
    pub critical_risk_events: u64,
    pub high_risk_events: u64,
    pub medium_risk_events: u64,
    pub low_risk_events: u64,
}

/// Global security logger instance
static GLOBAL_SECURITY_LOGGER: std::sync::OnceLock<Arc<SecurityLogger>> =
    std::sync::OnceLock::new();

/// Initialize global security logger
pub fn init_security_logger(config: SecurityLoggerConfig) -> Result<(), FortressError> {
    let logger = Arc::new(SecurityLogger::new(config));
    GLOBAL_SECURITY_LOGGER.set(logger).map_err(|_| {
        FortressError::configuration(
            "Security logger already initialized".to_string(),
            None,
            crate::error::ConfigurationErrorCode::InvalidFormat,
        )
    })?;
    Ok(())
}

/// Get global security logger
pub fn get_security_logger() -> Option<Arc<SecurityLogger>> {
    GLOBAL_SECURITY_LOGGER.get().cloned()
}

/// Convenience function to log security events
pub async fn log_security_event(event: SecurityAuditEvent) -> Result<(), FortressError> {
    if let Some(logger) = get_security_logger() {
        logger.log_security_event(event).await
    } else {
        // Fallback to structured logging
        tracing::info!(
            target: "security_audit",
            action = %event.action,
            result = ?event.result,
            "Security event (logger not initialized)"
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::time::{sleep, Duration};

    #[tokio::test]
    async fn test_security_audit_event_creation() {
        let event = SecurityAuditEvent::new(
            SecurityEventType::Authentication,
            "login_attempt".to_string(),
            SecurityEventResult::Success,
        )
        .with_user("user123".to_string())
        .with_network("192.168.1.1".to_string(), Some("Mozilla/5.0".to_string()))
        .with_risk_score(25);

        assert_eq!(event.event_type, SecurityEventType::Authentication);
        assert_eq!(event.action, "login_attempt");
        assert_eq!(event.result, SecurityEventResult::Success);
        assert_eq!(event.user_id, Some("user123".to_string()));
        assert_eq!(event.ip_address, Some("192.168.1.1".to_string()));
        assert_eq!(event.risk_score, 25);
    }

    #[tokio::test]
    async fn test_security_logger() {
        let logger = SecurityLogger::default();

        let event = SecurityAuditEvent::new(
            SecurityEventType::Authentication,
            "login_attempt".to_string(),
            SecurityEventResult::Success,
        )
        .with_user("test_user".to_string());

        logger.log_security_event(event).await.unwrap();

        let events = logger.get_events(1, 10).await.unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].user_id, Some("test_user".to_string()));
    }

    #[tokio::test]
    async fn test_risk_score_calculation() {
        let mut event = SecurityAuditEvent::new(
            SecurityEventType::ThreatDetection,
            "suspicious_activity".to_string(),
            SecurityEventResult::Blocked,
        );

        event.calculate_risk_score();
        assert!(event.risk_score >= 80); // Should be high risk
    }

    #[tokio::test]
    async fn test_security_stats() {
        let logger = SecurityLogger::default();

        // Add some test events
        for i in 0..10 {
            let event = SecurityAuditEvent::new(
                if i % 2 == 0 {
                    SecurityEventType::Authentication
                } else {
                    SecurityEventType::Authorization
                },
                format!("test_event_{}", i),
                if i % 3 == 0 {
                    SecurityEventResult::Success
                } else {
                    SecurityEventResult::Failure
                },
            );
            logger.log_security_event(event).await.unwrap();
        }

        let stats = logger.get_security_stats().await.unwrap();
        assert_eq!(stats.total_events, 10);
        assert_eq!(stats.authentication_events, 5);
        assert_eq!(stats.authorization_events, 5);
        assert_eq!(stats.successful_events, 4);
        assert_eq!(stats.failed_events, 6);
    }

    #[tokio::test]
    async fn test_event_filtering() {
        let logger = SecurityLogger::default();

        // Add events with different risk scores
        for i in 0..5 {
            let mut event = SecurityAuditEvent::new(
                SecurityEventType::Authentication,
                format!("test_event_{}", i),
                SecurityEventResult::Success,
            );
            event.risk_score = (i * 20) as u8; // 0, 20, 40, 60, 80
            logger.log_security_event(event).await.unwrap();
        }

        let high_risk_events = logger.get_high_risk_events(60).await.unwrap();
        assert_eq!(high_risk_events.len(), 2); // 60 and 80
    }
}
