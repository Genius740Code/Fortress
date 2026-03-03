//! Alert management system for Fortress
//!
//! Provides comprehensive alerting with rules, notifications, and
//! escalation policies for monitoring and incident response.

use crate::error::{FortressError, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use uuid::Uuid;

/// Alert management configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertConfig {
    /// Enable alert system
    pub enabled: bool,
    /// Alert evaluation interval in seconds
    pub evaluation_interval_seconds: u64,
    /// Maximum active alerts
    pub max_active_alerts: usize,
    /// Alert retention period in hours
    pub retention_hours: u32,
    /// Notification configuration
    pub notifications: NotificationConfig,
    /// Escalation configuration
    pub escalation: EscalationConfig,
}

/// Notification configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotificationConfig {
    /// Enable notifications
    pub enabled: bool,
    /// Notification channels
    pub channels: Vec<NotificationChannel>,
    /// Rate limiting configuration
    pub rate_limit: RateLimitConfig,
    /// Retry configuration
    pub retry: RetryConfig,
}

/// Rate limiting configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitConfig {
    /// Maximum notifications per minute
    pub max_per_minute: u32,
    /// Maximum notifications per hour
    pub max_per_hour: u32,
    /// Maximum notifications per day
    pub max_per_day: u32,
}

/// Retry configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetryConfig {
    /// Maximum retry attempts
    pub max_attempts: u32,
    /// Initial retry delay in seconds
    pub initial_delay_seconds: u64,
    /// Backoff multiplier
    pub backoff_multiplier: f64,
    /// Maximum retry delay in seconds
    pub max_delay_seconds: u64,
}

/// Escalation configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EscalationConfig {
    /// Enable escalation
    pub enabled: bool,
    /// Escalation policies
    pub policies: Vec<EscalationPolicy>,
}

/// Escalation policy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EscalationPolicy {
    /// Policy name
    pub name: String,
    /// Alert severity levels to escalate
    pub severities: Vec<AlertSeverity>,
    /// Time before escalation in minutes
    pub escalation_time_minutes: u64,
    /// Escalation channels
    pub channels: Vec<NotificationChannel>,
}

/// Notification channel types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotificationChannel {
    /// Channel ID
    pub id: String,
    /// Channel name
    pub name: String,
    /// Channel type
    pub channel_type: ChannelType,
    /// Channel configuration
    pub config: HashMap<String, String>,
    /// Enabled status
    pub enabled: bool,
}

/// Channel types
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum ChannelType {
    /// Email notification
    Email,
    /// Slack notification
    Slack,
    /// PagerDuty notification
    PagerDuty,
    /// Webhook notification
    Webhook,
    /// SMS notification
    Sms,
    /// Console notification
    Console,
}

impl Default for AlertConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            evaluation_interval_seconds: 60,
            max_active_alerts: 1000,
            retention_hours: 168, // 7 days
            notifications: NotificationConfig::default(),
            escalation: EscalationConfig::default(),
        }
    }
}

impl Default for NotificationConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            channels: vec![NotificationChannel {
                id: "console".to_string(),
                name: "Console".to_string(),
                channel_type: ChannelType::Console,
                config: HashMap::new(),
                enabled: true,
            }],
            rate_limit: RateLimitConfig::default(),
            retry: RetryConfig::default(),
        }
    }
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            max_per_minute: 10,
            max_per_hour: 100,
            max_per_day: 1000,
        }
    }
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            max_attempts: 3,
            initial_delay_seconds: 5,
            backoff_multiplier: 2.0,
            max_delay_seconds: 300,
        }
    }
}

impl Default for EscalationConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            policies: Vec::new(),
        }
    }
}

/// Alert severity levels
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum AlertSeverity {
    /// Informational
    Info,
    /// Warning
    Warning,
    /// Error
    Error,
    /// Critical
    Critical,
}

impl std::fmt::Display for AlertSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AlertSeverity::Info => write!(f, "INFO"),
            AlertSeverity::Warning => write!(f, "WARNING"),
            AlertSeverity::Error => write!(f, "ERROR"),
            AlertSeverity::Critical => write!(f, "CRITICAL"),
        }
    }
}

/// Alert status
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum AlertStatus {
    /// Alert is active
    Active,
    /// Alert is acknowledged
    Acknowledged,
    /// Alert is resolved
    Resolved,
    /// Alert is suppressed
    Suppressed,
}

/// Alert rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertRule {
    /// Rule ID
    pub id: String,
    /// Rule name
    pub name: String,
    /// Rule description
    pub description: String,
    /// Rule enabled status
    pub enabled: bool,
    /// Rule condition
    pub condition: AlertCondition,
    /// Alert severity
    pub severity: AlertSeverity,
    /// Notification channels
    pub notification_channels: Vec<String>,
    /// Cooldown period in seconds
    pub cooldown_seconds: u64,
    /// Rule metadata
    pub metadata: HashMap<String, String>,
}

/// Alert condition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AlertCondition {
    /// Threshold condition
    Threshold {
        /// Metric name
        metric: String,
        /// Operator
        operator: ComparisonOperator,
        /// Threshold value
        threshold: f64,
        /// Duration in seconds
        duration_seconds: u64,
    },
    /// Composite condition
    Composite {
        /// Operator
        operator: LogicalOperator,
        /// Sub-conditions
        conditions: Vec<AlertCondition>,
    },
    /// Custom condition
    Custom {
        /// Condition expression
        expression: String,
        /// Parameters
        parameters: HashMap<String, String>,
    },
}

/// Comparison operators
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum ComparisonOperator {
    /// Greater than
    GreaterThan,
    /// Greater than or equal
    GreaterThanOrEqual,
    /// Less than
    LessThan,
    /// Less than or equal
    LessThanOrEqual,
    /// Equal
    Equal,
    /// Not equal
    NotEqual,
}

/// Logical operators
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum LogicalOperator {
    /// AND operator
    And,
    /// OR operator
    Or,
    /// NOT operator
    Not,
}

/// Alert instance
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Alert {
    /// Alert ID
    pub id: String,
    /// Rule ID
    pub rule_id: String,
    /// Rule name
    pub rule_name: String,
    /// Alert severity
    pub severity: AlertSeverity,
    /// Alert status
    pub status: AlertStatus,
    /// Alert title
    pub title: String,
    /// Alert message
    pub message: String,
    /// Alert details
    pub details: HashMap<String, String>,
    /// Current value
    pub current_value: f64,
    /// Threshold value
    pub threshold_value: f64,
    /// Creation timestamp
    pub created_at: chrono::DateTime<chrono::Utc>,
    /// Last updated timestamp
    pub updated_at: chrono::DateTime<chrono::Utc>,
    /// Acknowledged timestamp
    pub acknowledged_at: Option<chrono::DateTime<chrono::Utc>>,
    /// Resolved timestamp
    pub resolved_at: Option<chrono::DateTime<chrono::Utc>>,
    /// Acknowledged by
    pub acknowledged_by: Option<String>,
    /// Notification sent status
    pub notifications_sent: Vec<NotificationStatus>,
}

/// Notification status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotificationStatus {
    /// Channel ID
    pub channel_id: String,
    /// Sent timestamp
    pub sent_at: chrono::DateTime<chrono::Utc>,
    /// Delivery status
    pub status: NotificationDeliveryStatus,
    /// Error message if any
    pub error: Option<String>,
}

/// Notification delivery status
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum NotificationDeliveryStatus {
    /// Pending delivery
    Pending,
    /// Successfully delivered
    Delivered,
    /// Delivery failed
    Failed,
    /// Delivery timed out
    TimedOut,
}

/// Alert manager
pub struct AlertManager {
    /// Configuration
    config: AlertConfig,
    /// Alert rules
    rules: Arc<RwLock<HashMap<String, AlertRule>>>,
    /// Active alerts
    alerts: Arc<RwLock<HashMap<String, Alert>>>,
    /// Notification history
    notification_history: Arc<RwLock<Vec<NotificationStatus>>>,
    /// Metrics provider (for evaluation)
    metrics_provider: Arc<dyn MetricsProvider + Send + Sync>,
}

/// Metrics provider trait
#[async_trait::async_trait]
pub trait MetricsProvider: Send + Sync {
    /// Get metric value
    async fn get_metric(&self, name: &str) -> Result<Option<f64>>;
}

impl AlertManager {
    /// Create a new alert manager
    pub fn new(
        config: AlertConfig,
        metrics_provider: Arc<dyn MetricsProvider + Send + Sync>,
    ) -> Self {
        Self {
            config,
            rules: Arc::new(RwLock::new(HashMap::new())),
            alerts: Arc::new(RwLock::new(HashMap::new())),
            notification_history: Arc::new(RwLock::new(Vec::new())),
            metrics_provider,
        }
    }

    /// Add an alert rule
    pub async fn add_rule(&self, rule: AlertRule) -> Result<()> {
        if !self.config.enabled {
            return Ok(());
        }

        let mut rules = self.rules.write().await;
        
        if rules.contains_key(&rule.id) {
            return Err(FortressError::validation(
                format!("Alert rule '{}' already exists", rule.id),
                None,
                None,
            ));
        }

        rules.insert(rule.id.clone(), rule.clone());
        tracing::info!("Added alert rule: {}", rule.id);

        Ok(())
    }

    /// Remove an alert rule
    pub async fn remove_rule(&self, rule_id: &str) -> Result<()> {
        let mut rules = self.rules.write().await;
        
        if rules.remove(rule_id).is_none() {
            return Err(FortressError::validation(
                format!("Alert rule '{}' not found", rule_id),
                None,
                None,
            ));
        }

        tracing::info!("Removed alert rule: {}", rule_id);
        Ok(())
    }

    /// Get all alert rules
    pub async fn get_rules(&self) -> Vec<AlertRule> {
        let rules = self.rules.read().await;
        rules.values().cloned().collect()
    }

    /// Get active alerts
    pub async fn get_active_alerts(&self) -> Vec<Alert> {
        let alerts = self.alerts.read().await;
        alerts
            .values()
            .filter(|alert| matches!(alert.status, AlertStatus::Active))
            .cloned()
            .collect()
    }

    /// Get all alerts
    pub async fn get_all_alerts(&self) -> Vec<Alert> {
        let alerts = self.alerts.read().await;
        alerts.values().cloned().collect()
    }

    /// Acknowledge an alert
    pub async fn acknowledge_alert(&self, alert_id: &str, acknowledged_by: &str) -> Result<()> {
        let mut alerts = self.alerts.write().await;
        
        if let Some(alert) = alerts.get_mut(alert_id) {
            alert.status = AlertStatus::Acknowledged;
            alert.acknowledged_at = Some(chrono::Utc::now());
            alert.acknowledged_by = Some(acknowledged_by.to_string());
            alert.updated_at = chrono::Utc::now();
            
            tracing::info!("Alert {} acknowledged by {}", alert_id, acknowledged_by);
            Ok(())
        } else {
            Err(FortressError::validation(
                format!("Alert '{}' not found", alert_id),
                None,
                None,
            ))
        }
    }

    /// Resolve an alert
    pub async fn resolve_alert(&self, alert_id: &str) -> Result<()> {
        let mut alerts = self.alerts.write().await;
        
        if let Some(alert) = alerts.get_mut(alert_id) {
            alert.status = AlertStatus::Resolved;
            alert.resolved_at = Some(chrono::Utc::now());
            alert.updated_at = chrono::Utc::now();
            
            tracing::info!("Alert {} resolved", alert_id);
            Ok(())
        } else {
            Err(FortressError::validation(
                format!("Alert '{}' not found", alert_id),
                None,
                None,
            ))
        }
    }

    /// Suppress an alert
    pub async fn suppress_alert(&self, alert_id: &str) -> Result<()> {
        let mut alerts = self.alerts.write().await;
        
        if let Some(alert) = alerts.get_mut(alert_id) {
            alert.status = AlertStatus::Suppressed;
            alert.updated_at = chrono::Utc::now();
            
            tracing::info!("Alert {} suppressed", alert_id);
            Ok(())
        } else {
            Err(FortressError::validation(
                format!("Alert '{}' not found", alert_id),
                None,
                None,
            ))
        }
    }

    /// Evaluate all alert rules
    pub async fn evaluate_rules(&self) -> Result<Vec<Alert>> {
        if !self.config.enabled {
            return Ok(Vec::new());
        }

        let rules = self.rules.read().await;
        let mut new_alerts = Vec::new();

        for rule in rules.values() {
            if !rule.enabled {
                continue;
            }

            match self.evaluate_rule(rule).await {
                Ok(Some(alert)) => {
                    new_alerts.push(alert);
                }
                Ok(None) => {
                    // No alert triggered
                }
                Err(e) => {
                    tracing::error!("Error evaluating rule {}: {}", rule.id, e);
                }
            }
        }

        Ok(new_alerts)
    }

    /// Evaluate a single alert rule
    async fn evaluate_rule(&self, rule: &AlertRule) -> Result<Option<Alert>> {
        let triggered = self.evaluate_condition(&rule.condition).await?;

        if triggered {
            // Check if we already have an active alert for this rule
            let alerts = self.alerts.read().await;
            let existing_alert = alerts.values().find(|alert| {
                alert.rule_id == rule.id && matches!(alert.status, AlertStatus::Active | AlertStatus::Acknowledged)
            });

            if let Some(existing) = existing_alert {
                // Check cooldown period
                let cooldown_passed = existing.updated_at + Duration::from_secs(rule.cooldown_seconds) <= chrono::Utc::now();
                if !cooldown_passed {
                    return Ok(None);
                }
            }

            // Create new alert
            let alert = Alert {
                id: Uuid::new_v4().to_string(),
                rule_id: rule.id.clone(),
                rule_name: rule.name.clone(),
                severity: rule.severity,
                status: AlertStatus::Active,
                title: format!("{}: {}", rule.name, rule.description),
                message: self.generate_alert_message(rule).await?,
                details: rule.metadata.clone(),
                current_value: 0.0, // Would be set by condition evaluation
                threshold_value: 0.0, // Would be set by condition evaluation
                created_at: chrono::Utc::now(),
                updated_at: chrono::Utc::now(),
                acknowledged_at: None,
                resolved_at: None,
                acknowledged_by: None,
                notifications_sent: Vec::new(),
            };

            // Store alert
            drop(alerts);
            let mut alerts = self.alerts.write().await;
            alerts.insert(alert.id.clone(), alert.clone());

            // Send notifications
            self.send_notifications(&alert).await?;

            Ok(Some(alert))
        } else {
            // Check if we need to resolve existing alerts
            self.resolve_alerts_for_rule(&rule.id).await?;
            Ok(None)
        }
    }

    /// Evaluate alert condition
    fn evaluate_condition<'a>(&'a self, condition: &'a AlertCondition) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<bool>> + Send + 'a>> {
        Box::pin(async move {
            match condition {
                AlertCondition::Threshold { metric, operator, threshold, duration_seconds } => {
                    let value = self.metrics_provider.get_metric(metric).await?;
                    
                    if let Some(value) = value {
                        let condition_met = match operator {
                            ComparisonOperator::GreaterThan => value > *threshold,
                            ComparisonOperator::GreaterThanOrEqual => value >= *threshold,
                            ComparisonOperator::LessThan => value < *threshold,
                            ComparisonOperator::LessThanOrEqual => value <= *threshold,
                            ComparisonOperator::Equal => (value - *threshold).abs() < f64::EPSILON,
                            ComparisonOperator::NotEqual => (value - *threshold).abs() >= f64::EPSILON,
                        };

                        // For duration-based conditions, we'd need to check historical data
                        // For now, we'll just return the current condition
                        Ok(condition_met)
                    } else {
                        Ok(false)
                    }
                }
                AlertCondition::Composite { operator, conditions } => {
                    let mut results = Vec::new();
                    for condition in conditions {
                        let result = self.evaluate_condition(condition).await?;
                        results.push(result);
                    }

                    Ok(match operator {
                        LogicalOperator::And => results.iter().all(|&r| r),
                        LogicalOperator::Or => results.iter().any(|&r| r),
                        LogicalOperator::Not => results.iter().all(|&r| !r),
                    })
                }
                AlertCondition::Custom { expression: _, parameters: _ } => {
                    // Custom conditions would require expression evaluation
                    // For now, return false
                    Ok(false)
                }
            }
        })
    }

    /// Generate alert message
    async fn generate_alert_message(&self, rule: &AlertRule) -> Result<String> {
        match &rule.condition {
            AlertCondition::Threshold { metric, operator, threshold, .. } => {
                let value = self.metrics_provider.get_metric(metric).await?;
                
                if let Some(value) = value {
                    let operator_str = match operator {
                        ComparisonOperator::GreaterThan => ">",
                        ComparisonOperator::GreaterThanOrEqual => ">=",
                        ComparisonOperator::LessThan => "<",
                        ComparisonOperator::LessThanOrEqual => "<=",
                        ComparisonOperator::Equal => "==",
                        ComparisonOperator::NotEqual => "!=",
                    };

                    Ok(format!(
                        "Metric '{}' is {} {} (threshold: {})",
                        metric, value, operator_str, threshold
                    ))
                } else {
                    Ok(format!("Metric '{}' is not available", metric))
                }
            }
            _ => Ok(rule.description.clone()),
        }
    }

    /// Resolve alerts for a rule
    async fn resolve_alerts_for_rule(&self, rule_id: &str) -> Result<()> {
        let mut alerts = self.alerts.write().await;
        
        for alert in alerts.values_mut() {
            if alert.rule_id == rule_id && matches!(alert.status, AlertStatus::Active | AlertStatus::Acknowledged) {
                alert.status = AlertStatus::Resolved;
                alert.resolved_at = Some(chrono::Utc::now());
                alert.updated_at = chrono::Utc::now();
                
                tracing::info!("Auto-resolved alert {} for rule {}", alert.id, rule_id);
            }
        }

        Ok(())
    }

    /// Send notifications for an alert
    async fn send_notifications(&self, alert: &Alert) -> Result<()> {
        if !self.config.notifications.enabled {
            return Ok(());
        }

        let rules = self.rules.read().await;
        if let Some(rule) = rules.get(&alert.rule_id) {
            for channel_id in &rule.notification_channels {
                if let Some(channel) = self.config.notifications.channels.iter().find(|c| c.id == *channel_id) {
                    if channel.enabled {
                        self.send_notification(channel, alert).await?;
                    }
                }
            }
        }

        Ok(())
    }

    /// Send notification to a specific channel
    async fn send_notification(&self, channel: &NotificationChannel, alert: &Alert) -> Result<()> {
        let status = match channel.channel_type {
            ChannelType::Console => {
                tracing::warn!(
                    "ALERT [{}]: {} - {}",
                    alert.severity,
                    alert.title,
                    alert.message
                );
                
                NotificationStatus {
                    channel_id: channel.id.clone(),
                    sent_at: chrono::Utc::now(),
                    status: NotificationDeliveryStatus::Delivered,
                    error: None,
                }
            }
            ChannelType::Email => {
                // Would implement email sending
                tracing::info!("Email notification sent for alert {}", alert.id);
                NotificationStatus {
                    channel_id: channel.id.clone(),
                    sent_at: chrono::Utc::now(),
                    status: NotificationDeliveryStatus::Delivered,
                    error: None,
                }
            }
            ChannelType::Slack => {
                // Would implement Slack webhook
                tracing::info!("Slack notification sent for alert {}", alert.id);
                NotificationStatus {
                    channel_id: channel.id.clone(),
                    sent_at: chrono::Utc::now(),
                    status: NotificationDeliveryStatus::Delivered,
                    error: None,
                }
            }
            ChannelType::PagerDuty => {
                // Would implement PagerDuty integration
                tracing::info!("PagerDuty notification sent for alert {}", alert.id);
                NotificationStatus {
                    channel_id: channel.id.clone(),
                    sent_at: chrono::Utc::now(),
                    status: NotificationDeliveryStatus::Delivered,
                    error: None,
                }
            }
            ChannelType::Webhook => {
                // Would implement webhook call
                tracing::info!("Webhook notification sent for alert {}", alert.id);
                NotificationStatus {
                    channel_id: channel.id.clone(),
                    sent_at: chrono::Utc::now(),
                    status: NotificationDeliveryStatus::Delivered,
                    error: None,
                }
            }
            ChannelType::Sms => {
                // Would implement SMS sending
                tracing::info!("SMS notification sent for alert {}", alert.id);
                NotificationStatus {
                    channel_id: channel.id.clone(),
                    sent_at: chrono::Utc::now(),
                    status: NotificationDeliveryStatus::Delivered,
                    error: None,
                }
            }
        };

        // Record notification status
        let mut alerts = self.alerts.write().await;
        if let Some(alert) = alerts.get_mut(&alert.id) {
            alert.notifications_sent.push(status);
        }

        Ok(())
    }

    /// Start the alert manager
    pub async fn start(&self) -> Result<()> {
        if !self.config.enabled {
            return Ok(());
        }

        // Start background evaluation task
        self.start_evaluation_task().await;

        tracing::info!("Alert manager started");
        Ok(())
    }

    /// Shutdown the alert manager
    pub async fn shutdown(&self) -> Result<()> {
        if self.config.enabled {
            tracing::info!("Alert manager shutdown");
        }
        Ok(())
    }

    /// Start background evaluation task
    async fn start_evaluation_task(&self) {
        let alert_manager = self.clone();
        let interval = Duration::from_secs(self.config.evaluation_interval_seconds);

        tokio::spawn(async move {
            let mut timer = tokio::time::interval(interval);
            
            loop {
                timer.tick().await;
                
                if let Err(e) = alert_manager.evaluate_rules().await {
                    tracing::error!("Alert evaluation failed: {}", e);
                }
            }
        });
    }
}

impl Clone for AlertManager {
    fn clone(&self) -> Self {
        Self {
            config: self.config.clone(),
            rules: self.rules.clone(),
            alerts: self.alerts.clone(),
            notification_history: self.notification_history.clone(),
            metrics_provider: self.metrics_provider.clone(),
        }
    }
}

/// Mock metrics provider for testing
pub struct MockMetricsProvider {
    metrics: Arc<RwLock<HashMap<String, f64>>>,
}

impl MockMetricsProvider {
    pub fn new() -> Self {
        Self {
            metrics: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub async fn set_metric(&self, name: &str, value: f64) {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_alert_manager_creation() {
        let config = AlertConfig::default();
        let metrics_provider = Arc::new(MockMetricsProvider::new());
        let manager = AlertManager::new(config, metrics_provider);
        assert!(manager.config.enabled);
    }

    #[tokio::test]
    async fn test_alert_rule_management() {
        let config = AlertConfig::default();
        let metrics_provider = Arc::new(MockMetricsProvider::new());
        let manager = AlertManager::new(config, metrics_provider);

        let rule = AlertRule {
            id: "test_rule".to_string(),
            name: "Test Rule".to_string(),
            description: "Test alert rule".to_string(),
            enabled: true,
            condition: AlertCondition::Threshold {
                metric: "test_metric".to_string(),
                operator: ComparisonOperator::GreaterThan,
                threshold: 100.0,
                duration_seconds: 300,
            },
            severity: AlertSeverity::Warning,
            notification_channels: vec!["console".to_string()],
            cooldown_seconds: 300,
            metadata: HashMap::new(),
        };

        manager.add_rule(rule.clone()).await.unwrap();
        
        let rules = manager.get_rules().await;
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].id, rule.id);

        manager.remove_rule(&rule.id).await.unwrap();
        
        let rules = manager.get_rules().await;
        assert_eq!(rules.len(), 0);
    }

    #[tokio::test]
    async fn test_alert_evaluation() {
        let config = AlertConfig::default();
        let metrics_provider = Arc::new(MockMetricsProvider::new());
        
        // Set metric value that should trigger alert
        metrics_provider.set_metric("cpu_usage", 85.0).await;

        let manager = AlertManager::new(config, metrics_provider);

        let rule = AlertRule {
            id: "cpu_alert".to_string(),
            name: "High CPU Usage".to_string(),
            description: "CPU usage is too high".to_string(),
            enabled: true,
            condition: AlertCondition::Threshold {
                metric: "cpu_usage".to_string(),
                operator: ComparisonOperator::GreaterThan,
                threshold: 80.0,
                duration_seconds: 60,
            },
            severity: AlertSeverity::Warning,
            notification_channels: vec!["console".to_string()],
            cooldown_seconds: 300,
            metadata: HashMap::new(),
        };

        manager.add_rule(rule).await.unwrap();
        
        let alerts = manager.evaluate_rules().await.unwrap();
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].severity, AlertSeverity::Warning);
    }

    #[tokio::test]
    async fn test_alert_acknowledgment() {
        let config = AlertConfig::default();
        let metrics_provider = Arc::new(MockMetricsProvider::new());
        let manager = AlertManager::new(config, metrics_provider);

        // Create a mock alert
        let alert = Alert {
            id: "test_alert".to_string(),
            rule_id: "test_rule".to_string(),
            rule_name: "Test Rule".to_string(),
            severity: AlertSeverity::Warning,
            status: AlertStatus::Active,
            title: "Test Alert".to_string(),
            message: "Test message".to_string(),
            details: HashMap::new(),
            current_value: 0.0,
            threshold_value: 0.0,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            acknowledged_at: None,
            resolved_at: None,
            acknowledged_by: None,
            notifications_sent: Vec::new(),
        };

        let mut alerts = manager.alerts.write().await;
        alerts.insert(alert.id.clone(), alert.clone());
        drop(alerts);

        manager.acknowledge_alert(&alert.id, "test_user").await.unwrap();
        
        let alerts = manager.get_all_alerts().await;
        let updated_alert = alerts.iter().find(|a| a.id == alert.id).unwrap();
        assert_eq!(updated_alert.status, AlertStatus::Acknowledged);
        assert_eq!(updated_alert.acknowledged_by.as_ref().unwrap(), "test_user");
    }
}
