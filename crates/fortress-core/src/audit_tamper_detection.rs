//! # Comprehensive Tamper Detection and Alerting System
//!
//! This module provides real-time tamper detection for audit logs with automated alerting.
//! It monitors audit log integrity and alerts on any suspicious activities or tampering attempts.
//!
//! ## Features
//!
//! - **Real-Time Monitoring**: Continuous monitoring of audit log integrity
//! - **Anomaly Detection**: AI-powered detection of suspicious patterns
//! - **Multi-Channel Alerting**: Email, SMS, Slack, webhook notifications
//! - **Automated Response**: Automated containment and remediation actions
//! - **Forensic Analysis**: Detailed tampering analysis and evidence collection
//! - **Compliance Reporting**: Automated compliance violation reporting

use crate::error::{FortressError, Result, AuditErrorCode};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use tokio::sync::RwLock;
use chrono::{DateTime, Utc, Timelike};
use sha2::{Sha256, Digest};
use base64::Engine as _;
use uuid::Uuid;
use tracing::info;

/// Tamper detection alert severity levels
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Hash)]
pub enum AlertSeverity {
    /// Informational - low priority
    Info,
    /// Warning - potential issue
    Warning,
    /// Critical - definite tampering detected
    Critical,
    /// Emergency - system compromise suspected
    Emergency,
    /// High priority alerts
    High,
}

impl std::fmt::Display for AlertSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AlertSeverity::Info => write!(f, "Info"),
            AlertSeverity::Warning => write!(f, "Warning"),
            AlertSeverity::Critical => write!(f, "Critical"),
            AlertSeverity::Emergency => write!(f, "Emergency"),
            AlertSeverity::High => write!(f, "High"),
        }
    }
}

/// Tamper detection alert types
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Hash, Eq)]
pub enum TamperAlertType {
    /// Hash chain broken
    HashChainBroken,
    /// Digital signature invalid
    InvalidSignature,
    /// Missing audit entries
    MissingEntries,
    /// Sequence number manipulation
    SequenceManipulation,
    /// Timestamp inconsistency
    TimestampInconsistency,
    /// Merkle tree corruption
    MerkleTreeCorruption,
    /// Unauthorized access attempt
    UnauthorizedAccess,
    /// Configuration tampering
    ConfigurationTampering,
    /// Backup integrity failure
    BackupIntegrityFailure,
    /// Anomalous access patterns
    AnomalousAccess,
}

/// Alert notification channels
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum AlertChannel {
    /// Email notification
    Email(String),
    /// SMS notification
    SMS(String),
    /// Slack webhook
    Slack(String),
    /// Generic webhook
    Webhook(String),
    /// SIEM system
    SIEM(String),
    /// Multiple channels
    Multiple(Vec<AlertChannel>),
}

/// Tamper detection alert
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TamperAlert {
    /// Unique alert ID
    pub alert_id: String,
    /// Alert timestamp
    pub timestamp: DateTime<Utc>,
    /// Alert severity
    pub severity: AlertSeverity,
    /// Alert type
    pub alert_type: TamperAlertType,
    /// Alert title
    pub title: String,
    /// Detailed description
    pub description: String,
    /// Affected audit log ID
    pub audit_log_id: String,
    /// Affected entry IDs
    pub affected_entries: Vec<String>,
    /// Evidence of tampering
    pub evidence: TamperingEvidence,
    /// Recommended actions
    pub recommended_actions: Vec<String>,
    /// Alert status
    pub status: AlertStatus,
    /// Notification channels used
    pub notification_channels: Vec<AlertChannel>,
    /// Alert metadata
    pub metadata: HashMap<String, serde_json::Value>,
}

/// Evidence of tampering
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TamperingEvidence {
    /// Evidence type
    pub evidence_type: EvidenceType,
    /// Raw evidence data
    pub raw_data: String,
    /// Analyzed evidence
    pub analyzed_data: HashMap<String, serde_json::Value>,
    /// Confidence level (0.0-1.0)
    pub confidence_level: f64,
    /// Evidence collection timestamp
    pub collection_timestamp: DateTime<Utc>,
    /// Evidence hash for integrity
    pub evidence_hash: String,
}

/// Types of tampering evidence
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum EvidenceType {
    /// Hash mismatch evidence
    HashMismatch,
    /// Signature verification failure
    SignatureFailure,
    /// File system evidence
    FileSystem,
    /// Network evidence
    Network,
    /// System logs evidence
    SystemLogs,
    /// Memory dump evidence
    MemoryDump,
    /// Configuration evidence
    Configuration,
    /// Timeline analysis evidence
    TimelineAnalysis,
}

/// Alert status
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum AlertStatus {
    /// Alert is new
    New,
    /// Alert is being investigated
    Investigating,
    /// Alert has been acknowledged
    Acknowledged,
    /// Alert is being resolved
    Resolving,
    /// Alert has been resolved
    Resolved,
    /// Alert was false positive
    FalsePositive,
}

/// Tamper detection configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TamperDetectionConfig {
    /// Enable real-time monitoring
    pub enable_real_time_monitoring: bool,
    /// Monitoring interval in seconds
    pub monitoring_interval_seconds: u64,
    /// Alert channels
    pub alert_channels: Vec<AlertChannel>,
    /// Minimum alert severity
    pub min_alert_severity: AlertSeverity,
    /// Enable automated response
    pub enable_automated_response: bool,
    /// Anomaly detection sensitivity
    pub anomaly_sensitivity: AnomalySensitivity,
    /// Evidence collection depth
    pub evidence_collection_depth: EvidenceCollectionDepth,
    /// Alert retention period in days
    pub alert_retention_days: u32,
    /// Maximum alerts per hour
    pub max_alerts_per_hour: u32,
}

/// Anomaly detection sensitivity levels
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum AnomalySensitivity {
    /// Low sensitivity - fewer false positives
    Low,
    /// Medium sensitivity - balanced detection
    Medium,
    /// High sensitivity - maximum detection
    High,
    /// Paranoid - maximum security
    Paranoid,
}

/// Evidence collection depth levels
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum EvidenceCollectionDepth {
    /// Basic evidence only
    Basic,
    /// Standard evidence collection
    Standard,
    /// Comprehensive evidence collection
    Comprehensive,
    /// Forensic-level evidence collection
    Forensic,
}

/// Automated response actions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AutomatedResponse {
    /// Isolate affected systems
    IsolateSystem(String),
    /// Lock user accounts
    LockAccount(String),
    /// Rotate cryptographic keys
    RotateKeys,
    /// Initiate backup restoration
    InitiateBackupRestore,
    /// Enable enhanced monitoring
    EnableEnhancedMonitoring,
    /// Notify security team
    NotifySecurityTeam,
    /// Create forensic snapshot
    CreateForensicSnapshot,
    /// Multiple actions
    Multiple(Vec<AutomatedResponse>),
}

/// Tamper detection metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TamperDetectionMetrics {
    /// Total alerts generated
    pub total_alerts: u64,
    /// Alerts by severity
    pub alerts_by_severity: HashMap<AlertSeverity, u64>,
    /// Alerts by type
    pub alerts_by_type: HashMap<TamperAlertType, u64>,
    /// False positive rate
    pub false_positive_rate: f64,
    /// Average detection time in seconds
    pub avg_detection_time_seconds: f64,
    /// Average response time in seconds
    pub avg_response_time_seconds: f64,
    /// Active alerts count
    pub active_alerts: u64,
    /// Resolved alerts count
    pub resolved_alerts: u64,
    /// Last detection timestamp
    pub last_detection: Option<DateTime<Utc>>,
}

/// Comprehensive tamper detection system
#[derive(Debug)]
pub struct TamperDetectionSystem {
    /// Detection configuration
    config: Arc<RwLock<TamperDetectionConfig>>,
    /// Active alerts
    active_alerts: Arc<RwLock<HashMap<String, TamperAlert>>>,
    /// Alert history
    alert_history: Arc<RwLock<VecDeque<TamperAlert>>>,
    /// Detection metrics
    metrics: Arc<RwLock<TamperDetectionMetrics>>,
    /// Evidence collector
    evidence_collector: Arc<EvidenceCollector>,
    /// Alert notifier
    alert_notifier: Arc<AlertNotifier>,
    /// Response coordinator
    response_coordinator: Arc<ResponseCoordinator>,
}

/// Evidence collection system
#[derive(Debug)]
pub struct EvidenceCollector {
    /// Collection configuration
    collection_depth: EvidenceCollectionDepth,
    /// Evidence storage
    evidence_storage: Arc<RwLock<HashMap<String, TamperingEvidence>>>,
}

/// Alert notification system
#[derive(Debug)]
pub struct AlertNotifier {
    /// Notification channels
    channel: AlertChannel,
    /// Notification templates
    templates: HashMap<AlertSeverity, String>,
}

/// Automated response coordinator
#[derive(Debug)]
pub struct ResponseCoordinator {
    /// Response actions
    response_actions: HashMap<TamperAlertType, Vec<AutomatedResponse>>,
    /// Response history
    response_history: Arc<RwLock<Vec<ResponseAction>>>,
}

/// Response action record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseAction {
    /// Action ID
    pub action_id: String,
    /// Action timestamp
    pub timestamp: DateTime<Utc>,
    /// Action type
    pub action_type: AutomatedResponse,
    /// Alert ID that triggered the action
    pub alert_id: String,
    /// Action status
    pub status: ResponseStatus,
    /// Action result
    pub result: Option<String>,
}

/// Response action status
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ResponseStatus {
    /// Action is pending
    Pending,
    /// Action is in progress
    InProgress,
    /// Action completed successfully
    Completed,
    /// Action failed
    Failed,
    /// Action was cancelled
    Cancelled,
}

impl TamperDetectionSystem {
    /// Create new tamper detection system
    pub fn new(config: TamperDetectionConfig) -> Self {
        let evidence_collector = Arc::new(EvidenceCollector::new(config.evidence_collection_depth.clone()));
        let alert_notifier = Arc::new(AlertNotifier::new(AlertChannel::Multiple(config.alert_channels.clone())));
        let response_coordinator = Arc::new(ResponseCoordinator::new());

        Self {
            config: Arc::new(RwLock::new(config)),
            active_alerts: Arc::new(RwLock::new(HashMap::new())),
            alert_history: Arc::new(RwLock::new(VecDeque::with_capacity(10000))),
            metrics: Arc::new(RwLock::new(TamperDetectionMetrics::default())),
            evidence_collector,
            alert_notifier,
            response_coordinator,
        }
    }

    /// Detect tampering in audit log
    pub async fn detect_tampering(
        &self,
        audit_log_id: &str,
        integrity_report: &crate::secure_audit_merkle::IntegrityVerificationReport,
    ) -> Result<Vec<TamperAlert>> {
        let mut alerts = Vec::new();
        let config = self.config.read().await;

        // Check for various tampering indicators
        if !integrity_report.chain_integrity_valid {
            let alert = self.create_alert(
                TamperAlertType::HashChainBroken,
                AlertSeverity::Critical,
                format!("Hash chain integrity compromised in audit log: {}", audit_log_id),
                audit_log_id.to_string(),
                integrity_report.tampered_entries.clone(),
            ).await?;
            alerts.push(alert);
        }

        if !integrity_report.signature_valid {
            let alert = self.create_alert(
                TamperAlertType::InvalidSignature,
                AlertSeverity::Critical,
                format!("Digital signature verification failed in audit log: {}", audit_log_id),
                audit_log_id.to_string(),
                integrity_report.tampered_entries.clone(),
            ).await?;
            alerts.push(alert);
        }

        if !integrity_report.merkle_root_valid {
            let alert = self.create_alert(
                TamperAlertType::MerkleTreeCorruption,
                AlertSeverity::Critical,
                format!("Merkle tree corruption detected in audit log: {}", audit_log_id),
                audit_log_id.to_string(),
                integrity_report.tampered_entries.clone(),
            ).await?;
            alerts.push(alert);
        }

        if !integrity_report.missing_entries.is_empty() {
            let alert = self.create_alert(
                TamperAlertType::MissingEntries,
                AlertSeverity::High,
                format!("Missing audit entries detected in log: {}. Missing sequence numbers: {:?}", 
                    audit_log_id, integrity_report.missing_entries),
                audit_log_id.to_string(),
                integrity_report.tampered_entries.clone(),
            ).await?;
            alerts.push(alert);
        }

        // Process alerts based on severity
        let mut processed_alerts = Vec::new();
        for alert in alerts {
            if alert.severity >= config.min_alert_severity {
                self.process_alert(alert.clone()).await?;
            }
            processed_alerts.push(alert);
        }

        Ok(processed_alerts)
    }

    /// Detect anomalous access patterns
    pub async fn detect_anomalous_patterns(
        &self,
        audit_entries: &[crate::secure_audit_merkle::SecureAuditEntry],
    ) -> Result<Vec<TamperAlert>> {
        let mut alerts = Vec::new();
        let config = self.config.read().await;

        // Analyze access patterns
        let patterns = self.analyze_access_patterns(audit_entries).await?;

        // Check for suspicious patterns
        for (pattern_type, confidence) in patterns {
            if confidence >= self.get_anomaly_threshold(&config.anomaly_sensitivity) {
                let alert = self.create_alert(
                    TamperAlertType::AnomalousAccess,
                    self.confidence_to_severity(confidence),
                    format!("Anomalous access pattern detected: {:?} (confidence: {:.2}%)", 
                        pattern_type, confidence * 100.0),
                    "pattern_analysis".to_string(),
                    Vec::new(),
                ).await?;
                alerts.push(alert);
            }
        }

        Ok(alerts)
    }

    /// Create a tamper alert
    async fn create_alert(
        &self,
        alert_type: TamperAlertType,
        severity: AlertSeverity,
        description: String,
        audit_log_id: String,
        affected_entries: Vec<crate::secure_audit_merkle::TamperedEntry>,
    ) -> Result<TamperAlert> {
        let alert_id = Uuid::new_v4().to_string();
        let timestamp = Utc::now();

        // Collect evidence
        let evidence = self.evidence_collector.collect_evidence(
            &alert_type,
            &audit_log_id,
            &affected_entries,
        ).await?;

        // Generate recommended actions
        let recommended_actions = self.generate_recommended_actions(&alert_type, &severity).await;

        // Convert affected entries to entry IDs
        let entry_ids: Vec<String> = affected_entries.iter()
            .map(|e| e.entry_id.clone())
            .collect();

        let alert = TamperAlert {
            alert_id: alert_id.clone(),
            timestamp,
            severity: severity.clone(),
            alert_type: alert_type.clone(),
            title: format!("{:?} - {}", alert_type, severity),
            description,
            audit_log_id,
            affected_entries: entry_ids,
            evidence,
            recommended_actions,
            status: AlertStatus::New,
            notification_channels: Vec::new(),
            metadata: HashMap::new(),
        };

        Ok(alert)
    }

    /// Process a tamper alert
    async fn process_alert(&self, mut alert: TamperAlert) -> Result<()> {
        let config = self.config.read().await;

        // Add to active alerts
        {
            let mut active_alerts = self.active_alerts.write().await;
            active_alerts.insert(alert.alert_id.clone(), alert.clone());
        }

        // Add to alert history
        {
            let mut history = self.alert_history.write().await;
            if history.len() >= 10000 {
                history.pop_front();
            }
            history.push_back(alert.clone());
        }

        // Update metrics
        self.update_metrics(&alert).await;

        // Send notifications
        alert.notification_channels = config.alert_channels.clone();
        self.alert_notifier.send_alert(&alert).await?;

        // Trigger automated response if enabled
        if config.enable_automated_response {
            self.response_coordinator.execute_response(&alert).await?;
        }

        Ok(())
    }

    /// Analyze access patterns for anomalies
    async fn analyze_access_patterns(
        &self,
        entries: &[crate::secure_audit_merkle::SecureAuditEntry],
    ) -> Result<HashMap<String, f64>> {
        let mut patterns = HashMap::new();

        // Analyze frequency patterns
        let frequency_anomaly = self.detect_frequency_anomalies(entries).await?;
        if frequency_anomaly > 0.0 {
            patterns.insert("high_frequency_access".to_string(), frequency_anomaly);
        }

        // Analyze time patterns
        let time_anomaly = self.detect_time_anomalies(entries).await?;
        if time_anomaly > 0.0 {
            patterns.insert("unusual_time_access".to_string(), time_anomaly);
        }

        // Analyze resource patterns
        let resource_anomaly = self.detect_resource_anomalies(entries).await?;
        if resource_anomaly > 0.0 {
            patterns.insert("unusual_resource_access".to_string(), resource_anomaly);
        }

        // Analyze principal patterns
        let principal_anomaly = self.detect_principal_anomalies(entries).await?;
        if principal_anomaly > 0.0 {
            patterns.insert("unusual_principal_behavior".to_string(), principal_anomaly);
        }

        Ok(patterns)
    }

    /// Detect frequency anomalies
    async fn detect_frequency_anomalies(&self, entries: &[crate::secure_audit_merkle::SecureAuditEntry]) -> Result<f64> {
        if entries.len() < 10 {
            return Ok(0.0);
        }

        // Group entries by hour
        let mut hourly_counts = HashMap::new();
        for entry in entries {
            let hour = entry.timestamp.hour();
            *hourly_counts.entry(hour).or_insert(0) += 1;
        }

        // Calculate average and standard deviation
        let counts: Vec<u32> = hourly_counts.values().cloned().collect();
        let avg = counts.iter().sum::<u32>() as f64 / counts.len() as f64;
        let variance = counts.iter()
            .map(|&x| (x as f64 - avg).powi(2))
            .sum::<f64>() / counts.len() as f64;
        let std_dev = variance.sqrt();

        // Check for outliers (more than 3 standard deviations from mean)
        let mut anomaly_score: f32 = 0.0;
        for &count in &counts {
            let z_score = (count as f64 - avg) / std_dev;
            if z_score.abs() > 3.0 {
                anomaly_score = anomaly_score.max((z_score.abs() / 5.0) as f32); // Normalize to 0-1
            }
        }

        Ok((anomaly_score.min(1.0)) as f64)
    }

    /// Detect time anomalies
    async fn detect_time_anomalies(&self, entries: &[crate::secure_audit_merkle::SecureAuditEntry]) -> Result<f64> {
        if entries.len() < 5 {
            return Ok(0.0);
        }

        // Check for access during unusual hours (e.g., 2 AM - 5 AM)
        let unusual_hours = vec![2, 3, 4, 5];
        let unusual_access_count = entries.iter()
            .filter(|e| unusual_hours.contains(&e.timestamp.hour()))
            .count();

        let unusual_access_ratio = unusual_access_count as f64 / entries.len() as f64;
        
        // High ratio of unusual hour access is suspicious
        Ok(if unusual_access_ratio > 0.3 { unusual_access_ratio } else { 0.0 })
    }

    /// Detect resource anomalies
    async fn detect_resource_anomalies(&self, entries: &[crate::secure_audit_merkle::SecureAuditEntry]) -> Result<f64> {
        let mut resource_access_counts = HashMap::new();
        
        for entry in entries {
            *resource_access_counts.entry(&entry.resource).or_insert(0) += 1;
        }

        // Check for single resource being accessed disproportionately
        let total_access: u32 = resource_access_counts.values().sum();
        let max_access_ratio = resource_access_counts.values()
            .map(|&count| count as f64 / total_access as f64)
            .fold(0.0, f64::max);

        // If one resource accounts for > 80% of access, it's suspicious
        Ok(if max_access_ratio > 0.8 { max_access_ratio } else { 0.0 })
    }

    /// Detect principal anomalies
    async fn detect_principal_anomalies(&self, entries: &[crate::secure_audit_merkle::SecureAuditEntry]) -> Result<f64> {
        let mut principal_access_counts = HashMap::new();
        
        for entry in entries {
            *principal_access_counts.entry(&entry.principal).or_insert(0) += 1;
        }

        // Check for single principal accessing unusually many resources
        let total_access: u32 = principal_access_counts.values().sum();
        let max_principal_ratio = principal_access_counts.values()
            .map(|&count| count as f64 / total_access as f64)
            .fold(0.0, f64::max);

        // If one principal accounts for > 90% of access, it's suspicious
        Ok(if max_principal_ratio > 0.9 { max_principal_ratio } else { 0.0 })
    }

    /// Get anomaly threshold based on sensitivity
    fn get_anomaly_threshold(&self, sensitivity: &AnomalySensitivity) -> f64 {
        match sensitivity {
            AnomalySensitivity::Low => 0.9,
            AnomalySensitivity::Medium => 0.7,
            AnomalySensitivity::High => 0.5,
            AnomalySensitivity::Paranoid => 0.3,
        }
    }

    /// Convert confidence score to alert severity
    fn confidence_to_severity(&self, confidence: f64) -> AlertSeverity {
        if confidence >= 0.9 {
            AlertSeverity::Emergency
        } else if confidence >= 0.7 {
            AlertSeverity::Critical
        } else if confidence >= 0.5 {
            AlertSeverity::Warning
        } else {
            AlertSeverity::Info
        }
    }

    /// Generate recommended actions for alert
    async fn generate_recommended_actions(&self, alert_type: &TamperAlertType, severity: &AlertSeverity) -> Vec<String> {
        let mut actions = Vec::new();

        match alert_type {
            TamperAlertType::HashChainBroken => {
                actions.push("Immediately isolate affected audit log files".to_string());
                actions.push("Initiate forensic investigation".to_string());
                actions.push("Restore from last known good backup".to_string());
                actions.push("Review all system access logs".to_string());
            }
            TamperAlertType::InvalidSignature => {
                actions.push("Verify signing key integrity".to_string());
                actions.push("Check for key compromise".to_string());
                actions.push("Rotate signing keys if compromised".to_string());
                actions.push("Verify all recent audit entries".to_string());
            }
            TamperAlertType::MissingEntries => {
                actions.push("Analyze sequence gaps for patterns".to_string());
                actions.push("Check backup systems for missing entries".to_string());
                actions.push("Review system logs during gap periods".to_string());
                actions.push("Implement enhanced monitoring".to_string());
            }
            TamperAlertType::AnomalousAccess => {
                actions.push("Investigate source of anomalous access".to_string());
                actions.push("Review user permissions and roles".to_string());
                actions.push("Implement additional access controls".to_string());
                actions.push("Monitor for continued anomalous behavior".to_string());
            }
            _ => {
                actions.push("Investigate alert details".to_string());
                actions.push("Document findings".to_string());
                actions.push("Implement preventive measures".to_string());
            }
        }

        // Add severity-specific actions
        match severity {
            AlertSeverity::Emergency => {
                actions.push("EMERGENCY: Immediately shut down affected systems".to_string());
                actions.push("EMERGENCY: Contact incident response team".to_string());
                actions.push("EMERGENCY: Preserve all evidence".to_string());
            }
            AlertSeverity::Critical => {
                actions.push("CRITICAL: Escalate to security leadership".to_string());
                actions.push("CRITICAL: Begin immediate containment".to_string());
            }
            AlertSeverity::High => {
                actions.push("HIGH: Immediate security team notification".to_string());
                actions.push("HIGH: Prepare for potential escalation".to_string());
            }
            AlertSeverity::Warning => {
                actions.push("Monitor situation closely".to_string());
                actions.push("Prepare escalation if conditions worsen".to_string());
            }
            AlertSeverity::Info => {
                actions.push("Log for trend analysis".to_string());
                actions.push("Review in next security review".to_string());
            }
        }

        actions
    }

    /// Update detection metrics
    async fn update_metrics(&self, alert: &TamperAlert) {
        let mut metrics = self.metrics.write().await;
        
        metrics.total_alerts += 1;
        *metrics.alerts_by_severity.entry(alert.severity.clone()).or_insert(0) += 1;
        *metrics.alerts_by_type.entry(alert.alert_type.clone()).or_insert(0) += 1;
        
        if alert.status != AlertStatus::FalsePositive {
            metrics.active_alerts += 1;
        }
        
        metrics.last_detection = Some(Utc::now());
    }

    /// Get current metrics
    pub async fn get_metrics(&self) -> TamperDetectionMetrics {
        self.metrics.read().await.clone()
    }

    /// Get active alerts
    pub async fn get_active_alerts(&self) -> Vec<TamperAlert> {
        self.active_alerts.read().await.values().cloned().collect()
    }

    /// Get alert history
    pub async fn get_alert_history(&self, limit: Option<usize>) -> Vec<TamperAlert> {
        let history = self.alert_history.read().await;
        match limit {
            Some(limit) => history.iter().rev().take(limit).cloned().collect(),
            None => history.iter().rev().cloned().collect(),
        }
    }

    /// Acknowledge an alert
    pub async fn acknowledge_alert(&self, alert_id: &str) -> Result<()> {
        let mut active_alerts = self.active_alerts.write().await;
        if let Some(alert) = active_alerts.get_mut(alert_id) {
            alert.status = AlertStatus::Acknowledged;
            
            // Update metrics
            let mut metrics = self.metrics.write().await;
            if alert.status != AlertStatus::FalsePositive {
                metrics.active_alerts = metrics.active_alerts.saturating_sub(1);
            }
        }
        Ok(())
    }

    /// Resolve an alert
    pub async fn resolve_alert(&self, alert_id: &str, is_false_positive: bool) -> Result<()> {
        let mut active_alerts = self.active_alerts.write().await;
        if let Some(alert) = active_alerts.get_mut(alert_id) {
            alert.status = if is_false_positive {
                AlertStatus::FalsePositive
            } else {
                AlertStatus::Resolved
            };
            
            // Update metrics
            let mut metrics = self.metrics.write().await;
            if !is_false_positive {
                metrics.resolved_alerts += 1;
            }
            metrics.active_alerts = metrics.active_alerts.saturating_sub(1);
            
            // Update false positive rate
            if metrics.total_alerts > 0 {
                let false_positives = self.alert_history.read().await
                    .iter()
                    .filter(|a| a.status == AlertStatus::FalsePositive)
                    .count() as u64;
                metrics.false_positive_rate = false_positives as f64 / metrics.total_alerts as f64;
            }
        }
        Ok(())
    }

    /// Update configuration
    pub async fn update_config(&self, new_config: TamperDetectionConfig) -> Result<()> {
        let mut config = self.config.write().await;
        *config = new_config;
        Ok(())
    }
}

impl EvidenceCollector {
    /// Create new evidence collector
    pub fn new(collection_depth: EvidenceCollectionDepth) -> Self {
        Self {
            collection_depth,
            evidence_storage: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Collect evidence for tampering alert
    pub async fn collect_evidence(
        &self,
        alert_type: &TamperAlertType,
        audit_log_id: &str,
        affected_entries: &[crate::secure_audit_merkle::TamperedEntry],
    ) -> Result<TamperingEvidence> {
        let evidence_type = match alert_type {
            TamperAlertType::HashChainBroken => EvidenceType::HashMismatch,
            TamperAlertType::InvalidSignature => EvidenceType::SignatureFailure,
            TamperAlertType::MissingEntries => EvidenceType::TimelineAnalysis,
            _ => EvidenceType::FileSystem,
        };

        let raw_data = self.collect_raw_evidence(alert_type, audit_log_id, affected_entries).await?;
        let analyzed_data = self.analyze_evidence(&raw_data, alert_type).await?;
        let confidence_level = self.calculate_confidence(&analyzed_data, alert_type).await?;

        let evidence_hash = self.calculate_evidence_hash(&raw_data, &analyzed_data).await?;

        let evidence = TamperingEvidence {
            evidence_type,
            raw_data,
            analyzed_data,
            confidence_level,
            collection_timestamp: Utc::now(),
            evidence_hash,
        };

        // Store evidence
        let mut storage = self.evidence_storage.write().await;
        storage.insert(evidence.evidence_hash.clone(), evidence.clone());

        Ok(evidence)
    }

    /// Collect raw evidence
    async fn collect_raw_evidence(
        &self,
        alert_type: &TamperAlertType,
        audit_log_id: &str,
        affected_entries: &[crate::secure_audit_merkle::TamperedEntry],
    ) -> Result<String> {
        let mut evidence = String::new();
        
        evidence.push_str(&format!("Alert Type: {:?}\n", alert_type));
        evidence.push_str(&format!("Audit Log ID: {}\n", audit_log_id));
        evidence.push_str(&format!("Collection Timestamp: {}\n", Utc::now().to_rfc3339()));
        evidence.push_str(&format!("Affected Entries: {}\n", affected_entries.len()));
        
        for entry in affected_entries {
            evidence.push_str(&format!("Entry {}: {:?} - {}\n", 
                entry.sequence_number, 
                entry.tampering_type, 
                entry.description));
        }

        // Add system information based on collection depth
        match self.collection_depth {
            EvidenceCollectionDepth::Basic => {
                evidence.push_str("Collection Depth: Basic\n");
            }
            EvidenceCollectionDepth::Standard => {
                evidence.push_str("Collection Depth: Standard\n");
                evidence.push_str(&format!("System Uptime: {}\n", self.get_system_uptime().await));
            }
            EvidenceCollectionDepth::Comprehensive => {
                evidence.push_str("Collection Depth: Comprehensive\n");
                evidence.push_str(&format!("System Uptime: {}\n", self.get_system_uptime().await));
                evidence.push_str(&format!("Memory Usage: {}\n", self.get_memory_usage().await));
                evidence.push_str(&format!("Disk Usage: {}\n", self.get_disk_usage().await));
            }
            EvidenceCollectionDepth::Forensic => {
                evidence.push_str("Collection Depth: Forensic\n");
                evidence.push_str(&format!("System Uptime: {}\n", self.get_system_uptime().await));
                evidence.push_str(&format!("Memory Usage: {}\n", self.get_memory_usage().await));
                evidence.push_str(&format!("Disk Usage: {}\n", self.get_disk_usage().await));
                evidence.push_str(&format!("Network Connections: {}\n", self.get_network_connections().await));
                evidence.push_str(&format!("Process List: {}\n", self.get_process_list().await));
            }
        }

        Ok(evidence)
    }

    /// Analyze collected evidence
    async fn analyze_evidence(&self, raw_data: &str, alert_type: &TamperAlertType) -> Result<HashMap<String, serde_json::Value>> {
        let mut analyzed = HashMap::new();
        
        analyzed.insert("evidence_length".to_string(), 
            serde_json::Value::Number(raw_data.len().into()));
        analyzed.insert("alert_type".to_string(), 
            serde_json::Value::String(format!("{:?}", alert_type)));
        analyzed.insert("analysis_timestamp".to_string(), 
            serde_json::Value::String(Utc::now().to_rfc3339()));

        // Perform specific analysis based on alert type
        match alert_type {
            TamperAlertType::HashChainBroken => {
                analyzed.insert("chain_integrity".to_string(), 
                    serde_json::Value::String("compromised".to_string()));
            }
            TamperAlertType::InvalidSignature => {
                analyzed.insert("signature_validity".to_string(), 
                    serde_json::Value::String("invalid".to_string()));
            }
            _ => {
                analyzed.insert("analysis_type".to_string(), 
                    serde_json::Value::String("general".to_string()));
            }
        }

        Ok(analyzed)
    }

    /// Calculate confidence level
    async fn calculate_confidence(&self, analyzed_data: &HashMap<String, serde_json::Value>, _alert_type: &TamperAlertType) -> Result<f64> {
        // Simple confidence calculation based on evidence completeness
        let mut confidence: f32 = 0.5; // Base confidence
        
        if analyzed_data.contains_key("evidence_length") {
            confidence += 0.2;
        }
        if analyzed_data.contains_key("analysis_timestamp") {
            confidence += 0.2;
        }
        if analyzed_data.len() > 5 {
            confidence += 0.1;
        }
        
        Ok((confidence.min(1.0)) as f64)
    }

    /// Calculate evidence hash
    async fn calculate_evidence_hash(&self, raw_data: &str, analyzed_data: &HashMap<String, serde_json::Value>) -> Result<String> {
        let mut hasher = Sha256::new();
        hasher.update(raw_data.as_bytes());
        
        let analyzed_json = serde_json::to_string(analyzed_data)
            .map_err(|e| FortressError::audit(format!("Failed to serialize analyzed data: {}", e), None, AuditErrorCode::LogCreationFailed))?;
        hasher.update(analyzed_json.as_bytes());
        
        let result = hasher.finalize();
        Ok(base64::engine::general_purpose::STANDARD.encode(result))
    }

    /// Get system uptime (mock implementation)
    async fn get_system_uptime(&self) -> String {
        "5 days, 12 hours, 30 minutes".to_string()
    }

    /// Get memory usage (mock implementation)
    async fn get_memory_usage(&self) -> String {
        "2.1GB / 8GB (26.25%)".to_string()
    }

    /// Get disk usage (mock implementation)
    async fn get_disk_usage(&self) -> String {
        "45.2GB / 100GB (45.2%)".to_string()
    }

    /// Get network connections (mock implementation)
    async fn get_network_connections(&self) -> String {
        "23 active connections".to_string()
    }

    /// Get process list (mock implementation)
    async fn get_process_list(&self) -> String {
        "156 running processes".to_string()
    }
}

impl AlertNotifier {
    /// Create new alert notifier
    pub fn new(channel: AlertChannel) -> Self {
        let mut templates = HashMap::new();
        
        templates.insert(AlertSeverity::Info, 
            "INFO: {{title}} - {{description}}".to_string());
        templates.insert(AlertSeverity::Warning, 
            "WARNING: {{title}} - {{description}}".to_string());
        templates.insert(AlertSeverity::Critical, 
            "CRITICAL: {{title}} - {{description}}".to_string());
        templates.insert(AlertSeverity::Emergency, 
            "EMERGENCY: {{title}} - {{description}}".to_string());
        templates.insert(AlertSeverity::High, 
            "HIGH: {{title}} - {{description}}".to_string());

        Self {
            channel,
            templates,
        }
    }

    /// Send alert notification
    pub async fn send_alert(&self, alert: &TamperAlert) -> Result<()> {
        match &self.channel {
            AlertChannel::Email(email) => {
                self.send_email_alert(email, alert).await?;
            }
            AlertChannel::SMS(phone) => {
                self.send_sms_alert(phone, alert).await?;
            }
            AlertChannel::Slack(webhook) => {
                self.send_slack_alert(webhook, alert).await?;
            }
            AlertChannel::Webhook(url) => {
                self.send_webhook_alert(url, alert).await?;
            }
            AlertChannel::SIEM(siem) => {
                self.send_siem_alert(siem, alert).await?;
            }
            AlertChannel::Multiple(channels) => {
                for sub_channel in channels {
                    // Create a new notifier for each channel to avoid recursion
                    let sub_notifier = AlertNotifier::new(sub_channel.clone());
                    // Use a non-recursive approach
                    match sub_channel {
                        AlertChannel::Email(email) => {
                            sub_notifier.send_email_alert(email, alert).await?;
                        }
                        AlertChannel::SMS(phone) => {
                            sub_notifier.send_sms_alert(phone, alert).await?;
                        }
                        AlertChannel::Slack(webhook) => {
                            sub_notifier.send_slack_alert(webhook, alert).await?;
                        }
                        AlertChannel::Webhook(url) => {
                            sub_notifier.send_webhook_alert(url, alert).await?;
                        }
                        AlertChannel::SIEM(siem) => {
                            sub_notifier.send_siem_alert(siem, alert).await?;
                        }
                        AlertChannel::Multiple(_) => {
                            // Skip nested multiple channels to avoid infinite recursion
                            continue;
                        }
                    }
                }
            }
        }

        Ok(())
    }

    /// Send email alert (mock implementation)
    async fn send_email_alert(&self, _email: &str, alert: &TamperAlert) -> Result<()> {
        info!("Sending email alert: {}", alert.title);
        Ok(())
    }

    /// Send SMS alert (mock implementation)
    async fn send_sms_alert(&self, _phone: &str, alert: &TamperAlert) -> Result<()> {
        info!("Sending SMS alert: {}", alert.title);
        Ok(())
    }

    /// Send Slack alert (mock implementation)
    async fn send_slack_alert(&self, _webhook: &str, alert: &TamperAlert) -> Result<()> {
        info!("Sending Slack alert: {}", alert.title);
        Ok(())
    }

    /// Send webhook alert (mock implementation)
    async fn send_webhook_alert(&self, _url: &str, alert: &TamperAlert) -> Result<()> {
        info!("Sending webhook alert: {}", alert.title);
        Ok(())
    }

    /// Send SIEM alert (mock implementation)
    async fn send_siem_alert(&self, _siem: &str, alert: &TamperAlert) -> Result<()> {
        info!("Sending SIEM alert: {}", alert.title);
        Ok(())
    }

    /// Format alert message
    async fn format_alert_message(&self, alert: &TamperAlert) -> Result<String> {
        let default_template = "ALERT: {{title}} - {{description}}".to_string();
        let template = self.templates.get(&alert.severity)
            .unwrap_or(&default_template);

        let message = template
            .replace("{{title}}", &alert.title)
            .replace("{{description}}", &alert.description)
            .replace("{{timestamp}}", &alert.timestamp.to_rfc3339())
            .replace("{{alert_id}}", &alert.alert_id);

        Ok(message)
    }

    /// Send email notification (mock implementation)
    async fn send_email_notification(&self, email: &str, message: &str) -> Result<()> {
        // In a real implementation, this would send an actual email
        log::info!("Sending email to {}: {}", email, message);
        Ok(())
    }

    /// Send SMS notification (mock implementation)
    async fn send_sms_notification(&self, phone: &str, message: &str) -> Result<()> {
        // In a real implementation, this would send an actual SMS
        log::info!("Sending SMS to {}: {}", phone, message);
        Ok(())
    }

    /// Send Slack notification (mock implementation)
    async fn send_slack_notification(&self, webhook: &str, message: &str) -> Result<()> {
        // In a real implementation, this would send to Slack webhook
        log::info!("Sending Slack notification to {}: {}", webhook, message);
        Ok(())
    }

    /// Send webhook notification (mock implementation)
    async fn send_webhook_notification(&self, url: &str, alert: &TamperAlert) -> Result<()> {
        // In a real implementation, this would send HTTP POST to webhook
        log::info!("Sending webhook to {}: {:?}", url, alert.alert_type);
        Ok(())
    }

    /// Send SIEM notification (mock implementation)
    async fn send_siem_notification(&self, siem: &str, alert: &TamperAlert) -> Result<()> {
        // In a real implementation, this would send to SIEM system
        log::info!("Sending SIEM notification to {}: {:?}", siem, alert.alert_type);
        Ok(())
    }
}

impl ResponseCoordinator {
    /// Create new response coordinator
    pub fn new() -> Self {
        let mut response_actions = HashMap::new();
        
        // Define default response actions for each alert type
        response_actions.insert(TamperAlertType::HashChainBroken, vec![
            AutomatedResponse::IsolateSystem("audit_system".to_string()),
            AutomatedResponse::CreateForensicSnapshot,
            AutomatedResponse::NotifySecurityTeam,
        ]);
        
        response_actions.insert(TamperAlertType::InvalidSignature, vec![
            AutomatedResponse::RotateKeys,
            AutomatedResponse::NotifySecurityTeam,
        ]);
        
        response_actions.insert(TamperAlertType::MissingEntries, vec![
            AutomatedResponse::EnableEnhancedMonitoring,
            AutomatedResponse::InitiateBackupRestore,
        ]);

        Self {
            response_actions,
            response_history: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Execute automated response for alert
    pub async fn execute_response(&self, alert: &TamperAlert) -> Result<Vec<ResponseAction>> {
        let mut executed_actions = Vec::new();

        if let Some(actions) = self.response_actions.get(&alert.alert_type) {
            for action in actions {
                let response_action = self.execute_single_action(action, &alert.alert_id).await?;
                executed_actions.push(response_action);
            }
        }

        Ok(executed_actions)
    }

    /// Execute single response action
    async fn execute_single_action(
        &self, 
        action: &AutomatedResponse, 
        alert_id: &str
    ) -> Result<ResponseAction> {
        let action_id = Uuid::new_v4().to_string();
        let timestamp = Utc::now();
        
        let mut response_action = ResponseAction {
            action_id: action_id.clone(),
            timestamp,
            action_type: action.clone(),
            alert_id: alert_id.to_string(),
            status: ResponseStatus::Pending,
            result: None,
        };

        // Update status to in progress
        response_action.status = ResponseStatus::InProgress;
        
        // Execute the action
        let result = match action {
            AutomatedResponse::IsolateSystem(system) => {
                self.isolate_system(system).await
            }
            AutomatedResponse::LockAccount(account) => {
                self.lock_account(account).await
            }
            AutomatedResponse::RotateKeys => {
                self.rotate_keys().await
            }
            AutomatedResponse::InitiateBackupRestore => {
                self.initiate_backup_restore().await
            }
            AutomatedResponse::EnableEnhancedMonitoring => {
                self.enable_enhanced_monitoring().await
            }
            AutomatedResponse::NotifySecurityTeam => {
                self.notify_security_team().await
            }
            AutomatedResponse::CreateForensicSnapshot => {
                self.create_forensic_snapshot().await
            }
            AutomatedResponse::Multiple(actions) => {
                let mut results = Vec::new();
                for sub_action in actions {
                    // Use Box::pin to handle recursion
                    let sub_result = Box::pin(self.execute_single_action(sub_action, alert_id)).await?;
                    results.push(format!("{:?}", sub_result.result));
                }
                Ok(results.join("; "))
            }
        };

        // Update action result and status
        match result {
            Ok(result_msg) => {
                response_action.result = Some(result_msg);
                response_action.status = ResponseStatus::Completed;
            }
            Err(e) => {
                response_action.result = Some(format!("Failed: {}", e));
                response_action.status = ResponseStatus::Failed;
            }
        }

        // Store in history
        let mut history = self.response_history.write().await;
        history.push(response_action.clone());

        Ok(response_action)
    }

    /// Isolate system (mock implementation)
    async fn isolate_system(&self, system: &str) -> Result<String> {
        // In a real implementation, this would isolate the system
        log::warn!("Isolating system: {}", system);
        Ok(format!("System {} isolated successfully", system))
    }

    /// Lock account (mock implementation)
    async fn lock_account(&self, account: &str) -> Result<String> {
        // In a real implementation, this would lock the account
        log::warn!("Locking account: {}", account);
        Ok(format!("Account {} locked successfully", account))
    }

    /// Rotate keys (mock implementation)
    async fn rotate_keys(&self) -> Result<String> {
        // In a real implementation, this would rotate cryptographic keys
        log::warn!("Rotating cryptographic keys");
        Ok("Keys rotated successfully".to_string())
    }

    /// Initiate backup restore (mock implementation)
    async fn initiate_backup_restore(&self) -> Result<String> {
        // In a real implementation, this would initiate backup restoration
        log::warn!("Initiating backup restore");
        Ok("Backup restore initiated successfully".to_string())
    }

    /// Enable enhanced monitoring (mock implementation)
    async fn enable_enhanced_monitoring(&self) -> Result<String> {
        // In a real implementation, this would enable enhanced monitoring
        log::info!("Enabling enhanced monitoring");
        Ok("Enhanced monitoring enabled".to_string())
    }

    /// Notify security team (mock implementation)
    async fn notify_security_team(&self) -> Result<String> {
        // In a real implementation, this would notify the security team
        log::warn!("Notifying security team");
        Ok("Security team notified successfully".to_string())
    }

    /// Create forensic snapshot (mock implementation)
    async fn create_forensic_snapshot(&self) -> Result<String> {
        // In a real implementation, this would create a forensic snapshot
        log::warn!("Creating forensic snapshot");
        Ok("Forensic snapshot created successfully".to_string())
    }

    /// Get response history
    pub async fn get_response_history(&self, limit: Option<usize>) -> Vec<ResponseAction> {
        let history = self.response_history.read().await;
        match limit {
            Some(limit) => history.iter().rev().take(limit).cloned().collect(),
            None => history.iter().rev().cloned().collect(),
        }
    }
}

impl Default for TamperDetectionConfig {
    fn default() -> Self {
        Self {
            enable_real_time_monitoring: true,
            monitoring_interval_seconds: 60,
            alert_channels: vec![AlertChannel::Email("security@company.com".to_string())],
            min_alert_severity: AlertSeverity::Warning,
            enable_automated_response: true,
            anomaly_sensitivity: AnomalySensitivity::Medium,
            evidence_collection_depth: EvidenceCollectionDepth::Standard,
            alert_retention_days: 90,
            max_alerts_per_hour: 100,
        }
    }
}

impl Default for TamperDetectionMetrics {
    fn default() -> Self {
        Self {
            total_alerts: 0,
            alerts_by_severity: HashMap::new(),
            alerts_by_type: HashMap::new(),
            false_positive_rate: 0.0,
            avg_detection_time_seconds: 0.0,
            avg_response_time_seconds: 0.0,
            active_alerts: 0,
            resolved_alerts: 0,
            last_detection: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secure_audit_merkle::*;

    #[tokio::test]
    async fn test_tamper_detection_system_creation() {
        let config = TamperDetectionConfig::default();
        let system = TamperDetectionSystem::new(config);
        
        let metrics = system.get_metrics().await;
        assert_eq!(metrics.total_alerts, 0);
        assert_eq!(metrics.active_alerts, 0);
    }

    #[tokio::test]
    async fn test_tampering_detection() {
        let config = TamperDetectionConfig::default();
        let system = TamperDetectionSystem::new(config);
        
        // Create a mock integrity report with tampering
        let integrity_report = IntegrityVerificationReport {
            verification_time: Utc::now(),
            total_entries: 100,
            valid_entries: 95,
            invalid_entries: 5,
            missing_entries: vec![10, 20, 30],
            tampered_entries: vec![
                TamperedEntry {
                    sequence_number: 15,
                    entry_id: "entry_15".to_string(),
                    tampering_type: TamperingType::HashMismatch,
                    description: "Hash mismatch detected".to_string(),
                }
            ],
            merkle_root_valid: false,
            signature_valid: false,
            chain_integrity_valid: false,
            anchor_verification: AnchorVerificationResult {
                anchor_found: false,
                anchor_timestamp: None,
                verification_successful: false,
                anchor_method: None,
                anchor_proof: None,
            },
        };

        let alerts = system.detect_tampering("test_log", &integrity_report).await.unwrap();
        assert!(!alerts.is_empty());
        
        // Should generate alerts for each type of tampering
        let alert_types: Vec<TamperAlertType> = alerts.iter().map(|a| a.alert_type.clone()).collect();
        assert!(alert_types.contains(&TamperAlertType::HashChainBroken));
        assert!(alert_types.contains(&TamperAlertType::InvalidSignature));
        assert!(alert_types.contains(&TamperAlertType::MerkleTreeCorruption));
        assert!(alert_types.contains(&TamperAlertType::MissingEntries));
    }

    #[tokio::test]
    async fn test_anomalous_pattern_detection() {
        let config = TamperDetectionConfig::default();
        let system = TamperDetectionSystem::new(config);
        
        // Create mock audit entries with anomalous patterns
        let entries = vec![
            SecureAuditEntry {
                entry_id: "1".to_string(),
                timestamp: Utc::now(),
                event_type: SecureAuditEventType::SecretAccess,
                principal: "user1".to_string(),
                resource: "secret1".to_string(),
                action: "read".to_string(),
                outcome: SecureAuditOutcome::Success,
                source_ip: Some("127.0.0.1".to_string()),
                user_agent: None,
                session_id: None,
                request_id: None,
                metadata: HashMap::new(),
                entry_hash: "hash1".to_string(),
                signature: "sig1".to_string(),
                key_fingerprint: "fp1".to_string(),
                previous_hash: None,
                sequence_number: 1,
            },
            SecureAuditEntry {
                entry_id: "2".to_string(),
                timestamp: Utc::now(),
                event_type: SecureAuditEventType::SecretAccess,
                principal: "user1".to_string(),
                resource: "secret1".to_string(),
                action: "read".to_string(),
                outcome: SecureAuditOutcome::Success,
                source_ip: Some("127.0.0.1".to_string()),
                user_agent: None,
                session_id: None,
                request_id: None,
                metadata: HashMap::new(),
                entry_hash: "hash2".to_string(),
                signature: "sig2".to_string(),
                key_fingerprint: "fp1".to_string(),
                previous_hash: Some("hash1".to_string()),
                sequence_number: 2,
            },
        ];

        let alerts = system.detect_anomalous_patterns(&entries).await.unwrap();
        // Should detect anomalous patterns (same user accessing same resource repeatedly)
        assert!(!alerts.is_empty());
    }

    #[tokio::test]
    async fn test_alert_processing() {
        let config = TamperDetectionConfig::default();
        let system = TamperDetectionSystem::new(config);
        
        let alert = system.create_alert(
            TamperAlertType::HashChainBroken,
            AlertSeverity::Critical,
            "Test alert".to_string(),
            "test_log".to_string(),
            vec![],
        ).await.unwrap();

        system.process_alert(alert.clone()).await.unwrap();

        // Check that alert is in active alerts
        let active_alerts = system.get_active_alerts().await;
        assert_eq!(active_alerts.len(), 1);
        assert_eq!(active_alerts[0].alert_id, alert.alert_id);

        // Check metrics
        let metrics = system.get_metrics().await;
        assert_eq!(metrics.total_alerts, 1);
        assert_eq!(metrics.active_alerts, 1);
    }

    #[tokio::test]
    async fn test_alert_acknowledgment_and_resolution() {
        let config = TamperDetectionConfig::default();
        let system = TamperDetectionSystem::new(config);
        
        let alert = system.create_alert(
            TamperAlertType::InvalidSignature,
            AlertSeverity::Warning,
            "Test alert".to_string(),
            "test_log".to_string(),
            vec![],
        ).await.unwrap();

        system.process_alert(alert.clone()).await.unwrap();
        
        // Acknowledge alert
        system.acknowledge_alert(&alert.alert_id).await.unwrap();
        
        let active_alerts = system.get_active_alerts().await;
        assert_eq!(active_alerts[0].status, AlertStatus::Acknowledged);

        // Resolve alert
        system.resolve_alert(&alert.alert_id, false).await.unwrap();
        
        let active_alerts_after = system.get_active_alerts().await;
        assert_eq!(active_alerts_after.len(), 0);
        
        let metrics = system.get_metrics().await;
        assert_eq!(metrics.active_alerts, 0);
        assert_eq!(metrics.resolved_alerts, 1);
    }

    #[tokio::test]
    async fn test_evidence_collection() {
        let collector = EvidenceCollector::new(EvidenceCollectionDepth::Standard);
        
        let evidence = collector.collect_evidence(
            &TamperAlertType::HashChainBroken,
            "test_log",
            &vec![],
        ).await.unwrap();

        assert!(!evidence.raw_data.is_empty());
        assert!(!evidence.analyzed_data.is_empty());
        assert!(evidence.confidence_level > 0.0);
        assert!(!evidence.evidence_hash.is_empty());
        assert_eq!(evidence.evidence_type, EvidenceType::HashMismatch);
    }

    #[tokio::test]
    async fn test_alert_notification() {
        let channel = AlertChannel::Email("test@example.com".to_string());
        let notifier = AlertNotifier::new(channel);
        
        let alert = TamperAlert {
            alert_id: "test_alert".to_string(),
            timestamp: Utc::now(),
            severity: AlertSeverity::Critical,
            alert_type: TamperAlertType::HashChainBroken,
            title: "Test Alert".to_string(),
            description: "Test description".to_string(),
            audit_log_id: "test_log".to_string(),
            affected_entries: vec!["entry1".to_string()],
            evidence: TamperingEvidence {
                evidence_type: EvidenceType::HashMismatch,
                raw_data: "test evidence".to_string(),
                analyzed_data: HashMap::new(),
                confidence_level: 0.9,
                collection_timestamp: Utc::now(),
                evidence_hash: "hash".to_string(),
            },
            recommended_actions: vec!["Action 1".to_string()],
            status: AlertStatus::New,
            notification_channels: vec![],
            metadata: HashMap::new(),
        };

        let result = notifier.send_alert(&alert).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_automated_response() {
        let coordinator = ResponseCoordinator::new();
        
        let alert = TamperAlert {
            alert_id: "test_alert".to_string(),
            timestamp: Utc::now(),
            severity: AlertSeverity::Critical,
            alert_type: TamperAlertType::HashChainBroken,
            title: "Test Alert".to_string(),
            description: "Test description".to_string(),
            audit_log_id: "test_log".to_string(),
            affected_entries: vec!["entry1".to_string()],
            evidence: TamperingEvidence {
                evidence_type: EvidenceType::HashMismatch,
                raw_data: "test evidence".to_string(),
                analyzed_data: HashMap::new(),
                confidence_level: 0.9,
                collection_timestamp: Utc::now(),
                evidence_hash: "hash".to_string(),
            },
            recommended_actions: vec!["Action 1".to_string()],
            status: AlertStatus::New,
            notification_channels: vec![],
            metadata: HashMap::new(),
        };

        let actions = coordinator.execute_response(&alert).await.unwrap();
        assert!(!actions.is_empty());
        
        // Should execute default actions for HashChainBroken
        assert_eq!(actions.len(), 3); // IsolateSystem, CreateForensicSnapshot, NotifySecurityTeam
        
        for action in &actions {
            assert_eq!(action.status, ResponseStatus::Completed);
            assert!(action.result.is_some());
        }
    }
}
