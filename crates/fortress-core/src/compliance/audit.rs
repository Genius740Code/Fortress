//! Compliance Audit Logging Module
//!
//! Provides comprehensive audit logging capabilities for compliance frameworks
//! with structured logging, retention policies, and audit trail integrity.

use crate::error::Result;
use crate::compliance::framework::*;
use async_trait::async_trait;
use chrono::{DateTime, Utc, Duration};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

/// Audit logger for compliance events
pub struct ComplianceAuditLogger {
    storage: Box<dyn AuditStorage>,
    retention_policy: RetentionPolicy,
    integrity_checker: Box<dyn IntegrityChecker>,
}

/// Audit storage trait
#[async_trait]
pub trait AuditStorage: Send + Sync {
    async fn store_event(&self, event: &AuditEvent) -> Result<()>;
    async fn retrieve_events(&self, filter: &AuditFilter) -> Result<Vec<AuditEvent>>;
    async fn delete_old_events(&self, before: DateTime<Utc>) -> Result<u64>;
}

/// Integrity checker trait
#[async_trait]
pub trait IntegrityChecker: Send + Sync {
    async fn verify_integrity(&self, events: &[AuditEvent]) -> Result<IntegrityReport>;
    async fn generate_checksum(&self, events: &[AuditEvent]) -> Result<String>;
}

/// Retention policy for audit events
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetentionPolicy {
    /// Default number of days to retain events
    pub default_retention_days: u32,
    /// Framework-specific retention periods
    pub framework_retentions: HashMap<ComplianceFramework, u32>,
    /// Event type-specific retention periods
    pub event_type_retentions: HashMap<String, u32>,
    /// Whether automatic cleanup is enabled
    pub auto_cleanup_enabled: bool,
    /// Interval in hours for cleanup runs
    pub cleanup_interval_hours: u32,
}

/// Audit filter for retrieving audit events
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditFilter {
    /// Start date for filtering events (inclusive)
    pub start_date: Option<DateTime<Utc>>,
    /// End date for filtering events (inclusive)
    pub end_date: Option<DateTime<Utc>>,
    /// Compliance frameworks to filter by
    pub frameworks: Vec<ComplianceFramework>,
    /// Event types to filter by
    pub event_types: Vec<String>,
    /// Event severities to filter by
    pub severities: Vec<EventSeverity>,
    /// Users to filter by
    pub users: Vec<String>,
    /// Resources to filter by
    pub resources: Vec<String>,
    /// Maximum number of events to return
    pub limit: Option<u32>,
}

/// Comprehensive audit event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    /// Unique identifier for the audit event
    pub id: Uuid,
    /// Timestamp when the event occurred
    pub timestamp: DateTime<Utc>,
    /// Sequential number for event ordering
    pub sequence_number: u64,
    /// Compliance framework this event belongs to
    pub framework: ComplianceFramework,
    /// Type of audit event
    pub event_type: String,
    /// Severity level of the event
    pub severity: EventSeverity,
    /// ID of the user who performed the action
    pub user_id: Option<String>,
    /// Session identifier for the user session
    pub session_id: Option<String>,
    /// IP address of the source
    pub source_ip: Option<String>,
    /// User agent string from client
    pub user_agent: Option<String>,
    /// Action that was performed
    pub action: String,
    /// Type of resource that was accessed
    pub resource_type: String,
    /// ID of the specific resource accessed
    pub resource_id: Option<String>,
    /// Outcome of the action (success/failure)
    pub outcome: EventOutcome,
    /// Human-readable description of the event
    pub description: String,
    /// Additional metadata about the event
    pub details: HashMap<String, String>,
    /// List of affected data subjects (e.g., user IDs)
    pub affected_data_subjects: Vec<String>,
    /// Legal basis for processing (GDPR)
    pub legal_basis: Option<String>,
    /// Consent identifier for data processing
    pub consent_id: Option<String>,
    /// Number of days this event should be retained
    pub retention_period_days: Option<u32>,
    /// Checksum for integrity verification
    pub checksum: Option<String>,
    /// ID of the previous event in a sequence
    pub previous_event_id: Option<Uuid>,
}

/// Integrity report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntegrityReport {
    /// Timestamp when the integrity check was performed
    pub check_timestamp: DateTime<Utc>,
    /// Total number of events that were checked
    pub total_events_checked: u64,
    /// Whether the integrity check passed overall
    pub integrity_passed: bool,
    /// List of missing event IDs
    pub missing_events: Vec<Uuid>,
    /// List of events that appear to have been tampered with
    pub tampered_events: Vec<Uuid>,
    /// List of events with checksum mismatches
    pub checksum_mismatches: Vec<Uuid>,
    /// Recommendations for fixing integrity issues
    pub recommendations: Vec<String>,
}

impl ComplianceAuditLogger {
    /// Create a new compliance audit logger
    /// 
    /// # Arguments
    /// * `storage` - Storage backend for audit events
    /// * `retention_policy` - Policy for event retention
    /// * `integrity_checker` - Checker for verifying event integrity
    pub fn new(
        storage: Box<dyn AuditStorage>,
        retention_policy: RetentionPolicy,
        integrity_checker: Box<dyn IntegrityChecker>,
    ) -> Self {
        Self {
            storage,
            retention_policy,
            integrity_checker,
        }
    }

    /// Log a compliance event to the audit trail
    /// 
    /// # Arguments
    /// * `event` - The compliance event to log
    pub async fn log_event(&self, event: &ComplianceEvent) -> Result<()> {
        let audit_event = self.convert_to_audit_event(event).await?;
        
        // Store the event
        self.storage.store_event(&audit_event).await?;
        
        // If this is a critical event, trigger immediate integrity check
        if matches!(event.severity, EventSeverity::Critical) {
            self.verify_recent_events().await?;
        }
        
        Ok(())
    }

    async fn convert_to_audit_event(&self, event: &ComplianceEvent) -> Result<AuditEvent> {
        let retention_days = self.determine_retention_period(event);
        
        Ok(AuditEvent {
            id: event.id,
            timestamp: event.timestamp,
            sequence_number: 0, // Will be assigned by storage
            framework: event.framework.clone(),
            event_type: event.event_type.clone(),
            severity: event.severity.clone(),
            user_id: Some(event.actor.clone()),
            session_id: None,
            source_ip: None,
            user_agent: None,
            action: "compliance_event".to_string(),
            resource_type: "compliance".to_string(),
            resource_id: Some(event.affected_resources.first().cloned().unwrap_or_default()),
            outcome: event.outcome.clone(),
            description: event.description.clone(),
            details: event.metadata.clone(),
            affected_data_subjects: vec![],
            legal_basis: None,
            consent_id: None,
            retention_period_days: Some(retention_days),
            checksum: None,
            previous_event_id: None,
        })
    }

    fn determine_retention_period(&self, event: &ComplianceEvent) -> u32 {
        // Check framework-specific retention
        if let Some(days) = self.retention_policy.framework_retentions.get(&event.framework) {
            return *days;
        }
        
        // Check event type-specific retention
        if let Some(days) = self.retention_policy.event_type_retentions.get(&event.event_type) {
            return *days;
        }
        
        // Use default retention
        self.retention_policy.default_retention_days
    }

    /// Retrieve audit trail events based on filter criteria
    /// 
    /// # Arguments
    /// * `filter` - Filter criteria for retrieving events
    /// 
    /// # Returns
    /// Vector of audit events matching the filter
    pub async fn retrieve_audit_trail(&self, filter: &AuditFilter) -> Result<Vec<AuditEvent>> {
        self.storage.retrieve_events(filter).await
    }

    /// Verify the integrity of audit events
    /// 
    /// # Arguments
    /// * `filter` - Optional filter for events to check (None checks all)
    /// 
    /// # Returns
    /// Integrity report with findings and recommendations
    pub async fn verify_integrity(&self, filter: Option<&AuditFilter>) -> Result<IntegrityReport> {
        let events = if let Some(f) = filter {
            self.storage.retrieve_events(f).await?
        } else {
            // Get all events for full integrity check
            self.storage.retrieve_events(&AuditFilter {
                start_date: None,
                end_date: None,
                frameworks: vec![],
                event_types: vec![],
                severities: vec![],
                users: vec![],
                resources: vec![],
                limit: None,
            }).await?
        };

        self.integrity_checker.verify_integrity(&events).await
    }

    async fn verify_recent_events(&self) -> Result<()> {
        let recent_filter = AuditFilter {
            start_date: Some(Utc::now() - Duration::hours(24)),
            end_date: Some(Utc::now()),
            frameworks: vec![],
            event_types: vec![],
            severities: vec![EventSeverity::Critical, EventSeverity::Error],
            users: vec![],
            resources: vec![],
            limit: Some(1000),
        };

        let integrity_report = self.verify_integrity(Some(&recent_filter)).await?;
        
        if !integrity_report.integrity_passed {
            log::error!("Audit integrity check failed: {:?}", integrity_report);
            
            // Create alert for integrity failure
            let alert_event = ComplianceEvent {
                id: Uuid::new_v4(),
                timestamp: Utc::now(),
                framework: ComplianceFramework::GDPR, // Use GDPR as it has strict audit requirements
                event_type: "audit_integrity_failure".to_string(),
                severity: EventSeverity::Critical,
                description: "Audit trail integrity check failed".to_string(),
                affected_resources: vec![],
                actor: "system".to_string(),
                outcome: EventOutcome::Failure,
                metadata: HashMap::new(),
            };
            
            // Log the alert (without infinite recursion)
            let audit_event = self.convert_to_audit_event(&alert_event).await?;
            self.storage.store_event(&audit_event).await?;
        }
        
        Ok(())
    }

    /// Clean up old audit events based on retention policy
    /// 
    /// # Returns
    /// Number of events that were cleaned up
    pub async fn cleanup_old_events(&self) -> Result<u64> {
        if !self.retention_policy.auto_cleanup_enabled {
            return Ok(0);
        }

        let cutoff_date = Utc::now() - Duration::days(self.retention_policy.default_retention_days as i64);
        self.storage.delete_old_events(cutoff_date).await
    }
}

/// Default audit storage implementation
pub struct DefaultAuditStorage {
    /// Thread-safe storage for audit events
    events: std::sync::Arc<tokio::sync::RwLock<Vec<AuditEvent>>>,
}

impl DefaultAuditStorage {
    /// Create a new default audit storage instance
    pub fn new() -> Self {
        Self {
            events: std::sync::Arc::new(tokio::sync::RwLock::new(Vec::new())),
        }
    }
}

impl Default for DefaultAuditStorage {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl AuditStorage for DefaultAuditStorage {
    async fn store_event(&self, event: &AuditEvent) -> Result<()> {
        let mut events = self.events.write().await;
        let new_event = AuditEvent {
            id: event.id,
            timestamp: event.timestamp,
            sequence_number: events.len() as u64,
            framework: event.framework.clone(),
            event_type: event.event_type.clone(),
            severity: event.severity.clone(),
            user_id: event.user_id.clone(),
            session_id: event.session_id.clone(),
            source_ip: event.source_ip.clone(),
            user_agent: event.user_agent.clone(),
            action: event.action.clone(),
            resource_type: event.resource_type.clone(),
            resource_id: event.resource_id.clone(),
            outcome: event.outcome.clone(),
            description: event.description.clone(),
            details: event.details.clone(),
            affected_data_subjects: event.affected_data_subjects.clone(),
            legal_basis: event.legal_basis.clone(),
            consent_id: event.consent_id.clone(),
            retention_period_days: event.retention_period_days,
            checksum: event.checksum.clone(),
            previous_event_id: event.previous_event_id,
        };
        events.push(new_event);
        Ok(())
    }

    async fn retrieve_events(&self, filter: &AuditFilter) -> Result<Vec<AuditEvent>> {
        let events = self.events.read().await;
        
        let filtered_events: Vec<AuditEvent> = events
            .iter()
            .filter(|e| {
                // Date range filter
                if let Some(start) = filter.start_date {
                    if e.timestamp < start {
                        return false;
                    }
                }
                if let Some(end) = filter.end_date {
                    if e.timestamp > end {
                        return false;
                    }
                }
                
                // Framework filter
                if !filter.frameworks.is_empty() && !filter.frameworks.contains(&e.framework) {
                    return false;
                }
                
                // Event type filter
                if !filter.event_types.is_empty() && !filter.event_types.contains(&e.event_type) {
                    return false;
                }
                
                // Severity filter
                if !filter.severities.is_empty() && !filter.severities.contains(&e.severity) {
                    return false;
                }
                
                // User filter
                if !filter.users.is_empty() {
                    if let Some(user_id) = &e.user_id {
                        if !filter.users.contains(user_id) {
                            return false;
                        }
                    } else {
                        return false;
                    }
                }
                
                // Resource filter
                if !filter.resources.is_empty() {
                    if let Some(resource_id) = &e.resource_id {
                        if !filter.resources.contains(resource_id) {
                            return false;
                        }
                    } else {
                        return false;
                    }
                }
                
                true
            })
            .cloned()
            .take(filter.limit.unwrap_or(u32::MAX) as usize)
            .collect();
        
        Ok(filtered_events)
    }

    async fn delete_old_events(&self, before: DateTime<Utc>) -> Result<u64> {
        let mut events = self.events.write().await;
        let initial_count = events.len();
        events.retain(|e| e.timestamp >= before);
        let deleted_count = initial_count - events.len();
        Ok(deleted_count as u64)
    }
}

/// Default integrity checker
pub struct DefaultIntegrityChecker;

impl Default for DefaultIntegrityChecker {
    fn default() -> Self {
        Self
    }
}

#[async_trait]
impl IntegrityChecker for DefaultIntegrityChecker {
    async fn verify_integrity(&self, events: &[AuditEvent]) -> Result<IntegrityReport> {
        let mut missing_events = Vec::new();
        let tampered_events = Vec::new();
        let mut checksum_mismatches = Vec::new();
        
        // Check for sequence number gaps
        if !events.is_empty() {
            let mut expected_seq = 0;
            for event in events {
                if event.sequence_number != expected_seq {
                    missing_events.push(event.id);
                }
                expected_seq = event.sequence_number + 1;
            }
        }
        
        // Verify checksums
        for event in events {
            if let Some(stored_checksum) = &event.checksum {
                let calculated_checksum = self.generate_checksum(&[event.clone()]).await?;
                if stored_checksum != &calculated_checksum {
                    checksum_mismatches.push(event.id);
                }
            }
        }
        
        let integrity_passed = missing_events.is_empty() 
            && tampered_events.is_empty() 
            && checksum_mismatches.is_empty();
        
        let mut recommendations = Vec::new();
        if !missing_events.is_empty() {
            recommendations.push("Investigate missing audit events".to_string());
        }
        if !checksum_mismatches.is_empty() {
            recommendations.push("Review events with checksum mismatches".to_string());
        }
        if integrity_passed {
            recommendations.push("Audit trail integrity verified".to_string());
        }
        
        Ok(IntegrityReport {
            check_timestamp: Utc::now(),
            total_events_checked: events.len() as u64,
            integrity_passed,
            missing_events,
            tampered_events,
            checksum_mismatches,
            recommendations,
        })
    }

    async fn generate_checksum(&self, events: &[AuditEvent]) -> Result<String> {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        
        let mut hasher = DefaultHasher::new();
        
        for event in events {
            event.id.hash(&mut hasher);
            event.timestamp.hash(&mut hasher);
            event.sequence_number.hash(&mut hasher);
            event.framework.hash(&mut hasher);
            event.event_type.hash(&mut hasher);
            event.severity.hash(&mut hasher);
            event.action.hash(&mut hasher);
            event.outcome.hash(&mut hasher);
        }
        
        Ok(format!("{:x}", hasher.finish()))
    }
}
