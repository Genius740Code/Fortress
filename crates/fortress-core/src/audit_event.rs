//! Audit event structures for compliance integration

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Simplified audit event for compliance integration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    /// Unique identifier for the audit event
    pub id: String,
    /// Timestamp when the event occurred
    pub timestamp: DateTime<Utc>,
    /// Type of audit event (e.g., "key_created", "data_accessed")
    pub event_type: String,
    /// ID of the user who performed the action
    pub user_id: Option<String>,
    /// ID of the resource that was accessed or modified
    pub resource_id: Option<String>,
    /// Outcome of the operation (e.g., "success", "failure", "denied")
    pub outcome: String,
    /// Additional details about the event as key-value pairs
    pub details: HashMap<String, String>,
}
