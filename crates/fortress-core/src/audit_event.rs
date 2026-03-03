//! Audit event structures for compliance integration

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Simplified audit event for compliance integration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    pub id: String,
    pub timestamp: DateTime<Utc>,
    pub event_type: String,
    pub user_id: Option<String>,
    pub resource_id: Option<String>,
    pub outcome: String,
    pub details: HashMap<String, String>,
}
