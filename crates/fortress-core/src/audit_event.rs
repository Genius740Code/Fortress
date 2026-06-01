//! Audit event structures for compliance integration

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

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

impl AuditEvent {
    /// Create a new audit event
    pub fn new(
        event_type: String,
        user_id: Option<String>,
        resource_id: Option<String>,
        outcome: String,
    ) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            timestamp: Utc::now(),
            event_type,
            user_id,
            resource_id,
            outcome,
            details: HashMap::new(),
        }
    }

    /// Add a detail to the event
    pub fn add_detail(mut self, key: String, value: String) -> Self {
        self.details.insert(key, value);
        self
    }

    /// Add multiple details to the event
    pub fn add_details(mut self, details: HashMap<String, String>) -> Self {
        self.details.extend(details);
        self
    }

    /// Get a detail value by key
    pub fn get_detail(&self, key: &str) -> Option<&String> {
        self.details.get(key)
    }

    /// Check if the event was successful
    pub fn is_success(&self) -> bool {
        self.outcome == "success"
    }

    /// Check if the event failed
    pub fn is_failure(&self) -> bool {
        self.outcome == "failure"
    }

    /// Check if the event was denied
    pub fn is_denied(&self) -> bool {
        self.outcome == "denied"
    }

    /// Get the age of the event in seconds
    pub fn age_seconds(&self) -> i64 {
        Utc::now()
            .signed_duration_since(self.timestamp)
            .num_seconds()
    }

    /// Create a key creation event
    pub fn key_created(user_id: String, key_id: String, algorithm: String) -> Self {
        Self::new(
            "key_created".to_string(),
            Some(user_id),
            Some(key_id),
            "success".to_string(),
        )
        .add_detail("algorithm".to_string(), algorithm)
    }

    /// Create a data access event
    pub fn data_accessed(user_id: String, resource_id: String, access_type: String) -> Self {
        Self::new(
            "data_accessed".to_string(),
            Some(user_id),
            Some(resource_id),
            "success".to_string(),
        )
        .add_detail("access_type".to_string(), access_type)
    }

    /// Create a login event
    pub fn login(user_id: String, outcome: String, ip_address: Option<String>) -> Self {
        let mut event = Self::new("login".to_string(), Some(user_id), None, outcome);

        if let Some(ip) = ip_address {
            event = event.add_detail("ip_address".to_string(), ip);
        }

        event
    }

    /// Create a permission denied event
    pub fn permission_denied(user_id: String, resource_id: String, permission: String) -> Self {
        Self::new(
            "permission_denied".to_string(),
            Some(user_id),
            Some(resource_id),
            "denied".to_string(),
        )
        .add_detail("permission".to_string(), permission)
    }

    /// Create a system error event
    pub fn system_error(error_code: String, error_message: String, component: String) -> Self {
        Self::new(
            "system_error".to_string(),
            None,
            None,
            "failure".to_string(),
        )
        .add_detail("error_code".to_string(), error_code)
        .add_detail("error_message".to_string(), error_message)
        .add_detail("component".to_string(), component)
    }
}

impl Default for AuditEvent {
    fn default() -> Self {
        Self::new("unknown".to_string(), None, None, "unknown".to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn test_audit_event_creation() {
        let event = AuditEvent::new(
            "test_event".to_string(),
            Some("user123".to_string()),
            Some("resource456".to_string()),
            "success".to_string(),
        );

        assert_eq!(event.event_type, "test_event");
        assert_eq!(event.user_id, Some("user123".to_string()));
        assert_eq!(event.resource_id, Some("resource456".to_string()));
        assert_eq!(event.outcome, "success");
        assert!(!event.id.is_empty());
        assert!(event.details.is_empty());
    }

    #[test]
    fn test_audit_event_with_details() {
        let mut details = HashMap::new();
        details.insert("key1".to_string(), "value1".to_string());
        details.insert("key2".to_string(), "value2".to_string());

        let event = AuditEvent::new("test_event".to_string(), None, None, "failure".to_string())
            .add_details(details)
            .add_detail("key3".to_string(), "value3".to_string());

        assert_eq!(event.get_detail("key1"), Some(&"value1".to_string()));
        assert_eq!(event.get_detail("key2"), Some(&"value2".to_string()));
        assert_eq!(event.get_detail("key3"), Some(&"value3".to_string()));
        assert_eq!(event.get_detail("nonexistent"), None);
        assert_eq!(event.details.len(), 3);
    }

    #[test]
    fn test_audit_event_outcome_checks() {
        let success_event = AuditEvent::new("test".to_string(), None, None, "success".to_string());
        assert!(success_event.is_success());
        assert!(!success_event.is_failure());
        assert!(!success_event.is_denied());

        let failure_event = AuditEvent::new("test".to_string(), None, None, "failure".to_string());
        assert!(!failure_event.is_success());
        assert!(failure_event.is_failure());
        assert!(!failure_event.is_denied());

        let denied_event = AuditEvent::new("test".to_string(), None, None, "denied".to_string());
        assert!(!denied_event.is_success());
        assert!(!denied_event.is_failure());
        assert!(denied_event.is_denied());
    }

    #[test]
    fn test_audit_event_age() {
        let event = AuditEvent::new("test".to_string(), None, None, "success".to_string());

        // Age should be very small (less than 1 second)
        let age = event.age_seconds();
        assert!(age >= 0);
        assert!(age < 1);
    }

    #[test]
    fn test_key_created_event() {
        let event = AuditEvent::key_created(
            "user123".to_string(),
            "key456".to_string(),
            "AES-256".to_string(),
        );

        assert_eq!(event.event_type, "key_created");
        assert_eq!(event.user_id, Some("user123".to_string()));
        assert_eq!(event.resource_id, Some("key456".to_string()));
        assert_eq!(event.outcome, "success");
        assert_eq!(event.get_detail("algorithm"), Some(&"AES-256".to_string()));
    }

    #[test]
    fn test_data_accessed_event() {
        let event = AuditEvent::data_accessed(
            "user123".to_string(),
            "resource456".to_string(),
            "read".to_string(),
        );

        assert_eq!(event.event_type, "data_accessed");
        assert_eq!(event.user_id, Some("user123".to_string()));
        assert_eq!(event.resource_id, Some("resource456".to_string()));
        assert_eq!(event.outcome, "success");
        assert_eq!(event.get_detail("access_type"), Some(&"read".to_string()));
    }

    #[test]
    fn test_login_event() {
        let event = AuditEvent::login(
            "user123".to_string(),
            "success".to_string(),
            Some("192.168.1.1".to_string()),
        );

        assert_eq!(event.event_type, "login");
        assert_eq!(event.user_id, Some("user123".to_string()));
        assert_eq!(event.outcome, "success");
        assert_eq!(
            event.get_detail("ip_address"),
            Some(&"192.168.1.1".to_string())
        );

        // Test login without IP address
        let event_no_ip = AuditEvent::login("user123".to_string(), "failure".to_string(), None);
        assert_eq!(event_no_ip.get_detail("ip_address"), None);
    }

    #[test]
    fn test_permission_denied_event() {
        let event = AuditEvent::permission_denied(
            "user123".to_string(),
            "resource456".to_string(),
            "admin".to_string(),
        );

        assert_eq!(event.event_type, "permission_denied");
        assert_eq!(event.user_id, Some("user123".to_string()));
        assert_eq!(event.resource_id, Some("resource456".to_string()));
        assert_eq!(event.outcome, "denied");
        assert_eq!(event.get_detail("permission"), Some(&"admin".to_string()));
    }

    #[test]
    fn test_system_error_event() {
        let event = AuditEvent::system_error(
            "E001".to_string(),
            "Database connection failed".to_string(),
            "database".to_string(),
        );

        assert_eq!(event.event_type, "system_error");
        assert_eq!(event.user_id, None);
        assert_eq!(event.resource_id, None);
        assert_eq!(event.outcome, "failure");
        assert_eq!(event.get_detail("error_code"), Some(&"E001".to_string()));
        assert_eq!(
            event.get_detail("error_message"),
            Some(&"Database connection failed".to_string())
        );
        assert_eq!(event.get_detail("component"), Some(&"database".to_string()));
    }

    #[test]
    fn test_audit_event_serialization() {
        let event = AuditEvent::new(
            "test_event".to_string(),
            Some("user123".to_string()),
            Some("resource456".to_string()),
            "success".to_string(),
        )
        .add_detail("test_key".to_string(), "test_value".to_string());

        // Test serialization to JSON
        let json = serde_json::to_string(&event).expect("Failed to serialize event");
        assert!(!json.is_empty());

        // Test deserialization from JSON
        let deserialized: AuditEvent =
            serde_json::from_str(&json).expect("Failed to deserialize event");
        assert_eq!(deserialized.event_type, event.event_type);
        assert_eq!(deserialized.user_id, event.user_id);
        assert_eq!(deserialized.resource_id, event.resource_id);
        assert_eq!(deserialized.outcome, event.outcome);
        assert_eq!(
            deserialized.get_detail("test_key"),
            Some(&"test_value".to_string())
        );
    }

    #[test]
    fn test_audit_event_default() {
        let event = AuditEvent::default();

        assert_eq!(event.event_type, "unknown");
        assert_eq!(event.user_id, None);
        assert_eq!(event.resource_id, None);
        assert_eq!(event.outcome, "unknown");
        assert!(!event.id.is_empty());
        assert!(event.details.is_empty());
    }

    #[test]
    fn test_audit_event_clone() {
        let original = AuditEvent::new(
            "test_event".to_string(),
            Some("user123".to_string()),
            Some("resource456".to_string()),
            "success".to_string(),
        )
        .add_detail("key".to_string(), "value".to_string());

        let cloned = original.clone();

        assert_eq!(original.id, cloned.id);
        assert_eq!(original.event_type, cloned.event_type);
        assert_eq!(original.user_id, cloned.user_id);
        assert_eq!(original.resource_id, cloned.resource_id);
        assert_eq!(original.outcome, cloned.outcome);
        assert_eq!(original.details, cloned.details);
    }

    #[test]
    fn test_audit_event_debug_format() {
        let event = AuditEvent::new(
            "test_event".to_string(),
            Some("user123".to_string()),
            Some("resource456".to_string()),
            "success".to_string(),
        );

        let debug_str = format!("{:?}", event);
        assert!(debug_str.contains("AuditEvent"));
        assert!(debug_str.contains("test_event"));
        assert!(debug_str.contains("user123"));
        assert!(debug_str.contains("resource456"));
        assert!(debug_str.contains("success"));
    }

    #[test]
    fn test_multiple_details_addition() {
        let event = AuditEvent::new("test".to_string(), None, None, "success".to_string())
            .add_detail("key1".to_string(), "value1".to_string())
            .add_detail("key2".to_string(), "value2".to_string())
            .add_detail("key3".to_string(), "value3".to_string());

        assert_eq!(event.details.len(), 3);
        assert_eq!(event.get_detail("key1"), Some(&"value1".to_string()));
        assert_eq!(event.get_detail("key2"), Some(&"value2".to_string()));
        assert_eq!(event.get_detail("key3"), Some(&"value3".to_string()));
    }

    #[test]
    fn test_audit_event_with_empty_details() {
        let empty_details = HashMap::new();
        let event = AuditEvent::new("test".to_string(), None, None, "success".to_string())
            .add_details(empty_details);

        assert!(event.details.is_empty());
    }

    #[test]
    fn test_complex_audit_event_scenario() {
        // Create a comprehensive audit event for a complex scenario
        let mut details = HashMap::new();
        details.insert("source_ip".to_string(), "192.168.1.100".to_string());
        details.insert("user_agent".to_string(), "Mozilla/5.0".to_string());
        details.insert("request_id".to_string(), "req-12345".to_string());
        details.insert("duration_ms".to_string(), "150".to_string());

        let event = AuditEvent::new(
            "api_request".to_string(),
            Some("user123".to_string()),
            Some("api-endpoint-456".to_string()),
            "success".to_string(),
        )
        .add_details(details)
        .add_detail("auth_method".to_string(), "jwt".to_string())
        .add_detail("permissions_used".to_string(), "read,write".to_string());

        // Verify all aspects of the complex event
        assert_eq!(event.event_type, "api_request");
        assert_eq!(event.user_id, Some("user123".to_string()));
        assert_eq!(event.resource_id, Some("api-endpoint-456".to_string()));
        assert!(event.is_success());
        assert!(!event.is_failure());
        assert!(!event.is_denied());

        // Verify all details are present
        assert_eq!(event.details.len(), 6);
        assert_eq!(
            event.get_detail("source_ip"),
            Some(&"192.168.1.100".to_string())
        );
        assert_eq!(
            event.get_detail("user_agent"),
            Some(&"Mozilla/5.0".to_string())
        );
        assert_eq!(
            event.get_detail("request_id"),
            Some(&"req-12345".to_string())
        );
        assert_eq!(event.get_detail("duration_ms"), Some(&"150".to_string()));
        assert_eq!(event.get_detail("auth_method"), Some(&"jwt".to_string()));
        assert_eq!(
            event.get_detail("permissions_used"),
            Some(&"read,write".to_string())
        );
    }

    #[test]
    fn test_audit_event_timestamp_consistency() {
        let event1 = AuditEvent::new("test1".to_string(), None, None, "success".to_string());

        // Wait a tiny bit to ensure different timestamps
        std::thread::sleep(std::time::Duration::from_millis(1));

        let event2 = AuditEvent::new("test2".to_string(), None, None, "success".to_string());

        // Event 2 should have a later timestamp
        assert!(event2.timestamp > event1.timestamp);
        assert!(event2.age_seconds() < event1.age_seconds());
    }
}
