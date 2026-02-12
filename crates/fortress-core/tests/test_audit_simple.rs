//! Simple integration tests for audit logging system

use fortress_core::audit::{
    AuditConfig, AuditEntry, AuditEventType, SecurityLevel, EventOutcome,
    DefaultAuditLogger, init_audit_logger, log_event_with_metadata,
};
use std::collections::HashMap;

#[test]
fn test_audit_entry_creation() {
    let mut config = AuditConfig::default();
    // Generate a test HMAC key
    let hmac_key = base64::encode("test_hmac_key_32_bytes_long_1234");
    config.hmac_key = Some(hmac_key);

    let mut logger = DefaultAuditLogger::new(config).unwrap();
    
    let mut metadata = HashMap::new();
    metadata.insert("test_field".to_string(), "test_value".to_string());
    
    let entry = logger.create_entry(
        AuditEventType::Authentication,
        SecurityLevel::High,
        Some("test_user".to_string()),
        Some("/login".to_string()),
        "user_login".to_string(),
        EventOutcome::Success,
        metadata,
    ).unwrap();

    assert!(!entry.id.is_empty());
    assert!(!entry.current_hash.is_empty());
    assert!(!entry.signature.is_empty());
    assert_eq!(entry.event_type, AuditEventType::Authentication);
    assert_eq!(entry.security_level, SecurityLevel::High);
    assert_eq!(entry.principal, Some("test_user".to_string()));
    assert_eq!(entry.resource, Some("/login".to_string()));
    assert_eq!(entry.action, "user_login");
    assert_eq!(entry.outcome, EventOutcome::Success);
    assert_eq!(entry.metadata.get("test_field"), Some(&"test_value".to_string()));
}

#[test]
fn test_audit_config_defaults() {
    let config = AuditConfig::default();
    assert!(config.enabled);
    assert_eq!(config.min_security_level, SecurityLevel::Low);
    assert_eq!(config.retention_days, 90);
    assert!(config.tamper_evident);
    assert!(config.enable_rotation);
    assert_eq!(config.max_file_size, 100 * 1024 * 1024); // 100MB
    assert_eq!(config.max_rotated_files, 10);
}

#[test]
fn test_security_level_ordering() {
    assert!(SecurityLevel::Low < SecurityLevel::Medium);
    assert!(SecurityLevel::Medium < SecurityLevel::High);
    assert!(SecurityLevel::High < SecurityLevel::Critical);
}

#[test]
fn test_event_outcome_display() {
    assert_eq!(format!("{}", EventOutcome::Success), "Success");
    assert_eq!(format!("{}", EventOutcome::Failure), "Failure");
    assert_eq!(format!("{}", EventOutcome::Denied), "Denied");
    assert_eq!(format!("{}", EventOutcome::Error), "Error");
}

#[test]
fn test_security_level_display() {
    assert_eq!(format!("{}", SecurityLevel::Low), "Low");
    assert_eq!(format!("{}", SecurityLevel::Medium), "Medium");
    assert_eq!(format!("{}", SecurityLevel::High), "High");
    assert_eq!(format!("{}", SecurityLevel::Critical), "Critical");
}
