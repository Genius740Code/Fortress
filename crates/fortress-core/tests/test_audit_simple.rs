//! Simple integration tests for audit logging system

use fortress_core::audit::{
    AuditConfig, AuditEventType, SecurityLevel, EventOutcome,
    DefaultAuditLogger, log_event_with_metadata,
};
use std::collections::HashMap;

#[test]
fn test_audit_entry_creation() {
    let mut config = AuditConfig::default();
    // Generate a test HMAC key
    use base64::{Engine as _, engine::general_purpose};
    let hmac_key = general_purpose::STANDARD.encode("test_hmac_key_32_bytes_long_1234");
    config.hmac_key = Some(hmac_key);

    let _logger = DefaultAuditLogger::new(config).unwrap();
    
    let mut metadata = HashMap::new();
    metadata.insert("test_field".to_string(), "test_value".to_string());
    
    // Test logging an event instead of directly creating an entry
    let result = log_event_with_metadata(
        AuditEventType::Authentication,
        SecurityLevel::High,
        Some("test_user".to_string()),
        Some("/login".to_string()),
        "user_login".to_string(),
        EventOutcome::Success,
        metadata,
    );
    
    assert!(result.is_ok());
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
    assert_eq!(format!("{}", EventOutcome::Blocked), "Blocked");
    assert_eq!(format!("{}", EventOutcome::RequiresReview), "RequiresReview");
}

#[test]
fn test_security_level_display() {
    assert_eq!(format!("{}", SecurityLevel::Low), "Low");
    assert_eq!(format!("{}", SecurityLevel::Medium), "Medium");
    assert_eq!(format!("{}", SecurityLevel::High), "High");
    assert_eq!(format!("{}", SecurityLevel::Critical), "Critical");
}
