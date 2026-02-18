//! Comprehensive integration tests for the audit logging system
//!
//! This test suite validates the complete audit logging functionality including:
//! - Tamper-evident logging with hash chains
//! - HMAC signature verification
//! - Log querying and filtering
//! - Integrity verification
//! - Statistics collection
//! - Log rotation

use std::collections::HashMap;
use std::fs;
use std::thread;
use std::time::Duration;

use fortress_core::audit::{
    AuditConfig, AuditEntry, AuditEventType, SecurityLevel, EventOutcome,
    DefaultAuditLogger, AuditLogger, AuditQuery, init_audit_logger,
    log_event_with_metadata,
};
use fortress_core::audit_analysis::{AuditAnalyzer, SecurityAnomaly};
use tempfile::TempDir;

#[test]
fn test_complete_audit_workflow() {
    let temp_dir = TempDir::new().unwrap();
    let log_path = temp_dir.path().join("test_audit.log");
    
    // Create audit configuration
    let mut config = AuditConfig::default();
    config.log_path = Some(log_path.to_string_lossy().to_string());
    config.hmac_key = Some(base64::encode("test_hmac_key_32_bytes_long_1234"));
    config.enabled = true;
    config.tamper_evident = true;
    config.enable_rotation = false; // Disable rotation for this test

    // Create audit logger
    let mut logger = DefaultAuditLogger::new(config).unwrap();

    // Create test audit entries
    let entries = vec![
        create_test_entry(
            AuditEventType::Authentication,
            SecurityLevel::High,
            Some("user1".to_string()),
            Some("/login".to_string()),
            "user_login".to_string(),
            EventOutcome::Success,
        ),
        create_test_entry(
            AuditEventType::DataAccess,
            SecurityLevel::Medium,
            Some("user1".to_string()),
            Some("/api/data".to_string()),
            "data_read".to_string(),
            EventOutcome::Success,
        ),
        create_test_entry(
            AuditEventType::Authentication,
            SecurityLevel::High,
            Some("user2".to_string()),
            Some("/login".to_string()),
            "user_login".to_string(),
            EventOutcome::Failure,
        ),
    ];

    // Log entries
    for entry in entries {
        logger.log(entry).unwrap();
    }

    // Test querying
    let query = AuditQuery {
        start_time: None,
        end_time: None,
        event_types: Some(vec![AuditEventType::Authentication]),
        security_levels: None,
        principal: None,
        resource: None,
        action: None,
        outcome: None,
        limit: Some(10),
        offset: Some(0),
    };

    let results = logger.query(query).unwrap();
    assert_eq!(results.len(), 2); // Should find 2 authentication events

    // Test statistics
    let stats = logger.get_statistics().unwrap();
    assert_eq!(stats.total_entries, 3);
    assert_eq!(stats.entries_by_event_type.get(&AuditEventType::Authentication), Some(&2));
    assert_eq!(stats.entries_by_event_type.get(&AuditEventType::DataAccess), Some(&1));
    assert_eq!(stats.entries_by_security_level.get(&SecurityLevel::High), Some(&2));
    assert_eq!(stats.entries_by_security_level.get(&SecurityLevel::Medium), Some(&1));

    // Test integrity verification
    let integrity_report = logger.verify_integrity().unwrap();
    assert_eq!(integrity_report.total_entries, 3);
    assert_eq!(integrity_report.valid_entries, 3);
    assert_eq!(integrity_report.violations, 0);
    assert!(integrity_report.violation_details.is_empty());
}

#[test]
fn test_tamper_detection() {
    let temp_dir = TempDir::new().unwrap();
    let log_path = temp_dir.path().join("test_audit.log");
    
    let mut config = AuditConfig::default();
    config.log_path = Some(log_path.to_string_lossy().to_string());
    config.hmac_key = Some(base64::encode("test_hmac_key_32_bytes_long_1234"));

    let mut logger = DefaultAuditLogger::new(config).unwrap();

    // Log a legitimate entry
    let entry = create_test_entry(
        AuditEventType::Authentication,
        SecurityLevel::High,
        Some("user1".to_string()),
        Some("/login".to_string()),
        "user_login".to_string(),
        EventOutcome::Success,
    );
    logger.log(entry).unwrap();

    // Tamper with the log file
    let log_content = fs::read_to_string(&log_path).unwrap();
    let tampered_content = log_content.replace("user1", "attacker");
    fs::write(&log_path, tampered_content).unwrap();

    // Verify integrity should detect tampering
    let integrity_report = logger.verify_integrity().unwrap();
    assert_eq!(integrity_report.total_entries, 1);
    assert_eq!(integrity_report.valid_entries, 0);
    assert_eq!(integrity_report.violations, 1);
    assert!(!integrity_report.violation_details.is_empty());
}

#[test]
fn test_hash_chain_integrity() {
    let temp_dir = TempDir::new().unwrap();
    let log_path = temp_dir.path().join("test_audit.log");
    
    let mut config = AuditConfig::default();
    config.log_path = Some(log_path.to_string_lossy().to_string());
    config.hmac_key = Some(base64::encode("test_hmac_key_32_bytes_long_1234"));

    let mut logger = DefaultAuditLogger::new(config).unwrap();

    // Log multiple entries to establish hash chain
    for i in 0..5 {
        let entry = create_test_entry(
            AuditEventType::DataAccess,
            SecurityLevel::Medium,
            Some(format!("user{}", i)),
            Some(format!("/resource/{}", i)),
            format!("action_{}", i),
            EventOutcome::Success,
        );
        logger.log(entry).unwrap();
    }

    // Verify hash chain integrity
    let integrity_report = logger.verify_integrity().unwrap();
    assert_eq!(integrity_report.total_entries, 5);
    assert_eq!(integrity_report.valid_entries, 5);
    assert_eq!(integrity_report.violations, 0);

    // Break the hash chain by modifying an entry
    let log_content = fs::read_to_string(&log_path).unwrap();
    let lines: Vec<&str> = log_content.lines().collect();
    if lines.len() >= 2 {
        // Modify the second entry
        let mut modified_lines = lines.to_vec();
        modified_lines[1] = modified_lines[1].replace("user1", "malicious_user");
        let modified_content = modified_lines.join("\n");
        fs::write(&log_path, modified_content).unwrap();

        // Verify that hash chain is broken
        let integrity_report = logger.verify_integrity().unwrap();
        assert!(integrity_report.violations > 0);
        assert!(!integrity_report.violation_details.is_empty());
    }
}

#[test]
fn test_query_filtering() {
    let temp_dir = TempDir::new().unwrap();
    let log_path = temp_dir.path().join("test_audit.log");
    
    let mut config = AuditConfig::default();
    config.log_path = Some(log_path.to_string_lossy().to_string());
    config.hmac_key = Some(base64::encode("test_hmac_key_32_bytes_long_1234"));

    let mut logger = DefaultAuditLogger::new(config).unwrap();

    // Create diverse test data
    let test_data = vec![
        (AuditEventType::Authentication, SecurityLevel::High, "admin", "/login", "login", EventOutcome::Success),
        (AuditEventType::Authentication, SecurityLevel::High, "user1", "/login", "login", EventOutcome::Failure),
        (AuditEventType::DataAccess, SecurityLevel::Medium, "user1", "/api/data", "read", EventOutcome::Success),
        (AuditEventType::DataAccess, SecurityLevel::Medium, "user2", "/api/data", "read", EventOutcome::Success),
        (AuditEventType::ConfigurationChange, SecurityLevel::Critical, "admin", "/config", "update", EventOutcome::Success),
        (AuditEventType::KeyManagement, SecurityLevel::Critical, "admin", "/keys", "rotate", EventOutcome::Success),
    ];

    for (event_type, security_level, principal, resource, action, outcome) in test_data {
        let entry = create_test_entry(
            event_type,
            security_level,
            Some(principal.to_string()),
            Some(resource.to_string()),
            action.to_string(),
            outcome,
        );
        logger.log(entry).unwrap();
    }

    // Test filtering by event type
    let auth_query = AuditQuery {
        event_types: Some(vec![AuditEventType::Authentication]),
        ..Default::default()
    };
    let auth_results = logger.query(auth_query).unwrap();
    assert_eq!(auth_results.len(), 2);

    // Test filtering by security level
    let critical_query = AuditQuery {
        security_levels: Some(vec![SecurityLevel::Critical]),
        ..Default::default()
    };
    let critical_results = logger.query(critical_query).unwrap();
    assert_eq!(critical_results.len(), 2);

    // Test filtering by principal
    let admin_query = AuditQuery {
        principal: Some("admin".to_string()),
        ..Default::default()
    };
    let admin_results = logger.query(admin_query).unwrap();
    assert_eq!(admin_results.len(), 3);

    // Test filtering by outcome
    let failure_query = AuditQuery {
        outcome: Some(EventOutcome::Failure),
        ..Default::default()
    };
    let failure_results = logger.query(failure_query).unwrap();
    assert_eq!(failure_results.len(), 1);

    // Test wildcard action matching
    let wildcard_query = AuditQuery {
        action: Some("log*".to_string()),
        ..Default::default()
    };
    let wildcard_results = logger.query(wildcard_query).unwrap();
    assert_eq!(wildcard_results.len(), 2); // Should match both "login" actions
}

#[test]
fn test_audit_analysis_integration() {
    let temp_dir = TempDir::new().unwrap();
    let log_path = temp_dir.path().join("test_audit.log");
    
    let mut config = AuditConfig::default();
    config.log_path = Some(log_path.to_string_lossy().to_string());
    config.hmac_key = Some(base64::encode("test_hmac_key_32_bytes_long_1234"));

    let mut logger = DefaultAuditLogger::new(config).unwrap();

    // Create data that should trigger anomalies
    // Multiple failed authentications for brute force detection
    for i in 0..15 {
        let entry = create_test_entry(
            AuditEventType::Authentication,
            SecurityLevel::High,
            Some("attacker".to_string()),
            Some("/login".to_string()),
            "login_attempt".to_string(),
            EventOutcome::Failure,
        );
        logger.log(entry).unwrap();
        
        // Small delay to create realistic timestamps
        thread::sleep(Duration::from_millis(10));
    }

    // Excessive configuration changes
    for i in 0..60 {
        let entry = create_test_entry(
            AuditEventType::ConfigurationChange,
            SecurityLevel::Critical,
            Some("suspicious_user".to_string()),
            Some("/config".to_string()),
            format!("config_change_{}", i),
            EventOutcome::Success,
        );
        logger.log(entry).unwrap();
    }

    // Analyze the audit log
    let query = AuditQuery::default();
    let entries = logger.query(query).unwrap();
    let analyzer = AuditAnalyzer::new(entries);
    
    // Detect anomalies
    let anomalies = analyzer.detect_anomalies().unwrap();
    assert!(!anomalies.is_empty());
    
    // Should detect brute force attack
    let brute_force_detected = anomalies.iter().any(|a| 
        matches!(a.anomaly_type, fortress_core::audit_analysis::AnomalyType::BruteForceAttack)
    );
    assert!(brute_force_detected);

    // Should detect configuration tampering
    let config_tampering_detected = anomalies.iter().any(|a| 
        matches!(a.anomaly_type, fortress_core::audit_analysis::AnomalyType::ConfigurationTampering)
    );
    assert!(config_tampering_detected);

    // Generate insights
    let insights = analyzer.generate_insights().unwrap();
    assert_eq!(insights.total_entries, 75); // 15 auth + 60 config changes
    assert!(insights.failed_auth_by_principal.contains_key("attacker"));
    assert_eq!(insights.failed_auth_by_principal["attacker"], 15);
}

#[test]
fn test_global_audit_logger() {
    let temp_dir = TempDir::new().unwrap();
    let log_path = temp_dir.path().join("global_audit.log");
    
    // Initialize global audit logger
    let mut config = AuditConfig::default();
    config.log_path = Some(log_path.to_string_lossy().to_string());
    config.hmac_key = Some(base64::encode("test_hmac_key_32_bytes_long_1234"));
    
    init_audit_logger(config).unwrap();

    // Use convenience function to log events
    let mut metadata = HashMap::new();
    metadata.insert("source_ip".to_string(), "192.168.1.100".to_string());
    
    log_event_with_metadata(
        AuditEventType::Authentication,
        SecurityLevel::High,
        Some("test_user".to_string()),
        Some("/api/login".to_string()),
        "api_login".to_string(),
        EventOutcome::Success,
        metadata,
    ).unwrap();

    // Verify the event was logged
    thread::sleep(Duration::from_millis(100)); // Give time for async logging
    
    let log_content = fs::read_to_string(&log_path).unwrap();
    assert!(!log_content.is_empty());
    assert!(log_content.contains("test_user"));
    assert!(log_content.contains("api_login"));
    assert!(log_content.contains("192.168.1.100"));
}

#[test]
fn test_log_rotation_integration() {
    let temp_dir = TempDir::new().unwrap();
    let log_path = temp_dir.path().join("test_audit.log");
    
    let mut config = AuditConfig::default();
    config.log_path = Some(log_path.to_string_lossy().to_string());
    config.hmac_key = Some(base64::encode("test_hmac_key_32_bytes_long_1234"));
    config.enable_rotation = true;
    config.max_file_size = 1000; // Very small to trigger rotation

    let mut logger = DefaultAuditLogger::new(config).unwrap();

    // Create enough entries to trigger rotation
    for i in 0..50 {
        let entry = create_test_entry(
            AuditEventType::DataAccess,
            SecurityLevel::Medium,
            Some(format!("user{}", i)),
            Some(format!("/resource/{}", i)),
            format!("action_{}", i),
            EventOutcome::Success,
        );
        logger.log(entry).unwrap();
    }

    // Test rotation
    let rotation_result = logger.rotate_logs();
    assert!(rotation_result.is_ok());

    // Verify that rotation occurred (check for rotated files)
    let rotated_files: Vec<_> = fs::read_dir(temp_dir.path())
        .unwrap()
        .filter_map(|entry| entry.ok())
        .filter(|entry| {
            let file_name = entry.file_name().to_string_lossy();
            file_name.starts_with("audit_") && (file_name.ends_with(".log") || file_name.ends_with(".log.gz"))
        })
        .collect();

    assert!(!rotated_files.is_empty());
}

/// Helper function to create test audit entries
fn create_test_entry(
    event_type: AuditEventType,
    security_level: SecurityLevel,
    principal: Option<String>,
    resource: Option<String>,
    action: String,
    outcome: EventOutcome,
) -> AuditEntry {
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;

    let id = format!("{}-{}", timestamp, uuid::Uuid::new_v4());
    let metadata = HashMap::new();

    AuditEntry {
        id,
        timestamp,
        event_type,
        security_level,
        principal,
        resource,
        action,
        outcome,
        metadata,
        previous_hash: None,
        current_hash: String::new(),
        signature: String::new(),
    }
}

impl Default for AuditQuery {
    fn default() -> Self {
        Self {
            start_time: None,
            end_time: None,
            event_types: None,
            security_levels: None,
            principal: None,
            resource: None,
            action: None,
            outcome: None,
            limit: None,
            offset: None,
        }
    }
}
