//! Integration tests for the audit logging system

use fortress_core::audit::{
    AuditConfig, AuditEntry, AuditEventType, SecurityLevel, EventOutcome,
    DefaultAuditLogger, init_audit_logger, log_event_with_metadata,
};
use fortress_core::audit_analysis::{AuditAnalyzer, SecurityAnomaly, AnomalyType};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

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
fn test_audit_logging_integration() {
    // Initialize the global audit logger
    let mut config = AuditConfig::default();
    let hmac_key = base64::encode("integration_test_hmac_key_32_bytes");
    config.hmac_key = Some(hmac_key);
    config.enabled = true;

    init_audit_logger(config).unwrap();

    // Test logging an event
    let mut metadata = HashMap::new();
    metadata.insert("source_ip".to_string(), "192.168.1.100".to_string());
    metadata.insert("user_agent".to_string(), "Fortress-Client/1.0".to_string());

    let result = log_event_with_metadata(
        AuditEventType::Authentication,
        SecurityLevel::Medium,
        Some("user123".to_string()),
        Some("/api/auth".to_string()),
        "login_attempt".to_string(),
        EventOutcome::Success,
        metadata,
    );

    assert!(result.is_ok());
}

#[test]
fn test_audit_anomaly_detection() {
    // Create test entries that simulate a brute force attack
    let mut entries = Vec::new();
    let base_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;

    // Simulate 10 failed authentication attempts within 2 minutes
    for i in 0..10 {
        let entry = AuditEntry {
            id: format!("{}-{}", base_time + i * 12000, i), // 12 seconds apart
            timestamp: base_time + i * 12000,
            event_type: AuditEventType::Authentication,
            security_level: SecurityLevel::Medium,
            principal: Some("attacker".to_string()),
            resource: Some("/login".to_string()),
            action: "login".to_string(),
            outcome: EventOutcome::Failure,
            metadata: HashMap::new(),
            previous_hash: if i > 0 { Some(format!("hash_{}", i - 1)) } else { None },
            current_hash: format!("hash_{}", i),
            signature: format!("sig_{}", i),
        };
        entries.push(entry);
    }

    let analyzer = AuditAnalyzer::new(entries);
    let anomalies = analyzer.detect_anomalies().unwrap();

    // Should detect brute force attack
    assert!(!anomalies.is_empty());
    let brute_force_anomalies: Vec<_> = anomalies.iter()
        .filter(|a| matches!(a.anomaly_type, AnomalyType::BruteForceAttack))
        .collect();
    
    assert!(!brute_force_anomalies.is_empty());
    assert_eq!(brute_force_anomalies[0].principal, Some("attacker".to_string()));
}

#[test]
fn test_audit_insights_generation() {
    let mut entries = Vec::new();
    let base_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;

    // Create diverse test entries
    let test_cases = vec![
        (AuditEventType::Authentication, SecurityLevel::Medium, EventOutcome::Success, "user1"),
        (AuditEventType::Authentication, SecurityLevel::Medium, EventOutcome::Failure, "user2"),
        (AuditEventType::KeyManagement, SecurityLevel::High, EventOutcome::Success, "system"),
        (AuditEventType::DataAccess, SecurityLevel::Low, EventOutcome::Success, "user1"),
        (AuditEventType::ConfigurationChange, SecurityLevel::Critical, EventOutcome::Success, "admin"),
    ];

    for (i, (event_type, security_level, outcome, principal)) in test_cases.into_iter().enumerate() {
        let entry = AuditEntry {
            id: format!("entry_{}", i),
            timestamp: base_time + i as u64 * 1000,
            event_type,
            security_level,
            principal: Some(principal.to_string()),
            resource: Some(format!("/resource_{}", i)),
            action: format!("action_{}", i),
            outcome,
            metadata: HashMap::new(),
            previous_hash: if i > 0 { Some(format!("hash_{}", i - 1)) } else { None },
            current_hash: format!("hash_{}", i),
            signature: format!("sig_{}", i),
        };
        entries.push(entry);
    }

    let analyzer = AuditAnalyzer::new(entries);
    let insights = analyzer.generate_insights().unwrap();

    assert_eq!(insights.total_entries, 5);
    assert_eq!(insights.active_principals.len(), 4); // user1, user2, system, admin
    assert!(insights.entries_by_event_type.contains_key(&AuditEventType::Authentication));
    assert!(insights.entries_by_level.contains_key(&SecurityLevel::High));
    assert!(insights.entries_by_outcome.contains_key(&EventOutcome::Success));
}

#[test]
fn test_security_level_ordering() {
    assert!(SecurityLevel::Low < SecurityLevel::Medium);
    assert!(SecurityLevel::Medium < SecurityLevel::High);
    assert!(SecurityLevel::High < SecurityLevel::Critical);
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
fn test_mass_data_access_detection() {
    let mut entries = Vec::new();
    let base_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;

    // Simulate 15,000 data access events in a 1-minute window
    for i in 0..15000 {
        let entry = AuditEntry {
            id: format!("data_access_{}", i),
            timestamp: base_time + (i % 60000), // All within 1 minute
            event_type: AuditEventType::DataAccess,
            security_level: SecurityLevel::Low,
            principal: Some("data_scraping_user".to_string()),
            resource: Some(format!("/data/record_{}", i)),
            action: "read".to_string(),
            outcome: EventOutcome::Success,
            metadata: HashMap::new(),
            previous_hash: if i > 0 { Some(format!("hash_{}", i - 1)) } else { None },
            current_hash: format!("hash_{}", i),
            signature: format!("sig_{}", i),
        };
        entries.push(entry);
    }

    let analyzer = AuditAnalyzer::new(entries);
    let anomalies = analyzer.detect_anomalies().unwrap();

    // Should detect mass data access
    let mass_data_anomalies: Vec<_> = anomalies.iter()
        .filter(|a| matches!(a.anomaly_type, AnomalyType::MassDataAccess))
        .collect();
    
    assert!(!mass_data_anomalies.is_empty());
}

#[test]
fn test_privilege_escalation_detection() {
    let mut entries = Vec::new();
    let base_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;

    // Simulate 6 role changes for a single principal
    for i in 0..6 {
        let entry = AuditEntry {
            id: format!("role_change_{}", i),
            timestamp: base_time + i as u64 * 60000, // 1 minute apart
            event_type: AuditEventType::Authorization,
            security_level: SecurityLevel::High,
            principal: Some("suspicious_user".to_string()),
            resource: None,
            action: format!("role_change_to_admin_{}", i),
            outcome: EventOutcome::Success,
            metadata: HashMap::new(),
            previous_hash: if i > 0 { Some(format!("hash_{}", i - 1)) } else { None },
            current_hash: format!("hash_{}", i),
            signature: format!("sig_{}", i),
        };
        entries.push(entry);
    }

    let analyzer = AuditAnalyzer::new(entries);
    let anomalies = analyzer.detect_anomalies().unwrap();

    // Should detect privilege escalation
    let privilege_escalation_anomalies: Vec<_> = anomalies.iter()
        .filter(|a| matches!(a.anomaly_type, AnomalyType::PrivilegeEscalation))
        .collect();
    
    assert!(!privilege_escalation_anomalies.is_empty());
    assert_eq!(privilege_escalation_anomalies[0].principal, Some("suspicious_user".to_string()));
    assert_eq!(privilege_escalation_anomalies[0].severity, SecurityLevel::Critical);
}

#[test]
fn test_audit_query_functionality() {
    let mut entries = Vec::new();
    let base_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;

    // Create test entries with different properties
    for i in 0..10 {
        let entry = AuditEntry {
            id: format!("query_test_{}", i),
            timestamp: base_time + i as u64 * 3600000, // 1 hour apart
            event_type: if i % 2 == 0 { AuditEventType::Authentication } else { AuditEventType::DataAccess },
            security_level: match i % 3 {
                0 => SecurityLevel::Low,
                1 => SecurityLevel::Medium,
                _ => SecurityLevel::High,
            },
            principal: Some(if i % 2 == 0 { "user1" } else { "user2" }.to_string()),
            resource: Some(format!("/resource_{}", i)),
            action: format!("action_{}", i),
            outcome: if i % 4 == 0 { EventOutcome::Failure } else { EventOutcome::Success },
            metadata: HashMap::new(),
            previous_hash: if i > 0 { Some(format!("hash_{}", i - 1)) } else { None },
            current_hash: format!("hash_{}", i),
            signature: format!("sig_{}", i),
        };
        entries.push(entry);
    }

    let analyzer = AuditAnalyzer::new(entries);

    // Test filtering by event type
    let auth_query = fortress_core::audit::AuditQuery {
        start_time: None,
        end_time: None,
        event_types: Some(vec![AuditEventType::Authentication]),
        security_levels: None,
        principal: None,
        resource: None,
        action: None,
        outcome: None,
        limit: None,
        offset: None,
    };

    let auth_results = analyzer.search(&auth_query).unwrap();
    assert_eq!(auth_results.len(), 5); // Every other entry

    // Test filtering by principal
    let user1_query = fortress_core::audit::AuditQuery {
        start_time: None,
        end_time: None,
        event_types: None,
        security_levels: None,
        principal: Some("user1".to_string()),
        resource: None,
        action: None,
        outcome: None,
        limit: None,
        offset: None,
    };

    let user1_results = analyzer.search(&user1_query).unwrap();
    assert_eq!(user1_results.len(), 5); // user1 appears in 5 entries
}
