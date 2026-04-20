//! Test Phase 1 Infrastructure Implementation
//!
//! This test module verifies that the Phase 1 infrastructure extensions
//! are working correctly, including:
//! - Extended Storage Backend Interface
//! - Enhanced Error Handling
//! - Configuration System Extensions

use fortress_core::storage::{StorageBackend, InMemoryStorage};
use fortress_core::config::{Config, StorageConfig, TransactionConfig, StreamingConfig, BackupConfig, AuditConfig};
use fortress_core::error::{FortressError, TransactionErrorCode, BackupErrorCode, StreamingErrorCode, AuditErrorCode};
use fortress_core::storage::{TransactionId, StreamId, BackupId, AuditEvent, AuditEventType, AuditEventOutcome};
use uuid::Uuid;

#[tokio::test]
async fn test_storage_backend_extensions() {
    let storage = InMemoryStorage::new();
    
    // Test that the storage backend has the new capability flags
    let metadata = storage.metadata();
    assert!(!metadata.supports_transactions);
    assert!(!metadata.supports_streaming);
    assert!(!metadata.supports_backup_restore);
    assert!(!metadata.supports_audit_logging);
    
    // Test that new methods return appropriate errors for unsupported backends
    let tx_result = storage.begin_transaction().await;
    assert!(tx_result.is_err());
    match tx_result.unwrap_err() {
        FortressError::Storage { code, .. } => {
            assert_eq!(code, fortress_core::error::StorageErrorCode::NotImplemented);
        }
        _ => assert!(false, "Expected Storage error, got {:?}", e),
    }
    
    // Test streaming methods
    let stream_config = fortress_core::storage::StreamConfig {
        name: "test_stream".to_string(),
        stream_type: fortress_core::storage::StreamType::Read,
        buffer_size: 1024,
        max_message_size: 1024,
        timeout_seconds: 60,
        compression: None,
        encryption: None,
        metadata: std::collections::HashMap::new(),
    };
    
    let stream_result = storage.create_stream(stream_config).await;
    assert!(stream_result.is_err());
    
    // Test backup methods
    let backup_config = fortress_core::storage::BackupConfig {
        name: "test_backup".to_string(),
        backup_type: fortress_core::storage::BackupType::Full,
        compression: None,
        encryption: None,
        retention_policy: None,
        filters: vec![],
        metadata: std::collections::HashMap::new(),
    };
    
    let backup_result = storage.create_backup(backup_config).await;
    assert!(backup_result.is_err());
    
    // Test audit methods
    let audit_event = AuditEvent {
        event_id: Uuid::new_v4(),
        event_type: AuditEventType::Authentication,
        timestamp: chrono::Utc::now(),
        user_id: Some("test_user".to_string()),
        action: "login".to_string(),
        resource: None,
        outcome: AuditEventOutcome::Success,
        client_ip: Some("127.0.0.1".to_string()),
        user_agent: Some("test_agent".to_string()),
        session_id: None,
        request_id: None,
        data: std::collections::HashMap::new(),
    };
    
    let audit_result = storage.log_audit_event(audit_event).await;
    assert!(audit_result.is_err());
}

#[test]
fn test_enhanced_error_handling() {
    // Test transaction error creation
    let tx_id = TransactionId(Uuid::new_v4());
    let tx_error = FortressError::transaction(
        "Transaction timeout",
        Some(tx_id.0.to_string()),
        TransactionErrorCode::TransactionTimeout,
    );
    
    assert!(tx_error.is_retryable());
    assert!(!tx_error.is_security_error());
    assert_eq!(tx_error.category(), "transaction");
    
    // Test backup error creation
    let backup_id = BackupId(Uuid::new_v4());
    let backup_error = FortressError::backup(
        "Backup creation failed",
        Some(backup_id.0.to_string()),
        BackupErrorCode::CreationFailed,
    );
    
    assert!(!backup_error.is_retryable());
    assert!(!backup_error.is_security_error());
    assert_eq!(backup_error.category(), "backup");
    
    // Test streaming error creation
    let stream_id = StreamId(Uuid::new_v4());
    let streaming_error = FortressError::streaming(
        "Stream connection failed",
        Some(stream_id.0.to_string()),
        StreamingErrorCode::ConnectionFailed,
    );
    
    assert!(streaming_error.is_retryable());
    assert!(!streaming_error.is_security_error());
    assert_eq!(streaming_error.category(), "streaming");
    
    // Test audit error creation
    let audit_error = FortressError::audit(
        "Audit log corruption detected",
        Some("log_123".to_string()),
        AuditErrorCode::LogCorruptionDetected,
    );
    
    assert!(!audit_error.is_retryable());
    assert!(audit_error.is_security_error());
    assert_eq!(audit_error.category(), "audit");
}

#[test]
fn test_configuration_extensions() {
    let config = Config::default();
    
    // Test that new configuration sections are optional
    assert!(config.transactions.is_none());
    assert!(config.streaming.is_none());
    assert!(config.backup.is_none());
    assert!(config.audit.is_none());
    
    // Test transaction configuration defaults
    let tx_config = TransactionConfig::default();
    assert_eq!(tx_config.default_isolation_level, "read_committed");
    assert_eq!(tx_config.timeout_seconds, 300);
    assert!(tx_config.deadlock_detection);
    assert!(tx_config.savepoints_enabled);
    
    // Test streaming configuration defaults
    let stream_config = StreamingConfig::default();
    assert_eq!(stream_config.default_buffer_size, 64 * 1024);
    assert_eq!(stream_config.max_buffer_size, 10 * 1024 * 1024);
    assert!(stream_config.compression_enabled);
    assert!(stream_config.encryption_enabled);
    
    // Test backup configuration defaults
    let backup_config = BackupConfig::default();
    assert_eq!(backup_config.default_backup_type, "incremental");
    assert!(backup_config.compression_enabled);
    assert!(backup_config.encryption_enabled);
    assert!(backup_config.verification_enabled);
    assert_eq!(backup_config.retention_policy.max_backups, 30);
    
    // Test audit configuration defaults
    let audit_config = AuditConfig::default();
    assert!(audit_config.enabled);
    assert!(audit_config.encryption_enabled);
    assert!(audit_config.compression_enabled);
    assert!(audit_config.real_time_monitoring);
    assert_eq!(audit_config.log_level, fortress_core::config::AuditLogLevel::Standard);
    assert!(audit_config.audited_events.contains(&"authentication".to_string()));
}

#[test]
fn test_new_type_definitions() {
    // Test TransactionId
    let tx_id = TransactionId(Uuid::new_v4());
    let tx_id2 = TransactionId(tx_id.0);
    assert_eq!(tx_id, tx_id2);
    
    // Test StreamId
    let stream_id = StreamId(Uuid::new_v4());
    let stream_id2 = StreamId(stream_id.0);
    assert_eq!(stream_id, stream_id2);
    
    // Test BackupId
    let backup_id = BackupId(Uuid::new_v4());
    let backup_id2 = BackupId(backup_id.0);
    assert_eq!(backup_id, backup_id2);
    
    // Test audit event types
    let event_types = vec![
        AuditEventType::Authentication,
        AuditEventType::Authorization,
        AuditEventType::DataAccess,
        AuditEventType::DataModification,
        AuditEventType::ConfigurationChange,
        AuditEventType::System,
        AuditEventType::Security,
        AuditEventType::Compliance,
        AuditEventType::Backup,
        AuditEventType::Restore,
        AuditEventType::Transaction,
    ];
    
    assert_eq!(event_types.len(), 11);
    
    // Test audit event outcomes
    let outcomes = vec![
        AuditEventOutcome::Success,
        AuditEventOutcome::Failure,
        AuditEventOutcome::Denied,
        AuditEventOutcome::Error,
    ];
    
    assert_eq!(outcomes.len(), 4);
}

#[test]
fn test_serialization_deserialization() {
    // Test that new types can be serialized and deserialized
    let tx_id = TransactionId(Uuid::new_v4());
    let serialized = serde_json::to_string(&tx_id).unwrap();
    let deserialized: TransactionId = serde_json::from_str(&serialized).unwrap();
    assert_eq!(tx_id, deserialized);
    
    let stream_id = StreamId(Uuid::new_v4());
    let serialized = serde_json::to_string(&stream_id).unwrap();
    let deserialized: StreamId = serde_json::from_str(&serialized).unwrap();
    assert_eq!(stream_id, deserialized);
    
    let backup_id = BackupId(Uuid::new_v4());
    let serialized = serde_json::to_string(&backup_id).unwrap();
    let deserialized: BackupId = serde_json::from_str(&serialized).unwrap();
    assert_eq!(backup_id, deserialized);
    
    // Test audit event serialization
    let audit_event = AuditEvent {
        event_id: Uuid::new_v4(),
        event_type: AuditEventType::Security,
        timestamp: chrono::Utc::now(),
        user_id: Some("test_user".to_string()),
        action: "suspicious_activity".to_string(),
        resource: Some("system".to_string()),
        outcome: AuditEventOutcome::Failure,
        client_ip: Some("192.168.1.100".to_string()),
        user_agent: Some("malicious_bot".to_string()),
        session_id: Some("session_123".to_string()),
        request_id: Some("req_456".to_string()),
        data: {
            let mut data = std::collections::HashMap::new();
            data.insert("threat_level".to_string(), serde_json::Value::String("high".to_string()));
            data
        },
    };
    
    let serialized = serde_json::to_string(&audit_event).unwrap();
    let deserialized: AuditEvent = serde_json::from_str(&serialized).unwrap();
    assert_eq!(audit_event.event_id, deserialized.event_id);
    assert_eq!(audit_event.event_type, deserialized.event_type);
    assert_eq!(audit_event.action, deserialized.action);
}

#[test]
fn test_configuration_serialization() {
    let config = Config {
        database: fortress_core::config::DatabaseConfig::default(),
        encryption: fortress_core::config::EncryptionConfig::default(),
        storage: StorageConfig {
            backend: "in_memory".to_string(),
            base_path: None,
            s3: None,
            azure_blob: None,
            gcs: None,
            compression: false,
            checksum: "none".to_string(),
        },
        api: None,
        monitoring: None,
        transactions: Some(TransactionConfig::default()),
        streaming: Some(StreamingConfig::default()),
        backup: Some(BackupConfig::default()),
        audit: Some(AuditConfig::default()),
    };
    
    // Test JSON serialization
    let json_str = serde_json::to_string_pretty(&config).unwrap();
    let loaded_config: Config = serde_json::from_str(&json_str).unwrap();
    
    assert!(loaded_config.transactions.is_some());
    assert!(loaded_config.streaming.is_some());
    assert!(loaded_config.backup.is_some());
    assert!(loaded_config.audit.is_some());
    
    // Test TOML serialization
    let toml_str = toml::to_string_pretty(&config).unwrap();
    let loaded_config: Config = toml::from_str(&toml_str).unwrap();
    
    assert!(loaded_config.transactions.is_some());
    assert!(loaded_config.streaming.is_some());
    assert!(loaded_config.backup.is_some());
    assert!(loaded_config.audit.is_some());
}
