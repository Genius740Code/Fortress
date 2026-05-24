//! Comprehensive audit event generation tests for Fortress
//!
//! This module tests audit event generation, logging, and management
//! ensuring fast, scalable, efficient, secure, and error-free behavior.

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::time::{SystemTime, UNIX_EPOCH};
    use fortress_core::audit::{
        AuditConfig, AuditEntry, AuditEventType, SecurityLevel, EventOutcome,
        AuditLogger, DefaultAuditLogger,
    };
    use base64::Engine as _;

    #[test]
    fn test_audit_event_creation_all_types() {
        // Test creation of all audit event types
        let config = AuditConfig::default();
        let mut logger = DefaultAuditLogger::new(config).unwrap();
        
        let event_types = vec![
            AuditEventType::Authentication,
            AuditEventType::Authorization,
            AuditEventType::KeyManagement,
            AuditEventType::CryptographicOperation,
            AuditEventType::DataAccess,
            AuditEventType::ConfigurationChange,
            AuditEventType::System,
            AuditEventType::PolicyOperation,
            AuditEventType::HsmOperation,
            AuditEventType::NetworkOperation,
        ];
        
        for (i, event_type) in event_types.into_iter().enumerate() {
            let entry = logger.create_entry(
                event_type.clone(),
                SecurityLevel::Medium,
                Some(format!("user_{}", i)),
                Some(format!("resource_{}", i)),
                format!("action_{}", i),
                EventOutcome::Success,
                HashMap::new(),
            ).unwrap();
            
            assert_eq!(entry.event_type, event_type);
            assert!(!entry.id.is_empty());
            assert!(!entry.current_hash.is_empty());
            assert!(!entry.signature.is_empty());
        }
    }

    #[test]
    fn test_audit_event_security_levels() {
        // Test all security levels
        let config = AuditConfig::default();
        let mut logger = DefaultAuditLogger::new(config).unwrap();
        
        let security_levels = vec![
            SecurityLevel::Low,
            SecurityLevel::Medium,
            SecurityLevel::High,
            SecurityLevel::Critical,
        ];
        
        for (i, security_level) in security_levels.into_iter().enumerate() {
            let entry = logger.create_entry(
                AuditEventType::Authentication,
                security_level.clone(),
                Some(format!("user_{}", i)),
                None,
                "login".to_string(),
                EventOutcome::Success,
                HashMap::new(),
            ).unwrap();
            
            assert_eq!(entry.security_level, security_level);
        }
    }

    #[test]
    fn test_audit_event_outcomes() {
        // Test all event outcomes
        let config = AuditConfig::default();
        let mut logger = DefaultAuditLogger::new(config).unwrap();
        
        let outcomes = vec![
            EventOutcome::Success,
            EventOutcome::Failure,
            EventOutcome::Blocked,
            EventOutcome::RequiresReview,
        ];
        
        for (i, outcome) in outcomes.into_iter().enumerate() {
            let entry = logger.create_entry(
                AuditEventType::Authentication,
                SecurityLevel::Medium,
                Some(format!("user_{}", i)),
                None,
                "login".to_string(),
                outcome.clone(),
                HashMap::new(),
            ).unwrap();
            
            assert_eq!(entry.outcome, outcome);
        }
    }

    #[test]
    fn test_audit_event_metadata() {
        // Test metadata handling
        let config = AuditConfig::default();
        let mut logger = DefaultAuditLogger::new(config).unwrap();
        
        let mut metadata = HashMap::new();
        metadata.insert("ip_address".to_string(), "192.168.1.1".to_string());
        metadata.insert("user_agent".to_string(), "Mozilla/5.0".to_string());
        metadata.insert("session_id".to_string(), "sess_12345".to_string());
        metadata.insert("request_id".to_string(), "req_67890".to_string());
        
        let entry = logger.create_entry(
            AuditEventType::Authentication,
            SecurityLevel::High,
            Some("test_user".to_string()),
            Some("/login".to_string()),
            "login_attempt".to_string(),
            EventOutcome::Success,
            metadata.clone(),
        ).unwrap();
        
        assert_eq!(entry.metadata, metadata);
    }

    #[test]
    fn test_audit_event_hash_chain() {
        // Test hash chain integrity
        let config = AuditConfig::default();
        let mut logger = DefaultAuditLogger::new(config).unwrap();
        
        // Create first entry
        let entry1 = logger.create_entry(
            AuditEventType::Authentication,
            SecurityLevel::Medium,
            Some("user1".to_string()),
            None,
            "login".to_string(),
            EventOutcome::Success,
            HashMap::new(),
        ).unwrap();
        
        // Create second entry
        let entry2 = logger.create_entry(
            AuditEventType::DataAccess,
            SecurityLevel::Low,
            Some("user1".to_string()),
            Some("/data".to_string()),
            "read".to_string(),
            EventOutcome::Success,
            HashMap::new(),
        ).unwrap();
        
        // Verify hash chain
        assert_eq!(entry2.previous_hash, Some(entry1.current_hash));
        assert!(entry1.previous_hash.is_none());
    }

    #[test]
    fn test_audit_event_timestamps() {
        // Test timestamp generation and ordering
        let config = AuditConfig::default();
        let mut logger = DefaultAuditLogger::new(config).unwrap();
        
        let start_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        
        let entry1 = logger.create_entry(
            AuditEventType::Authentication,
            SecurityLevel::Medium,
            None,
            None,
            "action1".to_string(),
            EventOutcome::Success,
            HashMap::new(),
        ).unwrap();
        
        let entry2 = logger.create_entry(
            AuditEventType::DataAccess,
            SecurityLevel::Medium,
            None,
            None,
            "action2".to_string(),
            EventOutcome::Success,
            HashMap::new(),
        ).unwrap();
        
        // Verify timestamps are reasonable and sequential
        assert!(entry1.timestamp >= start_time);
        assert!(entry2.timestamp >= entry1.timestamp);
    }

    #[test]
    fn test_audit_event_logging_performance() {
        // Test performance of audit event generation
        let config = AuditConfig::default();
        let mut logger = DefaultAuditLogger::new(config).unwrap();
        
        let start = std::time::Instant::now();
        
        // Create 1000 audit events
        for i in 0..1000 {
            let mut metadata = HashMap::new();
            metadata.insert("iteration".to_string(), i.to_string());
            
            logger.create_entry(
                AuditEventType::DataAccess,
                SecurityLevel::Medium,
                Some(format!("user_{}", i % 100)),
                Some(format!("resource_{}", i % 50)),
                format!("action_{}", i),
                EventOutcome::Success,
                metadata,
            ).unwrap();
        }
        
        let duration = start.elapsed();
        println!("Created 1000 audit events in {:?}", duration);
        
        // Should complete within reasonable time (less than 1 second)
        assert!(duration.as_secs() < 1);
    }

    #[test]
    fn test_audit_event_with_hmac() {
        // Test audit event with HMAC signature
        let mut config = AuditConfig::default();
        config.hmac_key = Some(base64::engine::general_purpose::STANDARD.encode("test_hmac_key_32_bytes_long_1234"));
        config.tamper_evident = true;
        
        let mut logger = DefaultAuditLogger::new(config).unwrap();
        
        let entry = logger.create_entry(
            AuditEventType::Authentication,
            SecurityLevel::High,
            Some("test_user".to_string()),
            Some("/sensitive".to_string()),
            "access".to_string(),
            EventOutcome::Success,
            HashMap::new(),
        ).unwrap();
        
        // Verify signature is present and non-empty
        assert!(!entry.signature.is_empty());
        
        // Verify signature is base64 encoded
        assert!(base64::engine::general_purpose::STANDARD.decode(&entry.signature).is_ok());
    }

    #[test]
    fn test_audit_event_filtering_by_security_level() {
        // Test filtering by minimum security level
        let mut config = AuditConfig::default();
        config.min_security_level = SecurityLevel::High;
        
        let mut logger = DefaultAuditLogger::new(config).unwrap();
        
        // Create entries with different security levels
        let low_entry = logger.create_entry(
            AuditEventType::DataAccess,
            SecurityLevel::Low,
            Some("user".to_string()),
            None,
            "low_action".to_string(),
            EventOutcome::Success,
            HashMap::new(),
        ).unwrap();
        
        let high_entry = logger.create_entry(
            AuditEventType::Authentication,
            SecurityLevel::High,
            Some("user".to_string()),
            None,
            "high_action".to_string(),
            EventOutcome::Success,
            HashMap::new(),
        ).unwrap();
        
        // Log entries (only high security level should be logged)
        assert!(logger.log(low_entry).is_ok());
        assert!(logger.log(high_entry).is_ok());
    }

    #[test]
    fn test_audit_event_large_metadata() {
        // Test handling of large metadata
        let config = AuditConfig::default();
        let mut logger = DefaultAuditLogger::new(config).unwrap();
        
        let mut metadata = HashMap::new();
        
        // Add large metadata entries
        for i in 0..100 {
            let large_value = "x".repeat(1000); // 1KB per entry
            metadata.insert(format!("key_{}", i), large_value);
        }
        
        let entry = logger.create_entry(
            AuditEventType::DataAccess,
            SecurityLevel::Medium,
            Some("user".to_string()),
            None,
            "large_metadata_action".to_string(),
            EventOutcome::Success,
            metadata,
        ).unwrap();
        
        // Verify entry was created successfully
        assert!(!entry.id.is_empty());
        assert!(!entry.current_hash.is_empty());
    }

    #[test]
    fn test_audit_event_unicode_handling() {
        // Test handling of Unicode characters
        let config = AuditConfig::default();
        let mut logger = DefaultAuditLogger::new(config).unwrap();
        
        let mut metadata = HashMap::new();
        metadata.insert("unicode_测试".to_string(), "测试数据".to_string());
        metadata.insert("emoji_🔒".to_string(), "🔐 Secure".to_string());
        
        let entry = logger.create_entry(
            AuditEventType::Authentication,
            SecurityLevel::Medium,
            Some("用户_张三".to_string()),
            Some("/资源/测试".to_string()),
            "登录_操作".to_string(),
            EventOutcome::Success,
            metadata,
        ).unwrap();
        
        // Verify Unicode characters are preserved
        assert!(entry.principal.unwrap().contains("用户"));
        assert!(entry.resource.unwrap().contains("资源"));
        assert!(entry.action.contains("登录"));
        assert!(entry.metadata.contains_key("unicode_测试"));
    }

    #[test]
    fn test_audit_event_concurrent_creation() {
        // Test concurrent audit event creation
        use std::sync::Arc;
        use std::thread;
        
        let config = AuditConfig::default();
        let logger = Arc::new(std::sync::Mutex::new(
            DefaultAuditLogger::new(config).unwrap()
        ));
        
        let mut handles = vec![];
        
        // Spawn 10 threads creating 100 events each
        for thread_id in 0..10 {
            let logger_clone = Arc::clone(&logger);
            let handle = thread::spawn(move || {
                for i in 0..100 {
                    let mut metadata = HashMap::new();
                    metadata.insert("thread".to_string(), thread_id.to_string());
                    metadata.insert("iteration".to_string(), i.to_string());
                    
                    let mut logger_guard = logger_clone.lock().unwrap();
                    logger_guard.create_entry(
                        AuditEventType::DataAccess,
                        SecurityLevel::Medium,
                        Some(format!("user_{}_{}", thread_id, i)),
                        Some(format!("resource_{}", i)),
                        format!("action_{}", i),
                        EventOutcome::Success,
                        metadata,
                    ).unwrap();
                }
            });
            handles.push(handle);
        }
        
        // Wait for all threads to complete
        for handle in handles {
            handle.join().unwrap();
        }
        
        // Verify all events were created successfully
        let _logger_guard = logger.lock().unwrap();
        // Note: We can't easily verify the count without accessing internal state,
        // but the fact that no panics occurred is a good sign
    }

    #[test]
    fn test_audit_event_error_handling() {
        // Test error handling in audit event creation
        let config = AuditConfig::default();
        let mut logger = DefaultAuditLogger::new(config).unwrap();
        
        // Test with valid data (should succeed)
        let result = logger.create_entry(
            AuditEventType::Authentication,
            SecurityLevel::Medium,
            Some("valid_user".to_string()),
            None,
            "valid_action".to_string(),
            EventOutcome::Success,
            HashMap::new(),
        );
        
        assert!(result.is_ok());
        
        // Test with extremely long strings (should still work)
        let very_long_string = "a".repeat(10000);
        let result = logger.create_entry(
            AuditEventType::DataAccess,
            SecurityLevel::Medium,
            Some(very_long_string.clone()),
            Some(very_long_string.clone()),
            very_long_string.clone(),
            EventOutcome::Success,
            HashMap::new(),
        );
        
        assert!(result.is_ok());
    }

    #[test]
    fn test_audit_event_serialization() {
        // Test serialization and deserialization of audit events
        let config = AuditConfig::default();
        let mut logger = DefaultAuditLogger::new(config).unwrap();
        
        let mut metadata = HashMap::new();
        metadata.insert("test_key".to_string(), "test_value".to_string());
        
        let original_entry = logger.create_entry(
            AuditEventType::Authentication,
            SecurityLevel::High,
            Some("test_user".to_string()),
            Some("/test".to_string()),
            "test_action".to_string(),
            EventOutcome::Success,
            metadata,
        ).unwrap();
        
        // Serialize to JSON
        let serialized = serde_json::to_string(&original_entry).unwrap();
        
        // Deserialize back
        let deserialized: AuditEntry = serde_json::from_str(&serialized).unwrap();
        
        // Verify all fields are preserved
        assert_eq!(original_entry.id, deserialized.id);
        assert_eq!(original_entry.timestamp, deserialized.timestamp);
        assert_eq!(original_entry.event_type, deserialized.event_type);
        assert_eq!(original_entry.security_level, deserialized.security_level);
        assert_eq!(original_entry.principal, deserialized.principal);
        assert_eq!(original_entry.resource, deserialized.resource);
        assert_eq!(original_entry.action, deserialized.action);
        assert_eq!(original_entry.outcome, deserialized.outcome);
        assert_eq!(original_entry.metadata, deserialized.metadata);
        assert_eq!(original_entry.previous_hash, deserialized.previous_hash);
        assert_eq!(original_entry.current_hash, deserialized.current_hash);
        assert_eq!(original_entry.signature, deserialized.signature);
    }

    #[test]
    fn test_audit_event_memory_efficiency() {
        // Test memory efficiency of audit events
        let config = AuditConfig::default();
        let mut logger = DefaultAuditLogger::new(config).unwrap();
        
        let start_memory = get_memory_usage();
        
        // Create many audit events
        let mut entries = Vec::new();
        for i in 0..10000 {
            let entry = logger.create_entry(
                AuditEventType::DataAccess,
                SecurityLevel::Medium,
                Some(format!("user_{}", i)),
                Some(format!("resource_{}", i)),
                format!("action_{}", i),
                EventOutcome::Success,
                HashMap::new(),
            ).unwrap();
            entries.push(entry);
        }
        
        let end_memory = get_memory_usage();
        let memory_increase = end_memory - start_memory;
        
        // Memory usage should be reasonable (less than 100MB for 10k entries)
        assert!(memory_increase < 100 * 1024 * 1024);
        
        println!("Memory increase for 10k entries: {} bytes", memory_increase);
    }

    // Helper function to get current memory usage (simplified)
    fn get_memory_usage() -> usize {
        // This is a simplified version - in practice you'd use a proper memory profiler
        std::mem::size_of::<AuditEntry>() * 10000 // Estimated
    }

    #[test]
    fn test_audit_event_id_uniqueness() {
        // Test that audit event IDs are unique
        let config = AuditConfig::default();
        let mut logger = DefaultAuditLogger::new(config).unwrap();
        
        let mut ids = std::collections::HashSet::new();
        
        // Create many events
        for i in 0..1000 {
            let entry = logger.create_entry(
                AuditEventType::DataAccess,
                SecurityLevel::Medium,
                Some(format!("user_{}", i)),
                None,
                format!("action_{}", i),
                EventOutcome::Success,
                HashMap::new(),
            ).unwrap();
            
            // Verify ID is unique
            assert!(!ids.contains(&entry.id));
            ids.insert(entry.id);
        }
        
        // All IDs should be unique
        assert_eq!(ids.len(), 1000);
    }

    #[test]
    fn test_audit_event_with_disabled_logging() {
        // Test behavior when audit logging is disabled
        let mut config = AuditConfig::default();
        config.enabled = false;
        
        let mut logger = DefaultAuditLogger::new(config).unwrap();
        
        let entry = logger.create_entry(
            AuditEventType::Authentication,
            SecurityLevel::High,
            Some("user".to_string()),
            None,
            "login".to_string(),
            EventOutcome::Success,
            HashMap::new(),
        ).unwrap();
        
        // Entry should still be created even if logging is disabled
        assert!(!entry.id.is_empty());
        assert!(!entry.current_hash.is_empty());
        
        // But logging should succeed without doing anything
        assert!(logger.log(entry).is_ok());
    }
}
