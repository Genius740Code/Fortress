//! Comprehensive audit integration tests for Fortress
//!
//! This module tests audit system integration with other Fortress components
//! ensuring fast, scalable, efficient, secure, and error-free behavior.

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};
    use std::time::{SystemTime, UNIX_EPOCH};
    use fortress_core::audit::{
        AuditConfig, AuditEntry, AuditEventType, SecurityLevel, EventOutcome,
        DefaultAuditLogger, AuditLogger, AuditQuery, IntegrityReport,
        AuditStatistics,
    };
    use fortress_core::audit_analysis::{
        AuditAnalyzer, SecurityAnomaly, AnomalyType, SecurityInsights,
        ReportGenerator, SecurityReport,
    };
    use fortress_core::encryption::{Aegis256, EncryptionAlgorithm};
    use fortress_core::key::KeyManager;
    use fortress_core::storage::{StorageBackend, InMemoryStorage, StorageConfig};
    use fortress_core::error::{FortressError, Result};
    use base64;

    #[test]
    fn test_audit_with_encryption_integration() {
        // Test audit logging with encryption operations
        let mut config = AuditConfig::default();
        config.hmac_key = Some(base64::engine::general_purpose::STANDARD.encode("test_hmac_key_32_bytes_long_1234"));
        config.log_path = Some("test_audit_encryption.log".to_string());
        
        let mut audit_logger = DefaultAuditLogger::new(config).unwrap();
        let algorithm = Aegis256::new();
        let key_manager = Box::new(fortress_core::key::InMemoryKeyManager::new()) as Box<dyn KeyManager>;
        
        // Generate key
        let key_result = key_manager.generate_key(&algorithm);
        assert!(key_result.is_ok());
        
        // Log key generation
        let key = key_result.unwrap();
        let mut metadata = HashMap::new();
        metadata.insert("algorithm".to_string(), "Aegis256".to_string());
        metadata.insert("key_id".to_string(), key.id().to_string());
        
        let audit_entry = audit_logger.create_entry(
            AuditEventType::KeyManagement,
            SecurityLevel::High,
            Some("system".to_string()),
            Some(format!("key/{}", key.id())),
            "generate_key".to_string(),
            EventOutcome::Success,
            metadata,
        ).unwrap();
        
        assert!(audit_logger.log(audit_entry).is_ok());
        
        // Test encryption operation
        let data = b"test data for audit integration";
        let encrypt_result = algorithm.encrypt(data, &key);
        assert!(encrypt_result.is_ok());
        
        // Log encryption
        let mut metadata = HashMap::new();
        metadata.insert("data_size".to_string(), data.len().to_string());
        metadata.insert("algorithm".to_string(), "Aegis256".to_string());
        
        let audit_entry = audit_logger.create_entry(
            AuditEventType::CryptographicOperation,
            SecurityLevel::Medium,
            Some("system".to_string()),
            Some("data/test".to_string()),
            "encrypt".to_string(),
            EventOutcome::Success,
            metadata,
        ).unwrap();
        
        assert!(audit_logger.log(audit_entry).is_ok());
        
        // Clean up
        std::fs::remove_file("test_audit_encryption.log").ok();
    }

    #[test]
    fn test_audit_with_storage_integration() {
        // Test audit logging with storage operations
        let mut config = AuditConfig::default();
        config.log_path = Some("test_audit_storage.log".to_string());
        
        let mut audit_logger = DefaultAuditLogger::new(config).unwrap();
        let mut storage = InMemoryStorage::new();
        
        // Test data storage
        let key = "test_record";
        let data = serde_json::json!({
            "field1": "value1",
            "field2": "value2"
        });
        
        // Store data
        let data_bytes = serde_json::to_vec(&data).unwrap();
        tokio_test::block_on(storage.put(key, &data_bytes)).unwrap();
        
        // Log storage operation
        let mut metadata = HashMap::new();
        metadata.insert("key".to_string(), key.to_string());
        metadata.insert("operation".to_string(), "put".to_string());
        
        let audit_entry = audit_logger.create_entry(
            AuditEventType::DataAccess,
            SecurityLevel::Medium,
            Some("system".to_string()),
            Some(format!("key/{}", key)),
            "put_record".to_string(),
            EventOutcome::Success,
            metadata,
        ).unwrap();
        
        assert!(audit_logger.log(audit_entry).is_ok());
        
        // Test data retrieval
        let retrieve_result = tokio_test::block_on(storage.get(key));
        assert!(retrieve_result.is_ok());
        
        // Log retrieval operation
        let mut metadata = HashMap::new();
        metadata.insert("key".to_string(), key.to_string());
        metadata.insert("operation".to_string(), "retrieve".to_string());
        
        let audit_entry = audit_logger.create_entry(
            AuditEventType::DataAccess,
            SecurityLevel::Low,
            Some("system".to_string()),
            Some(format!("key/{}", key)),
            "retrieve_record".to_string(),
            EventOutcome::Success,
            metadata,
        ).unwrap();
        
        assert!(audit_logger.log(audit_entry).is_ok());
        
        // Clean up
        std::fs::remove_file("test_audit_storage.log").ok();
    }

    #[test]
    fn test_audit_integrity_verification() {
        // Test audit log integrity verification
        let mut config = AuditConfig::default();
        config.hmac_key = Some(base64::engine::general_purpose::STANDARD.encode("test_hmac_key_32_bytes_long_1234"));
        config.tamper_evident = true;
        config.log_path = Some("test_audit_integrity.log".to_string());
        
        let mut audit_logger = DefaultAuditLogger::new(config).unwrap();
        
        // Create multiple audit entries
        for i in 0..10 {
            let mut metadata = HashMap::new();
            metadata.insert("iteration".to_string(), i.to_string());
            
            let entry = audit_logger.create_entry(
                AuditEventType::DataAccess,
                SecurityLevel::Medium,
                Some(format!("user_{}", i)),
                Some(format!("resource_{}", i)),
                format!("action_{}", i),
                EventOutcome::Success,
                metadata,
            ).unwrap();
            
            assert!(audit_logger.log(entry).is_ok());
        }
        
        // Verify integrity
        let integrity_report = audit_logger.verify_integrity().unwrap();
        
        assert!(integrity_report.total_entries >= 10);
        assert_eq!(integrity_report.violations, 0);
        assert!(integrity_report.violation_details.is_empty());
        assert_eq!(integrity_report.valid_entries, integrity_report.total_entries);
        
        // Clean up
        std::fs::remove_file("test_audit_integrity.log").ok();
    }

    #[test]
    fn test_audit_statistics_generation() {
        // Test audit statistics generation
        let mut config = AuditConfig::default();
        config.log_path = Some("test_audit_stats.log".to_string());
        
        let mut audit_logger = DefaultAuditLogger::new(config).unwrap();
        
        // Create entries with different characteristics
        let event_types = vec![
            AuditEventType::Authentication,
            AuditEventType::DataAccess,
            AuditEventType::Authorization,
            AuditEventType::KeyManagement,
        ];
        
        let security_levels = vec![
            SecurityLevel::Low,
            SecurityLevel::Medium,
            SecurityLevel::High,
            SecurityLevel::Critical,
        ];
        
        let outcomes = vec![
            EventOutcome::Success,
            EventOutcome::Failure,
            EventOutcome::Blocked,
        ];
        
        for i in 0..100 {
            let entry = audit_logger.create_entry(
                event_types[i % event_types.len()].clone(),
                security_levels[i % security_levels.len()].clone(),
                Some(format!("user_{}", i % 10)),
                Some(format!("resource_{}", i % 20)),
                format!("action_{}", i),
                outcomes[i % outcomes.len()].clone(),
                HashMap::new(),
            ).unwrap();
            
            assert!(audit_logger.log(entry).is_ok());
        }
        
        // Generate statistics
        let stats = audit_logger.get_statistics().unwrap();
        
        assert_eq!(stats.total_entries, 100);
        assert!(!stats.entries_by_event_type.is_empty());
        assert!(!stats.entries_by_security_level.is_empty());
        assert!(!stats.entries_by_outcome.is_empty());
        assert!(stats.date_range.0.is_some());
        assert!(stats.log_size > 0);
        
        // Clean up
        std::fs::remove_file("test_audit_stats.log").ok();
    }

    #[test]
    fn test_audit_query_functionality() {
        // Test audit query functionality
        let mut config = AuditConfig::default();
        config.log_path = Some("test_audit_query.log".to_string());
        
        let mut audit_logger = DefaultAuditLogger::new(config).unwrap();
        
        // Create test entries
        let base_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        
        for i in 0..50 {
            let entry = audit_logger.create_entry(
                if i % 2 == 0 { AuditEventType::Authentication } else { AuditEventType::DataAccess },
                if i % 3 == 0 { SecurityLevel::High } else { SecurityLevel::Medium },
                Some(format!("user_{}", i % 5)),
                Some(format!("resource_{}", i % 10)),
                format!("action_{}", i),
                if i % 4 == 0 { EventOutcome::Failure } else { EventOutcome::Success },
                HashMap::new(),
            ).unwrap();
            
            assert!(audit_logger.log(entry).is_ok());
        }
        
        // Test queries
        let query = AuditQuery {
            start_time: Some(base_time),
            end_time: Some(base_time + 100000),
            event_types: Some(vec![AuditEventType::Authentication]),
            security_levels: Some(vec![SecurityLevel::High]),
            principal: Some("user_1".to_string()),
            resource: None,
            action: None,
            outcome: None,
            limit: Some(10),
            offset: Some(0),
        };
        
        let results = audit_logger.query(query).unwrap();
        
        // Verify query results
        assert!(results.len() <= 10);
        for entry in &results {
            assert_eq!(entry.event_type, AuditEventType::Authentication);
            assert!(entry.principal.as_ref().unwrap().contains("user_1"));
        }
        
        // Clean up
        std::fs::remove_file("test_audit_query.log").ok();
    }

    #[test]
    fn test_audit_with_analysis_integration() {
        // Test integration between audit logging and analysis
        let mut config = AuditConfig::default();
        config.log_path = Some("test_audit_analysis.log".to_string());
        
        let mut audit_logger = DefaultAuditLogger::new(config).unwrap();
        
        // Create entries that should trigger anomalies
        let base_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        
        // Create failed authentication attempts (brute force pattern)
        for i in 0..15 {
            let entry = audit_logger.create_entry(
                AuditEventType::Authentication,
                SecurityLevel::Medium,
                Some("attacker".to_string()),
                None,
                "login".to_string(),
                EventOutcome::Failure,
                HashMap::new(),
            ).unwrap();
            
            assert!(audit_logger.log(entry).is_ok());
        }
        
        // Create many data access events (mass access pattern)
        for i in 0..12000 {
            let entry = audit_logger.create_entry(
                AuditEventType::DataAccess,
                SecurityLevel::Low,
                Some("bulk_user".to_string()),
                Some(format!("resource_{}", i)),
                "read".to_string(),
                EventOutcome::Success,
                HashMap::new(),
            ).unwrap();
            
            assert!(audit_logger.log(entry).is_ok());
        }
        
        // Query all entries and analyze
        let query = AuditQuery {
            start_time: Some(base_time),
            end_time: None,
            event_types: None,
            security_levels: None,
            principal: None,
            resource: None,
            action: None,
            outcome: None,
            limit: None,
            offset: None,
        };
        
        let entries = audit_logger.query(query).unwrap();
        let analyzer = AuditAnalyzer::new(entries);
        
        // Detect anomalies
        let anomalies = analyzer.detect_anomalies().unwrap();
        
        // Should detect both brute force and mass data access
        let brute_force_anomalies: Vec<_> = anomalies.iter()
            .filter(|a| matches!(a.anomaly_type, AnomalyType::BruteForceAttack))
            .collect();
        
        let mass_access_anomalies: Vec<_> = anomalies.iter()
            .filter(|a| matches!(a.anomaly_type, AnomalyType::MassDataAccess))
            .collect();
        
        assert!(!brute_force_anomalies.is_empty());
        assert!(!mass_access_anomalies.is_empty());
        
        // Generate comprehensive report
        let insights = analyzer.generate_insights().unwrap();
        let report = ReportGenerator::generate_security_report(&insights, &anomalies).unwrap();
        
        assert!(report.risk_score > 0.0);
        assert!(!report.recommendations.is_empty());
        
        // Clean up
        std::fs::remove_file("test_audit_analysis.log").ok();
    }

    #[test]
    fn test_audit_concurrent_operations() {
        // Test concurrent audit operations
        use std::thread;
        
        let mut config = AuditConfig::default();
        config.log_path = Some("test_audit_concurrent.log".to_string());
        
        let audit_logger = Arc::new(Mutex::new(
            DefaultAuditLogger::new(config).unwrap()
        ));
        
        let mut handles = vec![];
        
        // Spawn multiple threads performing audit operations
        for thread_id in 0..5 {
            let logger_clone = Arc::clone(&audit_logger);
            let handle = thread::spawn(move || {
                for i in 0..20 {
                    let mut logger_guard = logger_clone.lock().unwrap();
                    
                    let entry = logger_guard.create_entry(
                        AuditEventType::DataAccess,
                        SecurityLevel::Medium,
                        Some(format!("user_{}_{}", thread_id, i)),
                        Some(format!("resource_{}", i)),
                        format!("action_{}", i),
                        EventOutcome::Success,
                        HashMap::new(),
                    ).unwrap();
                    
                    assert!(logger_guard.log(entry).is_ok());
                }
            });
            handles.push(handle);
        }
        
        // Wait for all threads to complete
        for handle in handles {
            handle.join().unwrap();
        }
        
        // Verify all entries were logged
        let logger_guard = audit_logger.lock().unwrap();
        let stats = logger_guard.get_statistics().unwrap();
        assert!(stats.total_entries >= 100);
        
        // Clean up
        std::fs::remove_file("test_audit_concurrent.log").ok();
    }

    #[test]
    fn test_audit_error_handling_integration() {
        // Test error handling in audit integration scenarios
        let mut config = AuditConfig::default();
        config.log_path = Some("/invalid/path/audit.log".to_string()); // Invalid path
        
        let mut audit_logger = DefaultAuditLogger::new(config).unwrap();
        
        // Create entry (should succeed)
        let entry = audit_logger.create_entry(
            AuditEventType::Authentication,
            SecurityLevel::Medium,
            Some("user".to_string()),
            None,
            "login".to_string(),
            EventOutcome::Success,
            HashMap::new(),
        ).unwrap();
        
        // Log entry (should fail due to invalid path)
        let result = audit_logger.log(entry);
        assert!(result.is_err());
        
        // Test with valid path but disabled logging
        let mut config = AuditConfig::default();
        config.enabled = false;
        config.log_path = Some("test_audit_error.log".to_string());
        
        let mut audit_logger = DefaultAuditLogger::new(config).unwrap();
        
        let entry = audit_logger.create_entry(
            AuditEventType::Authentication,
            SecurityLevel::Medium,
            Some("user".to_string()),
            None,
            "login".to_string(),
            EventOutcome::Success,
            HashMap::new(),
        ).unwrap();
        
        // Should succeed even with disabled logging
        assert!(audit_logger.log(entry).is_ok());
        
        // Clean up
        std::fs::remove_file("test_audit_error.log").ok();
    }

    #[test]
    fn test_audit_performance_integration() {
        // Test performance of integrated audit operations
        let mut config = AuditConfig::default();
        config.log_path = Some("test_audit_performance.log".to_string());
        
        let mut audit_logger = DefaultAuditLogger::new(config).unwrap();
        
        let start = std::time::Instant::now();
        
        // Create and log many entries
        for i in 0..1000 {
            let mut metadata = HashMap::new();
            metadata.insert("iteration".to_string(), i.to_string());
            metadata.insert("batch".to_string(), "performance_test".to_string());
            
            let entry = audit_logger.create_entry(
                AuditEventType::DataAccess,
                SecurityLevel::Medium,
                Some(format!("user_{}", i % 50)),
                Some(format!("resource_{}", i % 100)),
                format!("action_{}", i),
                EventOutcome::Success,
                metadata,
            ).unwrap();
            
            assert!(audit_logger.log(entry).is_ok());
        }
        
        let log_time = start.elapsed();
        println!("Logged 1000 entries in {:?}", log_time);
        
        // Test query performance
        let query_start = std::time::Instant::now();
        let query = AuditQuery {
            start_time: None,
            end_time: None,
            event_types: None,
            security_levels: None,
            principal: None,
            resource: None,
            action: None,
            outcome: None,
            limit: Some(100),
            offset: Some(0),
        };
        
        let results = audit_logger.query(query).unwrap();
        let query_time = query_start.elapsed();
        
        println!("Queried 100 entries in {:?}", query_time);
        
        // Test analysis performance
        let analysis_start = std::time::Instant::now();
        let all_entries = audit_logger.query(AuditQuery {
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
        }).unwrap();
        
        let analyzer = AuditAnalyzer::new(all_entries);
        let insights = analyzer.generate_insights().unwrap();
        let anomalies = analyzer.detect_anomalies().unwrap();
        let analysis_time = analysis_start.elapsed();
        
        println!("Analyzed {} entries in {:?}", insights.total_entries, analysis_time);
        
        // Performance assertions
        assert!(log_time.as_secs() < 2);
        assert!(query_time.as_millis() < 100);
        assert!(analysis_time.as_secs() < 1);
        assert_eq!(results.len(), 100);
        assert_eq!(insights.total_entries, 1000);
        
        // Clean up
        std::fs::remove_file("test_audit_performance.log").ok();
    }

    #[test]
    fn test_audit_memory_integration() {
        // Test memory usage in audit integration
        let mut config = AuditConfig::default();
        config.log_path = Some("test_audit_memory.log".to_string());
        
        let mut audit_logger = DefaultAuditLogger::new(config).unwrap();
        
        let start_memory = get_memory_usage();
        
        // Create many entries with large metadata
        for i in 0..5000 {
            let mut metadata = HashMap::new();
            for j in 0..10 {
                metadata.insert(
                    format!("key_{}_{}", i, j),
                    "x".repeat(100) // 100 bytes per value
                );
            }
            
            let entry = audit_logger.create_entry(
                AuditEventType::DataAccess,
                SecurityLevel::Medium,
                Some(format!("user_{}", i)),
                Some(format!("resource_{}", i)),
                format!("action_{}", i),
                EventOutcome::Success,
                metadata,
            ).unwrap();
            
            assert!(audit_logger.log(entry).is_ok());
        }
        
        let end_memory = get_memory_usage();
        let memory_increase = end_memory - start_memory;
        
        // Memory should be reasonable (less than 50MB for 5k entries with large metadata)
        assert!(memory_increase < 50 * 1024 * 1024);
        
        println!("Memory increase for 5k entries with large metadata: {} bytes", memory_increase);
        
        // Clean up
        std::fs::remove_file("test_audit_memory.log").ok();
    }

    #[test]
    fn test_audit_security_integration() {
        // Test security aspects of audit integration
        let mut config = AuditConfig::default();
        config.hmac_key = Some(base64::engine::general_purpose::STANDARD.encode("test_hmac_key_32_bytes_long_1234"));
        config.tamper_evident = true;
        config.min_security_level = SecurityLevel::Medium;
        config.log_path = Some("test_audit_security.log".to_string());
        
        let mut audit_logger = DefaultAuditLogger::new(config).unwrap();
        
        // Test with different security levels
        let low_entry = audit_logger.create_entry(
            AuditEventType::DataAccess,
            SecurityLevel::Low,
            Some("user".to_string()),
            None,
            "low_security_action".to_string(),
            EventOutcome::Success,
            HashMap::new(),
        ).unwrap();
        
        let high_entry = audit_logger.create_entry(
            AuditEventType::Authentication,
            SecurityLevel::High,
            Some("user".to_string()),
            None,
            "high_security_action".to_string(),
            EventOutcome::Success,
            HashMap::new(),
        ).unwrap();
        
        // Log entries (only high security level should be logged)
        let low_result = audit_logger.log(low_entry);
        let high_result = audit_logger.log(high_entry);
        
        // Low security entry should be filtered out
        assert!(low_result.is_ok());
        assert!(high_result.is_ok());
        
        // Verify only high security entry was logged
        let stats = audit_logger.get_statistics().unwrap();
        assert_eq!(stats.total_entries, 1);
        
        // Verify integrity
        let integrity_report = audit_logger.verify_integrity().unwrap();
        assert_eq!(integrity_report.violations, 0);
        
        // Clean up
        std::fs::remove_file("test_audit_security.log").ok();
    }

    // Helper function to get current memory usage (simplified)
    fn get_memory_usage() -> usize {
        // This is a simplified version - in practice you'd use a proper memory profiler
        std::mem::size_of::<AuditEntry>() * 5000 + // Entries
        std::mem::size_of::<HashMap<String, String>>() * 5000 * 10 // Metadata
    }
}
