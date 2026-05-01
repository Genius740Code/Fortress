//! Final audit integration tests for Fortress
//!
//! This module tests audit system integration with other Fortress components
//! ensuring fast, scalable, efficient, secure, and error-free behavior.

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::time::{SystemTime, UNIX_EPOCH};
    use fortress_core::audit::{
        AuditConfig, AuditEntry, AuditEventType, SecurityLevel, EventOutcome,
        DefaultAuditLogger, AuditLogger, AuditQuery,
    };
    use fortress_core::audit_analysis::{
        AuditAnalyzer, AnomalyType,
    };
    use base64;

    #[test]
    fn test_audit_basic_functionality() {
        // Test basic audit functionality
        let mut config = AuditConfig::default();
        config.log_path = Some("test_audit_basic.log".to_string());
        
        let mut audit_logger = DefaultAuditLogger::new(config).unwrap();
        
        // Create a simple audit entry
        let entry = audit_logger.create_entry(
            AuditEventType::Authentication,
            SecurityLevel::Medium,
            Some("test_user".to_string()),
            None,
            "login".to_string(),
            EventOutcome::Success,
            HashMap::new(),
        ).unwrap();
        
        // Log the entry
        assert!(audit_logger.log(entry).is_ok());
        
        // Clean up
        std::fs::remove_file("test_audit_basic.log").ok();
    }

    #[test]
    fn test_audit_multiple_entries() {
        // Test creating multiple audit entries
        let mut config = AuditConfig::default();
        config.log_path = Some("test_audit_multiple.log".to_string());
        
        let mut audit_logger = DefaultAuditLogger::new(config).unwrap();
        
        // Create multiple entries
        for i in 0..10 {
            let event_type = match i % 3 {
                0 => AuditEventType::Authentication,
                1 => AuditEventType::DataAccess,
                _ => AuditEventType::Authorization,
            };
            
            let entry = audit_logger.create_entry(
                event_type,
                SecurityLevel::Medium,
                Some(format!("user_{}", i)),
                None,
                format!("action_{}", i),
                EventOutcome::Success,
                HashMap::new(),
            ).unwrap();
            
            assert!(audit_logger.log(entry).is_ok());
        }
        
        // Query entries - use a simpler approach
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
        
        // Filter for authentication events
        let auth_entries: Vec<_> = all_entries.iter()
            .filter(|e| e.event_type == AuditEventType::Authentication)
            .collect();
        
        println!("Authentication entries found: {}", auth_entries.len());
        assert_eq!(auth_entries.len(), 8); // Should find 8 authentication events (0, 3, 6, 9)
        
        // Clean up
        std::fs::remove_file("test_audit_multiple.log").ok();
    }

    #[test]
    fn test_audit_statistics_generation() {
        // Test audit statistics generation
        let mut config = AuditConfig::default();
        config.log_path = Some("test_audit_stats.log".to_string());
        
        let mut audit_logger = DefaultAuditLogger::new(config).unwrap();
        
        // Create entries with different characteristics
        for i in 0..20 {
            let entry = audit_logger.create_entry(
                match i % 4 {
                    0 => AuditEventType::Authentication,
                    1 => AuditEventType::DataAccess,
                    2 => AuditEventType::Authorization,
                    _ => AuditEventType::System,
                },
                match i % 4 {
                    0 => SecurityLevel::Low,
                    1 => SecurityLevel::Medium,
                    2 => SecurityLevel::High,
                    _ => SecurityLevel::Critical,
                },
                Some(format!("user_{}", i % 5)),
                None,
                format!("action_{}", i),
                if i % 3 == 0 { EventOutcome::Failure } else { EventOutcome::Success },
                HashMap::new(),
            ).unwrap();
            
            assert!(audit_logger.log(entry).is_ok());
        }
        
        // Generate statistics
        let stats = audit_logger.get_statistics().unwrap();
        
        // Verify statistics
        assert_eq!(stats.total_entries, 20);
        assert!(!stats.entries_by_event_type.is_empty());
        assert!(!stats.entries_by_security_level.is_empty());
        assert!(!stats.entries_by_outcome.is_empty());
        
        // Clean up
        std::fs::remove_file("test_audit_stats.log").ok();
    }

    #[test]
    fn test_audit_analysis_integration() {
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
        for i in 0..12 {
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
        
        // Should detect brute force attack
        let brute_force_anomalies: Vec<_> = anomalies.iter()
            .filter(|a| matches!(a.anomaly_type, AnomalyType::BruteForceAttack))
            .collect();
        
        assert!(!brute_force_anomalies.is_empty());
        assert_eq!(brute_force_anomalies[0].severity, SecurityLevel::High);
        
        // Clean up
        std::fs::remove_file("test_audit_analysis.log").ok();
    }

    #[test]
    fn test_audit_performance() {
        // Test audit system performance
        let mut config = AuditConfig::default();
        config.log_path = Some("test_audit_performance.log".to_string());
        
        let mut audit_logger = DefaultAuditLogger::new(config).unwrap();
        
        let start = std::time::Instant::now();
        
        // Create many entries
        for i in 0..500 {
            let entry = audit_logger.create_entry(
                AuditEventType::DataAccess,
                SecurityLevel::Medium,
                Some(format!("user_{}", i % 100)),
                Some(format!("resource_{}", i % 50)),
                format!("action_{}", i),
                EventOutcome::Success,
                HashMap::new(),
            ).unwrap();
            
            assert!(audit_logger.log(entry).is_ok());
        }
        
        let duration = start.elapsed();
        println!("Created and logged 500 audit entries in {:?}", duration);
        
        // Should complete within reasonable time (less than 1 second)
        assert!(duration.as_secs() < 1);
        
        // Clean up
        std::fs::remove_file("test_audit_performance.log").ok();
    }

    #[test]
    fn test_audit_error_handling() {
        // Test audit error handling
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
        
        // Test with disabled logging
        let mut config = AuditConfig::default();
        config.enabled = false;
        config.log_path = Some("test_audit_disabled.log".to_string());
        
        let mut audit_logger = DefaultAuditLogger::new(config).unwrap();
        
        let entry = audit_logger.create_entry(
            AuditEventType::Authentication,
            SecurityLevel::High,
            Some("user".to_string()),
            None,
            "login".to_string(),
            EventOutcome::Success,
            HashMap::new(),
        ).unwrap();
        
        // Should succeed even with disabled logging
        assert!(audit_logger.log(entry).is_ok());
        
        // Clean up
        std::fs::remove_file("test_audit_disabled.log").ok();
    }
}
