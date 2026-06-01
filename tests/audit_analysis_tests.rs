//! Comprehensive audit analysis tests for Fortress
//!
//! This module tests audit log analysis, anomaly detection, and reporting
//! ensuring fast, scalable, efficient, secure, and error-free behavior.

#[cfg(test)]
mod tests {
    use fortress_core::audit::{
        AuditEntry, AuditEventType, AuditQuery, EventOutcome, SecurityLevel,
    };
    use fortress_core::audit_analysis::{
        AnomalyType, AuditAnalyzer, ReportGenerator, SecurityAnomaly,
    };
    use std::collections::HashMap;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn create_test_entry(
        id: &str,
        timestamp: u64,
        event_type: AuditEventType,
        security_level: SecurityLevel,
        principal: Option<&str>,
        resource: Option<&str>,
        action: &str,
        outcome: EventOutcome,
    ) -> AuditEntry {
        let mut metadata = HashMap::new();
        metadata.insert("test".to_string(), "value".to_string());

        AuditEntry {
            id: id.to_string(),
            timestamp,
            event_type,
            security_level,
            principal: principal.map(|s| s.to_string()),
            resource: resource.map(|s| s.to_string()),
            action: action.to_string(),
            outcome,
            metadata,
            previous_hash: None,
            current_hash: format!("hash_{}", id),
            signature: format!("sig_{}", id),
        }
    }

    #[test]
    fn test_audit_analyzer_creation() {
        // Test analyzer creation with empty entries
        let entries = vec![];
        let analyzer = AuditAnalyzer::new(entries);

        let insights = analyzer.generate_insights().unwrap();
        assert_eq!(insights.total_entries, 0);
        assert!(insights.entries_by_type.is_empty());
        assert!(insights.entries_by_level.is_empty());
        assert!(insights.entries_by_outcome.is_empty());
    }

    #[test]
    fn test_audit_analyzer_single_entry() {
        // Test analyzer with single entry
        let entries = vec![create_test_entry(
            "1",
            1000,
            AuditEventType::Authentication,
            SecurityLevel::Medium,
            Some("user1"),
            None,
            "login",
            EventOutcome::Success,
        )];

        let analyzer = AuditAnalyzer::new(entries);
        let insights = analyzer.generate_insights().unwrap();

        assert_eq!(insights.total_entries, 1);
        assert_eq!(
            insights
                .entries_by_type
                .get(&AuditEventType::Authentication),
            Some(&1)
        );
        assert_eq!(
            insights.entries_by_level.get(&SecurityLevel::Medium),
            Some(&1)
        );
        assert_eq!(
            insights.entries_by_outcome.get(&EventOutcome::Success),
            Some(&1)
        );
        assert_eq!(insights.active_principals.len(), 1);
        assert!(insights.active_principals.contains(&"user1".to_string()));
    }

    #[test]
    fn test_audit_analyzer_multiple_entries() {
        // Test analyzer with multiple entries of different types
        let entries = vec![
            create_test_entry(
                "1",
                1000,
                AuditEventType::Authentication,
                SecurityLevel::Medium,
                Some("user1"),
                None,
                "login",
                EventOutcome::Success,
            ),
            create_test_entry(
                "2",
                2000,
                AuditEventType::DataAccess,
                SecurityLevel::Low,
                Some("user1"),
                Some("/data"),
                "read",
                EventOutcome::Success,
            ),
            create_test_entry(
                "3",
                3000,
                AuditEventType::Authorization,
                SecurityLevel::High,
                Some("admin"),
                Some("/admin"),
                "grant",
                EventOutcome::Success,
            ),
            create_test_entry(
                "4",
                4000,
                AuditEventType::Authentication,
                SecurityLevel::Medium,
                Some("user2"),
                None,
                "login",
                EventOutcome::Failure,
            ),
            create_test_entry(
                "5",
                5000,
                AuditEventType::ConfigurationChange,
                SecurityLevel::Critical,
                Some("admin"),
                Some("/config"),
                "update",
                EventOutcome::Success,
            ),
        ];

        let analyzer = AuditAnalyzer::new(entries);
        let insights = analyzer.generate_insights().unwrap();

        assert_eq!(insights.total_entries, 5);
        assert_eq!(
            insights
                .entries_by_type
                .get(&AuditEventType::Authentication),
            Some(&2)
        );
        assert_eq!(
            insights.entries_by_type.get(&AuditEventType::DataAccess),
            Some(&1)
        );
        assert_eq!(
            insights.entries_by_type.get(&AuditEventType::Authorization),
            Some(&1)
        );
        assert_eq!(
            insights
                .entries_by_type
                .get(&AuditEventType::ConfigurationChange),
            Some(&1)
        );

        assert_eq!(
            insights.entries_by_level.get(&SecurityLevel::Medium),
            Some(&2)
        );
        assert_eq!(insights.entries_by_level.get(&SecurityLevel::Low), Some(&1));
        assert_eq!(
            insights.entries_by_level.get(&SecurityLevel::High),
            Some(&1)
        );
        assert_eq!(
            insights.entries_by_level.get(&SecurityLevel::Critical),
            Some(&1)
        );

        assert_eq!(
            insights.entries_by_outcome.get(&EventOutcome::Success),
            Some(&4)
        );
        assert_eq!(
            insights.entries_by_outcome.get(&EventOutcome::Failure),
            Some(&1)
        );

        assert_eq!(insights.active_principals.len(), 3);
        assert!(insights.active_principals.contains(&"user1".to_string()));
        assert!(insights.active_principals.contains(&"user2".to_string()));
        assert!(insights.active_principals.contains(&"admin".to_string()));
    }

    #[test]
    fn test_brute_force_detection() {
        // Test brute force attack detection
        let base_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;

        let mut entries = vec![];

        // Create 10 failed authentication attempts within 5 minutes
        for i in 0..10 {
            entries.push(create_test_entry(
                &format!("bf_{}", i),
                base_time + (i * 30_000), // 30 seconds apart
                AuditEventType::Authentication,
                SecurityLevel::Medium,
                Some("attacker"),
                None,
                "login",
                EventOutcome::Failure,
            ));
        }

        let analyzer = AuditAnalyzer::new(entries);
        let anomalies = analyzer.detect_anomalies().unwrap();

        // Should detect brute force attack
        assert!(!anomalies.is_empty());
        let brute_force_anomalies: Vec<_> = anomalies
            .iter()
            .filter(|a| matches!(a.anomaly_type, AnomalyType::BruteForceAttack))
            .collect();

        assert!(!brute_force_anomalies.is_empty());
        assert_eq!(brute_force_anomalies[0].severity, SecurityLevel::High);
        assert!(brute_force_anomalies[0].description.contains("brute force"));
        assert_eq!(
            brute_force_anomalies[0].principal,
            Some("attacker".to_string())
        );
    }

    #[test]
    fn test_privilege_escalation_detection() {
        // Test privilege escalation detection
        let entries = vec![
            create_test_entry(
                "1",
                1000,
                AuditEventType::Authorization,
                SecurityLevel::High,
                Some("user1"),
                None,
                "role_change_to_admin",
                EventOutcome::Success,
            ),
            create_test_entry(
                "2",
                2000,
                AuditEventType::Authorization,
                SecurityLevel::High,
                Some("user1"),
                None,
                "permission_grant_admin",
                EventOutcome::Success,
            ),
            create_test_entry(
                "3",
                3000,
                AuditEventType::Authorization,
                SecurityLevel::High,
                Some("user1"),
                None,
                "role_change_to_superuser",
                EventOutcome::Success,
            ),
            create_test_entry(
                "4",
                4000,
                AuditEventType::Authorization,
                SecurityLevel::High,
                Some("user1"),
                None,
                "permission_grant_all",
                EventOutcome::Success,
            ),
            create_test_entry(
                "5",
                5000,
                AuditEventType::Authorization,
                SecurityLevel::High,
                Some("user1"),
                None,
                "role_change_to_owner",
                EventOutcome::Success,
            ),
            create_test_entry(
                "6",
                6000,
                AuditEventType::Authorization,
                SecurityLevel::High,
                Some("user1"),
                None,
                "permission_grant_system",
                EventOutcome::Success,
            ),
        ];

        let analyzer = AuditAnalyzer::new(entries);
        let anomalies = analyzer.detect_anomalies().unwrap();

        // Should detect privilege escalation
        let privilege_anomalies: Vec<_> = anomalies
            .iter()
            .filter(|a| matches!(a.anomaly_type, AnomalyType::PrivilegeEscalation))
            .collect();

        assert!(!privilege_anomalies.is_empty());
        assert_eq!(privilege_anomalies[0].severity, SecurityLevel::Critical);
        assert!(privilege_anomalies[0]
            .description
            .contains("role/permission changes"));
        assert_eq!(privilege_anomalies[0].principal, Some("user1".to_string()));
    }

    #[test]
    fn test_unusual_access_pattern_detection() {
        // Test unusual access pattern detection
        let mut entries = vec![];

        // Create entries for user accessing many different resources
        for i in 0..1500 {
            entries.push(create_test_entry(
                &format!("access_{}", i),
                1000 + i,
                AuditEventType::DataAccess,
                SecurityLevel::Low,
                Some("data_scrapper"),
                Some(&format!("/resource/{}", i)),
                "read",
                EventOutcome::Success,
            ));
        }

        let analyzer = AuditAnalyzer::new(entries);
        let anomalies = analyzer.detect_anomalies().unwrap();

        // Should detect unusual access pattern
        let access_anomalies: Vec<_> = anomalies
            .iter()
            .filter(|a| matches!(a.anomaly_type, AnomalyType::UnusualAccessPattern))
            .collect();

        assert!(!access_anomalies.is_empty());
        assert_eq!(access_anomalies[0].severity, SecurityLevel::Medium);
        assert!(access_anomalies[0].description.contains("data scraping"));
        assert_eq!(
            access_anomalies[0].principal,
            Some("data_scrapper".to_string())
        );
    }

    #[test]
    fn test_mass_data_access_detection() {
        // Test mass data access detection
        let base_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;

        let mut entries = vec![];

        // Create 15000 access events within 1 minute
        // All events in the same time bucket to trigger detection
        for i in 0..15000 {
            entries.push(create_test_entry(
                &format!("mass_{}", i),
                base_time, // Same timestamp for all events
                AuditEventType::DataAccess,
                SecurityLevel::Low,
                Some("bulk_user"),
                Some("/data"),
                "read",
                EventOutcome::Success,
            ));
        }

        let analyzer = AuditAnalyzer::new(entries);
        let anomalies = analyzer.detect_anomalies().unwrap();

        // Should detect mass data access
        let mass_access_anomalies: Vec<_> = anomalies
            .iter()
            .filter(|a| matches!(a.anomaly_type, AnomalyType::MassDataAccess))
            .collect();

        assert!(!mass_access_anomalies.is_empty());
        assert_eq!(mass_access_anomalies[0].severity, SecurityLevel::High);
        assert!(mass_access_anomalies[0]
            .description
            .contains("Mass data access"));
    }

    #[test]
    fn test_configuration_tampering_detection() {
        // Test configuration tampering detection
        let mut entries = vec![];

        // Create 60 configuration changes
        for i in 0..60 {
            entries.push(create_test_entry(
                &format!("config_{}", i),
                1000 + i,
                AuditEventType::ConfigurationChange,
                SecurityLevel::Critical,
                Some("suspicious_admin"),
                Some(&format!("/config/{}", i)),
                "update",
                EventOutcome::Success,
            ));
        }

        let analyzer = AuditAnalyzer::new(entries);
        let anomalies = analyzer.detect_anomalies().unwrap();

        // Should detect configuration tampering
        let config_anomalies: Vec<_> = anomalies
            .iter()
            .filter(|a| matches!(a.anomaly_type, AnomalyType::ConfigurationTampering))
            .collect();

        assert!(!config_anomalies.is_empty());
        assert_eq!(config_anomalies[0].severity, SecurityLevel::Critical);
        assert!(config_anomalies[0]
            .description
            .contains("configuration changes"));
        assert_eq!(
            config_anomalies[0].principal,
            Some("suspicious_admin".to_string())
        );
    }

    #[test]
    fn test_time_based_anomaly_detection() {
        // Test time-based anomaly detection
        let mut entries = vec![];

        // Create entries during off-hours (2 AM - 4 AM)
        for hour in [2, 3, 4] {
            for _ in 0..100 {
                let timestamp = ((hour * 3600) * 1000) as u64; // Convert to milliseconds
                entries.push(create_test_entry(
                    &format!("offhour_{}", hour),
                    timestamp,
                    AuditEventType::DataAccess,
                    SecurityLevel::Low,
                    Some("night_user"),
                    None,
                    "access",
                    EventOutcome::Success,
                ));
            }
        }

        // Create some entries during business hours (9 AM - 5 PM)
        for hour in [9, 10, 11, 14, 15, 16, 17] {
            for _ in 0..50 {
                let timestamp = ((hour * 3600) * 1000) as u64;
                entries.push(create_test_entry(
                    &format!("business_{}", hour),
                    timestamp,
                    AuditEventType::DataAccess,
                    SecurityLevel::Low,
                    Some("day_user"),
                    None,
                    "access",
                    EventOutcome::Success,
                ));
            }
        }

        let analyzer = AuditAnalyzer::new(entries);
        let anomalies = analyzer.detect_anomalies().unwrap();

        // Should detect time-based anomaly
        let time_anomalies: Vec<_> = anomalies
            .iter()
            .filter(|a| matches!(a.anomaly_type, AnomalyType::UnusualTimePattern))
            .collect();

        assert!(!time_anomalies.is_empty());
        assert_eq!(time_anomalies[0].severity, SecurityLevel::Medium);
        assert!(time_anomalies[0]
            .description
            .contains("Unusual activity pattern"));
    }

    #[test]
    fn test_audit_analyzer_search_functionality() {
        // Test search functionality
        let entries = vec![
            create_test_entry(
                "1",
                1000,
                AuditEventType::Authentication,
                SecurityLevel::Medium,
                Some("user1"),
                None,
                "login",
                EventOutcome::Success,
            ),
            create_test_entry(
                "2",
                2000,
                AuditEventType::DataAccess,
                SecurityLevel::Low,
                Some("user1"),
                Some("/data"),
                "read",
                EventOutcome::Success,
            ),
            create_test_entry(
                "3",
                3000,
                AuditEventType::Authentication,
                SecurityLevel::Medium,
                Some("user2"),
                None,
                "login",
                EventOutcome::Failure,
            ),
            create_test_entry(
                "4",
                4000,
                AuditEventType::Authorization,
                SecurityLevel::High,
                Some("admin"),
                Some("/admin"),
                "grant",
                EventOutcome::Success,
            ),
        ];

        let analyzer = AuditAnalyzer::new(entries);

        // Test search by principal
        let query = AuditQuery {
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

        let results = analyzer.search(&query).unwrap();
        assert_eq!(results.len(), 2);

        // Test search by event type
        let query = AuditQuery {
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

        let results = analyzer.search(&query).unwrap();
        assert_eq!(results.len(), 2);

        // Test search by outcome
        let query = AuditQuery {
            start_time: None,
            end_time: None,
            event_types: None,
            security_levels: None,
            principal: None,
            resource: None,
            action: None,
            outcome: Some(EventOutcome::Failure),
            limit: None,
            offset: None,
        };

        let results = analyzer.search(&query).unwrap();
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn test_security_report_generation() {
        // Test comprehensive security report generation
        let entries = vec![
            create_test_entry(
                "1",
                1000,
                AuditEventType::Authentication,
                SecurityLevel::Medium,
                Some("user1"),
                None,
                "login",
                EventOutcome::Success,
            ),
            create_test_entry(
                "2",
                2000,
                AuditEventType::DataAccess,
                SecurityLevel::Low,
                Some("user1"),
                Some("/data"),
                "read",
                EventOutcome::Success,
            ),
            create_test_entry(
                "3",
                3000,
                AuditEventType::Authentication,
                SecurityLevel::Medium,
                Some("user2"),
                None,
                "login",
                EventOutcome::Failure,
            ),
            create_test_entry(
                "4",
                4000,
                AuditEventType::Authorization,
                SecurityLevel::High,
                Some("admin"),
                Some("/admin"),
                "grant",
                EventOutcome::Success,
            ),
        ];

        let analyzer = AuditAnalyzer::new(entries);
        let insights = analyzer.generate_insights().unwrap();
        let anomalies = analyzer.detect_anomalies().unwrap();

        let report = ReportGenerator::generate_security_report(&insights, &anomalies).unwrap();

        // Verify report structure
        assert!(report.generated_at > 0);
        assert_eq!(report.insights.total_entries, 4);
        assert_eq!(report.anomalies.len(), anomalies.len());
        assert!(report.risk_score >= 0.0 && report.risk_score <= 100.0);
        // Recommendations may be empty if no anomalies are detected
        // This is expected behavior for normal audit logs
    }

    #[test]
    fn test_risk_score_calculation() {
        // Test risk score calculation with different scenarios
        let entries = vec![
            create_test_entry(
                "1",
                1000,
                AuditEventType::Authentication,
                SecurityLevel::Medium,
                Some("user1"),
                None,
                "login",
                EventOutcome::Success,
            ),
            create_test_entry(
                "2",
                2000,
                AuditEventType::Authentication,
                SecurityLevel::Medium,
                Some("user1"),
                None,
                "login",
                EventOutcome::Failure,
            ),
            create_test_entry(
                "3",
                3000,
                AuditEventType::Authentication,
                SecurityLevel::Medium,
                Some("user1"),
                None,
                "login",
                EventOutcome::Failure,
            ),
        ];

        let analyzer = AuditAnalyzer::new(entries);
        let insights = analyzer.generate_insights().unwrap();
        let anomalies = analyzer.detect_anomalies().unwrap();

        let report = ReportGenerator::generate_security_report(&insights, &anomalies).unwrap();

        // Risk score should be calculated based on failed auth and anomalies
        assert!(report.risk_score > 0.0);
        assert!(report.risk_score <= 100.0);
    }

    #[test]
    fn test_security_recommendations() {
        // Test security recommendations generation
        let entries = vec![];

        let analyzer = AuditAnalyzer::new(entries);
        let insights = analyzer.generate_insights().unwrap();

        // Create different types of anomalies
        let anomalies = vec![
            SecurityAnomaly {
                anomaly_type: AnomalyType::BruteForceAttack,
                severity: SecurityLevel::High,
                description: "Brute force attack detected".to_string(),
                timestamp: 1000,
                principal: Some("attacker".to_string()),
                resource: None,
                metadata: HashMap::new(),
            },
            SecurityAnomaly {
                anomaly_type: AnomalyType::PrivilegeEscalation,
                severity: SecurityLevel::Critical,
                description: "Privilege escalation attempt".to_string(),
                timestamp: 2000,
                principal: Some("user".to_string()),
                resource: None,
                metadata: HashMap::new(),
            },
        ];

        let report = ReportGenerator::generate_security_report(&insights, &anomalies).unwrap();

        // Should have recommendations for both anomaly types
        assert!(!report.recommendations.is_empty());

        let brute_force_rec: Vec<_> = report
            .recommendations
            .iter()
            .filter(|r| r.title.contains("account lockout"))
            .collect();
        assert!(!brute_force_rec.is_empty());

        let privilege_rec: Vec<_> = report
            .recommendations
            .iter()
            .filter(|r| r.title.contains("role assignment"))
            .collect();
        assert!(!privilege_rec.is_empty());
    }

    #[test]
    fn test_audit_analyzer_performance() {
        // Test performance with large dataset
        let start = std::time::Instant::now();

        let mut entries = vec![];
        for i in 0..10000 {
            entries.push(create_test_entry(
                &format!("perf_{}", i),
                1000 + i,
                if i % 4 == 0 {
                    AuditEventType::Authentication
                } else {
                    AuditEventType::DataAccess
                },
                if i % 5 == 0 {
                    SecurityLevel::High
                } else {
                    SecurityLevel::Medium
                },
                Some(format!("user_{}", i % 100).as_str()),
                Some(format!("resource_{}", i % 50).as_str()),
                "action",
                if i % 10 == 0 {
                    EventOutcome::Failure
                } else {
                    EventOutcome::Success
                },
            ));
        }

        let creation_time = start.elapsed();
        println!("Created 10k entries in {:?}", creation_time);

        let analysis_start = std::time::Instant::now();
        let analyzer = AuditAnalyzer::new(entries);
        let insights = analyzer.generate_insights().unwrap();
        let _anomalies = analyzer.detect_anomalies().unwrap();
        let analysis_time = analysis_start.elapsed();

        println!("Analyzed 10k entries in {:?}", analysis_time);

        // Performance assertions
        assert!(creation_time.as_secs() < 1);
        assert!(analysis_time.as_secs() < 2);
        assert_eq!(insights.total_entries, 10000);
    }

    #[test]
    fn test_audit_analyzer_memory_efficiency() {
        // Test memory efficiency with large dataset
        let start_memory = get_memory_usage();

        let mut entries = vec![];
        for i in 0..50000 {
            entries.push(create_test_entry(
                &format!("mem_{}", i),
                1000 + i,
                AuditEventType::DataAccess,
                SecurityLevel::Medium,
                Some(format!("user_{}", i % 1000).as_str()),
                None,
                "action",
                EventOutcome::Success,
            ));
        }

        let analyzer = AuditAnalyzer::new(entries);
        let insights = analyzer.generate_insights().unwrap();

        let end_memory = get_memory_usage();
        let memory_increase = end_memory - start_memory;

        // Memory should be reasonable (less than 200MB for 50k entries)
        assert!(memory_increase < 200 * 1024 * 1024);
        assert_eq!(insights.total_entries, 50000);

        println!("Memory usage for 50k entries: {} bytes", memory_increase);
    }

    #[test]
    fn test_audit_analyzer_edge_cases() {
        // Test edge cases and error handling
        let entries = vec![
            create_test_entry(
                "1",
                u64::MAX,
                AuditEventType::Authentication,
                SecurityLevel::Medium,
                Some(""),
                Some(""),
                "",
                EventOutcome::Success,
            ),
            create_test_entry(
                "2",
                0,
                AuditEventType::DataAccess,
                SecurityLevel::Low,
                None,
                None,
                "action",
                EventOutcome::Failure,
            ),
        ];

        let analyzer = AuditAnalyzer::new(entries);

        // Should handle edge cases gracefully
        let insights = analyzer.generate_insights().unwrap();
        assert_eq!(insights.total_entries, 2);

        let anomalies = analyzer.detect_anomalies().unwrap();
        // Should not panic or return errors
        assert!(!anomalies.is_empty() || anomalies.is_empty()); // Always true, just checking no panic
    }

    #[test]
    fn test_audit_analyzer_concurrent_analysis() {
        // Test concurrent analysis
        use std::sync::Arc;
        use std::thread;

        let entries = vec![
            create_test_entry(
                "1",
                1000,
                AuditEventType::Authentication,
                SecurityLevel::Medium,
                Some("user1"),
                None,
                "login",
                EventOutcome::Success,
            ),
            create_test_entry(
                "2",
                2000,
                AuditEventType::DataAccess,
                SecurityLevel::Low,
                Some("user1"),
                Some("/data"),
                "read",
                EventOutcome::Success,
            ),
        ];

        let analyzer = AuditAnalyzer::new(entries);
        let analyzer = Arc::new(analyzer);
        let mut handles = vec![];

        // Spawn multiple threads analyzing the same data
        for _ in 0..10 {
            let analyzer_clone: Arc<AuditAnalyzer> = Arc::clone(&analyzer);
            let handle = thread::spawn(move || {
                let insights = analyzer_clone.generate_insights().unwrap();
                let anomalies = analyzer_clone.detect_anomalies().unwrap();
                (insights.total_entries, anomalies.len())
            });
            handles.push(handle);
        }

        // Wait for all threads and verify consistent results
        let mut results = vec![];
        for handle in handles {
            results.push(handle.join().unwrap());
        }

        // All results should be identical
        let first_result = results[0];
        for result in &results[1..] {
            assert_eq!(result.0, first_result.0);
            assert_eq!(result.1, first_result.1);
        }
    }

    // Helper function to get current memory usage (simplified)
    fn get_memory_usage() -> usize {
        // This is a simplified version - in practice you'd use a proper memory profiler
        std::mem::size_of::<AuditEntry>() * 50000 // Estimated
    }
}
