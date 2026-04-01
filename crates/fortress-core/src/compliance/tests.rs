//! Compliance Framework Tests
//!
//! Comprehensive test suite for all compliance framework features
//! including GDPR, HIPAA, and PCI-DSS implementations.

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compliance::framework::*;
    use crate::compliance::gdpr::*;
    use crate::compliance::hipaa::*;
    use crate::compliance::pci_dss::*;
    use crate::compliance::config::*;
    use crate::compliance::audit::*;
    use chrono::Utc;
    use uuid::Uuid;

    #[tokio::test]
    async fn test_default_compliance_manager_initialization() {
        let manager = DefaultComplianceManager::new();
        let config = ComplianceConfig {
            enabled_frameworks: vec![ComplianceFramework::GDPR],
            default_retention_period: chrono::Duration::days(365),
            breach_notification: BreachNotificationConfig {
                notification_deadline_hours: 72,
                notification_recipients: vec!["test@example.com".to_string()],
                regulatory_bodies: vec!["ICO".to_string()],
                notification_template: "Test template".to_string(),
            },
            audit_logging: AuditConfig {
                enabled: true,
                retention_period: chrono::Duration::days(365),
                logged_events: vec!["test".to_string()],
                storage_location: "test".to_string(),
            },
            encryption: EncryptionConfig {
                required_algorithms: vec!["AES-256-GCM".to_string()],
                minimum_key_strength: 256,
                encryption_at_rest_required: true,
                encryption_in_transit_required: true,
            },
            access_control: AccessControlConfig {
                rbac_enabled: true,
                mfa_required: false,
                session_timeout_minutes: 30,
                password_policy: PasswordPolicy {
                    min_length: 12,
                    require_special_chars: true,
                    require_numbers: true,
                    require_uppercase: true,
                    expiration_days: 90,
                },
            },
        };

        let result = manager.initialize(&config).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_data_subject_registration() {
        let manager = DefaultComplianceManager::new();
        let subject = DataSubject {
            id: "test_subject_001".to_string(),
            subject_type: "customer".to_string(),
            contact_info: Some("test@example.com".to_string()),
            consent_records: vec![],
            rights_requests: vec![],
        };

        let result = manager.register_data_subject(&subject).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_consent_recording() {
        let manager = DefaultComplianceManager::new();
        let consent = ConsentRecord {
            id: Uuid::new_v4(),
            timestamp: Utc::now(),
            purposes: vec!["marketing".to_string()],
            withdrawable: true,
            expires_at: None,
            legal_basis: "consent".to_string(),
            metadata: std::collections::HashMap::new(),
        };

        // First register a data subject
        let subject = DataSubject {
            id: "test_subject_002".to_string(),
            subject_type: "customer".to_string(),
            contact_info: Some("test@example.com".to_string()),
            consent_records: vec![],
            rights_requests: vec![],
        };
        manager.register_data_subject(&subject).await.unwrap();

        let result = manager.record_consent("test_subject_002", &consent).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_rights_request_processing() {
        let manager = DefaultComplianceManager::new();
        let request = RightsRequest {
            id: Uuid::new_v4(),
            request_type: RightsRequestType::Access,
            received_at: Utc::now(),
            status: RequestStatus::Pending,
            completed_at: None,
            details: std::collections::HashMap::new(),
            notes: vec!["Test request".to_string()],
        };

        let result = manager.process_rights_request(&request).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_gdpr_manager_initialization() {
        let base_manager = Box::new(DefaultComplianceManager::new());
        let gdpr_manager = GdprComplianceManager::new(base_manager);
        let config = ComplianceConfig {
            enabled_frameworks: vec![ComplianceFramework::GDPR],
            default_retention_period: chrono::Duration::days(365),
            breach_notification: BreachNotificationConfig {
                notification_deadline_hours: 72,
                notification_recipients: vec!["dpo@example.com".to_string()],
                regulatory_bodies: vec!["ICO".to_string()],
                notification_template: "GDPR template".to_string(),
            },
            audit_logging: AuditConfig {
                enabled: true,
                retention_period: chrono::Duration::days(365),
                logged_events: vec!["data_access".to_string()],
                storage_location: "gdpr_audit".to_string(),
            },
            encryption: EncryptionConfig {
                required_algorithms: vec!["AES-256-GCM".to_string()],
                minimum_key_strength: 256,
                encryption_at_rest_required: true,
                encryption_in_transit_required: true,
            },
            access_control: AccessControlConfig {
                rbac_enabled: true,
                mfa_required: false,
                session_timeout_minutes: 30,
                password_policy: PasswordPolicy {
                    min_length: 12,
                    require_special_chars: true,
                    require_numbers: true,
                    require_uppercase: true,
                    expiration_days: 90,
                },
            },
        };

        let result = gdpr_manager.initialize(&config).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_data_processor_registration() {
        let base_manager = Box::new(DefaultComplianceManager::new());
        let gdpr_manager = GdprComplianceManager::new(base_manager);
        
        let processor = DataProcessor {
            id: "processor_001".to_string(),
            name: "Test Processor".to_string(),
            contact_info: "contact@test.com".to_string(),
            data_types: vec!["email".to_string(), "name".to_string()],
            purposes: vec!["marketing".to_string()],
            data_subject_categories: vec!["customers".to_string()],
            retention_periods: std::collections::HashMap::new(),
            security_measures: vec!["encryption".to_string()],
            international_transfers: vec![],
            registered_at: Utc::now(),
            updated_at: Utc::now(),
        };

        let result = gdpr_manager.register_data_processor(&processor).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_dpia_creation() {
        let base_manager = Box::new(DefaultComplianceManager::new());
        let gdpr_manager = GdprComplianceManager::new(base_manager);
        
        let dpia = Dpia {
            id: "dpia_001".to_string(),
            activity_name: "Data Processing Test".to_string(),
            description: "Test DPIA".to_string(),
            data_types: vec!["personal_data".to_string()],
            data_subjects: vec!["customers".to_string()],
            scope: "Test scope".to_string(),
            purposes: vec!["marketing".to_string()],
            risk_assessment: RiskAssessment {
                likelihood: 2,
                severity: 2,
                risk_score: 4,
                risk_categories: vec!["privacy".to_string()],
                risks: vec!["data_breach".to_string()],
            },
            mitigation_measures: vec!["encryption".to_string()],
            required: true,
            status: DpiaStatus::InProgress,
            review_date: None,
            assessor: "test_assessor".to_string(),
            approval: None,
        };

        let result = gdpr_manager.create_dpia(&dpia).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_data_breach_recording() {
        let base_manager = Box::new(DefaultComplianceManager::new());
        let gdpr_manager = GdprComplianceManager::new(base_manager);
        
        let breach = DataBreach {
            id: Uuid::new_v4(),
            discovered_at: Utc::now(),
            occurred_at: Some(Utc::now()),
            description: "Test data breach".to_string(),
            data_types_affected: vec!["personal_data".to_string()],
            subjects_affected: 100,
            subject_categories: vec!["customers".to_string()],
            likely_consequences: vec!["identity_theft".to_string()],
            measures_taken: vec!["containment".to_string()],
            measures_proposed: vec!["notification".to_string()],
            authority_notified: false,
            authority_notification_date: None,
            subjects_notified: false,
            subjects_notification_date: None,
            dpo_contact: "dpo@test.com".to_string(),
            severity: BreachSeverity::Medium,
            status: BreachStatus::Discovered,
        };

        let result = gdpr_manager.record_data_breach(&breach).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_hipaa_manager_initialization() {
        let base_manager = Box::new(DefaultComplianceManager::new());
        let hipaa_manager = HipaaComplianceManager::new(base_manager);
        let config = ComplianceConfig {
            enabled_frameworks: vec![ComplianceFramework::HIPAA],
            default_retention_period: chrono::Duration::days(365 * 6),
            breach_notification: BreachNotificationConfig {
                notification_deadline_hours: 60,
                notification_recipients: vec!["security@test.com".to_string()],
                regulatory_bodies: vec!["HHS".to_string()],
                notification_template: "HIPAA template".to_string(),
            },
            audit_logging: AuditConfig {
                enabled: true,
                retention_period: chrono::Duration::days(365 * 6),
                logged_events: vec!["phi_access".to_string()],
                storage_location: "hipaa_audit".to_string(),
            },
            encryption: EncryptionConfig {
                required_algorithms: vec!["AES-256-GCM".to_string()],
                minimum_key_strength: 256,
                encryption_at_rest_required: true,
                encryption_in_transit_required: true,
            },
            access_control: AccessControlConfig {
                rbac_enabled: true,
                mfa_required: true,
                session_timeout_minutes: 15,
                password_policy: PasswordPolicy {
                    min_length: 15,
                    require_special_chars: true,
                    require_numbers: true,
                    require_uppercase: true,
                    expiration_days: 60,
                },
            },
        };

        let result = hipaa_manager.initialize(&config).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_covered_entity_registration() {
        let base_manager = Box::new(DefaultComplianceManager::new());
        let hipaa_manager = HipaaComplianceManager::new(base_manager);
        
        let entity = CoveredEntity {
            id: "entity_001".to_string(),
            name: "Test Healthcare Provider".to_string(),
            entity_type: CoveredEntityType::HealthcareProvider,
            contact_info: "contact@test.com".to_string(),
            privacy_officer: "privacy@test.com".to_string(),
            security_officer: "security@test.com".to_string(),
            phi_types: vec![PhiType::Diagnostic, PhiType::Treatment],
            business_associates: vec![],
            registered_at: Utc::now(),
            compliance_status: ComplianceStatus::FullyCompliant,
        };

        let result = hipaa_manager.register_covered_entity(&entity).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_phi_registration() {
        let base_manager = Box::new(DefaultComplianceManager::new());
        let hipaa_manager = HipaaComplianceManager::new(base_manager);
        
        let phi = ProtectedHealthInfo {
            id: "phi_001".to_string(),
            patient_id: "patient_001".to_string(),
            phi_type: PhiType::Diagnostic,
            classification: DataClassification::Confidential,
            access_controls: vec![AccessControl {
                control_type: "role_based".to_string(),
                required_role: "healthcare_provider".to_string(),
                conditions: std::collections::HashMap::new(),
            }],
            retention_period: Some(chrono::Duration::days(365 * 6)),
            minimum_necessary: true,
            metadata: std::collections::HashMap::new(),
        };

        let result = hipaa_manager.register_phi(&phi).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_security_incident_recording() {
        let base_manager = Box::new(DefaultComplianceManager::new());
        let hipaa_manager = HipaaComplianceManager::new(base_manager);
        
        let incident = SecurityIncident {
            id: Uuid::new_v4(),
            discovered_at: Utc::now(),
            occurred_at: Utc::now(),
            incident_type: SecurityIncidentType::UnauthorizedAccess,
            description: "Unauthorized PHI access".to_string(),
            phi_affected: vec!["phi_001".to_string()],
            individuals_affected: 50,
            root_cause: Some("stolen_credentials".to_string()),
            impact_assessment: ImpactAssessment {
                phi_nature: vec!["diagnostic_info".to_string()],
                re_identification_risk: RiskLevel::Medium,
                potential_harm: vec!["privacy_breach".to_string()],
                impact_level: ImpactLevel::Moderate,
            },
            mitigation_measures: vec!["password_reset".to_string()],
            breach_notification_required: true,
            breach_notification_date: None,
            status: IncidentStatus::Investigating,
            reporter: "security_team".to_string(),
        };

        let result = hipaa_manager.record_security_incident(&incident).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_pci_dss_manager_initialization() {
        let base_manager = Box::new(DefaultComplianceManager::new());
        let pci_manager = PciDssComplianceManager::new(base_manager);
        let config = ComplianceConfig {
            enabled_frameworks: vec![ComplianceFramework::PCIDSS],
            default_retention_period: chrono::Duration::days(365 * 3),
            breach_notification: BreachNotificationConfig {
                notification_deadline_hours: 72,
                notification_recipients: vec!["compliance@test.com".to_string()],
                regulatory_bodies: vec!["PCI_SSC".to_string()],
                notification_template: "PCI-DSS template".to_string(),
            },
            audit_logging: AuditConfig {
                enabled: true,
                retention_period: chrono::Duration::days(365 * 3),
                logged_events: vec!["cardholder_data_access".to_string()],
                storage_location: "pci_audit".to_string(),
            },
            encryption: EncryptionConfig {
                required_algorithms: vec!["AES-256-GCM".to_string(), "RSA-2048".to_string()],
                minimum_key_strength: 128,
                encryption_at_rest_required: true,
                encryption_in_transit_required: true,
            },
            access_control: AccessControlConfig {
                rbac_enabled: true,
                mfa_required: true,
                session_timeout_minutes: 10,
                password_policy: PasswordPolicy {
                    min_length: 12,
                    require_special_chars: true,
                    require_numbers: true,
                    require_uppercase: true,
                    expiration_days: 90,
                },
            },
        };

        let result = pci_manager.initialize(&config).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_cardholder_data_registration() {
        let base_manager = Box::new(DefaultComplianceManager::new());
        let pci_manager = PciDssComplianceManager::new(base_manager);
        
        let card_data = CardholderData {
            id: "card_001".to_string(),
            pan_encrypted: "encrypted_pan".to_string(),
            expiration_encrypted: "encrypted_exp".to_string(),
            cvv_encrypted: "encrypted_cvv".to_string(),
            cardholder_name_encrypted: "encrypted_name".to_string(),
            pan_token: Some("tokenized_pan".to_string()),
            encryption_key_id: crate::key::KeyId::new("key_001"),
            access_log: vec![],
            compliance_requirements: vec![PciRequirement::DataProtection],
        };

        // First register an encryption key
        let key = PciEncryptionKey {
            key_id: crate::key::KeyId::new("key_001"),
            algorithm: "AES-256-GCM".to_string(),
            key_strength: 256,
            created_at: Utc::now(),
            expires_at: Utc::now() + chrono::Duration::days(365),
            purpose: KeyPurpose::PanEncryption,
            rotation_schedule: RotationSchedule {
                frequency_days: 365,
                next_rotation: Utc::now() + chrono::Duration::days(365),
                automatic_rotation: true,
                notification_period_days: 30,
            },
            access_list: vec!["payment_system".to_string()],
            active: true,
            version: 1,
        };
        pci_manager.register_encryption_key(&key).await.unwrap();

        let result = pci_manager.register_cardholder_data(&card_data).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_encryption_key_registration() {
        let base_manager = Box::new(DefaultComplianceManager::new());
        let pci_manager = PciDssComplianceManager::new(base_manager);
        
        let key = PciEncryptionKey {
            key_id: crate::key::KeyId::new("key_002"),
            algorithm: "RSA-2048".to_string(),
            key_strength: 2048,
            created_at: Utc::now(),
            expires_at: Utc::now() + chrono::Duration::days(365),
            purpose: KeyPurpose::KeyEncryption,
            rotation_schedule: RotationSchedule {
                frequency_days: 365,
                next_rotation: Utc::now() + chrono::Duration::days(365),
                automatic_rotation: true,
                notification_period_days: 30,
            },
            access_list: vec!["key_management".to_string()],
            active: true,
            version: 1,
        };

        let result = pci_manager.register_encryption_key(&key).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_security_control_registration() {
        let base_manager = Box::new(DefaultComplianceManager::new());
        let pci_manager = PciDssComplianceManager::new(base_manager);
        
        let control = SecurityControl {
            id: "control_001".to_string(),
            requirement: PciRequirement::DataProtection,
            name: "Encryption at Rest".to_string(),
            description: "All cardholder data is encrypted at rest".to_string(),
            status: ControlStatus::Implemented,
            last_assessed: Some(Utc::now()),
            next_assessment: Utc::now() + chrono::Duration::days(90),
            owner: "security_team".to_string(),
            evidence: vec!["encryption_verification".to_string()],
            gaps: vec![],
            remediation_plans: vec![],
        };

        let result = pci_manager.register_security_control(&control).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_vulnerability_scan_recording() {
        let base_manager = Box::new(DefaultComplianceManager::new());
        let pci_manager = PciDssComplianceManager::new(base_manager);
        
        let scan = VulnerabilityScan {
            id: Uuid::new_v4(),
            scan_date: Utc::now(),
            scan_type: ScanType::External,
            scanning_tool: "Nessus".to_string(),
            systems_scanned: vec!["payment_server".to_string()],
            total_vulnerabilities: 5,
            high_risk_vulnerabilities: 1,
            medium_risk_vulnerabilities: 2,
            low_risk_vulnerabilities: 2,
            findings: vec![VulnerabilityFinding {
                id: "vuln_001".to_string(),
                title: "SQL Injection".to_string(),
                severity: VulnerabilitySeverity::High,
                cvss_score: Some(8.5),
                affected_system: "payment_server".to_string(),
                description: "SQL injection vulnerability found".to_string(),
                remediation: "Apply security patch".to_string(),
                exploitable: true,
                business_impact: "High".to_string(),
            }],
            remediation_status: RemediationStatus::InProgress,
            approved_by: Some("security_manager".to_string()),
            approval_date: Some(Utc::now()),
        };

        let result = pci_manager.record_vulnerability_scan(&scan).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_compliance_configuration_validation() {
        let manager = ComplianceConfigManager::new();
        
        // Test GDPR configuration
        let gdpr_config = manager.get_default_config(ComplianceFramework::GDPR).unwrap();
        let issues = manager.validate_config(&gdpr_config).await.unwrap();
        assert!(issues.is_empty()); // Default config should be valid
        
        // Test invalid configuration
        let invalid_config = ComplianceConfig {
            enabled_frameworks: vec![],
            default_retention_period: chrono::Duration::days(365),
            breach_notification: BreachNotificationConfig {
                notification_deadline_hours: 100, // Invalid for GDPR
                notification_recipients: vec![],
                regulatory_bodies: vec![],
                notification_template: "".to_string(),
            },
            audit_logging: AuditConfig {
                enabled: false, // Invalid for compliance
                retention_period: chrono::Duration::days(365),
                logged_events: vec![],
                storage_location: "".to_string(),
            },
            encryption: EncryptionConfig {
                required_algorithms: vec![],
                minimum_key_strength: 64, // Too weak
                encryption_at_rest_required: false, // Invalid
                encryption_in_transit_required: false, // Invalid
            },
            access_control: AccessControlConfig {
                rbac_enabled: false, // Invalid
                mfa_required: false,
                session_timeout_minutes: 0,
                password_policy: PasswordPolicy {
                    min_length: 4, // Too short
                    require_special_chars: false,
                    require_numbers: false,
                    require_uppercase: false,
                    expiration_days: 0,
                },
            },
        };
        
        let issues = manager.validate_config(&invalid_config).await.unwrap();
        assert!(!issues.is_empty()); // Should have validation issues
    }

    #[tokio::test]
    async fn test_audit_logging() {
        let storage = Box::new(DefaultAuditStorage::new());
        let integrity_checker = Box::new(DefaultIntegrityChecker);
        let retention_policy = RetentionPolicy {
            default_retention_days: 365,
            framework_retentions: std::collections::HashMap::new(),
            event_type_retentions: std::collections::HashMap::new(),
            auto_cleanup_enabled: false,
            cleanup_interval_hours: 24,
        };
        
        let audit_logger = ComplianceAuditLogger::new(storage, retention_policy, integrity_checker);
        
        let event = ComplianceEvent {
            id: Uuid::new_v4(),
            timestamp: Utc::now(),
            framework: ComplianceFramework::GDPR,
            event_type: "test_event".to_string(),
            severity: EventSeverity::Info,
            description: "Test audit event".to_string(),
            affected_resources: vec!["test_resource".to_string()],
            actor: "test_user".to_string(),
            outcome: ComplianceEventOutcome::Success,
            metadata: std::collections::HashMap::new(),
        };
        
        let result = audit_logger.log_event(&event).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_audit_trail_retrieval() {
        let storage = Box::new(DefaultAuditStorage::new());
        let integrity_checker = Box::new(DefaultIntegrityChecker);
        let retention_policy = RetentionPolicy {
            default_retention_days: 365,
            framework_retentions: std::collections::HashMap::new(),
            event_type_retentions: std::collections::HashMap::new(),
            auto_cleanup_enabled: false,
            cleanup_interval_hours: 24,
        };
        
        let audit_logger = ComplianceAuditLogger::new(storage, retention_policy, integrity_checker);
        
        // Log some test events
        for i in 0..5 {
            let event = ComplianceEvent {
                id: Uuid::new_v4(),
                timestamp: Utc::now(),
                framework: ComplianceFramework::GDPR,
                event_type: format!("test_event_{}", i),
                severity: EventSeverity::Info,
                description: format!("Test audit event {}", i),
                affected_resources: vec![format!("test_resource_{}", i)],
                actor: "test_user".to_string(),
                outcome: ComplianceEventOutcome::Success,
                metadata: std::collections::HashMap::new(),
            };
            audit_logger.log_event(&event).await.unwrap();
        }
        
        let filter = AuditFilter {
            start_date: None,
            end_date: None,
            frameworks: vec![ComplianceFramework::GDPR],
            event_types: vec![],
            severities: vec![],
            users: vec![],
            resources: vec![],
            limit: Some(3),
        };
        
        let events = audit_logger.retrieve_audit_trail(&filter).await.unwrap();
        assert_eq!(events.len(), 3);
    }

    #[tokio::test]
    async fn test_integrity_verification() {
        let storage = Box::new(DefaultAuditStorage::new());
        let integrity_checker = Box::new(DefaultIntegrityChecker);
        let retention_policy = RetentionPolicy {
            default_retention_days: 365,
            framework_retentions: std::collections::HashMap::new(),
            event_type_retentions: std::collections::HashMap::new(),
            auto_cleanup_enabled: false,
            cleanup_interval_hours: 24,
        };
        
        let audit_logger = ComplianceAuditLogger::new(storage, retention_policy, integrity_checker);
        
        // Log a test event
        let event = ComplianceEvent {
            id: Uuid::new_v4(),
            timestamp: Utc::now(),
            framework: ComplianceFramework::GDPR,
            event_type: "integrity_test".to_string(),
            severity: EventSeverity::Info,
            description: "Test for integrity verification".to_string(),
            affected_resources: vec!["test_resource".to_string()],
            actor: "test_user".to_string(),
            outcome: ComplianceEventOutcome::Success,
            metadata: std::collections::HashMap::new(),
        };
        audit_logger.log_event(&event).await.unwrap();
        
        let integrity_report = audit_logger.verify_integrity(None).await.unwrap();
        assert!(integrity_report.integrity_passed);
        assert_eq!(integrity_report.total_events_checked, 1);
    }
}
