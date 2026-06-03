//! Multi-Party Authorization Integration Tests
//!
//! This module contains comprehensive integration tests for the MPA system,
//! testing complete workflows, edge cases, security scenarios, and performance.

use fortress_core::auth::{AuthManager, UserId};
use fortress_core::error::Result;
use fortress_core::mpa_service::MpaService;
use fortress_core::multi_person_auth::*;
use serde_json;
use std::sync::{Arc, RwLock};
use tokio::time::{sleep, Duration};

/// Test helper to create a complete MPA setup with multiple users
async fn setup_comprehensive_mpa_test() -> (MpaService, Vec<UserId>) {
    let auth_manager = Arc::new(RwLock::new(AuthManager::new()));
    let mpa_service = MpaService::new(auth_manager.clone());

    // Create test users with different roles
    let mut users = Vec::new();
    let user_configs = vec![
        ("admin1", "Admin_Password123", "Administrator"),
        ("admin2", "Admin2_Password123", "Administrator"),
        ("devops_engineer", "DevOps_Password123", "DevOps Engineer"),
        ("auditor", "Audit_Password123", "Internal Auditor"),
        (
            "security_analyst1",
            "Analyst1_Password123",
            "Security Analyst",
        ),
        (
            "security_analyst2",
            "Analyst2_Password123",
            "Security Analyst",
        ),
        ("requester_user", "Req_Password123", "Regular User"),
    ];

    for (_i, (username, password, _role)) in user_configs.iter().enumerate() {
        let mut auth = auth_manager.write().unwrap();
        let user_id = auth
            .create_user(username.to_string(), "test@example.com".to_string(), password.to_string())
            .await
            .unwrap();
        users.push(user_id);
    }

    (mpa_service, users)
}

/// Test helper to create a control group with multiple approvers
async fn create_control_group_with_approvers(
    mpa_service: &MpaService,
    admin_id: &UserId,
    approver_ids: &[UserId],
    group_name: &str,
    required_approvals: usize,
    operation_types: Vec<MultiPersonOperationType>,
) -> Result<String> {
    // Create control group
    let group_id = mpa_service
        .create_control_group(
            group_name.to_string(),
            format!("Control group for {}", group_name),
            required_approvals,
            operation_types,
            3600, // 1 hour timeout
            admin_id.clone(),
        )
        .await?;

    // Add approvers to the group
    for approver_id in approver_ids {
        mpa_service
            .add_control_group_member(
                &group_id,
                approver_id.clone(),
                ControlGroupRole::Approver,
                admin_id.clone(),
            )
            .await?;
    }

    Ok(group_id)
}

#[tokio::test]
async fn test_complete_critical_operations_workflow() {
    let (mpa_service, users) = setup_comprehensive_mpa_test().await;

    let admin_id = users[0].clone();
    let security_lead_id = users[1].clone();
    let compliance_officer_id = users[2].clone();
    let _devops_engineer_id = users[3].clone();
    let auditor_id = users[4].clone();
    let requester_id = users[6].clone();

    // Create high-security control group for critical operations
    let approvers = vec![
        security_lead_id.clone(),
        compliance_officer_id.clone(),
        auditor_id.clone(),
    ];
    let group_id = create_control_group_with_approvers(
        &mpa_service,
        &admin_id,
        &approvers,
        "Critical Security Operations",
        3, // Require all 3 approvals
        vec![
            MultiPersonOperationType::KeyGeneration,
            MultiPersonOperationType::Custom("KeyStorage".to_string()),
            MultiPersonOperationType::Custom("DatabaseQuery".to_string()),
        ],
    )
    .await
    .unwrap();

    // Test 1: Critical key generation request
    let request_id = mpa_service
        .create_approval_request(
            group_id.clone(),
            MultiPersonOperationType::KeyGeneration,
            "Generate new master encryption key for production database".to_string(),
            serde_json::json!({
                "key_type": "AES-256-GCM",
                "purpose": "database_encryption",
                "environment": "production",
                "key_size": 256,
                "rotation_period": "90_days",
                "requested_by": requester_id
            })
            .to_string(),
            requester_id.clone(),
        )
        .await
        .unwrap();

    // Verify request is pending and approvers can see it
    let request = mpa_service
        .get_approval_request(&request_id, requester_id.clone())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(request.status, ApprovalStatus::Pending);
    assert_eq!(request.decisions.len(), 0);

    // Each approver should see the pending request
    for approver_id in &approvers {
        let pending_requests = mpa_service
            .get_pending_requests_for_user(approver_id.clone())
            .await
            .unwrap();
        assert_eq!(pending_requests.len(), 1);
        assert_eq!(pending_requests[0].id, request_id);
    }

    // Test 2: Sequential approval process
    // First approval from Security Lead
    mpa_service
        .submit_approval_decision(
            &request_id,
            security_lead_id.clone(),
            Decision::Approve,
            Some(
                "Key generation parameters reviewed and approved. Security measures are adequate."
                    .to_string(),
            ),
            Some("192.168.1.100".to_string()),
            Some("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36".to_string()),
        )
        .await
        .unwrap();

    // Verify still pending (needs 3 approvals)
    let request = mpa_service
        .get_approval_request(&request_id, requester_id.clone())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(request.status, ApprovalStatus::Pending);
    assert_eq!(request.decisions.len(), 1);

    // Second approval from Compliance Officer
    mpa_service
        .submit_approval_decision(
            &request_id,
            compliance_officer_id.clone(),
            Decision::Approve,
            Some(
                "Compliance requirements verified. Key generation follows established policies."
                    .to_string(),
            ),
            Some("192.168.1.101".to_string()),
            Some("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36".to_string()),
        )
        .await
        .unwrap();

    // Verify still pending (needs 1 more approval)
    let request = mpa_service
        .get_approval_request(&request_id, requester_id.clone())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(request.status, ApprovalStatus::Pending);
    assert_eq!(request.decisions.len(), 2);

    // Third and final approval from Auditor
    mpa_service
        .submit_approval_decision(
            &request_id,
            auditor_id.clone(),
            Decision::Approve,
            Some("Audit trail verified. All documentation and approvals in place.".to_string()),
            Some("192.168.1.102".to_string()),
            Some("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36".to_string()),
        )
        .await
        .unwrap();

    // Verify request is now approved
    let request = mpa_service
        .get_approval_request(&request_id, requester_id.clone())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(request.status, ApprovalStatus::Approved);
    assert_eq!(request.decisions.len(), 3);

    // Verify operation is approved
    let is_approved = mpa_service
        .is_operation_approved(&request_id)
        .await
        .unwrap();
    assert!(is_approved);

    // Verify no more pending requests
    for approver_id in &approvers {
        let pending_requests = mpa_service
            .get_pending_requests_for_user(approver_id.clone())
            .await
            .unwrap();
        assert_eq!(pending_requests.len(), 0);
    }
}

#[tokio::test]
async fn test_emergency_approval_workflow() {
    let (mpa_service, users) = setup_comprehensive_mpa_test().await;

    let admin_id = users[0].clone();
    let security_lead_id = users[1].clone();
    let devops_engineer_id = users[3].clone();
    let requester_id = users[6].clone();

    // Create emergency control group with lower approval threshold
    let approvers = vec![security_lead_id.clone(), devops_engineer_id.clone()];
    let group_id = create_control_group_with_approvers(
        &mpa_service,
        &admin_id,
        &approvers,
        "Emergency Operations",
        1, // Only need 1 approval for emergencies
        vec![
            MultiPersonOperationType::SystemConfiguration,
            MultiPersonOperationType::Custom("DatabaseQuery".to_string()),
        ],
    )
    .await
    .unwrap();

    // Create emergency request
    let request_id = mpa_service
        .create_approval_request(
            group_id.clone(),
            MultiPersonOperationType::HsmOperation,
            "Emergency system restart - critical security patch deployment".to_string(),
            serde_json::json!({
                "operation": "system_restart",
                "reason": "critical_security_vulnerability",
                "patch_version": "v2.1.5",
                "urgency": "emergency",
                "impact": "temporary_service_interruption"
            })
            .to_string(),
            requester_id.clone(),
        )
        .await
        .unwrap();

    // Emergency approval (only 1 needed)
    mpa_service.submit_approval_decision(
        &request_id,
        security_lead_id.clone(),
        Decision::Approve,
        Some("Emergency approval granted. Critical security vulnerability requires immediate patching.".to_string()),
        Some("10.0.0.50".to_string()),
        Some("Mozilla/5.0 (iPhone; CPU iPhone OS 14_7_1 like Mac OS X)".to_string()),
    ).await.unwrap();

    // Verify immediate approval
    let request = mpa_service
        .get_approval_request(&request_id, requester_id.clone())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(request.status, ApprovalStatus::Approved);
    assert_eq!(request.decisions.len(), 1);

    let is_approved = mpa_service
        .is_operation_approved(&request_id)
        .await
        .unwrap();
    assert!(is_approved);
}

#[tokio::test]
async fn test_complex_rejection_scenarios() {
    let (mpa_service, users) = setup_comprehensive_mpa_test().await;

    let admin_id = users[0].clone();
    let approvers = vec![users[1].clone(), users[2].clone(), users[3].clone()];
    let requester_id = users[6].clone();

    // Create control group requiring 2 approvals out of 3
    let group_id = create_control_group_with_approvers(
        &mpa_service,
        &admin_id,
        &approvers,
        "Security Review Group",
        2,
        vec![MultiPersonOperationType::Custom("KeyStorage".to_string())],
    )
    .await
    .unwrap();

    // Scenario 1: Single rejection prevents approval
    let request1_id = mpa_service
        .create_approval_request(
            group_id.clone(),
            MultiPersonOperationType::KeyDeletion,
            "Delete old encryption keys".to_string(),
            serde_json::json!({"key_count": 50}).to_string(),
            requester_id.clone(),
        )
        .await
        .unwrap();

    // First approval
    mpa_service
        .submit_approval_decision(
            &request1_id,
            approvers[0].clone(),
            Decision::Approve,
            Some("Key deletion schedule reviewed and approved".to_string()),
            None,
            None,
        )
        .await
        .unwrap();

    // Single rejection (should make approval impossible)
    mpa_service
        .submit_approval_decision(
            &request1_id,
            approvers[1].clone(),
            Decision::Reject,
            Some(
                "Insufficient documentation for key deletion. Need detailed audit trail."
                    .to_string(),
            ),
            None,
            None,
        )
        .await
        .unwrap();

    // Verify request is rejected
    let request1 = mpa_service
        .get_approval_request(&request1_id, requester_id.clone())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(request1.status, ApprovalStatus::Rejected);

    // Scenario 2: Multiple rejections
    let request2_id = mpa_service
        .create_approval_request(
            group_id.clone(),
            MultiPersonOperationType::KeyDeletion,
            "Modify key access permissions".to_string(),
            serde_json::json!({"new_permissions": "read_only"}).to_string(),
            requester_id.clone(),
        )
        .await
        .unwrap();

    // Multiple rejections
    for approver_id in &approvers[0..2] {
        mpa_service.submit_approval_decision(
            &request2_id,
            approver_id.clone(),
            Decision::Reject,
            Some("Security policy violation. Cannot reduce key access permissions without board approval.".to_string()),
            None,
            None,
        ).await.unwrap();
    }

    // Verify request is rejected
    let request2 = mpa_service
        .get_approval_request(&request2_id, requester_id.clone())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(request2.status, ApprovalStatus::Rejected);
    assert_eq!(request2.decisions.len(), 2);

    // Verify no operation is approved
    let is_approved1 = mpa_service
        .is_operation_approved(&request1_id)
        .await
        .unwrap();
    let is_approved2 = mpa_service
        .is_operation_approved(&request2_id)
        .await
        .unwrap();
    assert!(!is_approved1);
    assert!(!is_approved2);
}

#[tokio::test]
async fn test_concurrent_approval_requests() {
    let (mpa_service, users) = setup_comprehensive_mpa_test().await;

    let admin_id = users[0].clone();
    let approvers = vec![users[1].clone(), users[2].clone()];
    let requester_id = users[6].clone();

    // Create control group
    let group_id = create_control_group_with_approvers(
        &mpa_service,
        &admin_id,
        &approvers,
        "Concurrent Test Group",
        2,
        vec![MultiPersonOperationType::Custom(
            "CacheOperation".to_string(),
        )],
    )
    .await
    .unwrap();

    // Create multiple concurrent requests
    let mut request_ids = Vec::new();
    for i in 1..=5 {
        let request_id = mpa_service
            .create_approval_request(
                group_id.clone(),
                MultiPersonOperationType::AuditLogModification,
                format!("Sign certificate for service-{}", i),
                serde_json::json!({
                    "service": format!("service-{}", i),
                    "certificate_type": "TLS",
                    "validity_period": "1_year"
                })
                .to_string(),
                requester_id.clone(),
            )
            .await
            .unwrap();
        request_ids.push(request_id);
    }

    // Verify all approvers see all pending requests
    for approver_id in &approvers {
        let pending_requests = mpa_service
            .get_pending_requests_for_user(approver_id.clone())
            .await
            .unwrap();
        assert_eq!(pending_requests.len(), 5);
    }

    // Process approvals concurrently
    let mut approval_tasks = Vec::new();

    for (i, request_id) in request_ids.iter().enumerate() {
        let mpa_service_clone = mpa_service.clone();
        let request_id_clone = request_id.clone();
        let approver_id = approvers[i % approvers.len()].clone();

        let task = tokio::spawn(async move {
            mpa_service_clone
                .submit_approval_decision(
                    &request_id_clone,
                    approver_id,
                    Decision::Approve,
                    Some(format!(
                        "Certificate signing approved for {}",
                        request_id_clone
                    )),
                    Some("192.168.1.100".to_string()),
                    Some("Mozilla/5.0".to_string()),
                )
                .await
        });
        approval_tasks.push(task);
    }

    // Wait for all approvals to complete
    for task in approval_tasks {
        let result = task.await.unwrap();
        assert!(result.is_ok(), "Concurrent approval should succeed");
    }

    // Verify all requests are approved
    for request_id in &request_ids {
        let request = mpa_service
            .get_approval_request(request_id, requester_id.clone())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(request.status, ApprovalStatus::Approved);
        let is_approved = mpa_service.is_operation_approved(request_id).await.unwrap();
        assert!(is_approved);
    }
}

#[tokio::test]
async fn test_time_sensitive_operations() {
    let (mpa_service, users) = setup_comprehensive_mpa_test().await;

    let admin_id = users[0].clone();
    let approver_id = users[1].clone();
    let requester_id = users[6].clone();

    // Create control group with very short timeout for testing
    let group_id = mpa_service
        .create_control_group(
            "Time-Sensitive Operations".to_string(),
            "Group with short timeout for time-sensitive testing".to_string(),
            1, // Only need 1 approval
            vec![MultiPersonOperationType::SystemConfiguration],
            2, // 2 second timeout
            admin_id.clone(),
        )
        .await
        .unwrap();

    // Add approver
    mpa_service
        .add_control_group_member(
            &group_id,
            approver_id.clone(),
            ControlGroupRole::Approver,
            admin_id.clone(),
        )
        .await
        .unwrap();

    // Create time-sensitive request
    let request_id = mpa_service
        .create_approval_request(
            group_id.clone(),
            MultiPersonOperationType::HsmOperation,
            "Time-critical system update".to_string(),
            serde_json::json!({"urgency": "high"}).to_string(),
            requester_id.clone(),
        )
        .await
        .unwrap();

    // Wait for expiration
    sleep(Duration::from_secs(3)).await;

    // Try to submit decision (should fail due to expiration)
    let result = mpa_service
        .submit_approval_decision(
            &request_id,
            approver_id.clone(),
            Decision::Approve,
            None,
            None,
            None,
        )
        .await;
    assert!(result.is_err());

    // Verify request is expired
    let request = mpa_service
        .get_approval_request(&request_id, requester_id.clone())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(request.status, ApprovalStatus::Expired);
}

#[tokio::test]
async fn test_role_based_permissions() {
    let (mpa_service, users) = setup_comprehensive_mpa_test().await;

    let admin_id = users[0].clone();
    let owner_id = users[1].clone();
    let approver_id = users[2].clone();
    let regular_user_id = users[6].clone();

    // Create control group
    let group_id = mpa_service
        .create_control_group(
            "Role-Based Test Group".to_string(),
            "Testing role-based permissions".to_string(),
            2,
            vec![MultiPersonOperationType::Custom(
                "NetworkRequest".to_string(),
            )],
            3600,
            admin_id.clone(),
        )
        .await
        .unwrap();

    // Add owner
    mpa_service
        .add_control_group_member(
            &group_id,
            owner_id.clone(),
            ControlGroupRole::Owner,
            admin_id.clone(),
        )
        .await
        .unwrap();

    // Add approver
    mpa_service
        .add_control_group_member(
            &group_id,
            approver_id.clone(),
            ControlGroupRole::Approver,
            admin_id.clone(),
        )
        .await
        .unwrap();

    // Test owner permissions (should be able to add members)
    let new_approver_id = users[3].clone();
    let result = mpa_service
        .add_control_group_member(
            &group_id,
            new_approver_id.clone(),
            ControlGroupRole::Approver,
            owner_id.clone(),
        )
        .await;
    assert!(result.is_ok());

    // Test approver permissions (should NOT be able to add members)
    let another_user_id = users[4].clone();
    let result = mpa_service
        .add_control_group_member(
            &group_id,
            another_user_id.clone(),
            ControlGroupRole::Approver,
            approver_id.clone(),
        )
        .await;
    assert!(result.is_err());

    // Test regular user permissions (should NOT be able to add members)
    let result = mpa_service
        .add_control_group_member(
            &group_id,
            regular_user_id.clone(),
            ControlGroupRole::Approver,
            regular_user_id.clone(),
        )
        .await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_custom_operation_types() {
    let (mpa_service, users) = setup_comprehensive_mpa_test().await;

    let admin_id = users[0].clone();
    let approver_id = users[1].clone();
    let requester_id = users[6].clone();

    // Create control group with custom operation types
    let group_id = mpa_service
        .create_control_group(
            "Custom Operations Group".to_string(),
            "Group for custom operation types".to_string(),
            1,
            vec![
                MultiPersonOperationType::SystemConfiguration,
                MultiPersonOperationType::SystemConfiguration,
                MultiPersonOperationType::Custom("DatabaseQuery".to_string()),
            ],
            3600,
            admin_id.clone(),
        )
        .await
        .unwrap();

    // Add approver
    mpa_service
        .add_control_group_member(
            &group_id,
            approver_id.clone(),
            ControlGroupRole::Approver,
            admin_id.clone(),
        )
        .await
        .unwrap();

    // Test custom operations (using standard operation types)
    let request1_id = mpa_service
        .create_approval_request(
            group_id.clone(),
            MultiPersonOperationType::UserManagement,
            "Execute production database migration".to_string(),
            serde_json::json!({
                "migration_version": "v3.2.1",
                "database": "production_main",
                "estimated_downtime": "15_minutes",
                "rollback_plan": "available"
            })
            .to_string(),
            requester_id.clone(),
        )
        .await
        .unwrap();

    let request2_id = mpa_service
        .create_approval_request(
            group_id.clone(),
            MultiPersonOperationType::UserManagement,
            "Create new cloud VM cluster".to_string(),
            serde_json::json!({
                "resource_type": "VM_cluster",
                "instance_count": 5,
                "instance_type": "t3.large",
                "region": "us-west-2"
            })
            .to_string(),
            requester_id.clone(),
        )
        .await
        .unwrap();

    // Verify both requests were created
    let request1 = mpa_service
        .get_approval_request(&request1_id, requester_id.clone())
        .await
        .unwrap()
        .unwrap();
    let request2 = mpa_service
        .get_approval_request(&request2_id, requester_id.clone())
        .await
        .unwrap()
        .unwrap();

    // Verify operation types
    assert_eq!(
        request1.operation_type,
        MultiPersonOperationType::UserManagement
    );
    assert_eq!(
        request2.operation_type,
        MultiPersonOperationType::UserManagement
    );

    // Approve both requests
    for request_id in [&request1_id, &request2_id] {
        mpa_service
            .submit_approval_decision(
                request_id,
                approver_id.clone(),
                Decision::Approve,
                Some("Custom operation reviewed and approved".to_string()),
                None,
                None,
            )
            .await
            .unwrap();
    }

    // Verify both operations are approved
    let is_approved1 = mpa_service
        .is_operation_approved(&request1_id)
        .await
        .unwrap();
    let is_approved2 = mpa_service
        .is_operation_approved(&request2_id)
        .await
        .unwrap();
    assert!(is_approved1);
    assert!(is_approved2);
}

#[tokio::test]
async fn test_audit_trail_and_compliance() {
    let (mpa_service, users) = setup_comprehensive_mpa_test().await;

    let admin_id = users[0].clone();
    let approver_id = users[1].clone();
    let requester_id = users[6].clone();

    // Create control group
    let group_id = mpa_service
        .create_control_group(
            "Audit Trail Test Group".to_string(),
            "Testing audit trail functionality".to_string(),
            1,
            vec![MultiPersonOperationType::Custom(
                "CacheOperation".to_string(),
            )],
            3600,
            admin_id.clone(),
        )
        .await
        .unwrap();

    // Add approver
    mpa_service
        .add_control_group_member(
            &group_id,
            approver_id.clone(),
            ControlGroupRole::Approver,
            admin_id.clone(),
        )
        .await
        .unwrap();

    // Create request with detailed audit information
    let request_id = mpa_service
        .create_approval_request(
            group_id.clone(),
            MultiPersonOperationType::AuditLogModification,
            "Archive old audit logs".to_string(),
            serde_json::json!({
                "archive_reason": "storage_optimization",
                "log_age_threshold": "7_years",
                "archive_location": "secure_storage",
                "compliance_requirements": ["GDPR", "SOX", "HIPAA"]
            })
            .to_string(),
            requester_id.clone(),
        )
        .await
        .unwrap();

    // Submit approval with comprehensive audit trail
    mpa_service.submit_approval_decision(
        &request_id,
        approver_id.clone(),
        Decision::Approve,
        Some("Audit log archival approved. All compliance requirements verified. Archive location meets security standards.".to_string()),
        Some("192.168.1.100".to_string()),
        Some("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36".to_string()),
    ).await.unwrap();

    // Verify complete audit trail
    let request = mpa_service
        .get_approval_request(&request_id, requester_id.clone())
        .await
        .unwrap()
        .unwrap();

    // Check audit trail completeness
    assert_eq!(request.status, ApprovalStatus::Approved);
    assert_eq!(request.decisions.len(), 1);

    let decision = &request.decisions[0];
    assert_eq!(decision.decision, Decision::Approve);
    assert!(decision.comment.is_some());
    assert!(decision.source_ip.is_some());
    assert!(decision.user_agent.is_some());
    assert!(decision.decided_at <= chrono::Utc::now().timestamp() as u64);

    // Verify audit trail contains all required information
    let comment = decision.comment.as_ref().unwrap();
    assert!(comment.contains("compliance"));
    assert!(comment.contains("security"));

    let source_ip = decision.source_ip.as_ref().unwrap();
    assert!(!source_ip.is_empty());

    let user_agent = decision.user_agent.as_ref().unwrap();
    assert!(!user_agent.is_empty());
    assert!(user_agent.contains("Mozilla"));
}

#[tokio::test]
async fn test_performance_under_load() {
    let (mpa_service, users) = setup_comprehensive_mpa_test().await;

    let admin_id = users[0].clone();
    let approver_id = users[1].clone();
    let requester_id = users[6].clone();

    // Create control group
    let group_id = mpa_service
        .create_control_group(
            "Performance Test Group".to_string(),
            "Testing performance under load".to_string(),
            1,
            vec![MultiPersonOperationType::SystemConfiguration],
            3600,
            admin_id.clone(),
        )
        .await
        .unwrap();

    // Add approver
    mpa_service
        .add_control_group_member(
            &group_id,
            approver_id.clone(),
            ControlGroupRole::Approver,
            admin_id.clone(),
        )
        .await
        .unwrap();

    // Performance test: Create 100 concurrent requests
    let start_time = std::time::Instant::now();
    let mut request_ids = Vec::new();
    let mut create_tasks = Vec::new();

    for i in 1..=100 {
        let mpa_service_clone = mpa_service.clone();
        let group_id_clone = group_id.clone();
        let requester_id_clone = requester_id.clone();

        let task = tokio::spawn(async move {
            mpa_service_clone
                .create_approval_request(
                    group_id_clone,
                    MultiPersonOperationType::HsmOperation,
                    format!("Performance test operation {}", i),
                    serde_json::json!({"test_id": i}).to_string(),
                    requester_id_clone,
                )
                .await
        });
        create_tasks.push(task);
    }

    // Wait for all requests to be created
    for task in create_tasks {
        let request_id = task.await.unwrap();
        assert!(
            request_id.is_ok(),
            "Request creation should succeed under load"
        );
        request_ids.push(request_id.unwrap());
    }

    let creation_time = start_time.elapsed();

    // Performance test: Approve all requests concurrently
    let approval_start = std::time::Instant::now();
    let mut approval_tasks = Vec::new();

    for request_id in &request_ids {
        let mpa_service_clone = mpa_service.clone();
        let request_id_clone = request_id.clone();
        let approver_id_clone = approver_id.clone();

        let task = tokio::spawn(async move {
            mpa_service_clone
                .submit_approval_decision(
                    &request_id_clone,
                    approver_id_clone,
                    Decision::Approve,
                    Some("Performance test approval".to_string()),
                    None,
                    None,
                )
                .await
        });
        approval_tasks.push(task);
    }

    // Wait for all approvals to complete
    for task in approval_tasks {
        let result = task.await.unwrap();
        assert!(result.is_ok(), "Approval should succeed under load");
    }

    let approval_time = approval_start.elapsed();
    let total_time = start_time.elapsed();

    // Verify all requests are approved
    for request_id in &request_ids {
        let is_approved = mpa_service.is_operation_approved(request_id).await.unwrap();
        assert!(is_approved);
    }

    // Performance assertions
    assert!(
        creation_time < Duration::from_secs(10),
        "Request creation should be fast under load"
    );
    assert!(
        approval_time < Duration::from_secs(10),
        "Approval should be fast under load"
    );
    assert!(
        total_time < Duration::from_secs(20),
        "Total operation should complete quickly"
    );

    println!("Performance Test Results:");
    println!("  Created 100 requests in: {:?}", creation_time);
    println!("  Approved 100 requests in: {:?}", approval_time);
    println!("  Total time: {:?}", total_time);
    println!("  Average per request: {:?}", total_time / 100);
}

#[tokio::test]
async fn test_error_handling_and_recovery() {
    let (mpa_service, users) = setup_comprehensive_mpa_test().await;

    let admin_id = users[0].clone();
    let approver_id = users[1].clone();
    let requester_id = users[6].clone();

    // Test 1: Invalid control group operations
    let result = mpa_service
        .create_approval_request(
            "non_existent_group".to_string(),
            MultiPersonOperationType::UserManagement,
            "Test request".to_string(),
            "{}".to_string(),
            requester_id.clone(),
        )
        .await;
    assert!(
        result.is_err(),
        "Should fail for non-existent control group"
    );

    // Test 2: Invalid approval decision
    let group_id = mpa_service
        .create_control_group(
            "Error Test Group".to_string(),
            "Testing error handling".to_string(),
            1,
            vec![MultiPersonOperationType::SystemConfiguration],
            3600,
            admin_id.clone(),
        )
        .await
        .unwrap();

    mpa_service
        .add_control_group_member(
            &group_id,
            approver_id.clone(),
            ControlGroupRole::Approver,
            admin_id.clone(),
        )
        .await
        .unwrap();

    let request_id = mpa_service
        .create_approval_request(
            group_id.clone(),
            MultiPersonOperationType::HsmOperation,
            "Test error handling".to_string(),
            "{}".to_string(),
            requester_id.clone(),
        )
        .await
        .unwrap();

    // Try to submit decision for non-existent request
    let result = mpa_service
        .submit_approval_decision(
            &"non_existent_request".to_string(),
            approver_id.clone(),
            Decision::Approve,
            None,
            None,
            None,
        )
        .await;
    assert!(result.is_err(), "Should fail for non-existent request");

    // Test 3: Duplicate decisions
    mpa_service
        .submit_approval_decision(
            &request_id,
            approver_id.clone(),
            Decision::Approve,
            Some("First decision".to_string()),
            None,
            None,
        )
        .await
        .unwrap();

    // Try to submit second decision from same user
    let result = mpa_service
        .submit_approval_decision(
            &request_id,
            approver_id.clone(),
            Decision::Reject,
            Some("Changed my mind".to_string()),
            None,
            None,
        )
        .await;
    assert!(result.is_err(), "Should fail for duplicate decision");

    // Test 4: Unauthorized operations
    let unauthorized_user_id = users[2].clone();
    let result = mpa_service
        .submit_approval_decision(
            &request_id,
            unauthorized_user_id.clone(),
            Decision::Approve,
            None,
            None,
            None,
        )
        .await;
    assert!(result.is_err(), "Should fail for unauthorized user");
}

#[tokio::test]
async fn test_cleanup_and_maintenance() {
    let (mpa_service, users) = setup_comprehensive_mpa_test().await;

    let admin_id = users[0].clone();
    let requester_id = users[6].clone();

    // Create control group with very short timeout
    let group_id = mpa_service
        .create_control_group(
            "Cleanup Test Group".to_string(),
            "Testing cleanup functionality".to_string(),
            1,
            vec![MultiPersonOperationType::SystemConfiguration],
            1, // 1 second timeout
            admin_id.clone(),
        )
        .await
        .unwrap();

    // Create multiple requests that will expire
    let mut request_ids = Vec::new();
    for i in 1..=10 {
        let request_id = mpa_service
            .create_approval_request(
                group_id.clone(),
                MultiPersonOperationType::HsmOperation,
                format!("Expiring request {}", i),
                "{}".to_string(),
                requester_id.clone(),
            )
            .await
            .unwrap();
        request_ids.push(request_id);
    }

    // Wait for all requests to expire
    sleep(Duration::from_secs(2)).await;

    // Run cleanup
    let cleaned_count = mpa_service.cleanup_expired_requests().await.unwrap();
    assert_eq!(cleaned_count, 10, "Should clean up all expired requests");

    // Verify all requests are marked as expired
    for request_id in &request_ids {
        let request = mpa_service
            .get_approval_request(request_id, requester_id.clone())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(request.status, ApprovalStatus::Expired);
    }
}

#[tokio::test]
async fn test_multi_group_operations() {
    let (mpa_service, users) = setup_comprehensive_mpa_test().await;

    let admin_id = users[0].clone();
    let approver_id = users[1].clone();
    let requester_id = users[6].clone();

    // Create multiple control groups
    let group1_id = mpa_service
        .create_control_group(
            "Group 1 - Key Operations".to_string(),
            "First control group".to_string(),
            1,
            vec![MultiPersonOperationType::KeyGeneration],
            3600,
            admin_id.clone(),
        )
        .await
        .unwrap();

    let group2_id = mpa_service
        .create_control_group(
            "Group 2 - System Operations".to_string(),
            "Second control group".to_string(),
            1,
            vec![MultiPersonOperationType::SystemConfiguration],
            3600,
            admin_id.clone(),
        )
        .await
        .unwrap();

    // Add approver to both groups
    mpa_service
        .add_control_group_member(
            &group1_id,
            approver_id.clone(),
            ControlGroupRole::Approver,
            admin_id.clone(),
        )
        .await
        .unwrap();

    mpa_service
        .add_control_group_member(
            &group2_id,
            approver_id.clone(),
            ControlGroupRole::Approver,
            admin_id.clone(),
        )
        .await
        .unwrap();

    // Create requests in both groups
    let request1_id = mpa_service
        .create_approval_request(
            group1_id.clone(),
            MultiPersonOperationType::UserManagement,
            "Generate key in group 1".to_string(),
            "{}".to_string(),
            requester_id.clone(),
        )
        .await
        .unwrap();

    let request2_id = mpa_service
        .create_approval_request(
            group2_id.clone(),
            MultiPersonOperationType::UserManagement,
            "System operation in group 2".to_string(),
            "{}".to_string(),
            requester_id.clone(),
        )
        .await
        .unwrap();

    // Verify approver sees requests from both groups
    let pending_requests = mpa_service
        .get_pending_requests_for_user(approver_id.clone())
        .await
        .unwrap();
    assert_eq!(pending_requests.len(), 2);

    // Approve both requests
    mpa_service
        .submit_approval_decision(
            &request1_id,
            approver_id.clone(),
            Decision::Approve,
            Some("Group 1 approval".to_string()),
            None,
            None,
        )
        .await
        .unwrap();

    mpa_service
        .submit_approval_decision(
            &request2_id,
            approver_id.clone(),
            Decision::Approve,
            Some("Group 2 approval".to_string()),
            None,
            None,
        )
        .await
        .unwrap();

    // Verify both operations are approved
    let is_approved1 = mpa_service
        .is_operation_approved(&request1_id)
        .await
        .unwrap();
    let is_approved2 = mpa_service
        .is_operation_approved(&request2_id)
        .await
        .unwrap();
    assert!(is_approved1);
    assert!(is_approved2);

    // Verify no more pending requests
    let pending_requests = mpa_service
        .get_pending_requests_for_user(approver_id.clone())
        .await
        .unwrap();
    assert_eq!(pending_requests.len(), 0);
}
