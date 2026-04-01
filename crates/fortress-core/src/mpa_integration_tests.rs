//! Multi-Person Authorization Integration Tests
//! 
//! This module contains comprehensive integration tests for the MPA system,
//! testing the complete workflow from control group creation to approval execution.

use crate::multi_person_auth::*;
use crate::mpa_service::MpaService;
use crate::auth::{AuthManager, UserId};
use std::sync::{Arc, RwLock};
use tokio::time::{sleep, Duration};

/// Test helper to create a complete MPA setup
async fn setup_mpa_test() -> (MpaService, Vec<UserId>) {
    let auth_manager = Arc::new(RwLock::new(AuthManager::new()));
    let mpa_service = MpaService::new(auth_manager.clone());
    
    // Create test users
    let mut users = Vec::new();
    let user_names = vec!["admin", "approver1", "approver2", "approver3", "requester"];
    
    for name in user_names {
        let mut auth = auth_manager.write().unwrap();
        let user_id = auth.create_user(name.to_string(), format!("{}_password", name)).await.unwrap();
        users.push(user_id);
    }
    
    (mpa_service, users)
}

#[tokio::test]
async fn test_complete_mpa_workflow() {
    let (mpa_service, users) = setup_mpa_test().await;
    
    let admin_id = users[0].clone();
    let approver1_id = users[1].clone();
    let approver2_id = users[2].clone();
    let requester_id = users[4].clone();
    
    // 1. Create a control group
    let group_id = mpa_service.create_control_group(
        "Critical Operations".to_string(),
        "Group for approving critical security operations".to_string(),
        2, // Require 2 approvals
        vec![
            OperationType::KeyGeneration,
            OperationType::KeyStorage,
            OperationType::DatabaseQuery,
        ],
        3600, // 1 hour timeout
        admin_id.clone(),
    ).await.unwrap();
    
    // 2. Add approvers to the control group
    mpa_service.add_control_group_member(
        &group_id,
        approver1_id.clone(),
        ControlGroupRole::Approver,
        admin_id.clone(),
    ).await.unwrap();
    
    mpa_service.add_control_group_member(
        &group_id,
        approver2_id.clone(),
        ControlGroupRole::Approver,
        admin_id.clone(),
    ).await.unwrap();
    
    // 3. Create an approval request
    let request_id = mpa_service.create_approval_request(
        group_id.clone(),
        OperationType::KeyGeneration,
        "Generate new master encryption key for production database".to_string(),
        serde_json::json!({
            "key_type": "AES-256-GCM",
            "purpose": "database_encryption",
            "environment": "production",
            "requested_by": requester_id
        }).to_string(),
        requester_id.clone(),
    ).await.unwrap();
    
    // 4. Verify request is pending
    let request = mpa_service.get_approval_request(&request_id, requester_id.clone()).await.unwrap().unwrap();
    assert_eq!(request.status, ApprovalStatus::Pending);
    assert_eq!(request.decisions.len(), 0);
    
    // 5. Get pending requests for approver1
    let pending_requests = mpa_service.get_pending_requests_for_user(approver1_id.clone()).await.unwrap();
    assert_eq!(pending_requests.len(), 1);
    assert_eq!(pending_requests[0].id, request_id);
    
    // 6. First approver submits approval
    mpa_service.submit_approval_decision(
        &request_id,
        approver1_id.clone(),
        Decision::Approve,
        Some("Key generation request is valid and necessary".to_string()),
        Some("192.168.1.100".to_string()),
        Some("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36".to_string()),
    ).await.unwrap();
    
    // 7. Verify request is still pending (needs 2 approvals)
    let request = mpa_service.get_approval_request(&request_id, requester_id.clone()).await.unwrap().unwrap();
    assert_eq!(request.status, ApprovalStatus::Pending);
    assert_eq!(request.decisions.len(), 1);
    assert_eq!(request.decisions[0].decision, Decision::Approve);
    
    // 8. Second approver submits approval
    mpa_service.submit_approval_decision(
        &request_id,
        approver2_id.clone(),
        Decision::Approve,
        Some("Confirmed key generation requirements and security measures".to_string()),
        Some("192.168.1.101".to_string()),
        Some("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36".to_string()),
    ).await.unwrap();
    
    // 9. Verify request is now approved
    let request = mpa_service.get_approval_request(&request_id, requester_id.clone()).await.unwrap().unwrap();
    assert_eq!(request.status, ApprovalStatus::Approved);
    assert_eq!(request.decisions.len(), 2);
    
    // 10. Verify operation is approved
    let is_approved = mpa_service.is_operation_approved(&request_id).await.unwrap();
    assert!(is_approved);
    
    // 11. Verify no more pending requests for approvers
    let pending_requests = mpa_service.get_pending_requests_for_user(approver1_id.clone()).await.unwrap();
    assert_eq!(pending_requests.len(), 0);
    
    let pending_requests = mpa_service.get_pending_requests_for_user(approver2_id.clone()).await.unwrap();
    assert_eq!(pending_requests.len(), 0);
}

#[tokio::test]
async fn test_rejection_workflow() {
    let (mpa_service, users) = setup_mpa_test().await;
    
    let admin_id = users[0].clone();
    let approver1_id = users[1].clone();
    let approver2_id = users[2].clone();
    let approver3_id = users[3].clone();
    let requester_id = users[4].clone();
    
    // Create control group with 3 approvers, require 2 approvals
    let group_id = mpa_service.create_control_group(
        "Security Operations".to_string(),
        "Group for security-critical operations".to_string(),
        2, // Require 2 approvals
        vec![OperationType::KeyStorage],
        3600,
        admin_id.clone(),
    ).await.unwrap();
    
    // Add 3 approvers
    for approver_id in [&approver1_id, &approver2_id, &approver3_id] {
        mpa_service.add_control_group_member(
            &group_id,
            approver_id.clone(),
            ControlGroupRole::Approver,
            admin_id.clone(),
        ).await.unwrap();
    }
    
    // Create approval request
    let request_id = mpa_service.create_approval_request(
        group_id.clone(),
        OperationType::KeyStorage,
        "Delete old encryption key".to_string(),
        serde_json::json!({"key_id": "old_key_123"}).to_string(),
        requester_id.clone(),
    ).await.unwrap();
    
    // First rejection
    mpa_service.submit_approval_decision(
        &request_id,
        approver1_id.clone(),
        Decision::Reject,
        Some("Key deletion not properly justified".to_string()),
        Some("192.168.1.100".to_string()),
        None,
    ).await.unwrap();
    
    // Second rejection (should make approval impossible)
    mpa_service.submit_approval_decision(
        &request_id,
        approver2_id.clone(),
        Decision::Reject,
        Some("Additional documentation required before deletion".to_string()),
        Some("192.168.1.101".to_string()),
        None,
    ).await.unwrap();
    
    // Verify request is rejected
    let request = mpa_service.get_approval_request(&request_id, requester_id.clone()).await.unwrap().unwrap();
    assert_eq!(request.status, ApprovalStatus::Rejected);
    
    // Verify operation is not approved
    let is_approved = mpa_service.is_operation_approved(&request_id).await.unwrap();
    assert!(!is_approved);
}

#[tokio::test]
async fn test_request_cancellation() {
    let (mpa_service, users) = setup_mpa_test().await;
    
    let admin_id = users[0].clone();
    let approver1_id = users[1].clone();
    let requester_id = users[4].clone();
    
    // Create control group
    let group_id = mpa_service.create_control_group(
        "Test Group".to_string(),
        "Test group for cancellation".to_string(),
        2,
        vec![OperationType::SystemOperation],
        3600,
        admin_id.clone(),
    ).await.unwrap();
    
    // Add approver
    mpa_service.add_control_group_member(
        &group_id,
        approver1_id.clone(),
        ControlGroupRole::Approver,
        admin_id.clone(),
    ).await.unwrap();
    
    // Create approval request
    let request_id = mpa_service.create_approval_request(
        group_id.clone(),
        OperationType::SystemOperation,
        "Update system configuration".to_string(),
        "{}".to_string(),
        requester_id.clone(),
    ).await.unwrap();
    
    // Verify request is pending
    let request = mpa_service.get_approval_request(&request_id, requester_id.clone()).await.unwrap().unwrap();
    assert_eq!(request.status, ApprovalStatus::Pending);
    
    // Cancel the request
    mpa_service.cancel_approval_request(&request_id, requester_id.clone()).await.unwrap();
    
    // Verify request is cancelled
    let request = mpa_service.get_approval_request(&request_id, requester_id.clone()).await.unwrap().unwrap();
    assert_eq!(request.status, ApprovalStatus::Cancelled);
    
    // Try to submit decision (should fail)
    let result = mpa_service.submit_approval_decision(
        &request_id,
        approver1_id.clone(),
        Decision::Approve,
        None,
        None,
        None,
    ).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_request_expiration() {
    let (mpa_service, users) = setup_mpa_test().await;
    
    let admin_id = users[0].clone();
    let approver1_id = users[1].clone();
    let requester_id = users[4].clone();
    
    // Create control group with short timeout
    let group_id = mpa_service.create_control_group(
        "Time-Sensitive Group".to_string(),
        "Group with short timeout for testing".to_string(),
        1, // Only need 1 approval
        vec![OperationType::CertificateSigning],
        2, // 2 second timeout
        admin_id.clone(),
    ).await.unwrap();
    
    // Add approver
    mpa_service.add_control_group_member(
        &group_id,
        approver1_id.clone(),
        ControlGroupRole::Approver,
        admin_id.clone(),
    ).await.unwrap();
    
    // Create approval request
    let request_id = mpa_service.create_approval_request(
        group_id.clone(),
        OperationType::CertificateSigning,
        "Sign certificate".to_string(),
        "{}".to_string(),
        requester_id.clone(),
    ).await.unwrap();
    
    // Wait for expiration
    sleep(Duration::from_secs(3)).await;
    
    // Try to submit decision (should fail due to expiration)
    let result = mpa_service.submit_approval_decision(
        &request_id,
        approver1_id.clone(),
        Decision::Approve,
        None,
        None,
        None,
    ).await;
    assert!(result.is_err());
    
    // Verify request is expired
    let request = mpa_service.get_approval_request(&request_id, requester_id.clone()).await.unwrap().unwrap();
    assert_eq!(request.status, ApprovalStatus::Expired);
}

#[tokio::test]
async fn test_control_group_management() {
    let (mpa_service, users) = setup_mpa_test().await;
    
    let admin_id = users[0].clone();
    let approver1_id = users[1].clone();
    let owner_id = users[2].clone();
    
    // Create control group
    let group_id = mpa_service.create_control_group(
        "Management Test".to_string(),
        "Group for testing management features".to_string(),
        2,
        vec![OperationType::UserManagement],
        3600,
        admin_id.clone(),
    ).await.unwrap();
    
    // Add owner
    mpa_service.add_control_group_member(
        &group_id,
        owner_id.clone(),
        ControlGroupRole::Owner,
        admin_id.clone(),
    ).await.unwrap();
    
    // Add approver
    mpa_service.add_control_group_member(
        &group_id,
        approver1_id.clone(),
        ControlGroupRole::Approver,
        owner_id.clone(),
    ).await.unwrap();
    
    // Get control groups for approver
    let groups = mpa_service.get_control_groups_for_user(approver1_id.clone()).await.unwrap();
    assert_eq!(groups.len(), 1);
    assert_eq!(groups[0].id, group_id);
    assert_eq!(groups[0].members.len(), 2);
    
    // Verify member roles
    let group = &groups[0];
    let owner_member = group.members.iter().find(|m| m.user_id == owner_id).unwrap();
    assert_eq!(owner_member.role, ControlGroupRole::Owner);
    
    let approver_member = group.members.iter().find(|m| m.user_id == approver1_id).unwrap();
    assert_eq!(approver_member.role, ControlGroupRole::Approver);
}

#[tokio::test]
async fn test_permission_validation() {
    let (mpa_service, users) = setup_mpa_test().await;
    
    let admin_id = users[0].clone();
    let requester_id = users[4].clone();
    
    // Create control group for specific operations
    let group_id = mpa_service.create_control_group(
        "Limited Operations".to_string(),
        "Group with limited operation types".to_string(),
        1,
        vec![OperationType::KeyGeneration], // Only allow key generation
        3600,
        admin_id.clone(),
    ).await.unwrap();
    
    // Try to create request for unauthorized operation type
    let result = mpa_service.create_approval_request(
        group_id.clone(),
        OperationType::KeyStorage, // Not authorized
        "Delete key".to_string(),
        "{}".to_string(),
        requester_id.clone(),
    ).await;
    assert!(result.is_err());
    
    // Create request for authorized operation type
    let request_id = mpa_service.create_approval_request(
        group_id.clone(),
        OperationType::KeyGeneration, // Authorized
        "Generate key".to_string(),
        "{}".to_string(),
        requester_id.clone(),
    ).await.unwrap();
    
    // Verify request was created successfully
    let request = mpa_service.get_approval_request(&request_id, requester_id.clone()).await.unwrap().unwrap();
    assert_eq!(request.operation_type, OperationType::KeyGeneration);
}

#[tokio::test]
async fn test_duplicate_decisions() {
    let (mpa_service, users) = setup_mpa_test().await;
    
    let admin_id = users[0].clone();
    let approver1_id = users[1].clone();
    let requester_id = users[4].clone();
    
    // Create control group
    let group_id = mpa_service.create_control_group(
        "Duplicate Test".to_string(),
        "Test duplicate decision prevention".to_string(),
        2,
        vec![OperationType::AuditLogModification],
        3600,
        admin_id.clone(),
    ).await.unwrap();
    
    // Add approver
    mpa_service.add_control_group_member(
        &group_id,
        approver1_id.clone(),
        ControlGroupRole::Approver,
        admin_id.clone(),
    ).await.unwrap();
    
    // Create approval request
    let request_id = mpa_service.create_approval_request(
        group_id.clone(),
        OperationType::AuditLogModification,
        "Modify audit log".to_string(),
        "{}".to_string(),
        requester_id.clone(),
    ).await.unwrap();
    
    // Submit first decision
    mpa_service.submit_approval_decision(
        &request_id,
        approver1_id.clone(),
        Decision::Approve,
        Some("First approval".to_string()),
        None,
        None,
    ).await.unwrap();
    
    // Try to submit second decision from same user (should fail)
    let result = mpa_service.submit_approval_decision(
        &request_id,
        approver1_id.clone(),
        Decision::Reject,
        Some("Changed my mind".to_string()),
        None,
        None,
    ).await;
    assert!(result.is_err());
    
    // Verify only one decision exists
    let request = mpa_service.get_approval_request(&request_id, requester_id.clone()).await.unwrap().unwrap();
    assert_eq!(request.decisions.len(), 1);
}

#[tokio::test]
async fn test_cleanup_expired_requests() {
    let (mpa_service, users) = setup_mpa_test().await;
    
    let admin_id = users[0].clone();
    let requester_id = users[4].clone();
    
    // Create control group with very short timeout
    let group_id = mpa_service.create_control_group(
        "Cleanup Test".to_string(),
        "Test cleanup of expired requests".to_string(),
        1,
        vec![OperationType::HsmOperation],
        1, // 1 second timeout
        admin_id.clone(),
    ).await.unwrap();
    
    // Create multiple approval requests
    let mut request_ids = Vec::new();
    for i in 0..3 {
        let request_id = mpa_service.create_approval_request(
            group_id.clone(),
            OperationType::HsmOperation,
            format!("HSM operation {}", i),
            "{}".to_string(),
            requester_id.clone(),
        ).await.unwrap();
        request_ids.push(request_id);
    }
    
    // Wait for expiration
    sleep(Duration::from_secs(2)).await;
    
    // Run cleanup
    let cleaned_count = mpa_service.cleanup_expired_requests().await.unwrap();
    assert_eq!(cleaned_count, 3);
    
    // Verify all requests are expired
    for request_id in request_ids {
        let request = mpa_service.get_approval_request(&request_id, requester_id.clone()).await.unwrap().unwrap();
        assert_eq!(request.status, ApprovalStatus::Expired);
    }
}

#[tokio::test]
async fn test_custom_operation_types() {
    let (mpa_service, users) = setup_mpa_test().await;
    
    let admin_id = users[0].clone();
    let approver1_id = users[1].clone();
    let requester_id = users[4].clone();
    
    // Create control group with custom operation type
    let group_id = mpa_service.create_control_group(
        "Custom Operations".to_string(),
        "Group for custom operation types".to_string(),
        1,
        vec![OperationType::Custom("DatabaseMigration".to_string())],
        3600,
        admin_id.clone(),
    ).await.unwrap();
    
    // Add approver
    mpa_service.add_control_group_member(
        &group_id,
        approver1_id.clone(),
        ControlGroupRole::Approver,
        admin_id.clone(),
    ).await.unwrap();
    
    // Create approval request for custom operation
    let request_id = mpa_service.create_approval_request(
        group_id.clone(),
        OperationType::Custom("DatabaseMigration".to_string()),
        "Execute database migration".to_string(),
        serde_json::json!({
            "migration_version": "v2.1.0",
            "database": "production",
            "estimated_downtime": "5 minutes"
        }).to_string(),
        requester_id.clone(),
    ).await.unwrap();
    
    // Verify request was created
    let request = mpa_service.get_approval_request(&request_id, requester_id.clone()).await.unwrap().unwrap();
    match request.operation_type {
        OperationType::Custom(name) => assert_eq!(name, "DatabaseMigration"),
        _ => panic!("Expected custom operation type"),
    }
    
    // Approve the custom operation
    mpa_service.submit_approval_decision(
        &request_id,
        approver1_id.clone(),
        Decision::Approve,
        Some("Migration plan reviewed and approved".to_string()),
        None,
        None,
    ).await.unwrap();
    
    // Verify operation is approved
    let is_approved = mpa_service.is_operation_approved(&request_id).await.unwrap();
    assert!(is_approved);
}
