//! Simple MPA Integration Tests
//! 
//! Basic tests to verify MPA functionality works correctly

use crate::multi_person_auth::*;
use crate::mpa_service::MpaService;
use crate::auth::{AuthManager, AuthConfig};
use std::sync::{Arc, RwLock};

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper to create test setup
    async fn setup_test() -> (MpaService, Vec<String>) {
        let auth_manager = Arc::new(RwLock::new(AuthManager::new(AuthConfig::default())));
        let mpa_service = MpaService::new(auth_manager.clone());
        
        // Create test users
        let mut users = Vec::new();
        let user_names = vec!["admin", "approver1", "approver2", "requester"];
        
        for name in user_names {
            let mut auth = auth_manager.write().unwrap();
            let user_id = auth.create_user(name.to_string(), format!("{}_password", name)).await.unwrap();
            users.push(user_id);
        }
        
        (mpa_service, users)
    }

    #[tokio::test]
    async fn test_basic_mpa_workflow() {
        let (mpa_service, users) = setup_test().await;
        
        let admin_id = users[0].clone();
        let approver1_id = users[1].clone();
        let approver2_id = users[2].clone();
        let requester_id = users[3].clone();
        
        // 1. Create a control group
        let group_id = mpa_service.create_control_group(
            "Critical Operations".to_string(),
            "Group for approving critical security operations".to_string(),
            2, // Require 2 approvals
            vec![OperationType::KeyGeneration],
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
            "Generate new master encryption key".to_string(),
            serde_json::json!({"key_type": "AES-256-GCM"}).to_string(),
            requester_id.clone(),
        ).await.unwrap();
        
        // 4. Verify request is pending
        let request = mpa_service.get_approval_request(&request_id, requester_id.clone()).await.unwrap().unwrap();
        assert_eq!(request.status, ApprovalStatus::Pending);
        assert_eq!(request.decisions.len(), 0);
        
        // 5. First approval
        mpa_service.submit_approval_decision(
            &request_id,
            approver1_id.clone(),
            Decision::Approve,
            Some("First approval".to_string()),
            Some("127.0.0.1".to_string()),
            Some("test-agent".to_string()),
        ).await.unwrap();
        
        // 6. Verify still pending
        let request = mpa_service.get_approval_request(&request_id, requester_id.clone()).await.unwrap().unwrap();
        assert_eq!(request.status, ApprovalStatus::Pending);
        assert_eq!(request.decisions.len(), 1);
        
        // 7. Second approval (should approve)
        mpa_service.submit_approval_decision(
            &request_id,
            approver2_id.clone(),
            Decision::Approve,
            Some("Second approval".to_string()),
            Some("127.0.0.1".to_string()),
            Some("test-agent".to_string()),
        ).await.unwrap();
        
        // 8. Verify approved
        let request = mpa_service.get_approval_request(&request_id, requester_id.clone()).await.unwrap().unwrap();
        assert_eq!(request.status, ApprovalStatus::Approved);
        assert_eq!(request.decisions.len(), 2);
    }

    #[tokio::test]
    async fn test_rejection_workflow() {
        let (mpa_service, users) = setup_test().await;
        
        let admin_id = users[0].clone();
        let approver1_id = users[1].clone();
        let requester_id = users[3].clone();
        
        // Create control group
        let group_id = mpa_service.create_control_group(
            "Test Group".to_string(),
            "Test group for rejection".to_string(),
            2,
            vec![OperationType::KeyStorage],
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
        
        // Create request
        let request_id = mpa_service.create_approval_request(
            group_id.clone(),
            OperationType::KeyStorage,
            "Delete old key".to_string(),
            "{}".to_string(),
            requester_id.clone(),
        ).await.unwrap();
        
        // Submit rejection
        mpa_service.submit_approval_decision(
            &request_id,
            approver1_id.clone(),
            Decision::Reject,
            Some("Rejecting this operation".to_string()),
            Some("127.0.0.1".to_string()),
            Some("test-agent".to_string()),
        ).await.unwrap();
        
        // Verify rejected
        let request = mpa_service.get_approval_request(&request_id, requester_id.clone()).await.unwrap().unwrap();
        assert_eq!(request.status, ApprovalStatus::Rejected);
    }

    #[tokio::test]
    async fn test_cancellation_workflow() {
        let (mpa_service, users) = setup_test().await;
        
        let admin_id = users[0].clone();
        let requester_id = users[3].clone();
        
        // Create control group
        let group_id = mpa_service.create_control_group(
            "Test Group".to_string(),
            "Test group for cancellation".to_string(),
            2,
            vec![OperationType::SystemOperation],
            3600,
            admin_id.clone(),
        ).await.unwrap();
        
        // Create request
        let request_id = mpa_service.create_approval_request(
            group_id.clone(),
            OperationType::SystemOperation,
            "Update system config".to_string(),
            "{}".to_string(),
            requester_id.clone(),
        ).await.unwrap();
        
        // Cancel the request
        mpa_service.cancel_approval_request(&request_id, requester_id.clone()).await.unwrap();
        
        // Verify cancelled
        let request = mpa_service.get_approval_request(&request_id, requester_id.clone()).await.unwrap().unwrap();
        assert_eq!(request.status, ApprovalStatus::Cancelled);
    }

    #[tokio::test]
    async fn test_control_group_management() {
        let (mpa_service, users) = setup_test().await;
        
        let admin_id = users[0].clone();
        let member_id = users[1].clone();
        
        // Create control group
        let group_id = mpa_service.create_control_group(
            "Management Test".to_string(),
            "Test group management".to_string(),
            2,
            vec![OperationType::UserManagement],
            3600,
            admin_id.clone(),
        ).await.unwrap();
        
        // Add member
        mpa_service.add_control_group_member(
            &group_id,
            member_id.clone(),
            ControlGroupRole::Member,
            admin_id.clone(),
        ).await.unwrap();
        
        // Get control groups for user
        let groups = mpa_service.get_control_groups_for_user(member_id.clone()).await.unwrap();
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].id, group_id);
    }

    #[tokio::test]
    async fn test_pending_requests_for_user() {
        let (mpa_service, users) = setup_test().await;
        
        let admin_id = users[0].clone();
        let approver_id = users[1].clone();
        let requester_id = users[3].clone();
        
        // Create control group
        let group_id = mpa_service.create_control_group(
            "Test Group".to_string(),
            "Test pending requests".to_string(),
            2,
            vec![OperationType::AuditLogModification],
            3600,
            admin_id.clone(),
        ).await.unwrap();
        
        // Add approver
        mpa_service.add_control_group_member(
            &group_id,
            approver_id.clone(),
            ControlGroupRole::Approver,
            admin_id.clone(),
        ).await.unwrap();
        
        // Create request
        let request_id = mpa_service.create_approval_request(
            group_id.clone(),
            OperationType::AuditLogModification,
            "Modify audit log".to_string(),
            "{}".to_string(),
            requester_id.clone(),
        ).await.unwrap();
        
        // Get pending requests for approver
        let pending_requests = mpa_service.get_pending_requests_for_user(approver_id.clone()).await.unwrap();
        assert_eq!(pending_requests.len(), 1);
        assert_eq!(pending_requests[0].id, request_id);
    }
}
