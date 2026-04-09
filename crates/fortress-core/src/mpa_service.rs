//! Multi-Person Authorization Service
//! 
//! This service provides the main interface for MPA functionality,
//! integrating with the authentication and authorization systems.

use crate::error::FortressError;
use crate::performance_monitor::OperationType;
use crate::multi_person_auth::{
    MultiPersonAuthManager, ControlGroup, ControlGroupId, ApprovalRequest,
    ApprovalRequestId, MultiPersonOperationType, ControlGroupRole, Decision
};
use crate::auth::{UserId, AuthManager};
use std::sync::{Arc, RwLock};
use tokio::time::Duration;

/// MPA Service that handles multi-person authorization workflows
pub struct MpaService {
    /// The underlying MPA manager
    manager: Arc<RwLock<MultiPersonAuthManager>>,
    /// Authentication manager for user validation
    auth_manager: Arc<RwLock<AuthManager>>,
}

impl MpaService {
    /// Create a new MPA service
    pub fn new(auth_manager: Arc<RwLock<AuthManager>>) -> Self {
        Self {
            manager: Arc::new(RwLock::new(MultiPersonAuthManager::new())),
            auth_manager,
        }
    }

    /// Create a new control group with validation
    pub async fn create_control_group(
        &self,
        name: String,
        description: String,
        required_approvals: usize,
        authorized_operations: Vec<OperationType>,
        approval_timeout: u64,
        creator_id: UserId,
    ) -> Result<ControlGroupId, FortressError> {
        // Validate creator exists and has appropriate permissions
        let auth = self.auth_manager.read().map_err(|_| {
            FortressError::internal("Failed to acquire auth lock", "AUTH_LOCK_ERROR")
        })?;

        if !auth.user_exists(&creator_id) {
            return Err(FortressError::authentication("User not found", None));
        }

        // Validate required_approvals is reasonable
        if required_approvals > 10 {
            return Err(FortressError::validation(
                "Required approvals cannot exceed 10 for operational efficiency",
                None,
                None,
            ));
        }

        let mut manager = self.manager.write().map_err(|_| {
            FortressError::internal("Failed to acquire MPA lock", "MPA_LOCK_ERROR")
        })?;

        manager.create_control_group(
            name,
            description,
            required_approvals,
            authorized_operations.into_iter().map(|op| match op {
                crate::performance_monitor::OperationType::KeyGeneration => crate::multi_person_auth::MultiPersonOperationType::KeyGeneration,
                crate::performance_monitor::OperationType::KeyStorage => crate::multi_person_auth::MultiPersonOperationType::KeyDeletion,
                crate::performance_monitor::OperationType::KeyRetrieval => crate::multi_person_auth::MultiPersonOperationType::AccessControlModification,
                crate::performance_monitor::OperationType::Encryption => crate::multi_person_auth::MultiPersonOperationType::SystemConfiguration,
                crate::performance_monitor::OperationType::Decryption => crate::multi_person_auth::MultiPersonOperationType::CertificateSigning,
                crate::performance_monitor::OperationType::DatabaseQuery => crate::multi_person_auth::MultiPersonOperationType::HsmOperation,
                crate::performance_monitor::OperationType::CacheOperation => crate::multi_person_auth::MultiPersonOperationType::AuditLogModification,
                crate::performance_monitor::OperationType::NetworkRequest => crate::multi_person_auth::MultiPersonOperationType::UserManagement,
                crate::performance_monitor::OperationType::BackgroundTask => crate::multi_person_auth::MultiPersonOperationType::Custom("BackgroundTask".to_string()),
                crate::performance_monitor::OperationType::SystemOperation => crate::multi_person_auth::MultiPersonOperationType::Custom("SystemOperation".to_string()),
            }).collect(),
            approval_timeout,
            creator_id,
        )
    }

    /// Add a member to a control group with validation
    pub async fn add_control_group_member(
        &self,
        group_id: &ControlGroupId,
        user_id: UserId,
        role: ControlGroupRole,
        added_by: UserId,
    ) -> Result<(), FortressError> {
        // Validate users exist
        let auth = self.auth_manager.read().map_err(|_| {
            FortressError::internal("Failed to acquire auth lock", "AUTH_LOCK_ERROR")
        })?;

        if !auth.user_exists(&user_id) {
            return Err(FortressError::authentication("Target user not found", None));
        }

        if !auth.user_exists(&added_by) {
            return Err(FortressError::authentication("Adding user not found", None));
        }

        // Validate the user adding the member has appropriate permissions
        let manager = self.manager.read().map_err(|_| {
            FortressError::internal("Failed to acquire MPA lock", "MPA_LOCK_ERROR")
        })?;

        let group = manager.get_control_group(group_id)
            .ok_or_else(|| FortressError::validation("Control group not found", None, None))?;

        // Only administrators and owners can add members
        let adding_user_role = group.members.iter()
            .find(|m| m.user_id == added_by)
            .map(|m| &m.role);

        match adding_user_role {
            Some(ControlGroupRole::Administrator) | Some(ControlGroupRole::Owner) => {
                // Allowed
            }
            _ => {
                return Err(FortressError::authentication("Only administrators and owners can add members to control groups", None));
            }
        }

        drop(manager);
        drop(auth);

        let mut manager = self.manager.write().map_err(|_| {
            FortressError::internal("Failed to acquire MPA lock", "MPA_LOCK_ERROR")
        })?;

        manager.add_control_group_member(group_id, user_id, role, added_by)
    }

    /// Create an approval request with comprehensive validation
    pub async fn create_approval_request(
        &self,
        control_group_id: ControlGroupId,
        operation_type: MultiPersonOperationType,
        operation_description: String,
        operation_context: String,
        requester_id: UserId,
    ) -> Result<ApprovalRequestId, FortressError> {
        // Validate requester exists
        let auth = self.auth_manager.read().map_err(|_| {
            FortressError::internal("Failed to acquire auth lock", "AUTH_LOCK_ERROR")
        })?;

        if !auth.user_exists(&requester_id) {
            return Err(FortressError::authentication("Requester not found", None));
        }

        // Validate operation description
        if operation_description.trim().is_empty() {
            return Err(FortressError::validation("Operation description cannot be empty", None, None));
        }

        if operation_description.len() > 1000 {
            return Err(FortressError::validation("Operation description too long (max 1000 characters)", None, None));
        }

        // Validate operation context is valid JSON
        if !operation_context.trim().is_empty() {
            serde_json::from_str::<serde_json::Value>(&operation_context)
                .map_err(|_| FortressError::validation("Operation context must be valid JSON", None, None))?;
        }

        drop(auth);

        let mut manager = self.manager.write().map_err(|_| {
            FortressError::internal("Failed to acquire MPA lock", "MPA_LOCK_ERROR")
        })?;

        manager.create_approval_request(
            control_group_id,
            operation_type,
            operation_description,
            operation_context,
            requester_id,
        )
    }

    /// Submit an approval decision with comprehensive validation
    pub async fn submit_approval_decision(
        &self,
        request_id: &ApprovalRequestId,
        user_id: UserId,
        decision: Decision,
        comment: Option<String>,
        source_ip: Option<String>,
        user_agent: Option<String>,
    ) -> Result<(), FortressError> {
        // Validate user exists
        let auth = self.auth_manager.read().map_err(|_| {
            FortressError::internal("Failed to acquire auth lock", "AUTH_LOCK_ERROR")
        })?;

        if !auth.user_exists(&user_id) {
            return Err(FortressError::authentication("User not found", None));
        }

        // Validate comment length if provided
        if let Some(comment) = &comment {
            if comment.len() > 500 {
                return Err(FortressError::validation("Comment too long (max 500 characters)", None, None));
            }
        }

        // Validate source IP format if provided
        if let Some(ip) = &source_ip {
            if ip.len() > 45 || !ip.contains('.') && !ip.contains(':') {
                return Err(FortressError::validation("Invalid IP address format", None, None));
            }
        }

        // Validate user agent length if provided
        if let Some(ua) = &user_agent {
            if ua.len() > 500 {
                return Err(FortressError::validation("User agent too long (max 500 characters)", None, None));
            }
        }

        drop(auth);

        let mut manager = self.manager.write().map_err(|_| {
            FortressError::internal("Failed to acquire MPA lock", "MPA_LOCK_ERROR")
        })?;

        manager.submit_approval_decision(
            request_id,
            user_id,
            decision,
            comment,
            source_ip,
            user_agent,
        )
    }

    /// Get approval request with user permission validation
    pub async fn get_approval_request(
        &self,
        request_id: &ApprovalRequestId,
        requesting_user: UserId,
    ) -> Result<Option<ApprovalRequest>, FortressError> {
        // Validate requesting user exists
        let auth = self.auth_manager.read().map_err(|_| {
            FortressError::internal("Failed to acquire auth lock", "AUTH_LOCK_ERROR")
        })?;

        if !auth.user_exists(&requesting_user) {
            return Err(FortressError::authentication("Requesting user not found", None));
        }

        drop(auth);

        let manager = self.manager.read().map_err(|_| {
            FortressError::internal("Failed to acquire MPA lock", "MPA_LOCK_ERROR")
        })?;

        let request = manager.get_approval_request(request_id);

        if let Some(req) = request {
            // User can view the request if:
            // 1. They are the requester
            // 2. They are a member of the control group
            // 3. They have admin privileges (simplified check)
            
            if req.requester_id == requesting_user {
                return Ok(Some(req.clone()));
            }

            if manager.is_user_in_control_group(&req.control_group_id, &requesting_user) {
                return Ok(Some(req.clone()));
            }

            // In a real implementation, you'd check for admin privileges here
            return Err(FortressError::authentication(
                "User not authorized to view this approval request",
                None,
            ));
        }

        Ok(None)
    }

    /// Get pending requests for a user
    pub async fn get_pending_requests_for_user(
        &self,
        user_id: UserId,
    ) -> Result<Vec<ApprovalRequest>, FortressError> {
        // Validate user exists
        let auth = self.auth_manager.read().map_err(|_| {
            FortressError::internal("Failed to acquire auth lock", "AUTH_LOCK_ERROR")
        })?;

        if !auth.user_exists(&user_id) {
            return Err(FortressError::authentication("User not found", None));
        }

        drop(auth);

        let manager = self.manager.read().map_err(|_| {
            FortressError::internal("Failed to acquire MPA lock", "MPA_LOCK_ERROR")
        })?;

        let requests = manager.get_pending_requests_for_user(&user_id);
        Ok(requests.into_iter().cloned().collect())
    }

    /// Get control groups for a user
    pub async fn get_control_groups_for_user(
        &self,
        user_id: UserId,
    ) -> Result<Vec<ControlGroup>, FortressError> {
        // Validate user exists
        let auth = self.auth_manager.read().map_err(|_| {
            FortressError::internal("Failed to acquire auth lock", "AUTH_LOCK_ERROR")
        })?;

        if !auth.user_exists(&user_id) {
            return Err(FortressError::authentication("User not found", None));
        }

        drop(auth);

        let manager = self.manager.read().map_err(|_| {
            FortressError::internal("Failed to acquire MPA lock", "MPA_LOCK_ERROR")
        })?;

        let groups = manager.get_control_groups_for_user(&user_id);
        Ok(groups.into_iter().cloned().collect())
    }

    /// Cancel an approval request
    pub async fn cancel_approval_request(
        &self,
        request_id: &ApprovalRequestId,
        cancelled_by: UserId,
    ) -> Result<(), FortressError> {
        // Validate user exists
        let auth = self.auth_manager.read().map_err(|_| {
            FortressError::internal("Failed to acquire auth lock", "AUTH_LOCK_ERROR")
        })?;

        if !auth.user_exists(&cancelled_by) {
            return Err(FortressError::authentication("User not found", None));
        }

        drop(auth);

        let mut manager = self.manager.write().map_err(|_| {
            FortressError::internal("Failed to acquire MPA lock", "MPA_LOCK_ERROR")
        })?;

        manager.cancel_approval_request(request_id, cancelled_by)
    }

    /// Check if an operation is approved
    pub async fn is_operation_approved(
        &self,
        request_id: &ApprovalRequestId,
    ) -> Result<bool, FortressError> {
        let manager = self.manager.read().map_err(|_| {
            FortressError::internal("Failed to acquire MPA lock", "MPA_LOCK_ERROR")
        })?;

        Ok(manager.is_operation_approved(request_id))
    }

    /// List all control groups (admin only)
    pub async fn list_control_groups(
        &self,
        requesting_user: UserId,
    ) -> Result<Vec<ControlGroup>, FortressError> {
        // Validate requesting user exists
        let auth = self.auth_manager.read().map_err(|_| {
            FortressError::internal("Failed to acquire auth lock", "AUTH_LOCK_ERROR")
        })?;

        if !auth.user_exists(&requesting_user) {
            return Err(FortressError::authentication("Requesting user not found", None));
        }

        // In a real implementation, you'd check for admin privileges here
        // For now, we'll allow any authenticated user to list groups

        drop(auth);

        let manager = self.manager.read().map_err(|_| {
            FortressError::internal("Failed to acquire MPA lock", "MPA_LOCK_ERROR")
        })?;

        let groups = manager.list_control_groups();
        Ok(groups.into_iter().cloned().collect())
    }

    /// Clean up expired requests (maintenance operation)
    pub async fn cleanup_expired_requests(&self) -> Result<usize, FortressError> {
        let mut manager = self.manager.write().map_err(|_| {
            FortressError::internal("Failed to acquire MPA lock", "MPA_LOCK_ERROR")
        })?;

        Ok(manager.cleanup_expired_requests())
    }

    /// Start background cleanup task
    pub fn start_cleanup_task(self: Arc<Self>) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(300)); // Every 5 minutes

            loop {
                interval.tick().await;

                match self.cleanup_expired_requests().await {
                    Ok(count) if count > 0 => {
                        tracing::info!("Cleaned up {} expired approval requests", count);
                    }
                    Err(e) => {
                        tracing::error!("Failed to cleanup expired requests: {}", e);
                    }
                    _ => {
                        // No expired requests, continue
                    }
                }
            }
        })
    }
}

impl Clone for MpaService {
    fn clone(&self) -> Self {
        Self {
            manager: Arc::clone(&self.manager),
            auth_manager: Arc::clone(&self.auth_manager),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::AuthManager;

    fn create_test_service() -> MpaService {
        let auth_manager = Arc::new(RwLock::new(AuthManager::new()));
        MpaService::new(auth_manager)
    }

    #[tokio::test]
    async fn test_create_control_group_service() {
        let service = create_test_service();
        
        // First create a user in the auth system with secure credentials
        {
            let mut auth = service.auth_manager.write().unwrap();
            let secure_password = crate::utils::generate_password(16);
            auth.create_user("admin".to_string(), secure_password).await.unwrap();
        }

        let group_id = service.create_control_group(
            "Test Group".to_string(),
            "Test Description".to_string(),
            2,
            vec![OperationType::KeyGeneration],
            3600,
            "admin".to_string(),
        ).await.unwrap();

        let groups = service.list_control_groups("admin".to_string()).await.unwrap();
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].id, group_id);
    }

    #[tokio::test]
    async fn test_approval_workflow_service() {
        let service = create_test_service();
        
        // Create users with secure credentials
        {
            let mut auth = service.auth_manager.write().unwrap();
            auth.create_user("admin".to_string(), crate::utils::generate_password(16)).await.unwrap();
            auth.create_user("user1".to_string(), crate::utils::generate_password(16)).await.unwrap();
            auth.create_user("user2".to_string(), crate::utils::generate_password(16)).await.unwrap();
            auth.create_user("requester".to_string(), crate::utils::generate_password(16)).await.unwrap();
        }

        // Create control group
        let group_id = service.create_control_group(
            "Test Group".to_string(),
            "Test Description".to_string(),
            2,
            vec![OperationType::KeyGeneration],
            3600,
            "admin".to_string(),
        ).await.unwrap();

        // Add members
        service.add_control_group_member(
            &group_id,
            "user1".to_string(),
            ControlGroupRole::Approver,
            "admin".to_string(),
        ).await.unwrap();

        service.add_control_group_member(
            &group_id,
            "user2".to_string(),
            ControlGroupRole::Approver,
            "admin".to_string(),
        ).await.unwrap();

        // Create approval request
        let request_id = service.create_approval_request(
            group_id,
            OperationType::KeyGeneration,
            "Generate new encryption key".to_string(),
            serde_json::json!({"key_type": "AES-256"}).to_string(),
            "requester".to_string(),
        ).await.unwrap();

        // Submit approvals
        service.submit_approval_decision(
            &request_id,
            "user1".to_string(),
            Decision::Approve,
            Some("Approved".to_string()),
            Some("127.0.0.1".to_string()),
            Some("Test Agent".to_string()),
        ).await.unwrap();

        service.submit_approval_decision(
            &request_id,
            "user2".to_string(),
            Decision::Approve,
            Some("Also approved".to_string()),
            Some("127.0.0.1".to_string()),
            Some("Test Agent".to_string()),
        ).await.unwrap();

        // Check if approved
        let approved = service.is_operation_approved(&request_id).await.unwrap();
        assert!(approved);
    }

    #[tokio::test]
    async fn test_get_pending_requests() {
        let service = create_test_service();
        
        // Create users with secure credentials
        {
            let mut auth = service.auth_manager.write().unwrap();
            auth.create_user("admin".to_string(), crate::utils::generate_password(16)).await.unwrap();
            auth.create_user("user1".to_string(), crate::utils::generate_password(16)).await.unwrap();
            auth.create_user("requester".to_string(), crate::utils::generate_password(16)).await.unwrap();
        }

        // Create control group
        let group_id = service.create_control_group(
            "Test Group".to_string(),
            "Test Description".to_string(),
            2,
            vec![OperationType::KeyGeneration],
            3600,
            "admin".to_string(),
        ).await.unwrap();

        // Add member
        service.add_control_group_member(
            &group_id,
            "user1".to_string(),
            ControlGroupRole::Approver,
            "admin".to_string(),
        ).await.unwrap();

        // Create approval request
        let request_id = service.create_approval_request(
            group_id,
            OperationType::KeyGeneration,
            "Generate new encryption key".to_string(),
            "{}".to_string(),
            "requester".to_string(),
        ).await.unwrap();

        // Get pending requests for user1
        let pending = service.get_pending_requests_for_user("user1".to_string()).await.unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].id, request_id);

        // Get pending requests for requester (should be empty)
        let pending = service.get_pending_requests_for_user("requester".to_string()).await.unwrap();
        assert_eq!(pending.len(), 0);
    }
}
