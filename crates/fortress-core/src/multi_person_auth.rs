//! Multi-Person Authorization (MPA) / Control Groups
//! 
//! This module implements an M-of-N approval system for critical operations,
//! requiring multiple authorized users to approve sensitive actions before execution.

use crate::error::FortressError;
use crate::auth::{UserId, Role};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

/// Unique identifier for a control group
pub type ControlGroupId = String;

/// Unique identifier for an approval request
pub type ApprovalRequestId = String;

/// Identifier for a specific approval decision
pub type ApprovalDecisionId = String;

/// Control group configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlGroup {
    /// Unique identifier for the control group
    pub id: ControlGroupId,
    /// Human-readable name for the control group
    pub name: String,
    /// Description of the control group's purpose
    pub description: String,
    /// List of members in this control group
    pub members: Vec<ControlGroupMember>,
    /// Required number of approvals (M in M-of-N)
    pub required_approvals: usize,
    /// Types of operations this group can approve
    pub authorized_operations: Vec<MultiPersonOperationType>,
    /// Time window for approvals (in seconds, 0 = no limit)
    pub approval_timeout: u64,
    /// Whether the group is currently active
    pub active: bool,
    /// When the group was created
    pub created_at: u64,
    /// Who created the group
    pub created_by: UserId,
    /// Last modification timestamp
    pub modified_at: u64,
    /// Who last modified the group
    pub modified_by: UserId,
}

/// Member of a control group
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlGroupMember {
    /// User ID of the member
    pub user_id: UserId,
    /// Role of the member within the control group
    pub role: ControlGroupRole,
    /// When the member was added to the group
    pub added_at: u64,
    /// Who added this member
    pub added_by: UserId,
    /// Whether the member is currently active
    pub active: bool,
}

/// Role within a control group
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ControlGroupRole {
    /// Regular approver
    Approver,
    /// Group administrator (can manage members)
    Administrator,
    /// Group owner (can modify group settings)
    Owner,
}

/// Types of operations that require MPA approval
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Hash)]
pub enum MultiPersonOperationType {
    /// Key generation operations
    KeyGeneration,
    /// Key deletion operations
    KeyDeletion,
    /// Access control modifications
    AccessControlModification,
    /// System configuration changes
    SystemConfiguration,
    /// Certificate signing operations
    CertificateSigning,
    /// HSM operations
    HsmOperation,
    /// Audit log modifications
    AuditLogModification,
    /// User management operations
    UserManagement,
    /// Custom operation type
    Custom(String),
}

/// Approval request for a critical operation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalRequest {
    /// Unique identifier for this approval request
    pub id: ApprovalRequestId,
    /// Control group that must approve this request
    pub control_group_id: ControlGroupId,
    /// Type of operation requiring approval
    pub operation_type: MultiPersonOperationType,
    /// Description of the operation
    pub operation_description: String,
    /// Context data for the operation (JSON)
    pub operation_context: String,
    /// Who initiated the request
    pub requester_id: UserId,
    /// Current status of the approval request
    pub status: ApprovalStatus,
    /// Collection of approval decisions
    pub decisions: Vec<ApprovalDecision>,
    /// When the request was created
    pub created_at: u64,
    /// When the request expires
    pub expires_at: u64,
    /// When the request was last updated
    pub updated_at: u64,
}

/// Individual approval decision
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalDecision {
    /// Unique identifier for this decision
    pub id: ApprovalDecisionId,
    /// Approval request this decision belongs to
    pub approval_request_id: ApprovalRequestId,
    /// User making the decision
    pub user_id: UserId,
    /// The decision made
    pub decision: Decision,
    /// Optional comment explaining the decision
    pub comment: Option<String>,
    /// When the decision was made
    pub decided_at: u64,
    /// IP address from which the decision was made
    pub source_ip: Option<String>,
    /// User agent used for the decision
    pub user_agent: Option<String>,
}

/// Approval decision type
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum Decision {
    /// Approve the operation
    Approve,
    /// Reject the operation
    Reject,
    /// Request more information before deciding
    RequestInformation,
}

/// Status of an approval request
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ApprovalStatus {
    /// Request is pending approvals
    Pending,
    /// Request has been approved and can proceed
    Approved,
    /// Request was rejected
    Rejected,
    /// Request expired before sufficient approvals
    Expired,
    /// Request was cancelled by the requester
    Cancelled,
}

/// Multi-Person Authorization Manager
pub struct MultiPersonAuthManager {
    /// Storage for control groups
    control_groups: HashMap<ControlGroupId, ControlGroup>,
    /// Storage for approval requests
    approval_requests: HashMap<ApprovalRequestId, ApprovalRequest>,
    /// User to control groups mapping for quick lookup
    user_control_groups: HashMap<UserId, Vec<ControlGroupId>>,
}

impl MultiPersonAuthManager {
    /// Create a new MPA manager
    pub fn new() -> Self {
        Self {
            control_groups: HashMap::new(),
            approval_requests: HashMap::new(),
            user_control_groups: HashMap::new(),
        }
    }

    /// Create a new control group
    pub fn create_control_group(
        &mut self,
        name: String,
        description: String,
        required_approvals: usize,
        authorized_operations: Vec<MultiPersonOperationType>,
        approval_timeout: u64,
        creator_id: UserId,
    ) -> Result<ControlGroupId, FortressError> {
        if required_approvals == 0 {
            return Err(FortressError::validation(
                "Required approvals must be greater than 0",
                None,
                None,
            ));
        }

        let group_id = Uuid::new_v4().to_string();
        let now = current_timestamp();

        let control_group = ControlGroup {
            id: group_id.clone(),
            name,
            description,
            members: Vec::new(),
            required_approvals,
            authorized_operations,
            approval_timeout,
            active: true,
            created_at: now,
            created_by: creator_id.clone(),
            modified_at: now,
            modified_by: creator_id,
        };

        self.control_groups.insert(group_id.clone(), control_group);
        Ok(group_id)
    }

    /// Add a member to a control group
    pub fn add_control_group_member(
        &mut self,
        group_id: &ControlGroupId,
        user_id: UserId,
        role: ControlGroupRole,
        added_by: UserId,
    ) -> Result<(), FortressError> {
        let group = self.control_groups.get_mut(group_id)
            .ok_or_else(|| FortressError::validation("Control group not found", None, None))?;

        // Check if user is already a member
        if group.members.iter().any(|m| m.user_id == user_id) {
            return Err(FortressError::validation("User is already a member of this control group", None, None));
        }

        let member = ControlGroupMember {
            user_id: user_id.clone(),
            role,
            added_at: current_timestamp(),
            added_by: added_by.clone(),
            active: true,
        };

        group.members.push(member);
        group.modified_at = current_timestamp();
        group.modified_by = added_by;

        // Update user to groups mapping
        self.user_control_groups
            .entry(user_id)
            .or_insert_with(Vec::new)
            .push(group_id.clone());

        Ok(())
    }

    /// Remove a member from a control group
    pub fn remove_control_group_member(
        &mut self,
        group_id: &ControlGroupId,
        user_id: &UserId,
        removed_by: UserId,
    ) -> Result<(), FortressError> {
        let group = self.control_groups.get_mut(group_id)
            .ok_or_else(|| FortressError::validation("Control group not found", None, None))?;

        // Remove the member
        group.members.retain(|m| &m.user_id != user_id);
        group.modified_at = current_timestamp();
        group.modified_by = removed_by;

        // Update user to groups mapping
        if let Some(groups) = self.user_control_groups.get_mut(user_id) {
            groups.retain(|g| g != group_id);
            if groups.is_empty() {
                self.user_control_groups.remove(user_id);
            }
        }

        Ok(())
    }

    /// Create a new approval request
    pub fn create_approval_request(
        &mut self,
        control_group_id: ControlGroupId,
        operation_type: MultiPersonOperationType,
        operation_description: String,
        operation_context: String,
        requester_id: UserId,
    ) -> Result<ApprovalRequestId, FortressError> {
        let group = self.control_groups.get(&control_group_id)
            .ok_or_else(|| FortressError::validation("Control group not found", None, None))?;

        // Check if the group is active
        if !group.active {
            return Err(FortressError::validation("Control group is not active", None, None));
        }

        // Check if the group can authorize this operation type
        if !group.authorized_operations.contains(&operation_type) {
            return Err(FortressError::validation("Control group is not authorized for this operation type", None, None));
        }

        // Check if there are enough active members to potentially approve
        let active_members = group.members.iter()
            .filter(|m| m.active)
            .count();
        
        if active_members < group.required_approvals {
            return Err(FortressError::validation(
                "Not enough active members in control group to meet approval requirements",
                None,
                None,
            ));
        }

        let request_id = Uuid::new_v4().to_string();
        let now = current_timestamp();
        let expires_at = if group.approval_timeout > 0 {
            now + group.approval_timeout
        } else {
            u64::MAX // No expiration
        };

        let approval_request = ApprovalRequest {
            id: request_id.clone(),
            control_group_id: control_group_id.clone(),
            operation_type,
            operation_description,
            operation_context,
            requester_id,
            status: ApprovalStatus::Pending,
            decisions: Vec::new(),
            created_at: now,
            expires_at,
            updated_at: now,
        };

        self.approval_requests.insert(request_id.clone(), approval_request);
        Ok(request_id)
    }

    /// Submit an approval decision
    pub fn submit_approval_decision(
        &mut self,
        request_id: &ApprovalRequestId,
        user_id: UserId,
        decision: Decision,
        comment: Option<String>,
        source_ip: Option<String>,
        user_agent: Option<String>,
    ) -> Result<(), FortressError> {
        let request = self.approval_requests.get_mut(request_id)
            .ok_or_else(|| FortressError::validation("Approval request not found", None, None))?;

        // Check if request is still pending
        if request.status != ApprovalStatus::Pending {
            return Err(FortressError::validation(
                "Approval request is no longer pending",
                None,
                None,
            ));
        }

        // Check if request has expired
        if current_timestamp() > request.expires_at {
            request.status = ApprovalStatus::Expired;
            return Err(FortressError::validation(
                "Approval request has expired",
                None,
                None,
            ));
        }

        // Verify user is a member of the control group
        let group = self.control_groups.get(&request.control_group_id)
            .ok_or_else(|| FortressError::validation(
                "Control group not found",
                None,
                None,
            ))?;

        let _member = group.members.iter()
            .find(|m| m.user_id == user_id && m.active)
            .ok_or_else(|| FortressError::validation(
                "User is not an active member of the control group",
                None,
                None,
            ))?;

        // Check if user has already decided
        if request.decisions.iter().any(|d| d.user_id == user_id) {
            return Err(FortressError::validation(
            "User has already submitted a decision for this request",
            None,
            None,
        ));
        }

        // Create the decision
        let decision_id = Uuid::new_v4().to_string();
        let approval_decision = ApprovalDecision {
            id: decision_id,
            approval_request_id: request_id.clone(),
            user_id: user_id.clone(),
            decision: decision.clone(),
            comment,
            decided_at: current_timestamp(),
            source_ip,
            user_agent,
        };

        request.decisions.push(approval_decision);
        request.updated_at = current_timestamp();

        // Update request status based on decisions
        let group_id = request.control_group_id.clone();
        let approvals_needed = request.decisions.iter().filter(|d| d.decision == Decision::Approve).count();
        let rejections = request.decisions.iter().filter(|d| d.decision == Decision::Reject).count();
        drop(request);
        
        let mut request = self.approval_requests.get_mut(request_id).unwrap();
        
        // Get the control group to check requirements
        let group = match self.control_groups.get(&group_id) {
            Some(g) => g,
            None => return Ok(()),
        };

        // Check if request is rejected (any rejection means rejected)
        if rejections > 0 {
            request.status = ApprovalStatus::Rejected;
            return Ok(());
        }

        // Check if request is approved (enough approvals)
        if approvals_needed >= group.required_approvals {
            request.status = ApprovalStatus::Approved;
            return Ok(());
        }

        // Otherwise, still pending
        request.status = ApprovalStatus::Pending;
        Ok(())
    }

    /// Update the status of an approval request based on current decisions
    fn update_approval_status(&mut self, request: &mut ApprovalRequest) {
        let group = match self.control_groups.get(&request.control_group_id) {
            Some(g) => g,
            None => return,
        };

        let approvals = request.decisions.iter()
            .filter(|d| d.decision == Decision::Approve)
            .count();

        let rejections = request.decisions.iter()
            .filter(|d| d.decision == Decision::Reject)
            .count();

        // Check if enough approvals have been received
        if approvals >= group.required_approvals {
            request.status = ApprovalStatus::Approved;
        }
        // Check if too many rejections make approval impossible
        else if rejections > (group.members.len() - group.required_approvals) {
            request.status = ApprovalStatus::Rejected;
        }
    }

    /// Get an approval request by ID
    pub fn get_approval_request(&self, request_id: &ApprovalRequestId) -> Option<&ApprovalRequest> {
        self.approval_requests.get(request_id)
    }

    /// Get all pending requests for a user
    pub fn get_pending_requests_for_user(&self, user_id: &UserId) -> Vec<&ApprovalRequest> {
        self.approval_requests.values()
            .filter(|r| {
                r.status == ApprovalStatus::Pending &&
                current_timestamp() <= r.expires_at &&
                self.is_user_in_control_group(&r.control_group_id, user_id)
            })
            .collect()
    }

    /// Get all control groups for a user
    pub fn get_control_groups_for_user(&self, user_id: &UserId) -> Vec<&ControlGroup> {
        self.user_control_groups.get(user_id)
            .unwrap_or(&Vec::new())
            .iter()
            .filter_map(|group_id| self.control_groups.get(group_id))
            .collect()
    }

    /// Check if a user is a member of a control group
    pub fn is_user_in_control_group(&self, group_id: &ControlGroupId, user_id: &UserId) -> bool {
        self.control_groups.get(group_id)
            .map(|group| group.members.iter().any(|m| &m.user_id == user_id && m.active))
            .unwrap_or(false)
    }

    /// Cancel an approval request
    pub fn cancel_approval_request(
        &mut self,
        request_id: &ApprovalRequestId,
        cancelled_by: UserId,
    ) -> Result<(), FortressError> {
        let request = self.approval_requests.get_mut(request_id)
            .ok_or_else(|| FortressError::validation("Approval request not found", None, None))?;

        // Only the requester can cancel
        if request.requester_id != cancelled_by {
            return Err(FortressError::validation(
                "Only the requester can cancel an approval request",
                None,
                None,
            ));
        }

        if request.status != ApprovalStatus::Pending {
            return Err(FortressError::validation(
                "Cannot cancel a request that is no longer pending",
                None,
                None,
            ));
        }

        request.status = ApprovalStatus::Cancelled;
        request.updated_at = current_timestamp();

        Ok(())
    }

    /// Get control group by ID
    pub fn get_control_group(&self, group_id: &ControlGroupId) -> Option<&ControlGroup> {
        self.control_groups.get(group_id)
    }

    /// List all control groups
    pub fn list_control_groups(&self) -> Vec<&ControlGroup> {
        self.control_groups.values().collect()
    }

    /// Check if an operation is approved
    pub fn is_operation_approved(&self, request_id: &ApprovalRequestId) -> bool {
        self.approval_requests.get(request_id)
            .map(|r| r.status == ApprovalStatus::Approved)
            .unwrap_or(false)
    }

    /// Clean up expired requests
    pub fn cleanup_expired_requests(&mut self) -> usize {
        let now = current_timestamp();
        let mut expired_count = 0;

        for request in self.approval_requests.values_mut() {
            if request.status == ApprovalStatus::Pending && now > request.expires_at {
                request.status = ApprovalStatus::Expired;
                expired_count += 1;
            }
        }

        expired_count
    }
}

impl Default for MultiPersonAuthManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Get current timestamp in seconds since Unix epoch
fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_manager() -> MultiPersonAuthManager {
        MultiPersonAuthManager::new()
    }

    #[test]
    fn test_create_control_group() {
        let mut manager = create_test_manager();
        let group_id = manager.create_control_group(
            "Test Group".to_string(),
            "Test Description".to_string(),
            2,
            vec![OperationType::KeyGeneration],
            3600,
            "user1".to_string(),
        ).unwrap();

        let group = manager.get_control_group(&group_id).unwrap();
        assert_eq!(group.name, "Test Group");
        assert_eq!(group.required_approvals, 2);
        assert!(group.active);
    }

    #[test]
    fn test_add_control_group_member() {
        let mut manager = create_test_manager();
        let group_id = manager.create_control_group(
            "Test Group".to_string(),
            "Test Description".to_string(),
            2,
            vec![OperationType::KeyGeneration],
            3600,
            "admin".to_string(),
        ).unwrap();

        manager.add_control_group_member(
            &group_id,
            "user1".to_string(),
            ControlGroupRole::Approver,
            "admin".to_string(),
        ).unwrap();

        let group = manager.get_control_group(&group_id).unwrap();
        assert_eq!(group.members.len(), 1);
        assert_eq!(group.members[0].user_id, "user1");
    }

    #[test]
    fn test_create_approval_request() {
        let mut manager = create_test_manager();
        let group_id = manager.create_control_group(
            "Test Group".to_string(),
            "Test Description".to_string(),
            2,
            vec![OperationType::KeyGeneration],
            3600,
            "admin".to_string(),
        ).unwrap();

        // Add members
        manager.add_control_group_member(
            &group_id,
            "user1".to_string(),
            ControlGroupRole::Approver,
            "admin".to_string(),
        ).unwrap();

        manager.add_control_group_member(
            &group_id,
            "user2".to_string(),
            ControlGroupRole::Approver,
            "admin".to_string(),
        ).unwrap();

        let request_id = manager.create_approval_request(
            group_id,
            OperationType::KeyGeneration,
            "Generate new encryption key".to_string(),
            "{}".to_string(),
            "requester".to_string(),
        ).unwrap();

        let request = manager.get_approval_request(&request_id).unwrap();
        assert_eq!(request.status, ApprovalStatus::Pending);
        assert_eq!(request.decisions.len(), 0);
    }

    #[test]
    fn test_approval_workflow() {
        let mut manager = create_test_manager();
        let group_id = manager.create_control_group(
            "Test Group".to_string(),
            "Test Description".to_string(),
            2,
            vec![OperationType::KeyGeneration],
            3600,
            "admin".to_string(),
        ).unwrap();

        // Add members
        manager.add_control_group_member(
            &group_id,
            "user1".to_string(),
            ControlGroupRole::Approver,
            "admin".to_string(),
        ).unwrap();

        manager.add_control_group_member(
            &group_id,
            "user2".to_string(),
            ControlGroupRole::Approver,
            "admin".to_string(),
        ).unwrap();

        let request_id = manager.create_approval_request(
            group_id,
            OperationType::KeyGeneration,
            "Generate new encryption key".to_string(),
            "{}".to_string(),
            "requester".to_string(),
        ).unwrap();

        // First approval
        manager.submit_approval_decision(
            &request_id,
            "user1".to_string(),
            Decision::Approve,
            Some("Looks good".to_string()),
            Some("127.0.0.1".to_string()),
            Some("Test Agent".to_string()),
        ).unwrap();

        let request = manager.get_approval_request(&request_id).unwrap();
        assert_eq!(request.status, ApprovalStatus::Pending);
        assert_eq!(request.decisions.len(), 1);

        // Second approval (should reach required count)
        manager.submit_approval_decision(
            &request_id,
            "user2".to_string(),
            Decision::Approve,
            Some("Approved".to_string()),
            Some("127.0.0.1".to_string()),
            Some("Test Agent".to_string()),
        ).unwrap();

        let request = manager.get_approval_request(&request_id).unwrap();
        assert_eq!(request.status, ApprovalStatus::Approved);
        assert_eq!(request.decisions.len(), 2);
    }

    #[test]
    fn test_rejection_workflow() {
        let mut manager = create_test_manager();
        let group_id = manager.create_control_group(
            "Test Group".to_string(),
            "Test Description".to_string(),
            2,
            vec![OperationType::KeyGeneration],
            3600,
            "admin".to_string(),
        ).unwrap();

        // Add members
        manager.add_control_group_member(
            &group_id,
            "user1".to_string(),
            ControlGroupRole::Approver,
            "admin".to_string(),
        ).unwrap();

        manager.add_control_group_member(
            &group_id,
            "user2".to_string(),
            ControlGroupRole::Approver,
            "admin".to_string(),
        ).unwrap();

        manager.add_control_group_member(
            &group_id,
            "user3".to_string(),
            ControlGroupRole::Approver,
            "admin".to_string(),
        ).unwrap();

        let request_id = manager.create_approval_request(
            group_id,
            OperationType::KeyGeneration,
            "Generate new encryption key".to_string(),
            "{}".to_string(),
            "requester".to_string(),
        ).unwrap();

        // First rejection
        manager.submit_approval_decision(
            &request_id,
            "user1".to_string(),
            Decision::Reject,
            Some("Not approved".to_string()),
            Some("127.0.0.1".to_string()),
            Some("Test Agent".to_string()),
        ).unwrap();

        // Second rejection (should make approval impossible)
        manager.submit_approval_decision(
            &request_id,
            "user2".to_string(),
            Decision::Reject,
            Some("Also not approved".to_string()),
            Some("127.0.0.1".to_string()),
            Some("Test Agent".to_string()),
        ).unwrap();

        let request = manager.get_approval_request(&request_id).unwrap();
        assert_eq!(request.status, ApprovalStatus::Rejected);
    }
}
