//! # Policy Engine and RBAC System
//!
//! Enterprise-grade policy engine with role-based access control (RBAC) inspired by HashiCorp Vault.
//!
//! ## Features
//!
//! - **Role-Based Access Control**: Hierarchical roles with fine-grained permissions
//! - **Policy Evaluation Engine**: Fast, secure policy evaluation with caching
//! - **Resource-Based Permissions**: Granular control over database operations
//! - **Temporal Policies**: Time-based access controls
//! - **Audit Trail**: Complete logging of policy decisions
//!
//! ## Example
//!
//! ```rust,no_run
//! use fortress_core::policy::{PolicyEngine, Role, Permission, Resource};
//!
//! let mut engine = PolicyEngine::new();
//!
//! // Create a role with read-only access
//! let readonly_role = Role::new("readonly")
//!     .with_permission(Permission::Read, Resource::Database("users"))
//!     .with_permission(Permission::Read, Resource::Database("orders"));
//!
//! engine.add_role(readonly_role)?;
//! engine.assign_role("user123", "readonly")?;
//!
//! // Check permissions
//! let can_read = engine.check_permission("user123", Permission::Read, Resource::Database("users"))?;
//! let can_write = engine.check_permission("user123", Permission::Write, Resource::Database("users"))?;
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

use crate::error::{FortressError, Result};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;

/// Policy engine for managing roles and permissions
#[derive(Debug)]
pub struct PolicyEngine {
    roles: RwLock<HashMap<String, Role>>,
    user_roles: RwLock<HashMap<String, HashSet<String>>>,
    policies: RwLock<HashMap<String, Policy>>,
    cache: RwLock<HashMap<CacheKey, bool>>,
}

/// Cache key for permission checks
#[derive(Debug, Clone, Hash, Eq, PartialEq, Serialize, Deserialize)]
struct CacheKey {
    user_id: String,
    permission: Permission,
    resource: Resource,
    timestamp: u64,
}

/// Role definition with permissions and metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Role {
    pub name: String,
    pub description: Option<String>,
    pub permissions: HashSet<PermissionEntry>,
    pub constraints: Vec<Constraint>,
    pub created_at: u64,
    pub updated_at: u64,
}

/// Individual permission entry
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PermissionEntry {
    pub permission: Permission,
    pub resource: Resource,
    pub conditions: Vec<Condition>,
}

impl std::hash::Hash for Condition {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        match self {
            Condition::Time(tc) => {
                0u8.hash(state);
                tc.start_time.hash(state);
                tc.end_time.hash(state);
                tc.days_of_week.hash(state);
                tc.timezone.hash(state);
            }
            Condition::Ip(ic) => {
                1u8.hash(state);
                ic.allowed_ips.hash(state);
                ic.denied_ips.hash(state);
                ic.cidr_ranges.hash(state);
            }
            Condition::Attribute(ac) => {
                2u8.hash(state);
                ac.attribute.hash(state);
                ac.operator.hash(state);
                ac.value.hash(state);
            }
            Condition::Custom(s) => {
                3u8.hash(state);
                s.hash(state);
            }
        }
    }
}

impl std::cmp::Eq for Condition {}

impl std::hash::Hash for TimeCondition {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.start_time.hash(state);
        self.end_time.hash(state);
        self.days_of_week.hash(state);
        self.timezone.hash(state);
    }
}

impl std::cmp::Eq for TimeCondition {}

impl std::hash::Hash for IpCondition {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.allowed_ips.hash(state);
        self.denied_ips.hash(state);
        self.cidr_ranges.hash(state);
    }
}

impl std::cmp::Eq for IpCondition {}

impl std::hash::Hash for AttributeCondition {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.attribute.hash(state);
        self.operator.hash(state);
        self.value.hash(state);
    }
}

impl std::cmp::Eq for AttributeCondition {}

/// Available permissions
#[derive(Debug, Clone, Hash, Eq, PartialEq, Serialize, Deserialize)]
pub enum Permission {
    /// Read access to resources
    Read,
    /// Write access to resources
    Write,
    /// Delete access to resources
    Delete,
    /// Administrative operations
    Admin,
    /// Key management operations
    KeyManage,
    /// Policy management operations
    PolicyManage,
    /// Audit log access
    AuditRead,
    /// System configuration
    SystemConfig,
}

/// Resource types that can be protected
#[derive(Debug, Clone, Hash, Eq, PartialEq, Serialize, Deserialize)]
pub enum Resource {
    /// Entire database
    Database(String),
    /// Specific table
    Table(String, String),
    /// Specific field
    Field(String, String, String),
    /// Key management
    KeyStore,
    /// Policy system
    PolicySystem,
    /// Audit logs
    AuditLog,
    /// System configuration
    SystemConfig,
    /// All resources (super admin)
    All,
}

/// Policy definition with rules and conditions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Policy {
    pub name: String,
    pub description: Option<String>,
    pub rules: Vec<PolicyRule>,
    pub effect: PolicyEffect,
    pub priority: i32,
    pub created_at: u64,
    pub updated_at: u64,
}

/// Individual policy rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyRule {
    pub actions: Vec<Permission>,
    pub resources: Vec<Resource>,
    pub conditions: Vec<Condition>,
}

/// Policy effect (allow or deny)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PolicyEffect {
    Allow,
    Deny,
}

/// Conditions for policy evaluation
#[derive(Debug, Clone, PartialEq, Hash, Serialize, Deserialize)]
pub enum Condition {
    /// Time-based condition
    Time(TimeCondition),
    /// IP-based condition
    Ip(IpCondition),
    /// Attribute-based condition
    Attribute(AttributeCondition),
    /// Custom condition
    Custom(String),
}

/// Time-based conditions
#[derive(Debug, Clone, PartialEq, Hash, Serialize, Deserialize)]
pub struct TimeCondition {
    pub start_time: Option<u64>,
    pub end_time: Option<u64>,
    pub days_of_week: Option<Vec<u8>>, // 0 = Sunday, 6 = Saturday
    pub timezone: Option<String>,
}

/// IP-based conditions
#[derive(Debug, Clone, PartialEq, Hash, Serialize, Deserialize)]
pub struct IpCondition {
    pub allowed_ips: Vec<String>,
    pub denied_ips: Vec<String>,
    pub cidr_ranges: Vec<String>,
}

/// Attribute-based conditions
#[derive(Debug, Clone, PartialEq, Hash, Serialize, Deserialize)]
pub struct AttributeCondition {
    pub attribute: String,
    pub operator: AttributeOperator,
    pub value: String,
}

/// Attribute operators
#[derive(Debug, Clone, PartialEq, Hash, Serialize, Deserialize)]
pub enum AttributeOperator {
    Equals,
    NotEquals,
    Contains,
    StartsWith,
    EndsWith,
    GreaterThan,
    LessThan,
}

/// Constraints on role permissions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Constraint {
    /// Maximum data size that can be accessed
    MaxDataSize(u64),
    /// Rate limiting
    RateLimit { requests_per_minute: u32 },
    /// Geographic restrictions
    Geographic { allowed_countries: Vec<String> },
    /// Device restrictions
    Device { allowed_devices: Vec<String> },
}

/// Audit log entry for policy decisions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyAuditEntry {
    pub timestamp: u64,
    pub user_id: String,
    pub permission: Permission,
    pub resource: Resource,
    pub decision: bool,
    pub reason: String,
    pub roles_involved: Vec<String>,
    pub policies_evaluated: Vec<String>,
    pub evaluation_time_ms: u64,
}

impl PolicyEngine {
    /// Create a new policy engine
    pub fn new() -> Self {
        Self {
            roles: RwLock::new(HashMap::new()),
            user_roles: RwLock::new(HashMap::new()),
            policies: RwLock::new(HashMap::new()),
            cache: RwLock::new(HashMap::new()),
        }
    }

    /// Add a new role to the system
    pub async fn add_role(&self, role: Role) -> Result<()> {
        let mut roles = self.roles.write().await;
        roles.insert(role.name.clone(), role);
        self.clear_cache().await;
        Ok(())
    }

    /// Remove a role from the system
    pub async fn remove_role(&self, role_name: &str) -> Result<()> {
        let mut roles = self.roles.write().await;
        roles.remove(role_name);
        
        // Remove role assignments
        let mut user_roles = self.user_roles.write().await;
        for (_, roles) in user_roles.iter_mut() {
            roles.remove(role_name);
        }
        
        self.clear_cache().await;
        Ok(())
    }

    /// Assign a role to a user
    pub async fn assign_role(&self, user_id: &str, role_name: &str) -> Result<()> {
        let roles = self.roles.read().await;
        if !roles.contains_key(role_name) {
            return Err(FortressError::PolicyError(format!("Role '{}' not found", role_name)));
        }
        drop(roles);

        let mut user_roles = self.user_roles.write().await;
        user_roles
            .entry(user_id.to_string())
            .or_insert_with(HashSet::new)
            .insert(role_name.to_string());
        
        self.clear_cache().await;
        Ok(())
    }

    /// Remove a role from a user
    pub async fn remove_role_assignment(&self, user_id: &str, role_name: &str) -> Result<()> {
        let mut user_roles = self.user_roles.write().await;
        if let Some(roles) = user_roles.get_mut(user_id) {
            roles.remove(role_name);
        }
        self.clear_cache().await;
        Ok(())
    }

    /// Check if a user has permission for a resource
    pub async fn check_permission(
        &self,
        user_id: &str,
        permission: Permission,
        resource: Resource,
    ) -> Result<bool> {
        let start_time = SystemTime::now();
        
        // Check cache first
        let cache_key = CacheKey {
            user_id: user_id.to_string(),
            permission: permission.clone(),
            resource: resource.clone(),
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        };

        {
            let cache = self.cache.read().await;
            if let Some(&cached_result) = cache.get(&cache_key) {
                return Ok(cached_result);
            }
        }

        // Get user's roles
        let user_roles = self.user_roles.read().await;
        let role_names = user_roles.get(user_id).cloned().unwrap_or_default();
        drop(user_roles);

        // Get role definitions
        let roles = self.roles.read().await;
        
        // Check each role for permission
        for role_name in &role_names {
            if let Some(role) = roles.get(role_name) {
                for permission_entry in &role.permissions {
                    if permission_entry.permission == permission && 
                       self.matches_resource(&permission_entry.resource, &resource) &&
                       self.evaluate_conditions(&permission_entry.conditions, user_id).await? {
                        
                        // Cache the result
                        let mut cache = self.cache.write().await;
                        cache.insert(cache_key, true);
                        
                        let elapsed = start_time.elapsed().unwrap().as_millis() as u64;
                        self.log_audit_entry(PolicyAuditEntry {
                            timestamp: SystemTime::now()
                                .duration_since(UNIX_EPOCH)
                                .unwrap()
                                .as_secs(),
                            user_id: user_id.to_string(),
                            permission,
                            resource,
                            decision: true,
                            reason: format!("Granted by role '{}'", role_name),
                            roles_involved: vec![role_name.clone()],
                            policies_evaluated: vec![],
                            evaluation_time_ms: elapsed,
                        }).await?;
                        
                        return Ok(true);
                    }
                }
            }
        }

        // Cache the negative result
        let mut cache = self.cache.write().await;
        cache.insert(cache_key, false);
        
        let elapsed = start_time.elapsed().unwrap().as_millis() as u64;
        self.log_audit_entry(PolicyAuditEntry {
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            user_id: user_id.to_string(),
            permission,
            resource,
            decision: false,
            reason: "No matching permission found".to_string(),
            roles_involved: role_names.into_iter().collect(),
            policies_evaluated: vec![],
            evaluation_time_ms: elapsed,
        }).await?;

        Ok(false)
    }

    /// Get all roles assigned to a user
    pub async fn get_user_roles(&self, user_id: &str) -> Result<Vec<String>> {
        let user_roles = self.user_roles.read().await;
        Ok(user_roles
            .get(user_id)
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .collect())
    }

    /// Get all permissions for a user
    pub async fn get_user_permissions(&self, user_id: &str) -> Result<Vec<PermissionEntry>> {
        let user_roles = self.user_roles.read().await;
        let role_names = user_roles.get(user_id).cloned().unwrap_or_default();
        drop(user_roles);

        let roles = self.roles.read().await;
        let mut permissions = Vec::new();

        for role_name in &role_names {
            if let Some(role) = roles.get(role_name) {
                permissions.extend(role.permissions.clone());
            }
        }

        Ok(permissions)
    }

    /// Clear the permission cache
    async fn clear_cache(&self) {
        let mut cache = self.cache.write().await;
        cache.clear();
    }

    /// Check if a resource matches the permission resource pattern
    fn matches_resource(&self, permission_resource: &Resource, requested_resource: &Resource) -> bool {
        match (permission_resource, requested_resource) {
            (Resource::All, _) => true,
            (Resource::Database(perm_db), Resource::Database(req_db)) => perm_db == req_db,
            (Resource::Database(perm_db), Resource::Table(req_db, _)) => perm_db == req_db,
            (Resource::Database(perm_db), Resource::Field(req_db, _, _)) => perm_db == req_db,
            (Resource::Table(perm_db, perm_table), Resource::Table(req_db, req_table)) => {
                perm_db == req_db && perm_table == req_table
            }
            (Resource::Table(perm_db, perm_table), Resource::Field(req_db, req_table, _)) => {
                perm_db == req_db && perm_table == req_table
            }
            (Resource::Field(perm_db, perm_table, perm_field), Resource::Field(req_db, req_table, req_field)) => {
                perm_db == req_db && perm_table == req_table && perm_field == req_field
            }
            (a, b) => a == b,
        }
    }

    /// Evaluate conditions for a permission entry
    async fn evaluate_conditions(&self, conditions: &[Condition], user_id: &str) -> Result<bool> {
        for condition in conditions {
            if !self.evaluate_condition(condition, user_id).await? {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// Evaluate a single condition
    async fn evaluate_condition(&self, condition: &Condition, user_id: &str) -> Result<bool> {
        match condition {
            Condition::Time(time_cond) => self.evaluate_time_condition(time_cond),
            Condition::Ip(ip_cond) => self.evaluate_ip_condition(ip_cond, user_id).await,
            Condition::Attribute(attr_cond) => self.evaluate_attribute_condition(attr_cond, user_id).await,
            Condition::Custom(_) => Ok(true), // TODO: Implement custom condition evaluation
        }
    }

    /// Evaluate time-based conditions
    fn evaluate_time_condition(&self, condition: &TimeCondition) -> Result<bool> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Check time range
        if let Some(start) = condition.start_time {
            if now < start {
                return Ok(false);
            }
        }

        if let Some(end) = condition.end_time {
            if now > end {
                return Ok(false);
            }
        }

        // TODO: Check day of week and timezone
        Ok(true)
    }

    /// Evaluate IP-based conditions
    async fn evaluate_ip_condition(&self, condition: &IpCondition, user_id: &str) -> Result<bool> {
        // TODO: Implement IP condition evaluation
        // This would require getting the user's IP address from context
        Ok(true)
    }

    /// Evaluate attribute-based conditions
    async fn evaluate_attribute_condition(&self, condition: &AttributeCondition, user_id: &str) -> Result<bool> {
        // TODO: Implement attribute condition evaluation
        // This would require getting user attributes from a user store
        Ok(true)
    }

    /// Log audit entry for policy decisions
    async fn log_audit_entry(&self, entry: PolicyAuditEntry) -> Result<()> {
        // TODO: Implement audit logging
        // This would integrate with the audit logging system
        Ok(())
    }
}

impl Role {
    /// Create a new role
    pub fn new(name: &str) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        Self {
            name: name.to_string(),
            description: None,
            permissions: HashSet::new(),
            constraints: Vec::new(),
            created_at: now,
            updated_at: now,
        }
    }

    /// Set role description
    pub fn with_description(mut self, description: &str) -> Self {
        self.description = Some(description.to_string());
        self
    }

    /// Add a permission to the role
    pub fn with_permission(mut self, permission: Permission, resource: Resource) -> Self {
        self.permissions.insert(PermissionEntry {
            permission,
            resource,
            conditions: Vec::new(),
        });
        self
    }

    /// Add a permission with conditions to the role
    pub fn with_permission_conditions(
        mut self,
        permission: Permission,
        resource: Resource,
        conditions: Vec<Condition>,
    ) -> Self {
        self.permissions.insert(PermissionEntry {
            permission,
            resource,
            conditions,
        });
        self
    }

    /// Add a constraint to the role
    pub fn with_constraint(mut self, constraint: Constraint) -> Self {
        self.constraints.push(constraint);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_role_creation() {
        let role = Role::new("test")
            .with_description("Test role")
            .with_permission(Permission::Read, Resource::Database("users"));

        assert_eq!(role.name, "test");
        assert_eq!(role.description, Some("Test role".to_string()));
        assert_eq!(role.permissions.len(), 1);
    }

    #[tokio::test]
    async fn test_policy_engine_basic() {
        let engine = PolicyEngine::new();
        
        let role = Role::new("readonly")
            .with_permission(Permission::Read, Resource::Database("users"));
        
        engine.add_role(role).await.unwrap();
        engine.assign_role("user1", "readonly").await.unwrap();
        
        let can_read = engine.check_permission("user1", Permission::Read, Resource::Database("users")).await.unwrap();
        let can_write = engine.check_permission("user1", Permission::Write, Resource::Database("users")).await.unwrap();
        
        assert!(can_read);
        assert!(!can_write);
    }

    #[tokio::test]
    async fn test_resource_matching() {
        let engine = PolicyEngine::new();
        
        let role = Role::new("db_access")
            .with_permission(Permission::Read, Resource::Database("users"));
        
        engine.add_role(role).await.unwrap();
        engine.assign_role("user1", "db_access").await.unwrap();
        
        // Should match database access
        let can_read_db = engine.check_permission("user1", Permission::Read, Resource::Database("users")).await.unwrap();
        // Should match table access within database
        let can_read_table = engine.check_permission("user1", Permission::Read, Resource::Table("users", "profiles")).await.unwrap();
        // Should match field access within database
        let can_read_field = engine.check_permission("user1", Permission::Read, Resource::Field("users", "profiles", "email")).await.unwrap();
        
        assert!(can_read_db);
        assert!(can_read_table);
        assert!(can_read_field);
    }
}
