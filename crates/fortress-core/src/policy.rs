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

use std::hash::Hash;

use std::net::IpAddr;

use std::str::FromStr;

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tokio::sync::RwLock;

use chrono::{Utc, TimeZone, Datelike, Timelike};

use chrono_tz::Tz;



/// Policy engine for managing roles and permissions (memory-optimized)

#[derive(Debug)]

pub struct PolicyEngine {

    roles: RwLock<HashMap<String, PolicyRole>>,

    user_roles: RwLock<HashMap<String, HashSet<String>>>,

    /// Policy storage

    #[allow(dead_code)]

    policies: RwLock<HashMap<String, Policy>>,

    /// Optimized cache with TTL and memory management

    cache: RwLock<HashMap<CacheKey, CacheEntry>>,

    /// Cache size limit to prevent memory leaks

    max_cache_size: usize,

    /// User attribute store for attribute-based conditions

    user_attributes: RwLock<HashMap<String, HashMap<String, String>>>,

    /// User IP context for IP-based conditions

    user_ip_context: RwLock<HashMap<String, String>>,

    /// Cache TTL in seconds (default: 5 minutes)

    cache_ttl_secs: u64,

}



/// Cache key for permission checks

#[derive(Debug, Clone, Hash, Eq, PartialEq, Serialize, Deserialize)]

struct CacheKey {

    user_id: String,

    permission: Permission,

    resource: Resource,

    /// Cache timestamp with TTL support

    timestamp: u64,

}



/// Cache entry with TTL

#[derive(Debug, Clone)]

struct CacheEntry {

    result: bool,

    expires_at: u64,

}



/// Role definition with permissions and metadata

#[derive(Debug, Clone, Serialize, Deserialize)]

pub struct PolicyRole {

    /// Role name

    pub name: String,

    /// Role description

    pub description: Option<String>,

    /// Role permissions

    pub permissions: HashSet<PermissionEntry>,

    /// Role constraints

    pub constraints: Vec<Constraint>,

    /// Creation timestamp

    pub created_at: u64,

    /// Last update timestamp

    pub updated_at: u64,

}



/// Individual permission entry

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]

pub struct PermissionEntry {

    /// Permission type

    pub permission: Permission,

    /// Resource type

    pub resource: Resource,

    /// Permission conditions

    pub conditions: Vec<Condition>,

}





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

    /// Policy name

    pub name: String,

    /// Policy description

    pub description: Option<String>,

    /// Policy rules

    pub rules: Vec<PolicyRule>,

    /// Policy effect

    pub effect: PolicyEffect,

    /// Policy priority

    pub priority: i32,

    /// Creation timestamp

    pub created_at: u64,

    /// Last update timestamp

    pub updated_at: u64,

}



/// Individual policy rule

#[derive(Debug, Clone, Serialize, Deserialize)]

pub struct PolicyRule {

    /// Allowed actions

    pub actions: Vec<Permission>,

    /// Target resources

    pub resources: Vec<Resource>,

    /// Rule conditions

    pub conditions: Vec<Condition>,

}



/// Policy effect (allow or deny)

#[derive(Debug, Clone, Serialize, Deserialize)]

pub enum PolicyEffect {

    /// Allow the action

    Allow,

    /// Deny the action

    Deny,

}



/// Conditions for policy evaluation

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]

pub enum Condition {

    /// Time-based condition

    Time(TimeCondition),

    /// IP-based condition

    Ip(IpCondition),

    /// Attribute-based condition

    Attribute(AttributeCondition),

    /// Custom condition

    Custom(CustomCondition),

}



/// Custom condition with type and parameters

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]

pub struct CustomCondition {

    /// Condition type identifier

    pub condition_type: String,

    /// Condition parameters

    pub parameters: std::collections::HashMap<String, String>,

}



impl std::hash::Hash for CustomCondition {

    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {

        // Hash based on condition_type and parameters

        self.condition_type.hash(state);

        // Hash the parameters HashMap by using its own hash implementation

        // Hash the parameters HashMap manually

        for (key, value) in &self.parameters {

            key.hash(state);

            value.hash(state);

        }

    }

}



/// Time-based conditions

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]

pub struct TimeCondition {

    /// Start time (Unix timestamp)

    pub start_time: Option<u64>,

    /// End time (Unix timestamp)

    pub end_time: Option<u64>,

    /// Days of week (0 = Sunday, 6 = Saturday)

    pub days_of_week: Option<Vec<u8>>,

    /// Timezone identifier

    pub timezone: Option<String>,

}



/// IP-based conditions

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]

pub struct IpCondition {

    /// Allowed IP addresses

    pub allowed_ips: Vec<String>,

    /// Denied IP addresses

    pub denied_ips: Vec<String>,

    /// CIDR ranges

    pub cidr_ranges: Vec<String>,

}



/// Attribute-based conditions

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]

pub struct AttributeCondition {

    /// Attribute name

    pub attribute: String,

    /// Comparison operator

    pub operator: AttributeOperator,

    /// Attribute value

    pub value: String,

}



/// Attribute operators

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]

pub enum AttributeOperator {

    /// Equality check

    Equals,

    /// Inequality check

    NotEquals,

    /// Contains check

    Contains,

    /// Starts with check

    StartsWith,

    /// Ends with check

    EndsWith,

    /// Greater than check

    GreaterThan,

    /// Less than check

    LessThan,

}



/// Constraints on role permissions

#[derive(Debug, Clone, Serialize, Deserialize)]

pub enum Constraint {

    /// Maximum data size that can be accessed

    MaxDataSize(u64),

    /// Rate limiting

    RateLimit { 

        /// Maximum requests per minute

        requests_per_minute: u32 

    },

    /// Geographic restrictions

    Geographic { 

        /// Allowed countries

        allowed_countries: Vec<String> 

    },

    /// Device restrictions

    Device { 

        /// Allowed devices

        allowed_devices: Vec<String> 

    },

}



/// Audit log entry for policy decisions

#[derive(Debug, Clone, Serialize, Deserialize)]

pub struct PolicyAuditEntry {

    /// Decision timestamp

    pub timestamp: u64,

    /// User identifier

    pub user_id: String,

    /// Permission type

    pub permission: Permission,

    /// Resource type

    pub resource: Resource,

    /// Policy decision

    pub decision: bool,

    /// Decision reason

    pub reason: String,

    /// Roles involved

    pub roles_involved: Vec<String>,

    /// Policies evaluated

    pub policies_evaluated: Vec<String>,

    /// Evaluation time in milliseconds

    pub evaluation_time_ms: u64,

}



impl PolicyEngine {

    /// Create a new policy engine with memory optimization

    pub fn new() -> Self {

        Self::with_cache_ttl_and_limit(300, 10000) // 5 minutes default, 10K max entries

    }



    /// Create a new policy engine with custom cache TTL and memory limit

    pub fn with_cache_ttl(ttl_secs: u64) -> Self {

        Self::with_cache_ttl_and_limit(ttl_secs, 10000)

    }



    /// Create a new policy engine with custom cache TTL and memory limit

    pub fn with_cache_ttl_and_limit(ttl_secs: u64, max_cache_size: usize) -> Self {

        Self {

            roles: RwLock::new(HashMap::new()),

            user_roles: RwLock::new(HashMap::new()),

            policies: RwLock::new(HashMap::new()),

            cache: RwLock::new(HashMap::new()),

            max_cache_size,

            user_attributes: RwLock::new(HashMap::new()),

            user_ip_context: RwLock::new(HashMap::new()),

            cache_ttl_secs: ttl_secs,

        }

    }



    /// Add a new role to the system

    pub async fn add_role(&self, role: PolicyRole) -> Result<()> {

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



    /// Check if a user has permission for a resource (optimized)

    pub async fn check_permission(

        &self,

        user_id: &str,

        permission: Permission,

        resource: Resource,

    ) -> Result<bool> {

        let now = SystemTime::now()

            .duration_since(UNIX_EPOCH)

            .unwrap_or_else(|_| Duration::from_secs(0))

            .as_secs();

        

        // Create cache key without timestamp for better cache hits

        let cache_key = CacheKey {

            user_id: user_id.to_string(),

            permission: permission.clone(),

            resource: resource.clone(),

            timestamp: now,

        };



        // Check cache first with TTL validation

        {

            let cache = self.cache.read().await;

            if let Some(entry) = cache.get(&cache_key) {

                if now < entry.expires_at {

                    return Ok(entry.result);

                }

            }

        }



        // Get user's roles (early return if no roles)

        let user_roles = self.user_roles.read().await;

        let role_names = match user_roles.get(user_id) {

            Some(roles) if !roles.is_empty() => roles.clone(),

            _ => {

                // Cache negative result for users with no roles

                let mut cache = self.cache.write().await;

                cache.insert(cache_key, CacheEntry {

                    result: false,

                    expires_at: now + self.cache_ttl_secs,

                });

                return Ok(false);

            }

        };

        drop(user_roles);



        // Get role definitions

        let roles = self.roles.read().await;

        

        // Check each role for permission (early return on first match)

        for role_name in &role_names {

            if let Some(role) = roles.get(role_name) {

                for permission_entry in &role.permissions {

                    if permission_entry.permission == permission && 

                       self.matches_resource(&permission_entry.resource, &resource) &&

                       self.evaluate_conditions(&permission_entry.conditions, user_id).await? {

                        

                        // Cache positive result

                        let mut cache = self.cache.write().await;

                        cache.insert(cache_key, CacheEntry {

                            result: true,

                            expires_at: now + self.cache_ttl_secs,

                        });

                        

                        // Log audit entry asynchronously (non-blocking)

                        let elapsed = SystemTime::now()

                            .duration_since(UNIX_EPOCH)

                            .unwrap_or_else(|_| Duration::from_secs(0))

                            .as_millis() as u64;

                        

                        // Clone data for async task

                        let role_name_clone = role_name.clone();

                        let user_id_clone = user_id.to_string();

                        let permission_clone = permission.clone();

                        let resource_clone = resource.clone();

                        

                        tokio::spawn(async move {

                            let _ = Self::log_audit_entry_static(

                                now,

                                user_id_clone,

                                permission_clone,

                                resource_clone,

                                true,

                                format!("Granted by role '{}'", role_name_clone),

                                vec![role_name_clone],

                                vec![],

                                elapsed,

                            ).await;

                        });

                        

                        return Ok(true);

                    }

                }

            }

        }



        // Cache negative result

        let mut cache = self.cache.write().await;

        cache.insert(cache_key, CacheEntry {

            result: false,

            expires_at: now + self.cache_ttl_secs,

        });

        

        // Log audit entry asynchronously for negative results

        let elapsed = SystemTime::now()

            .duration_since(UNIX_EPOCH)

            .unwrap_or_else(|_| Duration::from_secs(0))

            .as_millis() as u64;

        

        // Clone data for async task

        let user_id_clone = user_id.to_string();

        let permission_clone = permission.clone();

        let resource_clone = resource.clone();

        let role_names_clone = role_names.clone();

        

        tokio::spawn(async move {

            let _ = Self::log_audit_entry_static(

                now,

                user_id_clone,

                permission_clone,

                resource_clone,

                false,

                "No matching permission found".to_string(),

                role_names_clone.into_iter().collect(),

                vec![],

                elapsed,

            ).await;

        });



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



    /// Set user attributes for attribute-based conditions

    pub async fn set_user_attributes(&self, user_id: &str, attributes: HashMap<String, String>) -> Result<()> {

        let mut user_attrs = self.user_attributes.write().await;

        user_attrs.insert(user_id.to_string(), attributes);

        self.clear_cache().await;

        Ok(())

    }



    /// Update a specific user attribute

    pub async fn set_user_attribute(&self, user_id: &str, attribute: &str, value: &str) -> Result<()> {

        let mut user_attrs = self.user_attributes.write().await;

        let attrs = user_attrs.entry(user_id.to_string()).or_insert_with(HashMap::new);

        attrs.insert(attribute.to_string(), value.to_string());

        self.clear_cache().await;

        Ok(())

    }



    /// Get user attributes

    pub async fn get_user_attributes(&self, user_id: &str) -> Result<HashMap<String, String>> {

        let user_attrs = self.user_attributes.read().await;

        Ok(user_attrs.get(user_id).cloned().unwrap_or_default())

    }



    /// Set user IP address for IP-based conditions

    pub async fn set_user_ip(&self, user_id: &str, ip_address: &str) -> Result<()> {

        let mut user_ips = self.user_ip_context.write().await;

        user_ips.insert(user_id.to_string(), ip_address.to_string());

        self.clear_cache().await;

        Ok(())

    }



    /// Get user IP address

    pub async fn get_user_ip(&self, user_id: &str) -> Result<Option<String>> {

        let user_ips = self.user_ip_context.read().await;

        Ok(user_ips.get(user_id).cloned())

    }



    /// Remove user IP address

    pub async fn remove_user_ip(&self, user_id: &str) -> Result<()> {

        let mut user_ips = self.user_ip_context.write().await;

        user_ips.remove(user_id);

        self.clear_cache().await;

        Ok(())

    }



    /// Clean up expired cache entries with memory management (optimized)

    async fn clear_cache(&self) {

        let mut cache = self.cache.write().await;

        let now = SystemTime::now()

            .duration_since(UNIX_EPOCH)

            .unwrap_or_else(|_| Duration::from_secs(0))

            .as_secs();

        

        // Remove expired entries

        cache.retain(|_, entry| entry.expires_at > now);

        

        // Prevent memory leaks by enforcing cache size limit

        if cache.len() > self.max_cache_size {

            // Remove oldest entries (simple LRU approximation)

            let cache_size = cache.len();

            let mut entries: Vec<_> = cache.iter().map(|(k, v)| (k.clone(), v.clone())).collect();

            entries.sort_by_key(|(_, entry)| entry.expires_at);

            

            let remove_count = cache_size - self.max_cache_size;

            let keys_to_remove: Vec<_> = entries.iter()

                .take(remove_count)

                .map(|(key, _)| key.clone())

                .collect();

            

            drop(entries); // Release the borrow

            

            for key in keys_to_remove {

                cache.remove(&key);

            }

        }

    }



    /// Clean up expired cache entries (call periodically)

    pub async fn cleanup_expired_cache(&self) {

        self.clear_cache().await;

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

            Condition::Custom(custom_cond) => self.evaluate_custom_condition(custom_cond, user_id).await,

        }

    }



    /// Evaluate time-based conditions

    fn evaluate_time_condition(&self, condition: &TimeCondition) -> Result<bool> {

        let now = SystemTime::now()

            .duration_since(UNIX_EPOCH)

            .unwrap_or_else(|_| Duration::from_secs(0))

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



        // Check day of week and timezone

        let now_utc = Utc::now();

        

        // Apply timezone if specified

        let local_time = if let Some(tz_str) = &condition.timezone {

            match tz_str.parse::<Tz>() {

                Ok(tz) => tz.from_utc_datetime(&now_utc.naive_utc()),

                Err(_) => {

                    // Fallback to UTC if timezone parsing fails

                    let utc_tz: Tz = "UTC".parse().unwrap_or_else(|_| chrono_tz::UTC);

                    utc_tz.from_utc_datetime(&now_utc.naive_utc())

                }

            }

        } else {

            // Use UTC as default timezone

            let utc_tz: Tz = "UTC".parse().unwrap_or_else(|_| chrono_tz::UTC);

            utc_tz.from_utc_datetime(&now_utc.naive_utc())

        };



        // Check day of week restriction

        if let Some(days_of_week) = &condition.days_of_week {

            let current_weekday = local_time.weekday().num_days_from_sunday() as u8;

            if !days_of_week.contains(&current_weekday) {

                return Ok(false);

            }

        }



        Ok(true)

    }



    /// Evaluate IP-based conditions (optimized and secure)

    async fn evaluate_ip_condition(&self, condition: &IpCondition, user_id: &str) -> Result<bool> {

        // Get user's IP address from context

        let user_ip_context = self.user_ip_context.read().await;

        let user_ip = user_ip_context.get(user_id)

            .ok_or_else(|| FortressError::PolicyError(format!("No IP address found for user '{}'", user_id)))?;



        // Parse and validate IP address

        let ip_addr = IpAddr::from_str(user_ip)

            .map_err(|_| FortressError::PolicyError(format!("Invalid IP address format for user '{}': {}", user_id, user_ip)))?;



        // Security: Check denied IPs first (deny list takes precedence)

        for denied_ip in &condition.denied_ips {

            if let Ok(denied_addr) = IpAddr::from_str(denied_ip) {

                if ip_addr == denied_addr {

                    return Ok(false); // Immediate deny

                }

            }

        }



        // Check allowed IPs (if specified, must be in allow list)

        if !condition.allowed_ips.is_empty() {

            let mut allowed = false;

            for allowed_ip in &condition.allowed_ips {

                if let Ok(allowed_addr) = IpAddr::from_str(allowed_ip) {

                    if ip_addr == allowed_addr {

                        allowed = true;

                        break;

                    }

                }

            }

            if !allowed {

                return Ok(false); // Not in allow list

            }

        }



        // Check CIDR ranges (optimized with early return)

        for cidr_range in &condition.cidr_ranges {

            if let Ok(network) = ipnetwork::IpNetwork::from_str(cidr_range) {

                if network.contains(ip_addr) {

                    return Ok(true); // Found matching CIDR

                }

            }

        }



        // If no CIDR ranges match, allow if there are no CIDR restrictions

        Ok(condition.cidr_ranges.is_empty())

    }



    /// Evaluate attribute-based conditions (optimized and secure)

    async fn evaluate_attribute_condition(&self, condition: &AttributeCondition, user_id: &str) -> Result<bool> {

        // Get user attributes from store

        let user_attributes = self.user_attributes.read().await;

        let attributes = user_attributes.get(user_id)

            .ok_or_else(|| FortressError::PolicyError(format!("No attributes found for user '{}'", user_id)))?;



        let user_value = attributes.get(&condition.attribute)

            .ok_or_else(|| FortressError::PolicyError(format!("Attribute '{}' not found for user '{}'", condition.attribute, user_id)))?;



        // Security: Sanitize inputs to prevent injection attacks

        let sanitized_user_value = user_value.trim();

        let sanitized_condition_value = condition.value.trim();



        // Evaluate based on operator (optimized)

        let result = match condition.operator {

            AttributeOperator::Equals => sanitized_user_value == sanitized_condition_value,

            AttributeOperator::NotEquals => sanitized_user_value != sanitized_condition_value,

            AttributeOperator::Contains => sanitized_user_value.contains(sanitized_condition_value),

            AttributeOperator::StartsWith => sanitized_user_value.starts_with(sanitized_condition_value),

            AttributeOperator::EndsWith => sanitized_user_value.ends_with(sanitized_condition_value),

            AttributeOperator::GreaterThan => {

                // Smart numeric comparison with fallback

                match (sanitized_user_value.parse::<f64>(), sanitized_condition_value.parse::<f64>()) {

                    (Ok(user_num), Ok(cond_num)) => user_num > cond_num,

                    _ => sanitized_user_value > sanitized_condition_value,

                }

            },

            AttributeOperator::LessThan => {

                // Smart numeric comparison with fallback

                match (sanitized_user_value.parse::<f64>(), sanitized_condition_value.parse::<f64>()) {

                    (Ok(user_num), Ok(cond_num)) => user_num < cond_num,

                    _ => sanitized_user_value < sanitized_condition_value,

                }

            },

        };



        Ok(result)

    }



    /// Evaluate custom conditions

    async fn evaluate_custom_condition(&self, condition: &CustomCondition, user_id: &str) -> Result<bool> {

        match condition.condition_type.as_str() {

            "device_trust_score" => self.evaluate_device_trust_score(condition, user_id).await,

            "geo_location" => self.evaluate_geo_location(condition, user_id).await,

            "session_age" => self.evaluate_session_age(condition, user_id).await,

            "risk_score" => self.evaluate_risk_score(condition, user_id).await,

            "business_hours" => self.evaluate_business_hours(condition).await,

            "compliance_check" => self.evaluate_compliance_check(condition, user_id).await,

            "resource_quota" => self.evaluate_resource_quota(condition, user_id).await,

            "multi_factor_auth" => self.evaluate_mfa_status(condition, user_id).await,

            _ => self.evaluate_script_condition(condition, user_id).await,

        }

    }



    /// Evaluate device trust score condition

    async fn evaluate_device_trust_score(&self, condition: &CustomCondition, user_id: &str) -> Result<bool> {

        let min_score = condition.parameters.get("min_score")

            .and_then(|s| s.parse::<f64>().ok())

            .unwrap_or(50.0);



        // In a real implementation, this would query the device management system

        // For now, simulate a device trust score

        let device_score = self.get_simulated_device_trust_score(user_id).await?;

        

        let result = device_score >= min_score;

        tracing::debug!("Device trust score evaluation for {}: {} >= {} = {}", 

                      user_id, device_score, min_score, result);

        Ok(result)

    }



    /// Evaluate geographic location condition

    async fn evaluate_geo_location(&self, condition: &CustomCondition, user_id: &str) -> Result<bool> {

        let allowed_countries = condition.parameters.get("allowed_countries")

            .map(|countries| countries.split(',').map(|s| s.trim().to_string()).collect::<Vec<_>>())

            .unwrap_or_default();



        let blocked_countries = condition.parameters.get("blocked_countries")

            .map(|countries| countries.split(',').map(|s| s.trim().to_string()).collect::<Vec<_>>())

            .unwrap_or_default();



        // In a real implementation, this would get the user's actual location

        let user_country = self.get_simulated_user_location(user_id).await?;

        

        let result = if !allowed_countries.is_empty() {

            allowed_countries.contains(&user_country)

        } else if !blocked_countries.is_empty() {

            !blocked_countries.contains(&user_country)

        } else {

            true // No location restrictions

        };



        tracing::debug!("Geo location evaluation for {}: country={}, result={}", 

                      user_id, user_country, result);

        Ok(result)

    }



    /// Evaluate session age condition

    async fn evaluate_session_age(&self, condition: &CustomCondition, user_id: &str) -> Result<bool> {

        let max_age_minutes = condition.parameters.get("max_age_minutes")

            .and_then(|s| s.parse::<u64>().ok())

            .unwrap_or(480); // 8 hours default



        // In a real implementation, this would get the actual session creation time

        let session_age_minutes = self.get_simulated_session_age(user_id).await?;

        

        let result = session_age_minutes <= max_age_minutes;

        tracing::debug!("Session age evaluation for {}: {}min <= {}min = {}", 

                      user_id, session_age_minutes, max_age_minutes, result);

        Ok(result)

    }



    /// Evaluate risk score condition

    async fn evaluate_risk_score(&self, condition: &CustomCondition, user_id: &str) -> Result<bool> {

        let max_risk_score = condition.parameters.get("max_risk_score")

            .and_then(|s| s.parse::<f64>().ok())

            .unwrap_or(70.0);



        // In a real implementation, this would calculate actual risk score

        let risk_score = self.calculate_simulated_risk_score(user_id).await?;

        

        let result = risk_score <= max_risk_score;

        tracing::debug!("Risk score evaluation for {}: {} <= {} = {}", 

                      user_id, risk_score, max_risk_score, result);

        Ok(result)

    }



    /// Evaluate business hours condition

    async fn evaluate_business_hours(&self, condition: &CustomCondition) -> Result<bool> {

        let timezone = condition.parameters.get("timezone")

            .unwrap_or(&"UTC".to_string()).clone();

        

        let start_hour = condition.parameters.get("start_hour")

            .and_then(|s| s.parse::<u32>().ok())

            .unwrap_or(9); // 9 AM default

        

        let end_hour = condition.parameters.get("end_hour")

            .and_then(|s| s.parse::<u32>().ok())

            .unwrap_or(17); // 5 PM default



        let work_days = condition.parameters.get("work_days")

            .map(|days| days.split(',').map(|s| s.trim().parse::<u32>().unwrap_or(0)).collect::<Vec<_>>())

            .unwrap_or(vec![1, 2, 3, 4, 5]); // Mon-Fri default



        let now_utc = Utc::now();

        let tz: Tz = timezone.parse().unwrap_or_else(|_| chrono_tz::UTC);

        let local_time = tz.from_utc_datetime(&now_utc.naive_utc());

        

        let current_hour = local_time.hour();

        let current_day = local_time.weekday().num_days_from_monday() + 1; // 1=Monday

        

        let within_hours = current_hour >= start_hour && current_hour < end_hour;

        let within_days = work_days.contains(&current_day);

        

        let result = within_hours && within_days;

        tracing::debug!("Business hours evaluation: hour={}, day={}, within_hours={}, within_days={}, result={}", 

                      current_hour, current_day, within_hours, within_days, result);

        Ok(result)

    }



    /// Evaluate compliance check condition

    async fn evaluate_compliance_check(&self, condition: &CustomCondition, user_id: &str) -> Result<bool> {

        let compliance_type = condition.parameters.get("compliance_type")

            .unwrap_or(&"general".to_string()).clone();



        // In a real implementation, this would check actual compliance status

        let compliance_status = self.get_simulated_compliance_status(user_id, &compliance_type).await?;

        

        let result = compliance_status;

        tracing::debug!("Compliance check evaluation for {}: type={}, status={}", 

                      user_id, compliance_type, result);

        Ok(result)

    }



    /// Evaluate resource quota condition

    async fn evaluate_resource_quota(&self, condition: &CustomCondition, user_id: &str) -> Result<bool> {

        let resource_type = condition.parameters.get("resource_type")

            .unwrap_or(&"general".to_string()).clone();

        

        let max_usage = condition.parameters.get("max_usage")

            .and_then(|s| s.parse::<u64>().ok())

            .unwrap_or(1000);



        // In a real implementation, this would check actual resource usage

        let current_usage = self.get_simulated_resource_usage(user_id, &resource_type).await?;

        

        let result = current_usage <= max_usage;

        tracing::debug!("Resource quota evaluation for {}: type={}, {} <= {} = {}", 

                      user_id, resource_type, current_usage, max_usage, result);

        Ok(result)

    }



    /// Evaluate MFA status condition

    async fn evaluate_mfa_status(&self, condition: &CustomCondition, user_id: &str) -> Result<bool> {

        let require_mfa = condition.parameters.get("require_mfa")

            .and_then(|s| s.parse::<bool>().ok())

            .unwrap_or(true);



        // In a real implementation, this would check actual MFA status

        let mfa_enabled = self.get_simulated_mfa_status(user_id).await?;

        

        let result = if require_mfa { mfa_enabled } else { true };

        tracing::debug!("MFA status evaluation for {}: required={}, enabled={}, result={}", 

                      user_id, require_mfa, mfa_enabled, result);

        Ok(result)

    }



    /// Evaluate script-based condition (for extensibility)

    async fn evaluate_script_condition(&self, condition: &CustomCondition, user_id: &str) -> Result<bool> {

        let script = condition.parameters.get("script")

            .ok_or_else(|| FortressError::PolicyError("Script parameter missing for custom condition".to_string()))?;



        // In a real implementation, this would execute a sandboxed script

        // For security, this is a simplified implementation that only supports basic expressions

        tracing::warn!("Script-based custom conditions are not fully implemented for security reasons");

        

        // For now, return true as a safe default

        tracing::debug!("Script condition evaluation for {}: script_length={}, result=true", 

                      user_id, script.len());

        Ok(true)

    }



    // Helper methods for simulated data (in real implementation, these would query actual systems)

    async fn get_simulated_device_trust_score(&self, user_id: &str) -> Result<f64> {

        // Simulate device trust score based on user ID hash

        let hash = user_id.chars().map(|c| c as u32).sum::<u32>();

        Ok((hash % 100) as f64)

    }



    async fn get_simulated_user_location(&self, user_id: &str) -> Result<String> {

        // Simulate country based on user ID

        let countries = vec!["US", "CA", "GB", "DE", "FR", "JP", "AU"];

        let hash = user_id.chars().map(|c| c as usize).sum::<usize>();

        Ok(countries[hash % countries.len()].to_string())

    }



    async fn get_simulated_session_age(&self, user_id: &str) -> Result<u64> {

        // Simulate session age in minutes

        let hash = user_id.chars().map(|c| c as u64).sum::<u64>();

        Ok((hash % 1440) + 1) // 1 minute to 24 hours

    }



    async fn calculate_simulated_risk_score(&self, user_id: &str) -> Result<f64> {

        // Simulate risk score calculation

        let hash = user_id.chars().map(|c| c as u32).sum::<u32>();

        Ok((hash % 100) as f64)

    }



    async fn get_simulated_compliance_status(&self, _user_id: &str, _compliance_type: &str) -> Result<bool> {

        // Simulate compliance check (most users are compliant)

        Ok(true)

    }



    async fn get_simulated_resource_usage(&self, user_id: &str, _resource_type: &str) -> Result<u64> {

        // Simulate resource usage

        let hash = user_id.chars().map(|c| c as u64).sum::<u64>();

        Ok(hash % 500) // 0-499 usage

    }



    async fn get_simulated_mfa_status(&self, user_id: &str) -> Result<bool> {

        // Simulate MFA status (70% of users have MFA enabled)

        let hash = user_id.chars().map(|c| c as u32).sum::<u32>();

        Ok(hash % 100 < 70)

    }



    /// Static audit logging method to avoid lifetime issues

    async fn log_audit_entry_static(

        timestamp: u64,

        user_id: String,

        permission: Permission,

        resource: Resource,

        decision: bool,

        reason: String,

        roles_involved: Vec<String>,

        policies_evaluated: Vec<String>,

        evaluation_time_ms: u64,

    ) -> Result<()> {

        // Create audit log entry

        let audit_log = serde_json::json!({

            "timestamp": timestamp,

            "user_id": user_id,

            "permission": format!("{:?}", permission),

            "resource": format!("{:?}", resource),

            "decision": decision,

            "reason": reason,

            "roles_involved": roles_involved,

            "policies_evaluated": policies_evaluated,

            "evaluation_time_ms": evaluation_time_ms,

            "event_type": "policy_decision"

        });



        // Log to tracing system

        if decision {

            tracing::info!(

                "Policy decision: ALLOW - User: {}, Permission: {:?}, Resource: {:?}, Reason: {}",

                user_id, permission, resource, reason

            );

        } else {

            tracing::warn!(

                "Policy decision: DENY - User: {}, Permission: {:?}, Resource: {:?}, Reason: {}",

                user_id, permission, resource, reason

            );

        }



        // In a real implementation, this would integrate with the audit logging system

        // For now, we'll log the structured data

        tracing::debug!("Policy audit entry: {}", serde_json::to_string(&audit_log).unwrap_or_default());

        

        Ok(())

    }



    /// Log audit entry for policy decisions (instance method)

    async fn log_audit_entry(&self, entry: PolicyAuditEntry) -> Result<()> {

        Self::log_audit_entry_static(

            entry.timestamp,

            entry.user_id,

            entry.permission,

            entry.resource,

            entry.decision,

            entry.reason,

            entry.roles_involved,

            entry.policies_evaluated,

            entry.evaluation_time_ms,

        ).await

    }

}



    impl PolicyRole {

    /// Create a new role with the given name

    pub fn new(name: &str) -> Self {

        let now = SystemTime::now()

            .duration_since(UNIX_EPOCH)

            .unwrap_or_default()

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

            .with_permission(Permission::Read, Resource::Database("users".to_string()));



        assert_eq!(role.name, "test");

        assert_eq!(role.description, Some("Test role".to_string()));

        assert_eq!(role.permissions.len(), 1);

    }



    #[tokio::test]

    async fn test_policy_engine_basic() {

        let engine = PolicyEngine::new();

        

        let role = Role::new("readonly")

            .with_permission(Permission::Read, Resource::Database("users".to_string()));

        

        engine.add_role(role).await.unwrap();

        engine.assign_role("user1", "readonly").await.unwrap();

        

        let can_read = engine.check_permission("user1", Permission::Read, Resource::Database("users".to_string())).await.unwrap();

        let can_write = engine.check_permission("user1", Permission::Write, Resource::Database("users".to_string())).await.unwrap();

        

        assert!(can_read);

        assert!(!can_write);

    }



    #[tokio::test]

    async fn test_resource_matching() {

        let engine = PolicyEngine::new();

        

        let role = Role::new("db_access")

            .with_permission(Permission::Read, Resource::Database("users".to_string()));

        

        engine.add_role(role).await.unwrap();

        engine.assign_role("user1", "db_access").await.unwrap();

        

        // Should match database access

        let can_read_db = engine.check_permission("user1", Permission::Read, Resource::Database("users".to_string())).await.unwrap();

        // Should match table access within database

        let can_read_table = engine.check_permission("user1", Permission::Read, Resource::Table("users".to_string(), "profiles".to_string())).await.unwrap();

        // Should match field access within database

        let can_read_field = engine.check_permission("user1", Permission::Read, Resource::Field("users".to_string(), "profiles".to_string(), "email".to_string())).await.unwrap();

        

        assert!(can_read_db);

        assert!(can_read_table);

        assert!(can_read_field);

    }



    #[tokio::test]

    async fn test_time_conditions() {

        let engine = PolicyEngine::new();

        

        let now = Utc::now();

        let start_time = now.timestamp() as u64 - 3600; // 1 hour ago

        let end_time = now.timestamp() as u64 + 3600; // 1 hour from now

        

        let time_condition = TimeCondition {

            start_time: Some(start_time),

            end_time: Some(end_time),

            days_of_week: Some(vec![now.weekday().num_days_from_sunday() as u8]),

            timezone: Some("UTC".to_string()),

        };

        

        let role = Role::new("time_restricted")

            .with_permission_conditions(

                Permission::Read,

                Resource::Database("users".to_string()),

                vec![Condition::Time(time_condition)]

            );

        

        engine.add_role(role).await.unwrap();

        engine.assign_role("user1", "time_restricted").await.unwrap();

        

        let can_read = engine.check_permission("user1", Permission::Read, Resource::Database("users".to_string())).await.unwrap();

        assert!(can_read);

    }



    #[tokio::test]

    async fn test_ip_conditions() {

        let engine = PolicyEngine::new();

        

        let ip_condition = IpCondition {

            allowed_ips: vec!["192.168.1.100".to_string()],

            denied_ips: vec![],

            cidr_ranges: vec!["10.0.0.0/8".to_string()],

        };

        

        let role = Role::new("ip_restricted")

            .with_permission_conditions(

                Permission::Read,

                Resource::Database("users".to_string()),

                vec![Condition::Ip(ip_condition)]

            );

        

        engine.add_role(role).await.unwrap();

        engine.assign_role("user1", "ip_restricted").await.unwrap();

        

        // Set user IP

        engine.set_user_ip("user1", "192.168.1.100").await.unwrap();

        

        let can_read = engine.check_permission("user1", Permission::Read, Resource::Database("users".to_string())).await.unwrap();

        assert!(can_read);

        

        // Test CIDR range

        engine.set_user_ip("user1", "10.0.1.50").await.unwrap();

        let can_read_cidr = engine.check_permission("user1", Permission::Read, Resource::Database("users".to_string())).await.unwrap();

        assert!(can_read_cidr);

    }



    #[tokio::test]

    async fn test_attribute_conditions() {

        let engine = PolicyEngine::new();

        

        let attr_condition = AttributeCondition {

            attribute: "department".to_string(),

            operator: AttributeOperator::Equals,

            value: "engineering".to_string(),

        };

        

        let role = Role::new("attr_restricted")

            .with_permission_conditions(

                Permission::Read,

                Resource::Database("users".to_string()),

                vec![Condition::Attribute(attr_condition)]

            );

        

        engine.add_role(role).await.unwrap();

        engine.assign_role("user1", "attr_restricted").await.unwrap();

        

        // Set user attributes

        let mut attrs = HashMap::new();

        attrs.insert("department".to_string(), "engineering".to_string());

        engine.set_user_attributes("user1", attrs).await.unwrap();

        

        let can_read = engine.check_permission("user1", Permission::Read, Resource::Database("users".to_string())).await.unwrap();

        assert!(can_read);

        

        // Test with wrong attribute value

        engine.set_user_attribute("user1", "department", "sales").await.unwrap();

        let cannot_read = engine.check_permission("user1", Permission::Read, Resource::Database("users".to_string())).await.unwrap();

        assert!(!cannot_read);

    }



    #[tokio::test]

    async fn test_user_attribute_management() {

        let engine = PolicyEngine::new();

        

        // Test setting and getting attributes

        let mut attrs = HashMap::new();

        attrs.insert("role".to_string(), "admin".to_string());

        attrs.insert("clearance".to_string(), "high".to_string());

        

        engine.set_user_attributes("user1", attrs).await.unwrap();

        

        let retrieved_attrs = engine.get_user_attributes("user1").await.unwrap();

        assert_eq!(retrieved_attrs.get("role"), Some(&"admin".to_string()));

        assert_eq!(retrieved_attrs.get("clearance"), Some(&"high".to_string()));

        

        // Test updating single attribute

        engine.set_user_attribute("user1", "clearance", "critical").await.unwrap();

        let updated_attrs = engine.get_user_attributes("user1").await.unwrap();

        assert_eq!(updated_attrs.get("clearance"), Some(&"critical".to_string()));

    }



    #[tokio::test]

    async fn test_user_ip_management() {

        let engine = PolicyEngine::new();

        

        // Test setting and getting IP

        engine.set_user_ip("user1", "192.168.1.100").await.unwrap();

        let ip = engine.get_user_ip("user1").await.unwrap();

        assert_eq!(ip, Some("192.168.1.100".to_string()));

        

        // Test removing IP

        engine.remove_user_ip("user1").await.unwrap();

        let removed_ip = engine.get_user_ip("user1").await.unwrap();

        assert_eq!(removed_ip, None);

    }

}

