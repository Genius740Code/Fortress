//! Policy types and structures
//!
//! This module defines the core types used throughout the HCL policy engine.

use crate::error::Result;
use crate::token::TokenInfo;
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Parsed HCL policy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParsedPolicy {
    /// Policy name
    pub name: String,
    /// Policy path pattern
    pub path: String,
    /// Allowed capabilities
    pub capabilities: Vec<String>,
    /// Required parameters
    pub required_parameters: HashMap<String, ParameterType>,
    /// Allowed parameter values
    pub allowed_parameters: HashMap<String, Vec<String>>,
    /// Minimum TTL in seconds
    pub min_ttl: Option<i64>,
    /// Maximum TTL in seconds
    pub max_ttl: Option<i64>,
    /// Policy constraints
    pub constraints: Vec<PolicyConstraint>,
    /// Policy metadata
    pub metadata: HashMap<String, String>,
    /// Policy creation timestamp
    pub created_at: DateTime<Utc>,
    /// Policy last updated timestamp
    pub updated_at: DateTime<Utc>,
}

impl ParsedPolicy {
    /// Create a new parsed policy
    pub fn new(name: String, path: String) -> Self {
        let now = Utc::now();
        Self {
            name,
            path,
            capabilities: Vec::new(),
            required_parameters: HashMap::new(),
            allowed_parameters: HashMap::new(),
            min_ttl: None,
            max_ttl: None,
            constraints: Vec::new(),
            metadata: HashMap::new(),
            created_at: now,
            updated_at: now,
        }
    }

    /// Add a capability to the policy
    pub fn add_capability(&mut self, capability: String) {
        if !self.capabilities.contains(&capability) {
            self.capabilities.push(capability);
            self.updated_at = Utc::now();
        }
    }

    /// Add a required parameter
    pub fn add_required_parameter(&mut self, name: String, param_type: ParameterType) {
        self.required_parameters.insert(name, param_type);
        self.updated_at = Utc::now();
    }

    /// Add allowed parameter values
    pub fn add_allowed_parameter(&mut self, name: String, values: Vec<String>) {
        self.allowed_parameters.insert(name, values);
        self.updated_at = Utc::now();
    }

    /// Add a constraint
    pub fn add_constraint(&mut self, constraint: PolicyConstraint) {
        self.constraints.push(constraint);
        self.updated_at = Utc::now();
    }

    /// Check if the policy allows a specific capability
    pub fn allows_capability(&self, capability: &str) -> bool {
        self.capabilities.contains(&capability.to_string())
    }

    /// Check if the policy matches a path
    pub fn matches_path(&self, request_path: &str) -> bool {
        // Simple glob matching - could be enhanced with proper regex
        if self.path == "*" {
            return true;
        }

        if self.path.contains('*') {
            let pattern = self.path.replace('*', ".*");
            if let Ok(regex) = regex::Regex::new(&pattern) {
                return regex.is_match(request_path);
            }
        }

        self.path == request_path
    }
}

/// Parameter type enumeration
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ParameterType {
    /// String parameter
    String,
    /// Number parameter
    Number,
    /// Boolean parameter
    Boolean,
    /// Array parameter
    Array,
    /// Object parameter
    Object,
    /// Time parameter
    Time,
    /// Duration parameter
    Duration,
}

/// Policy constraint
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyConstraint {
    /// Field to constrain
    pub field: String,
    /// Constraint operator
    pub operator: ConstraintOperator,
    /// Constraint value
    pub value: serde_json::Value,
    /// Constraint description
    pub description: Option<String>,
}

/// Constraint operator enumeration
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ConstraintOperator {
    /// Equals
    Equals,
    /// Not equals
    NotEquals,
    /// Contains
    Contains,
    /// Does not contain
    NotContains,
    /// Greater than
    GreaterThan,
    /// Less than
    LessThan,
    /// Greater than or equal
    GreaterThanOrEqual,
    /// Less than or equal
    LessThanOrEqual,
    /// In list
    In,
    /// Not in list
    NotIn,
    /// Matches regex
    Matches,
    /// Does not match regex
    NotMatches,
    /// Starts with
    StartsWith,
    /// Ends with
    EndsWith,
}

/// Policy evaluation context
#[derive(Debug, Clone)]
pub struct PolicyContext {
    /// Token information
    pub token: TokenInfo,
    /// Request path
    pub path: String,
    /// Request operation
    pub operation: String,
    /// Request parameters
    pub parameters: HashMap<String, serde_json::Value>,
    /// Request timestamp
    pub time: DateTime<Utc>,
    /// Client IP address
    pub ip_address: Option<String>,
    /// User agent
    pub user_agent: Option<String>,
    /// Request method
    pub method: Option<String>,
    /// Request headers
    pub headers: HashMap<String, String>,
    /// Environment variables
    pub environment: HashMap<String, String>,
}

impl PolicyContext {
    /// Create a new policy context
    pub fn new(token: TokenInfo, path: String, operation: String) -> Self {
        Self {
            token,
            path,
            operation,
            parameters: HashMap::new(),
            time: Utc::now(),
            ip_address: None,
            user_agent: None,
            method: None,
            headers: HashMap::new(),
            environment: HashMap::new(),
        }
    }

    /// Get a parameter value
    pub fn get_parameter(&self, key: &str) -> Option<&serde_json::Value> {
        self.parameters.get(key)
    }

    /// Check if a parameter exists
    pub fn has_parameter(&self, key: &str) -> bool {
        self.parameters.contains_key(key)
    }

    /// Get a header value
    pub fn get_header(&self, key: &str) -> Option<&String> {
        self.headers.get(key)
    }

    /// Get an environment variable
    pub fn get_environment(&self, key: &str) -> Option<&String> {
        self.environment.get(key)
    }

    /// Add a parameter
    pub fn add_parameter(&mut self, key: String, value: serde_json::Value) {
        self.parameters.insert(key, value);
    }

    /// Add a header
    pub fn add_header(&mut self, key: String, value: String) {
        self.headers.insert(key, value);
    }

    /// Add an environment variable
    pub fn add_environment(&mut self, key: String, value: String) {
        self.environment.insert(key, value);
    }
}

/// Policy evaluation result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyResult {
    /// Whether access is allowed
    pub allowed: bool,
    /// Allowed capabilities
    pub allowed_capabilities: Vec<String>,
    /// Calculated TTL
    pub ttl: Duration,
    /// Denial reason
    pub reason: Option<String>,
    /// Applied policies
    pub applied_policies: Vec<String>,
    /// Evaluation timestamp
    pub evaluated_at: DateTime<Utc>,
    /// Additional metadata
    pub metadata: HashMap<String, String>,
}

impl PolicyResult {
    /// Create an allowed result
    pub fn allowed(capabilities: Vec<String>, ttl: Duration) -> Self {
        Self {
            allowed: true,
            allowed_capabilities: capabilities,
            ttl,
            reason: None,
            applied_policies: Vec::new(),
            evaluated_at: Utc::now(),
            metadata: HashMap::new(),
        }
    }

    /// Create a denied result
    pub fn denied(reason: String) -> Self {
        Self {
            allowed: false,
            allowed_capabilities: Vec::new(),
            ttl: Duration::zero(),
            reason: Some(reason),
            applied_policies: Vec::new(),
            evaluated_at: Utc::now(),
            metadata: HashMap::new(),
        }
    }

    /// Add an applied policy
    pub fn add_applied_policy(&mut self, policy_name: String) {
        self.applied_policies.push(policy_name);
    }

    /// Add metadata
    pub fn add_metadata(&mut self, key: String, value: String) {
        self.metadata.insert(key, value);
    }
}

/// Policy evaluation result for individual policies
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyEvaluationResult {
    /// Whether policy allows access
    pub allowed: bool,
    /// Allowed capabilities
    pub allowed_capabilities: Vec<String>,
    /// Denial reason
    pub reason: Option<String>,
    /// Policy name
    pub policy_name: String,
    /// Evaluation time in milliseconds
    pub evaluation_time_ms: u64,
}

impl PolicyEvaluationResult {
    /// Create an allowed result
    pub fn allowed(capabilities: Vec<String>, policy_name: String) -> Self {
        Self {
            allowed: true,
            allowed_capabilities: capabilities,
            reason: None,
            policy_name,
            evaluation_time_ms: 0,
        }
    }

    /// Create a denied result
    pub fn denied(reason: String, policy_name: String) -> Self {
        Self {
            allowed: false,
            allowed_capabilities: Vec::new(),
            reason: Some(reason),
            policy_name,
            evaluation_time_ms: 0,
        }
    }
}

/// Policy function trait
pub trait PolicyFunction: Send + Sync {
    /// Evaluate function with given arguments and context
    fn evaluate(
        &self,
        args: &[serde_json::Value],
        context: &PolicyContext,
    ) -> crate::error::Result<serde_json::Value>;

    /// Get function name
    fn name(&self) -> &str;

    /// Get function description
    fn description(&self) -> &str;

    /// Get parameter types
    fn parameter_types(&self) -> Vec<ParameterType>;
}

/// Role store trait for policy evaluation
pub trait RoleStore: Send + Sync {
    /// Add a role to an entity
    fn add_role(&self, entity_id: &str, role: &str) -> Result<()>;

    /// Remove a role from an entity
    fn remove_role(&self, entity_id: &str, role: &str) -> Result<()>;

    /// Get all roles for an entity
    fn get_roles(&self, entity_id: &str) -> Result<Vec<String>>;

    /// Check if an entity has a specific role
    fn check_role(&self, entity_id: &str, role: &str) -> Result<bool>;

    /// List all entities with a specific role
    fn list_entities_with_role(&self, role: &str) -> Result<Vec<String>>;
}

/// In-memory role store implementation
pub struct InMemoryRoleStore {
    roles: Arc<RwLock<HashMap<String, Vec<String>>>>,
}

impl InMemoryRoleStore {
    /// Create a new in-memory role store
    pub fn new() -> Self {
        Self {
            roles: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Add a role to an entity
    pub fn add_role(&self, entity_id: &str, role: &str) -> Result<()> {
        let mut roles = self.roles.blocking_write();
        roles
            .entry(entity_id.to_string())
            .or_insert_with(Vec::new)
            .push(role.to_string());
        Ok(())
    }

    /// Remove a role from an entity
    pub fn remove_role(&self, entity_id: &str, role: &str) -> Result<()> {
        let mut roles = self.roles.blocking_write();
        if let Some(entity_roles) = roles.get_mut(entity_id) {
            entity_roles.retain(|r| r != role);
            if entity_roles.is_empty() {
                roles.remove(entity_id);
            }
        }
        Ok(())
    }

    /// Get all roles for an entity
    pub fn get_roles(&self, entity_id: &str) -> Result<Vec<String>> {
        let roles = self.roles.blocking_read();
        Ok(roles.get(entity_id).cloned().unwrap_or_default())
    }

    /// Check if an entity has a specific role
    pub fn check_role(&self, entity_id: &str, role: &str) -> Result<bool> {
        let roles = self.get_roles(entity_id)?;
        Ok(roles.contains(&role.to_string()))
    }

    /// List all entities with a specific role
    pub fn list_entities_with_role(&self, role: &str) -> Result<Vec<String>> {
        let roles = self.roles.blocking_read();
        let mut entities = Vec::new();

        for (entity_id, entity_roles) in roles.iter() {
            if entity_roles.contains(&role.to_string()) {
                entities.push(entity_id.clone());
            }
        }

        Ok(entities)
    }
}

impl RoleStore for InMemoryRoleStore {
    fn get_roles(&self, entity_id: &str) -> Result<Vec<String>> {
        let roles = self.roles.blocking_read();
        Ok(roles.get(entity_id).cloned().unwrap_or_default())
    }

    fn check_role(&self, entity_id: &str, role: &str) -> Result<bool> {
        let roles = self.get_roles(entity_id)?;
        Ok(roles.contains(&role.to_string()))
    }

    fn add_role(&self, entity_id: &str, role: &str) -> Result<()> {
        let mut roles = self.roles.blocking_write();
        roles
            .entry(entity_id.to_string())
            .or_insert_with(Vec::new)
            .push(role.to_string());
        Ok(())
    }

    fn remove_role(&self, entity_id: &str, role: &str) -> Result<()> {
        let mut roles = self.roles.blocking_write();
        if let Some(entity_roles) = roles.get_mut(entity_id) {
            entity_roles.retain(|r| r != role);
            if entity_roles.is_empty() {
                roles.remove(entity_id);
            }
        }
        Ok(())
    }

    fn list_entities_with_role(&self, role: &str) -> Result<Vec<String>> {
        let roles = self.roles.blocking_read();
        let mut entities = Vec::new();

        for (entity_id, entity_roles) in roles.iter() {
            if entity_roles.contains(&role.to_string()) {
                entities.push(entity_id.clone());
            }
        }

        Ok(entities)
    }
}

/// Policy compilation error
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyCompilationError {
    /// Error message
    pub message: String,
    /// Line number where error occurred
    pub line: Option<u32>,
    /// Column number where error occurred
    pub column: Option<u32>,
    /// Error type
    pub error_type: PolicyErrorType,
}

/// Policy error type
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum PolicyErrorType {
    /// Syntax error
    Syntax,
    /// Semantic error
    Semantic,
    /// Reference error
    Reference,
    /// Type error
    Type,
    /// Runtime error
    Runtime,
}

/// Policy validation result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyValidationResult {
    /// Whether policy is valid
    pub valid: bool,
    /// Validation errors
    pub errors: Vec<PolicyCompilationError>,
    /// Validation warnings
    pub warnings: Vec<String>,
    /// Validation timestamp
    pub validated_at: DateTime<Utc>,
}

impl PolicyValidationResult {
    /// Create a valid result
    pub fn valid() -> Self {
        Self {
            valid: true,
            errors: Vec::new(),
            warnings: Vec::new(),
            validated_at: Utc::now(),
        }
    }

    /// Create an invalid result
    pub fn invalid(errors: Vec<PolicyCompilationError>) -> Self {
        Self {
            valid: false,
            errors,
            warnings: Vec::new(),
            validated_at: Utc::now(),
        }
    }

    /// Add a warning
    pub fn add_warning(&mut self, warning: String) {
        self.warnings.push(warning);
    }
}

/// Policy statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyStatistics {
    /// Total number of policies
    pub total_policies: u64,
    /// Number of active policies
    pub active_policies: u64,
    /// Number of disabled policies
    pub disabled_policies: u64,
    /// Average evaluation time in milliseconds
    pub avg_evaluation_time_ms: f64,
    /// Number of evaluations in the last hour
    pub evaluations_last_hour: u64,
    /// Number of allowed requests
    pub allowed_requests: u64,
    /// Number of denied requests
    pub denied_requests: u64,
    /// Most commonly used capabilities
    pub top_capabilities: Vec<(String, u64)>,
    /// Most active policies
    pub top_policies: Vec<(String, u64)>,
}

impl Default for PolicyStatistics {
    fn default() -> Self {
        Self {
            total_policies: 0,
            active_policies: 0,
            disabled_policies: 0,
            avg_evaluation_time_ms: 0.0,
            evaluations_last_hour: 0,
            allowed_requests: 0,
            denied_requests: 0,
            top_capabilities: Vec::new(),
            top_policies: Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::token::{TokenRole, TokenType};

    #[test]
    fn test_parsed_policy_creation() {
        let policy = ParsedPolicy::new("test-policy".to_string(), "secret/*".to_string());

        assert_eq!(policy.name, "test-policy");
        assert_eq!(policy.path, "secret/*");
        assert!(policy.capabilities.is_empty());
        assert!(policy.constraints.is_empty());
    }

    #[test]
    fn test_policy_capabilities() {
        let mut policy = ParsedPolicy::new("test-policy".to_string(), "secret/*".to_string());

        policy.add_capability("read".to_string());
        policy.add_capability("list".to_string());

        assert!(policy.allows_capability("read"));
        assert!(policy.allows_capability("list"));
        assert!(!policy.allows_capability("write"));
    }

    #[test]
    fn test_policy_path_matching() {
        let policy1 = ParsedPolicy::new("test-policy".to_string(), "*".to_string());
        let policy2 = ParsedPolicy::new("test-policy".to_string(), "secret/*".to_string());
        let policy3 = ParsedPolicy::new("test-policy".to_string(), "secret/data".to_string());

        assert!(policy1.matches_path("any/path"));
        assert!(policy2.matches_path("secret/data/test"));
        assert!(policy2.matches_path("secret/metadata"));
        assert!(!policy2.matches_path("public/data"));
        assert!(policy3.matches_path("secret/data"));
        assert!(!policy3.matches_path("secret/metadata"));
    }

    #[test]
    fn test_policy_context() {
        let token = crate::token::Token::new(
            TokenType::User,
            TokenRole::Admin,
            vec!["default".to_string()],
            chrono::Duration::hours(1),
            "user123".to_string(),
        );

        let token_info = crate::token::TokenInfo {
            token: token.clone(),
            display_name: "Test Token".to_string(),
            description: None,
            usage_stats: Default::default(),
            creation_context: Default::default(),
        };

        let mut context =
            PolicyContext::new(token_info, "secret/data".to_string(), "read".to_string());

        context.add_parameter(
            "key".to_string(),
            serde_json::Value::String("test-key".to_string()),
        );
        context.add_header("X-Request-ID".to_string(), "req-123".to_string());

        assert_eq!(context.path, "secret/data");
        assert_eq!(context.operation, "read");
        assert!(context.has_parameter("key"));
        assert_eq!(
            context.get_parameter("key"),
            Some(&serde_json::Value::String("test-key".to_string()))
        );
        assert_eq!(
            context.get_header("X-Request-ID"),
            Some(&"req-123".to_string())
        );
    }

    #[test]
    fn test_policy_result() {
        let result = PolicyResult::allowed(
            vec!["read".to_string(), "list".to_string()],
            chrono::Duration::hours(1),
        );

        assert!(result.allowed);
        assert_eq!(result.allowed_capabilities.len(), 2);
        assert!(result.reason.is_none());

        let denied = PolicyResult::denied("Access denied".to_string());
        assert!(!denied.allowed);
        assert_eq!(denied.reason, Some("Access denied".to_string()));
    }

    #[test]
    fn test_in_memory_role_store() {
        let role_store = InMemoryRoleStore::new();

        // Add roles
        role_store.add_role("user1", "admin").unwrap();
        role_store.add_role("user1", "operator").unwrap();
        role_store.add_role("user2", "operator").unwrap();

        // Check roles
        assert!(role_store.check_role("user1", "admin").unwrap());
        assert!(role_store.check_role("user1", "operator").unwrap());
        assert!(!role_store.check_role("user1", "auditor").unwrap());
        assert!(!role_store.check_role("user2", "admin").unwrap());

        // Get all roles
        let user1_roles = role_store.get_roles("user1").unwrap();
        assert_eq!(user1_roles.len(), 2);
        assert!(user1_roles.contains(&"admin".to_string()));
        assert!(user1_roles.contains(&"operator".to_string()));

        // List entities with role
        let operators = role_store.list_entities_with_role("operator").unwrap();
        assert_eq!(operators.len(), 2);
        assert!(operators.contains(&"user1".to_string()));
        assert!(operators.contains(&"user2".to_string()));

        // Remove role
        role_store.remove_role("user1", "admin").unwrap();
        assert!(!role_store.check_role("user1", "admin").unwrap());
        assert!(role_store.check_role("user1", "operator").unwrap());
    }

    #[test]
    fn test_policy_validation_result() {
        let valid = PolicyValidationResult::valid();
        assert!(valid.valid);
        assert!(valid.errors.is_empty());

        let errors = vec![PolicyCompilationError {
            message: "Syntax error".to_string(),
            line: Some(1),
            column: Some(5),
            error_type: PolicyErrorType::Syntax,
        }];

        let invalid = PolicyValidationResult::invalid(errors);
        assert!(!invalid.valid);
        assert_eq!(invalid.errors.len(), 1);
    }

    #[test]
    fn test_constraint_operators() {
        let operators = vec![
            ConstraintOperator::Equals,
            ConstraintOperator::NotEquals,
            ConstraintOperator::Contains,
            ConstraintOperator::GreaterThan,
            ConstraintOperator::In,
        ];

        for op in operators {
            // Just test that they can be created and compared
            let op2 = op.clone();
            assert_eq!(op, op2);
        }
    }

    #[test]
    fn test_parameter_types() {
        let types = vec![
            ParameterType::String,
            ParameterType::Number,
            ParameterType::Boolean,
            ParameterType::Array,
            ParameterType::Object,
        ];

        for param_type in types {
            // Just test that they can be created and compared
            let param_type2 = param_type.clone();
            assert_eq!(param_type, param_type2);
        }
    }
}
