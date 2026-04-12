//! HCL policy evaluator
//!
//! This module provides the main policy evaluation engine that evaluates
//! HCL policies against request contexts to determine access permissions.

use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use chrono::{DateTime, Utc, Duration, Datelike, Timelike};
use regex::Regex;
use serde::{Serialize, Deserialize};

use crate::error::{FortressError, Result};
use super::types::{
    ParsedPolicy, PolicyContext, PolicyResult, PolicyEvaluationResult,
    ConstraintOperator, RoleStore, PolicyFunction,
};
use super::builtin_functions::register_builtin_functions;

/// HCL Policy Engine
pub struct HclPolicyEngine {
    /// Loaded policies
    policies: Arc<RwLock<HashMap<String, ParsedPolicy>>>,
    /// Registered functions
    functions: Arc<RwLock<HashMap<String, Box<dyn PolicyFunction>>>>,
    /// Role store
    role_store: Arc<dyn RoleStore>,
    /// Policy evaluation statistics
    stats: Arc<RwLock<PolicyEngineStats>>,
}

/// Policy engine statistics
#[derive(Debug, Clone, Default)]
struct PolicyEngineStats {
    total_evaluations: u64,
    allowed_evaluations: u64,
    denied_evaluations: u64,
    avg_evaluation_time_ms: f64,
    policy_usage: HashMap<String, u64>,
}

impl HclPolicyEngine {
    /// Create a new HCL policy engine
    pub fn new(role_store: Arc<dyn RoleStore>) -> Self {
        let functions = register_builtin_functions();
        
        Self {
            policies: Arc::new(RwLock::new(HashMap::new())),
            functions: Arc::new(RwLock::new(functions)),
            role_store,
            stats: Arc::new(RwLock::new(PolicyEngineStats::default())),
        }
    }

    /// Load a policy
    pub async fn load_policy(&self, policy: ParsedPolicy) -> Result<()> {
        let mut policies = self.policies.write().await;
        policies.insert(policy.name.clone(), policy);
        Ok(())
    }

    /// Remove a policy
    pub async fn remove_policy(&self, policy_name: &str) -> Result<()> {
        let mut policies = self.policies.write().await;
        policies.remove(policy_name);
        Ok(())
    }

    /// Get all policies
    pub async fn get_policies(&self) -> Vec<ParsedPolicy> {
        let policies = self.policies.read().await;
        policies.values().cloned().collect()
    }

    /// Get a specific policy
    pub async fn get_policy(&self, policy_name: &str) -> Option<ParsedPolicy> {
        let policies = self.policies.read().await;
        policies.get(policy_name).cloned()
    }

    /// Evaluate policies for a request
    pub async fn evaluate_policies(&self, context: &PolicyContext) -> Result<PolicyResult> {
        let start_time = std::time::Instant::now();
        
        let policies = self.policies.read().await;
        let functions = self.functions.read().await;
        
        // Find matching policies
        let matching_policies = self.find_matching_policies(&policies, &context.path);
        
        if matching_policies.is_empty() {
            return Ok(PolicyResult::denied("No matching policies found".to_string()));
        }

        let mut allowed_capabilities = Vec::new();
        let mut applied_policies = Vec::new();
        let mut final_ttl = Duration::hours(1); // Default TTL
        let mut overall_allowed = true;
        let mut denial_reasons = Vec::new();

        // Evaluate each matching policy
        for policy in &matching_policies {
            let evaluation_start = std::time::Instant::now();
            
            match self.evaluate_single_policy(policy, context, &functions).await {
                Ok(result) => {
                    if result.allowed {
                        // Add capabilities from this policy
                        for capability in &result.allowed_capabilities {
                            if !allowed_capabilities.contains(capability) {
                                allowed_capabilities.push(capability.clone());
                            }
                        }
                        
                        // Update TTL (use the minimum)
                        if policy.min_ttl.is_some() && Duration::seconds(policy.min_ttl.unwrap()) < final_ttl {
                            final_ttl = Duration::seconds(policy.min_ttl.unwrap());
                        }
                        if policy.max_ttl.is_some() && Duration::seconds(policy.max_ttl.unwrap()) > final_ttl {
                            final_ttl = Duration::seconds(policy.max_ttl.unwrap());
                        }
                    } else {
                        overall_allowed = false;
                        if let Some(reason) = &result.reason {
                            denial_reasons.push(format!("{}: {}", policy.name, reason));
                        }
                    }
                    
                    applied_policies.push(policy.name.clone());
                    
                    // Update policy usage stats
                    let mut stats = self.stats.write().await;
                    *stats.policy_usage.entry(policy.name.clone()).or_insert(0) += 1;
                }
                Err(e) => {
                    overall_allowed = false;
                    denial_reasons.push(format!("{}: {}", policy.name, e));
                }
            }
            
            // Update evaluation time stats
            let evaluation_time = evaluation_start.elapsed().as_millis() as f64;
            let mut stats = self.stats.write().await;
            stats.total_evaluations += 1;
            stats.avg_evaluation_time_ms = 
                (stats.avg_evaluation_time_ms * (stats.total_evaluations - 1) as f64 + evaluation_time) / 
                stats.total_evaluations as f64;
        }

        // Update final stats
        {
            let mut stats = self.stats.write().await;
            if overall_allowed {
                stats.allowed_evaluations += 1;
            } else {
                stats.denied_evaluations += 1;
            }
        }

        let evaluation_time = start_time.elapsed().as_millis() as u64;

        if overall_allowed {
            let mut result = PolicyResult::allowed(allowed_capabilities, final_ttl);
            result.applied_policies = applied_policies;
            result.add_metadata("evaluation_time_ms".to_string(), evaluation_time.to_string());
            Ok(result)
        } else {
            let reason = if denial_reasons.is_empty() {
                "Access denied by policy".to_string()
            } else {
                denial_reasons.join("; ")
            };
            
            let mut result = PolicyResult::denied(reason);
            result.applied_policies = applied_policies;
            result.add_metadata("evaluation_time_ms".to_string(), evaluation_time.to_string());
            Ok(result)
        }
    }

    /// Evaluate a single policy
    async fn evaluate_single_policy(
        &self,
        policy: &ParsedPolicy,
        context: &PolicyContext,
        functions: &HashMap<String, Box<dyn PolicyFunction>>,
    ) -> Result<PolicyEvaluationResult> {
        let start_time = std::time::Instant::now();

        // Check if the operation is allowed by capabilities
        let mut allowed_capabilities = Vec::new();
        for capability in &policy.capabilities {
            if self.check_capability(context, capability) {
                allowed_capabilities.push(capability.clone());
            }
        }

        if allowed_capabilities.is_empty() {
            return Ok(PolicyEvaluationResult::denied(
                "Operation not allowed by capabilities".to_string(),
                policy.name.clone(),
            ));
        }

        // Check required parameters
        for (param_name, param_type) in &policy.required_parameters {
            if !context.has_parameter(param_name) {
                return Ok(PolicyEvaluationResult::denied(
                    format!("Required parameter '{}' is missing", param_name),
                    policy.name.clone(),
                ));
            }

            if let Some(param_value) = context.get_parameter(param_name) {
                if !self.validate_parameter_type(param_value, param_type) {
                    return Ok(PolicyEvaluationResult::denied(
                        format!("Parameter '{}' has invalid type", param_name),
                        policy.name.clone(),
                    ));
                }
            }
        }

        // Check allowed parameter values
        for (param_name, allowed_values) in &policy.allowed_parameters {
            if let Some(param_value) = context.get_parameter(param_name) {
                if let Some(param_str) = param_value.as_str() {
                    if !allowed_values.contains(&param_str.to_string()) {
                        return Ok(PolicyEvaluationResult::denied(
                            format!("Parameter '{}' value '{}' is not allowed", param_name, param_str),
                            policy.name.clone(),
                        ));
                    }
                }
            }
        }

        // Evaluate constraints
        for constraint in &policy.constraints {
            if !self.evaluate_constraint(constraint, context, functions).await? {
                return Ok(PolicyEvaluationResult::denied(
                    format!("Constraint failed: {}", constraint.field),
                    policy.name.clone(),
                ));
            }
        }

        let evaluation_time = start_time.elapsed().as_millis() as u64;
        let mut result = PolicyEvaluationResult::allowed(allowed_capabilities, policy.name.clone());
        result.evaluation_time_ms = evaluation_time;
        
        Ok(result)
    }

    /// Check if a capability is allowed for the context
    fn check_capability(&self, context: &PolicyContext, capability: &str) -> bool {
        // Simple capability check - could be enhanced
        match capability {
            "read" => context.operation == "read" || context.operation == "list",
            "write" => context.operation == "write" || context.operation == "create" || context.operation == "update",
            "delete" => context.operation == "delete",
            "list" => context.operation == "list",
            "sudo" => context.token.token.has_role(&crate::token::TokenRole::Admin),
            _ => false,
        }
    }

    /// Validate parameter type
    fn validate_parameter_type(&self, value: &serde_json::Value, param_type: &super::ParameterType) -> bool {
        match param_type {
            super::ParameterType::String => value.is_string(),
            super::ParameterType::Number => value.is_number(),
            super::ParameterType::Boolean => value.is_boolean(),
            super::ParameterType::Array => value.is_array(),
            super::ParameterType::Object => value.is_object(),
            super::ParameterType::Time => value.is_number(),
            super::ParameterType::Duration => value.is_number() || value.is_string(),
        }
    }

    /// Evaluate a constraint
    async fn evaluate_constraint(
        &self,
        constraint: &super::PolicyConstraint,
        context: &PolicyContext,
        functions: &HashMap<String, Box<dyn PolicyFunction>>,
    ) -> Result<bool> {
        // Get the field value
        let field_value = self.extract_field_value(&constraint.field, context, functions).await?;
        
        // Evaluate the constraint
        match constraint.operator {
            ConstraintOperator::Equals => self.evaluate_equals(&field_value, &constraint.value),
            ConstraintOperator::NotEquals => Ok(!self.evaluate_equals(&field_value, &constraint.value)?),
            ConstraintOperator::Contains => self.evaluate_contains(&field_value, &constraint.value),
            ConstraintOperator::NotContains => Ok(!self.evaluate_contains(&field_value, &constraint.value)?),
            ConstraintOperator::GreaterThan => self.evaluate_greater_than(&field_value, &constraint.value),
            ConstraintOperator::LessThan => self.evaluate_less_than(&field_value, &constraint.value),
            ConstraintOperator::GreaterThanOrEqual => Ok(
                self.evaluate_equals(&field_value, &constraint.value)? ||
                self.evaluate_greater_than(&field_value, &constraint.value)?
            ),
            ConstraintOperator::LessThanOrEqual => Ok(
                self.evaluate_equals(&field_value, &constraint.value)? ||
                self.evaluate_less_than(&field_value, &constraint.value)?
            ),
            ConstraintOperator::In => self.evaluate_in(&field_value, &constraint.value),
            ConstraintOperator::NotIn => Ok(!self.evaluate_in(&field_value, &constraint.value)?),
            ConstraintOperator::Matches => self.evaluate_matches(&field_value, &constraint.value),
            ConstraintOperator::NotMatches => Ok(!self.evaluate_matches(&field_value, &constraint.value)?),
            ConstraintOperator::StartsWith => self.evaluate_starts_with(&field_value, &constraint.value),
            ConstraintOperator::EndsWith => self.evaluate_ends_with(&field_value, &constraint.value),
        }
    }

    /// Extract field value from context
    async fn extract_field_value(
        &self,
        field: &str,
        context: &PolicyContext,
        functions: &HashMap<String, Box<dyn PolicyFunction>>,
    ) -> Result<serde_json::Value> {
        // Check if it's a function call
        if field.contains('(') && field.ends_with(')') {
            let func_name = field.split('(').next().unwrap();
            let args_str = field.split('(').nth(1).unwrap().trim_end_matches(')');
            
            let mut args = Vec::new();
            if !args_str.is_empty() {
                // Simple argument parsing - could be enhanced
                if args_str.starts_with('"') && args_str.ends_with('"') {
                    args.push(serde_json::Value::String(args_str[1..args_str.len()-1].to_string()));
                } else {
                    // Try to parse as number or boolean
                    if let Ok(num) = args_str.parse::<i64>() {
                        args.push(serde_json::Value::Number(num.into()));
                    } else if let Ok(num) = args_str.parse::<f64>() {
                        args.push(serde_json::Value::Number(serde_json::Number::from_f64(num).unwrap()));
                    } else if args_str == "true" {
                        args.push(serde_json::Value::Bool(true));
                    } else if args_str == "false" {
                        args.push(serde_json::Value::Bool(false));
                    } else {
                        args.push(serde_json::Value::String(args_str.to_string()));
                    }
                }
            }
            
            if let Some(func) = functions.get(func_name) {
                return func.evaluate(&args, context);
            } else {
                return Err(FortressError::policy(format!("Unknown function: {}", func_name)));
            }
        }

        // Extract from context
        match field {
            "identity" => Ok(serde_json::Value::String(context.token.token.id.clone())),
            "path" => Ok(serde_json::Value::String(context.path.clone())),
            "operation" => Ok(serde_json::Value::String(context.operation.clone())),
            "ip" => Ok(serde_json::Value::String(
                context.ip_address.clone().unwrap_or_else(|| "unknown".to_string())
            )),
            "user_agent" => Ok(serde_json::Value::String(
                context.user_agent.clone().unwrap_or_else(|| "unknown".to_string())
            )),
            "method" => Ok(serde_json::Value::String(
                context.method.clone().unwrap_or_else(|| "unknown".to_string())
            )),
            "time" => Ok(serde_json::Value::Number(context.time.timestamp().into())),
            "hour" => Ok(serde_json::Value::Number(context.time.hour().into())),
            "day" => Ok(serde_json::Value::Number(context.time.weekday().num_days_from_sunday().into())),
            "month" => Ok(serde_json::Value::Number(context.time.month().into())),
            "year" => Ok(serde_json::Value::Number(context.time.year().into())),
            _ => {
                // Check if it's a parameter
                if let Some(param_value) = context.get_parameter(field) {
                    Ok(param_value.clone())
                } else if let Some(header_value) = context.get_header(field) {
                    Ok(serde_json::Value::String(header_value.clone()))
                } else if let Some(env_value) = context.get_environment(field) {
                    Ok(serde_json::Value::String(env_value.clone()))
                } else {
                    Ok(serde_json::Value::Null)
                }
            }
        }
    }

    /// Evaluate equals constraint
    fn evaluate_equals(&self, left: &serde_json::Value, right: &serde_json::Value) -> Result<bool> {
        Ok(left == right)
    }

    /// Evaluate contains constraint
    fn evaluate_contains(&self, left: &serde_json::Value, right: &serde_json::Value) -> Result<bool> {
        if let (Some(left_str), Some(right_str)) = (left.as_str(), right.as_str()) {
            Ok(left_str.contains(right_str))
        } else {
            Ok(false)
        }
    }

    /// Evaluate greater than constraint
    fn evaluate_greater_than(&self, left: &serde_json::Value, right: &serde_json::Value) -> Result<bool> {
        if let (Some(left_num), Some(right_num)) = (left.as_f64(), right.as_f64()) {
            Ok(left_num > right_num)
        } else {
            Ok(false)
        }
    }

    /// Evaluate less than constraint
    fn evaluate_less_than(&self, left: &serde_json::Value, right: &serde_json::Value) -> Result<bool> {
        if let (Some(left_num), Some(right_num)) = (left.as_f64(), right.as_f64()) {
            Ok(left_num < right_num)
        } else {
            Ok(false)
        }
    }

    /// Evaluate in constraint
    fn evaluate_in(&self, left: &serde_json::Value, right: &serde_json::Value) -> Result<bool> {
        if let Some(right_array) = right.as_array() {
            Ok(right_array.contains(left))
        } else {
            Ok(false)
        }
    }

    /// Evaluate matches constraint
    fn evaluate_matches(&self, left: &serde_json::Value, right: &serde_json::Value) -> Result<bool> {
        if let (Some(left_str), Some(right_str)) = (left.as_str(), right.as_str()) {
            let regex = Regex::new(right_str).map_err(|e| {
                FortressError::policy(format!("Invalid regex: {}", e))
            })?;
            Ok(regex.is_match(left_str))
        } else {
            Ok(false)
        }
    }

    /// Evaluate starts with constraint
    fn evaluate_starts_with(&self, left: &serde_json::Value, right: &serde_json::Value) -> Result<bool> {
        if let (Some(left_str), Some(right_str)) = (left.as_str(), right.as_str()) {
            Ok(left_str.starts_with(right_str))
        } else {
            Ok(false)
        }
    }

    /// Evaluate ends with constraint
    fn evaluate_ends_with(&self, left: &serde_json::Value, right: &serde_json::Value) -> Result<bool> {
        if let (Some(left_str), Some(right_str)) = (left.as_str(), right.as_str()) {
            Ok(left_str.ends_with(right_str))
        } else {
            Ok(false)
        }
    }

    /// Find policies that match a path
    fn find_matching_policies(&self, policies: &HashMap<String, ParsedPolicy>, path: &str) -> Vec<ParsedPolicy> {
        policies
            .values()
            .filter(|policy| policy.matches_path(path))
            .cloned()
            .collect()
    }

    /// Register a custom function
    pub async fn register_function(&self, function: Box<dyn PolicyFunction>) -> Result<()> {
        let mut functions = self.functions.write().await;
        functions.insert(function.name().to_string(), function);
        Ok(())
    }

    /// Get evaluation statistics
    pub async fn get_statistics(&self) -> PolicyEngineStatistics {
        let stats = self.stats.read().await;
        let policies = self.policies.read().await;
        
        PolicyEngineStatistics {
            total_policies: policies.len() as u64,
            total_evaluations: stats.total_evaluations,
            allowed_evaluations: stats.allowed_evaluations,
            denied_evaluations: stats.denied_evaluations,
            avg_evaluation_time_ms: stats.avg_evaluation_time_ms,
            policy_usage: stats.policy_usage.clone(),
        }
    }

    /// Reset statistics
    pub async fn reset_statistics(&self) -> Result<()> {
        let mut stats = self.stats.write().await;
        *stats = PolicyEngineStats::default();
        Ok(())
    }
}

/// Policy engine statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyEngineStatistics {
    /// Total number of loaded policies
    pub total_policies: u64,
    /// Total number of evaluations
    pub total_evaluations: u64,
    /// Number of allowed evaluations
    pub allowed_evaluations: u64,
    /// Number of denied evaluations
    pub denied_evaluations: u64,
    /// Average evaluation time in milliseconds
    pub avg_evaluation_time_ms: f64,
    /// Policy usage statistics
    pub policy_usage: HashMap<String, u64>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::token::{TokenType, TokenRole, Token, TokenInfo, TokenUsageStats, TokenCreationContext};

    fn create_test_token() -> TokenInfo {
        let token = Token::new(
            TokenType::User,
            TokenRole::Admin,
            vec!["default".to_string()],
            Duration::hours(1),
            "user123".to_string(),
        );

        TokenInfo {
            token: token.clone(),
            display_name: "Test Token".to_string(),
            description: None,
            usage_stats: TokenUsageStats::default(),
            creation_context: TokenCreationContext::default(),
        }
    }

    fn create_test_context() -> PolicyContext {
        let token = create_test_token();
        let mut context = PolicyContext::new(token, "secret/data".to_string(), "read".to_string());
        context.ip_address = Some("192.168.1.1".to_string());
        context.user_agent = Some("Mozilla/5.0".to_string());
        context.add_parameter("environment".to_string(), serde_json::Value::String("production".to_string()));
        context.add_parameter("data_type".to_string(), serde_json::Value::String("sensitive".to_string()));
        context
    }

    #[tokio::test]
    async fn test_policy_engine_creation() {
        let role_store = Arc::new(super::types::InMemoryRoleStore::new());
        let engine = HclPolicyEngine::new(role_store);
        
        let stats = engine.get_statistics().await;
        assert_eq!(stats.total_policies, 0);
        assert_eq!(stats.total_evaluations, 0);
    }

    #[tokio::test]
    async fn test_load_and_evaluate_policy() {
        let role_store = Arc::new(super::types::InMemoryRoleStore::new());
        let engine = HclPolicyEngine::new(role_store);
        
        let mut policy = ParsedPolicy::new("test-policy".to_string(), "secret/*".to_string());
        policy.add_capability("read".to_string());
        policy.add_capability("list".to_string());
        
        engine.load_policy(policy.clone()).await.unwrap();
        
        let context = create_test_context();
        let result = engine.evaluate_policies(&context).await.unwrap();
        
        assert!(result.allowed);
        assert!(result.allowed_capabilities.contains(&"read".to_string()));
        assert!(result.allowed_capabilities.contains(&"list".to_string()));
    }

    #[tokio::test]
    async fn test_policy_constraints() {
        let role_store = Arc::new(super::types::InMemoryRoleStore::new());
        let engine = HclPolicyEngine::new(role_store);
        
        let mut policy = ParsedPolicy::new("test-policy".to_string(), "secret/*".to_string());
        policy.add_capability("read".to_string());
        
        // Add IP constraint
        let constraint = super::PolicyConstraint {
            field: "ip".to_string(),
            operator: ConstraintOperator::Equals,
            value: serde_json::Value::String("192.168.1.1".to_string()),
            description: None,
        };
        policy.add_constraint(constraint);
        
        engine.load_policy(policy).await.unwrap();
        
        let context = create_test_context();
        let result = engine.evaluate_policies(&context).await.unwrap();
        
        assert!(result.allowed);
        
        // Test with wrong IP
        let mut context_wrong_ip = create_test_context();
        context_wrong_ip.ip_address = Some("10.0.0.1".to_string());
        
        let result = engine.evaluate_policies(&context_wrong_ip).await.unwrap();
        assert!(!result.allowed);
    }

    #[tokio::test]
    async fn test_policy_with_parameters() {
        let role_store = Arc::new(super::types::InMemoryRoleStore::new());
        let engine = HclPolicyEngine::new(role_store);
        
        let mut policy = ParsedPolicy::new("test-policy".to_string(), "secret/*".to_string());
        policy.add_capability("read".to_string());
        policy.add_required_parameter("environment".to_string(), super::ParameterType::String);
        policy.add_allowed_parameter("environment".to_string(), vec!["production".to_string(), "staging".to_string()]);
        
        engine.load_policy(policy).await.unwrap();
        
        // Test with valid parameters
        let context = create_test_context();
        let result = engine.evaluate_policies(&context).await.unwrap();
        assert!(result.allowed);
        
        // Test with missing required parameter
        let mut context_missing_param = create_test_context();
        context_missing_param.parameters.remove("environment");
        
        let result = engine.evaluate_policies(&context_missing_param).await.unwrap();
        assert!(!result.allowed);
        
        // Test with disallowed parameter value
        let mut context_wrong_param = create_test_context();
        context_wrong_param.add_parameter("environment".to_string(), serde_json::Value::String("development".to_string()));
        
        let result = engine.evaluate_policies(&context_wrong_param).await.unwrap();
        assert!(!result.allowed);
    }

    #[tokio::test]
    async fn test_multiple_policies() {
        let role_store = Arc::new(super::types::InMemoryRoleStore::new());
        let engine = HclPolicyEngine::new(role_store);
        
        // Add first policy
        let mut policy1 = ParsedPolicy::new("policy1".to_string(), "secret/*".to_string());
        policy1.add_capability("read".to_string());
        policy1.min_ttl = Some(300);
        
        engine.load_policy(policy1).await.unwrap();
        
        // Add second policy
        let mut policy2 = ParsedPolicy::new("policy2".to_string(), "secret/*".to_string());
        policy2.add_capability("list".to_string());
        policy2.max_ttl = Some(7200);
        
        engine.load_policy(policy2).await.unwrap();
        
        let context = create_test_context();
        let result = engine.evaluate_policies(&context).await.unwrap();
        
        assert!(result.allowed);
        assert!(result.allowed_capabilities.contains(&"read".to_string()));
        assert!(result.allowed_capabilities.contains(&"list".to_string()));
        assert_eq!(result.applied_policies.len(), 2);
    }

    #[tokio::test]
    async fn test_policy_statistics() {
        let role_store = Arc::new(super::types::InMemoryRoleStore::new());
        let engine = HclPolicyEngine::new(role_store);
        
        let mut policy = ParsedPolicy::new("test-policy".to_string(), "secret/*".to_string());
        policy.add_capability("read".to_string());
        
        engine.load_policy(policy).await.unwrap();
        
        let context = create_test_context();
        
        // Evaluate multiple times
        for _ in 0..5 {
            engine.evaluate_policies(&context).await.unwrap();
        }
        
        let stats = engine.get_statistics().await;
        assert_eq!(stats.total_policies, 1);
        assert_eq!(stats.total_evaluations, 5);
        assert_eq!(stats.allowed_evaluations, 5);
        assert_eq!(stats.denied_evaluations, 0);
        assert!(stats.policy_usage.contains_key("test-policy"));
        assert_eq!(stats.policy_usage.get("test-policy"), Some(&5));
    }

    #[tokio::test]
    async fn test_custom_function_registration() {
        let role_store = Arc::new(super::types::InMemoryRoleStore::new());
        let engine = HclPolicyEngine::new(role_store);
        
        // Register a custom function
        struct CustomFunction;
        impl PolicyFunction for CustomFunction {
            fn evaluate(&self, args: &[serde_json::Value], _context: &PolicyContext) -> Result<serde_json::Value> {
                if args.len() != 1 {
                    return Err(FortressError::policy("custom() takes one argument"));
                }
                Ok(args[0].clone())
            }
            
            fn name(&self) -> &str { "custom" }
            fn description(&self) -> &str { "Custom test function" }
            fn parameter_types(&self) -> Vec<super::ParameterType> { vec![super::ParameterType::String] }
        }
        
        engine.register_function(Box::new(CustomFunction)).await.unwrap();
        
        let mut policy = ParsedPolicy::new("test-policy".to_string(), "secret/*".to_string());
        policy.add_capability("read".to_string());
        
        // Add constraint using custom function
        let constraint = super::PolicyConstraint {
            field: "custom(\"test\")".to_string(),
            operator: ConstraintOperator::Equals,
            value: serde_json::Value::String("test".to_string()),
            description: None,
        };
        policy.add_constraint(constraint);
        
        engine.load_policy(policy).await.unwrap();
        
        let context = create_test_context();
        let result = engine.evaluate_policies(&context).await.unwrap();
        assert!(result.allowed);
    }

    #[test]
    fn test_constraint_evaluation() {
        let role_store = Arc::new(super::types::InMemoryRoleStore::new());
        let engine = HclPolicyEngine::new(role_store);
        
        // Test equals
        let left = serde_json::Value::String("test".to_string());
        let right = serde_json::Value::String("test".to_string());
        assert!(engine.evaluate_equals(&left, &right).unwrap());
        
        // Test not equals
        let left = serde_json::Value::String("test".to_string());
        let right = serde_json::Value::String("other".to_string());
        assert!(!engine.evaluate_equals(&left, &right).unwrap());
        
        // Test contains
        let left = serde_json::Value::String("hello world".to_string());
        let right = serde_json::Value::String("world".to_string());
        assert!(engine.evaluate_contains(&left, &right).unwrap());
        
        // Test greater than
        let left = serde_json::Value::Number(10.into());
        let right = serde_json::Value::Number(5.into());
        assert!(engine.evaluate_greater_than(&left, &right).unwrap());
        
        // Test in
        let left = serde_json::Value::String("test".to_string());
        let right = serde_json::Value::Array(vec![
            serde_json::Value::String("test".to_string()),
            serde_json::Value::String("other".to_string()),
        ]);
        assert!(engine.evaluate_in(&left, &right).unwrap());
        
        // Test matches
        let left = serde_json::Value::String("hello world".to_string());
        let right = serde_json::Value::String("hello.*".to_string());
        assert!(engine.evaluate_matches(&left, &right).unwrap());
        
        // Test starts with
        let left = serde_json::Value::String("hello world".to_string());
        let right = serde_json::Value::String("hello".to_string());
        assert!(engine.evaluate_starts_with(&left, &right).unwrap());
        
        // Test ends with
        let left = serde_json::Value::String("hello world".to_string());
        let right = serde_json::Value::String("world".to_string());
        assert!(engine.evaluate_ends_with(&left, &right).unwrap());
    }

    #[test]
    fn test_parameter_validation() {
        let role_store = Arc::new(super::types::InMemoryRoleStore::new());
        let engine = HclPolicyEngine::new(role_store);
        
        // Test string validation
        let value = serde_json::Value::String("test".to_string());
        assert!(engine.validate_parameter_type(&value, &super::ParameterType::String));
        assert!(!engine.validate_parameter_type(&value, &super::ParameterType::Number));
        
        // Test number validation
        let value = serde_json::Value::Number(42.into());
        assert!(engine.validate_parameter_type(&value, &super::ParameterType::Number));
        assert!(!engine.validate_parameter_type(&value, &super::ParameterType::String));
        
        // Test boolean validation
        let value = serde_json::Value::Bool(true);
        assert!(engine.validate_parameter_type(&value, &super::ParameterType::Boolean));
        assert!(!engine.validate_parameter_type(&value, &super::ParameterType::String));
        
        // Test array validation
        let value = serde_json::Value::Array(vec![serde_json::Value::String("test".to_string())]);
        assert!(engine.validate_parameter_type(&value, &super::ParameterType::Array));
        assert!(!engine.validate_parameter_type(&value, &super::ParameterType::String));
        
        // Test object validation
        let value = serde_json::Value::Object(serde_json::Map::new());
        assert!(engine.validate_parameter_type(&value, &super::ParameterType::Object));
        assert!(!engine.validate_parameter_type(&value, &super::ParameterType::String));
    }

    #[tokio::test]
    async fn test_path_matching() {
        let role_store = Arc::new(super::types::InMemoryRoleStore::new());
        let engine = HclPolicyEngine::new(role_store);
        
        let policies = HashMap::new();
        
        // Test exact match
        let policy = ParsedPolicy::new("exact".to_string(), "secret/data".to_string());
        let matching = engine.find_matching_policies(&HashMap::from([("exact".to_string(), policy)]), "secret/data");
        assert_eq!(matching.len(), 1);
        
        // Test wildcard match
        let policy = ParsedPolicy::new("wildcard".to_string(), "secret/*".to_string());
        let matching = engine.find_matching_policies(&HashMap::from([("wildcard".to_string(), policy)]), "secret/data");
        assert_eq!(matching.len(), 1);
        
        // Test no match
        let policy = ParsedPolicy::new("nomatch".to_string(), "secret/*".to_string());
        let matching = engine.find_matching_policies(&HashMap::from([("nomatch".to_string(), policy)]), "public/data");
        assert_eq!(matching.len(), 0);
    }
}
