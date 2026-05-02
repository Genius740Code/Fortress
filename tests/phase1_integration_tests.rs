//! Phase 1 Integration Tests
//!
//! This module contains comprehensive integration tests for all Phase 1 features:
//! - Seal/Unseal mechanism with Shamir Secret Sharing
//! - Advanced Token System with leases, TTL, and revocation
//! - HCL Policy Engine with fine-grained access control

use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use chrono::{DateTime, Utc, Duration};

use fortress_core::{
    seal::{SealManager, SealConfig},
    shamir::ShamirSecretSharing,
    token::{TokenManager, TokenManagerConfig, TokenType, TokenRole, CreateTokenRequest},
    policy_hcl::{HclPolicyEngine, ParsedPolicy, PolicyContext, RoleStore},
    error::{FortressError, Result},
};

/// Test role store for integration tests
struct TestRoleStore {
    roles: Arc<RwLock<HashMap<String, Vec<String>>>>,
}

impl TestRoleStore {
    fn new() -> Self {
        Self {
            roles: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    async fn add_role(&self, entity_id: &str, role: &str) -> Result<()> {
        let mut roles = self.roles.write().await;
        roles.entry(entity_id.to_string())
            .or_insert_with(Vec::new)
            .push(role.to_string());
        Ok(())
    }
}

impl RoleStore for TestRoleStore {
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
        roles.entry(entity_id.to_string())
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

#[cfg(test)]
mod seal_tests {
    use super::*;
    use fortress_core::seal::{SecretShare, MasterKey};

    #[tokio::test]
    async fn test_seal_unseal_complete_workflow() {
        // Create seal manager
        let mut config = SealConfig::default(); // 3 of 5 shares required
        config.threshold = 3;
        config.shares = 5;
        let mut seal_manager = SealManager::new(config);

        // Initialize with master key
        let master_key = seal_manager.generate_master_key().unwrap();
        let shares = seal_manager.initialize_shamir(&master_key).unwrap();

        // Verify seal manager is unsealed
        assert!(!seal_manager.is_sealed());

        // Seal the manager
        seal_manager.seal().unwrap();
        assert!(seal_manager.is_sealed());

        // Try to access master key while sealed (should fail)
        let result = seal_manager.get_master_key();
        assert!(result.is_err());

        // Unseal with sufficient shares
        let unseal_result = seal_manager.unseal(&shares[0..3]).unwrap();
        assert!(unseal_result);

        // Verify manager is unsealed
        assert!(!seal_manager.is_sealed());

        // Verify master key is accessible
        let retrieved_key = seal_manager.get_master_key().unwrap();
        assert_eq!(master_key, retrieved_key);
    }

    #[tokio::test]
    async fn test_shamir_secret_sharing() {
        let shamir = ShamirSecretSharing::new();
        let secret = "test_secret_12345";
        let threshold = 3;
        let num_shares = 5;

        // Split secret
        let shares = shamir.split_secret(secret, threshold, num_shares).unwrap();
        assert_eq!(shares.len(), num_shares);

        // Reconstruct with sufficient shares
        let reconstructed = shamir.reconstruct_secret(&shares[0..3]).unwrap();
        assert_eq!(reconstructed, secret);

        // Try to reconstruct with insufficient shares (should fail)
        let result = shamir.reconstruct_secret(&shares[0..2]);
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_seal_key_rotation() {
        let config = SealConfig::new(3, 5);
        let mut seal_manager = SealManager::new(config);

        // Initialize with master key
        let master_key = seal_manager.generate_master_key().unwrap();
        let shares = seal_manager.initialize_shamir(&master_key).unwrap();

        // Rotate master key
        let new_master_key = seal_manager.generate_master_key().unwrap();
        let new_shares = seal_manager.rotate_master_key(&new_master_key).unwrap();

        // Verify new shares work
        seal_manager.seal().unwrap();
        let unseal_result = seal_manager.unseal(&new_shares[0..3]).unwrap();
        assert!(unseal_result);

        let retrieved_key = seal_manager.get_master_key().unwrap();
        assert_eq!(new_master_key, retrieved_key);
    }

    #[tokio::test]
    async fn test_seal_recovery_keys() {
        let config = SealConfig::new(3, 5);
        let mut seal_manager = SealManager::new(config);

        // Initialize with master key
        let master_key = seal_manager.generate_master_key().unwrap();
        let shares = seal_manager.initialize_shamir(&master_key).unwrap();

        // Generate recovery key
        let recovery_key = seal_manager.generate_recovery_key().unwrap();
        assert!(!recovery_key.is_empty());

        // Use recovery key to unseal
        seal_manager.seal().unwrap();
        let unseal_result = seal_manager.unseal_with_recovery_key(&recovery_key).unwrap();
        assert!(unseal_result);

        let retrieved_key = seal_manager.get_master_key().unwrap();
        assert_eq!(master_key, retrieved_key);
    }
}

#[cfg(test)]
mod token_tests {
    use super::*;
    use fortress_core::token::{TokenInfo, TokenUsageStats, TokenCreationContext};

    #[tokio::test]
    async fn test_token_creation_and_validation() {
        let config = TokenManagerConfig::default();
        let token_manager = TokenManager::new(config);

        // Create a token
        let request = CreateTokenRequest {
            token_type: TokenType::User,
            role: TokenRole::Admin,
            policies: vec!["default".to_string()],
            ttl: Duration::hours(1),
            entity_id: "user123".to_string(),
            metadata: Some(HashMap::new()),
        };

        let token_info = token_manager.create_token(request).await.unwrap();
        assert_eq!(token_info.token.entity_id, "user123");
        assert_eq!(token_info.token.role, TokenRole::Admin);
        assert!(token_info.token.has_policy("default"));

        // Validate the token
        let validation_result = token_manager.validate_token(&token_info.token).await.unwrap();
        assert!(validation_result.valid);
        assert!(!validation_result.expired);
        assert!(!validation_result.revoked);
    }

    #[tokio::test]
    async fn test_token_lease_management() {
        let config = TokenManagerConfig::default();
        let token_manager = TokenManager::new(config);

        // Create a token
        let request = CreateTokenRequest {
            token_type: TokenType::Service,
            role: TokenRole::Operator,
            policies: vec!["default".to_string()],
            ttl: Duration::hours(1),
            entity_id: "service123".to_string(),
            metadata: Some(HashMap::new()),
        };

        let token_info = token_manager.create_token(request).await.unwrap();

        // Create a lease
        let lease_id = token_manager.create_lease(
            &token_info.token,
            "secret/data".to_string(),
            Duration::minutes(30),
            HashMap::new(),
        ).await.unwrap();

        assert!(!lease_id.is_empty());

        // Get lease info
        let lease_info = token_manager.get_lease(&lease_id).await.unwrap();
        assert!(lease_info.is_some());
        assert_eq!(lease_info.unwrap().path, "secret/data");

        // Renew lease
        let renewed_lease = token_manager.renew_lease(&lease_id, Duration::minutes(45)).await.unwrap();
        assert!(renewed_lease.is_some());

        // Revoke lease
        let revoke_result = token_manager.revoke_lease(&lease_id).await.unwrap();
        assert!(revoke_result);

        // Verify lease is revoked
        let lease_info = token_manager.get_lease(&lease_id).await.unwrap();
        assert!(lease_info.is_none());
    }

    #[tokio::test]
    async fn test_token_revocation() {
        let config = TokenManagerConfig::default();
        let token_manager = TokenManager::new(config);

        // Create a token
        let request = CreateTokenRequest {
            token_type: TokenType::User,
            role: TokenRole::Operator,
            policies: vec!["default".to_string()],
            ttl: Duration::hours(1),
            entity_id: "user456".to_string(),
            metadata: Some(HashMap::new()),
        };

        let token_info = token_manager.create_token(request).await.unwrap();

        // Validate token (should be valid)
        let validation_result = token_manager.validate_token(&token_info.token).await.unwrap();
        assert!(validation_result.valid);

        // Revoke token
        let revoke_result = token_manager.revoke_token(&token_info.token.id, "Test revocation").await.unwrap();
        assert!(revoke_result);

        // Validate token again (should be revoked)
        let validation_result = token_manager.validate_token(&token_info.token).await.unwrap();
        assert!(!validation_result.valid);
        assert!(validation_result.revoked);
    }

    #[tokio::test]
    async fn test_token_renewal() {
        let config = TokenManagerConfig::default();
        let token_manager = TokenManager::new(config);

        // Create a token with short TTL
        let request = CreateTokenRequest {
            token_type: TokenType::User,
            role: TokenRole::Operator,
            policies: vec!["default".to_string()],
            ttl: Duration::minutes(30),
            entity_id: "user789".to_string(),
            metadata: Some(HashMap::new()),
        };

        let token_info = token_manager.create_token(request).await.unwrap();

        // Renew token
        let renewed_token = token_manager.renew_token(&token_info.token.id, Duration::hours(2)).await.unwrap();
        assert!(renewed_token.is_some());

        let renewed_info = renewed_token.unwrap();
        assert!(renewed_info.token.expires_at > token_info.token.expires_at);
        assert_eq!(renewed_info.token.entity_id, token_info.token.entity_id);
    }

    #[tokio::test]
    async fn test_token_lookup_and_search() {
        let config = TokenManagerConfig::default();
        let token_manager = TokenManager::new(config);

        // Create multiple tokens
        for i in 0..5 {
            let request = CreateTokenRequest {
                token_type: TokenType::User,
                role: TokenRole::Operator,
                policies: vec!["default".to_string()],
                ttl: Duration::hours(1),
                entity_id: format!("user{}", i),
                metadata: Some(HashMap::new()),
            };
            token_manager.create_token(request).await.unwrap();
        }

        // List tokens
        let tokens = token_manager.list_tokens(None, 10).await.unwrap();
        assert_eq!(tokens.len(), 5);

        // Search for specific entity
        let search_results = token_manager.search_tokens(&"user2".to_string(), None, 10).await.unwrap();
        assert_eq!(search_results.len(), 1);
        assert_eq!(search_results[0].token.entity_id, "user2");
    }
}

#[cfg(test)]
mod policy_tests {
    use super::*;
    use fortress_core::token::{Token, TokenInfo, TokenUsageStats, TokenCreationContext};

    fn create_test_token(entity_id: &str) -> TokenInfo {
        let token = Token::new(
            TokenType::User,
            TokenRole::Admin,
            vec!["default".to_string()],
            Duration::hours(1),
            entity_id.to_string(),
        );

        TokenInfo {
            token: token.clone(),
            display_name: "Test Token".to_string(),
            description: None,
            usage_stats: TokenUsageStats::default(),
            creation_context: TokenCreationContext::default(),
        }
    }

    #[tokio::test]
    async fn test_policy_loading_and_evaluation() {
        let role_store = Arc::new(TestRoleStore::new());
        let engine = HclPolicyEngine::new(role_store);

        // Create a policy
        let mut policy = ParsedPolicy::new("test-policy".to_string(), "secret/*".to_string());
        policy.add_capability("read".to_string());
        policy.add_capability("list".to_string());

        engine.load_policy(policy).await.unwrap();

        // Create context
        let token = create_test_token("user123");
        let context = PolicyContext::new(token, "secret/data".to_string(), "read".to_string());

        // Evaluate policy
        let result = engine.evaluate_policies(&context).await.unwrap();
        assert!(result.allowed);
        assert!(result.allowed_capabilities.contains(&"read".to_string()));
        assert!(result.allowed_capabilities.contains(&"list".to_string()));
    }

    #[tokio::test]
    async fn test_policy_constraints() {
        let role_store = Arc::new(TestRoleStore::new());
        let engine = HclPolicyEngine::new(role_store);

        // Create policy with constraints
        let mut policy = ParsedPolicy::new("constrained-policy".to_string(), "secret/*".to_string());
        policy.add_capability("read".to_string());

        // Add IP constraint
        let constraint = fortress_core::policy_hcl::PolicyConstraint {
            field: "ip".to_string(),
            operator: fortress_core::policy_hcl::ConstraintOperator::Equals,
            value: serde_json::Value::String("192.168.1.1".to_string()),
            description: None,
        };
        policy.add_constraint(constraint);

        engine.load_policy(policy).await.unwrap();

        // Test with matching IP
        let token = create_test_token("user123");
        let mut context = PolicyContext::new(token, "secret/data".to_string(), "read".to_string());
        context.ip_address = Some("192.168.1.1".to_string());

        let result = engine.evaluate_policies(&context).await.unwrap();
        assert!(result.allowed);

        // Test with non-matching IP
        let token = create_test_token("user456");
        let mut context = PolicyContext::new(token, "secret/data".to_string(), "read".to_string());
        context.ip_address = Some("10.0.0.1".to_string());

        let result = engine.evaluate_policies(&context).await.unwrap();
        assert!(!result.allowed);
    }

    #[tokio::test]
    async fn test_policy_parameters() {
        let role_store = Arc::new(TestRoleStore::new());
        let engine = HclPolicyEngine::new(role_store);

        // Create policy with parameters
        let mut policy = ParsedPolicy::new("param-policy".to_string(), "secret/*".to_string());
        policy.add_capability("read".to_string());
        policy.add_required_parameter("environment".to_string(), fortress_core::policy_hcl::ParameterType::String);
        policy.add_allowed_parameter("environment".to_string(), vec!["production".to_string(), "staging".to_string()]);

        engine.load_policy(policy).await.unwrap();

        // Test with valid parameter
        let token = create_test_token("user123");
        let mut context = PolicyContext::new(token, "secret/data".to_string(), "read".to_string());
        context.add_parameter("environment".to_string(), serde_json::Value::String("production".to_string()));

        let result = engine.evaluate_policies(&context).await.unwrap();
        assert!(result.allowed);

        // Test with invalid parameter value
        let token = create_test_token("user456");
        let mut context = PolicyContext::new(token, "secret/data".to_string(), "read".to_string());
        context.add_parameter("environment".to_string(), serde_json::Value::String("development".to_string()));

        let result = engine.evaluate_policies(&context).await.unwrap();
        assert!(!result.allowed);

        // Test with missing required parameter
        let token = create_test_token("user789");
        let context = PolicyContext::new(token, "secret/data".to_string(), "read".to_string());

        let result = engine.evaluate_policies(&context).await.unwrap();
        assert!(!result.allowed);
    }

    #[tokio::test]
    async fn test_role_based_policies() {
        let role_store = Arc::new(TestRoleStore::new());
        
        // Add roles
        role_store.add_role("admin_user", "admin").await.unwrap();
        role_store.add_role("operator_user", "operator").await.unwrap();

        let engine = HclPolicyEngine::new(role_store);

        // Create admin-only policy
        let mut admin_policy = ParsedPolicy::new("admin-policy".to_string(), "admin/*".to_string());
        admin_policy.add_capability("sudo".to_string());

        // Create operator policy
        let mut operator_policy = ParsedPolicy::new("operator-policy".to_string(), "data/*".to_string());
        operator_policy.add_capability("read".to_string());
        operator_policy.add_capability("write".to_string());

        engine.load_policy(admin_policy).await.unwrap();
        engine.load_policy(operator_policy).await.unwrap();

        // Test admin access
        let admin_token = create_test_token("admin_user");
        let admin_context = PolicyContext::new(admin_token, "admin/secrets".to_string(), "sudo".to_string());

        let result = engine.evaluate_policies(&admin_context).await.unwrap();
        assert!(result.allowed);

        // Test operator access (should not have sudo)
        let operator_token = create_test_token("operator_user");
        let operator_context = PolicyContext::new(operator_token, "admin/secrets".to_string(), "sudo".to_string());

        let result = engine.evaluate_policies(&operator_context).await.unwrap();
        assert!(!result.allowed);

        // Test operator access to data (should be allowed)
        let operator_context = PolicyContext::new(operator_token, "data/records".to_string(), "read".to_string());

        let result = engine.evaluate_policies(&operator_context).await.unwrap();
        assert!(result.allowed);
    }

    #[tokio::test]
    async fn test_policy_statistics() {
        let role_store = Arc::new(TestRoleStore::new());
        let engine = HclPolicyEngine::new(role_store);

        // Create and load policies
        let mut policy1 = ParsedPolicy::new("policy1".to_string(), "secret/*".to_string());
        policy1.add_capability("read".to_string());

        let mut policy2 = ParsedPolicy::new("policy2".to_string(), "data/*".to_string());
        policy2.add_capability("write".to_string());

        engine.load_policy(policy1).await.unwrap();
        engine.load_policy(policy2).await.unwrap();

        // Evaluate policies multiple times
        let token = create_test_token("user123");
        let context1 = PolicyContext::new(token.clone(), "secret/data".to_string(), "read".to_string());
        let context2 = PolicyContext::new(token, "data/records".to_string(), "write".to_string());

        for _ in 0..5 {
            engine.evaluate_policies(&context1).await.unwrap();
            engine.evaluate_policies(&context2).await.unwrap();
        }

        // Check statistics
        let stats = engine.get_statistics().await;
        assert_eq!(stats.total_policies, 2);
        assert_eq!(stats.total_evaluations, 10);
        assert_eq!(stats.allowed_evaluations, 10);
        assert_eq!(stats.denied_evaluations, 0);
        assert!(stats.policy_usage.contains_key("policy1"));
        assert!(stats.policy_usage.contains_key("policy2"));
    }
}

#[cfg(test)]
mod integration_tests {
    use super::*;

    #[tokio::test]
    async fn test_complete_phase1_workflow() {
        // Setup all components
        let seal_config = SealConfig::new(3, 5);
        let mut seal_manager = SealManager::new(seal_config);

        let token_config = TokenManagerConfig::default();
        let token_manager = TokenManager::new(token_config);

        let role_store = Arc::new(TestRoleStore::new());
        let policy_engine = HclPolicyEngine::new(role_store);

        // Step 1: Initialize seal manager
        let master_key = seal_manager.generate_master_key().unwrap();
        let shares = seal_manager.initialize_shamir(&master_key).unwrap();
        assert!(!seal_manager.is_sealed());

        // Step 2: Create policies
        let mut admin_policy = ParsedPolicy::new("admin-policy".to_string(), "admin/*".to_string());
        admin_policy.add_capability("read".to_string());
        admin_policy.add_capability("write".to_string());
        admin_policy.add_capability("sudo".to_string());

        let mut user_policy = ParsedPolicy::new("user-policy".to_string(), "user/*".to_string());
        user_policy.add_capability("read".to_string());

        policy_engine.load_policy(admin_policy).await.unwrap();
        policy_engine.load_policy(user_policy).await.unwrap();

        // Step 3: Setup roles
        role_store.add_role("admin_user", "admin").await.unwrap();
        role_store.add_role("regular_user", "user").await.unwrap();

        // Step 4: Create tokens
        let admin_request = CreateTokenRequest {
            token_type: TokenType::User,
            role: TokenRole::Admin,
            policies: vec!["admin-policy".to_string()],
            ttl: Duration::hours(2),
            entity_id: "admin_user".to_string(),
            metadata: Some(HashMap::new()),
        };

        let user_request = CreateTokenRequest {
            token_type: TokenType::User,
            role: TokenRole::Operator,
            policies: vec!["user-policy".to_string()],
            ttl: Duration::hours(1),
            entity_id: "regular_user".to_string(),
            metadata: Some(HashMap::new()),
        };

        let admin_token = token_manager.create_token(admin_request).await.unwrap();
        let user_token = token_manager.create_token(user_request).await.unwrap();

        // Step 5: Test policy evaluation
        let admin_context = PolicyContext::new(admin_token, "admin/secrets".to_string(), "read".to_string());
        let user_context = PolicyContext::new(user_token, "user/data".to_string(), "read".to_string());

        let admin_result = policy_engine.evaluate_policies(&admin_context).await.unwrap();
        let user_result = policy_engine.evaluate_policies(&user_context).await.unwrap();

        assert!(admin_result.allowed);
        assert!(user_result.allowed);

        // Step 6: Test unauthorized access
        let unauthorized_context = PolicyContext::new(user_token.clone(), "admin/secrets".to_string(), "read".to_string());
        let unauthorized_result = policy_engine.evaluate_policies(&unauthorized_context).await.unwrap();
        assert!(!unauthorized_result.allowed);

        // Step 7: Create leases
        let lease_id = token_manager.create_lease(
            &user_token.token,
            "user/data/record123".to_string(),
            Duration::minutes(30),
            HashMap::new(),
        ).await.unwrap();

        assert!(!lease_id.is_empty());

        // Step 8: Test token validation
        let admin_validation = token_manager.validate_token(&admin_token.token).await.unwrap();
        let user_validation = token_manager.validate_token(&user_token.token).await.unwrap();

        assert!(admin_validation.valid);
        assert!(user_validation.valid);

        // Step 9: Seal and unseal test
        seal_manager.seal().unwrap();
        assert!(seal_manager.is_sealed());

        let unseal_result = seal_manager.unseal(&shares[0..3]).unwrap();
        assert!(unseal_result);
        assert!(!seal_manager.is_sealed());

        // Step 10: Cleanup
        let revoke_admin = token_manager.revoke_token(&admin_token.token.id, "Test cleanup").await.unwrap();
        let revoke_user = token_manager.revoke_token(&user_token.token.id, "Test cleanup").await.unwrap();
        let revoke_lease = token_manager.revoke_lease(&lease_id).await.unwrap();

        assert!(revoke_admin);
        assert!(revoke_user);
        assert!(revoke_lease);

        // Verify cleanup
        let admin_validation_after = token_manager.validate_token(&admin_token.token).await.unwrap();
        let user_validation_after = token_manager.validate_token(&user_token.token).await.unwrap();

        assert!(!admin_validation_after.valid);
        assert!(!user_validation_after.valid);

        let lease_after = token_manager.get_lease(&lease_id).await.unwrap();
        assert!(lease_after.is_none());
    }

    #[tokio::test]
    async fn test_error_handling_and_recovery() {
        // Test error handling across all Phase 1 components
        
        // Seal errors
        let seal_config = SealConfig::new(3, 5);
        let mut seal_manager = SealManager::new(seal_config);

        // Try to unseal with insufficient shares
        let master_key = seal_manager.generate_master_key().unwrap();
        let shares = seal_manager.initialize_shamir(&master_key).unwrap();
        seal_manager.seal().unwrap();

        let result = seal_manager.unseal(&shares[0..2]);
        assert!(result.is_err());

        // Token errors
        let token_config = TokenManagerConfig::default();
        let token_manager = TokenManager::new(token_config);

        // Try to validate non-existent token
        let fake_token = token_manager.create_token(CreateTokenRequest {
            token_type: TokenType::User,
            role: TokenRole::Operator,
            policies: vec!["default".to_string()],
            ttl: Duration::hours(1),
            entity_id: "fake_user".to_string(),
            metadata: Some(HashMap::new()),
        }).await.unwrap();

        token_manager.revoke_token(&fake_token.token.id, "Test").await.unwrap();
        let validation_result = token_manager.validate_token(&fake_token.token).await.unwrap();
        assert!(!validation_result.valid);
        assert!(validation_result.revoked);

        // Policy errors
        let role_store = Arc::new(TestRoleStore::new());
        let engine = HclPolicyEngine::new(role_store);

        // Try to evaluate with no matching policies
        let token = token_manager.create_token(CreateTokenRequest {
            token_type: TokenType::User,
            role: TokenRole::Operator,
            policies: vec!["default".to_string()],
            ttl: Duration::hours(1),
            entity_id: "test_user".to_string(),
            metadata: Some(HashMap::new()),
        }).await.unwrap();

        let context = PolicyContext::new(token, "unknown/path".to_string(), "read".to_string());
        let result = engine.evaluate_policies(&context).await.unwrap();
        assert!(!result.allowed);
        assert!(result.reason.unwrap().contains("No matching policies"));
    }

    #[tokio::test]
    async fn test_performance_and_scalability() {
        // Test performance characteristics of Phase 1 components
        
        let token_config = TokenManagerConfig::default();
        let token_manager = TokenManager::new(token_config);

        let role_store = Arc::new(TestRoleStore::new());
        let engine = HclPolicyEngine::new(role_store);

        // Create multiple policies
        for i in 0..10 {
            let mut policy = ParsedPolicy::new(format!("policy-{}", i), format!("path{}/*", i));
            policy.add_capability("read".to_string());
            engine.load_policy(policy).await.unwrap();
        }

        // Create multiple tokens
        let mut tokens = Vec::new();
        for i in 0..100 {
            let request = CreateTokenRequest {
                token_type: TokenType::User,
                role: TokenRole::Operator,
                policies: vec![format!("policy-{}", i % 10)],
                ttl: Duration::hours(1),
                entity_id: format!("user{}", i),
                metadata: Some(HashMap::new()),
            };
            let token = token_manager.create_token(request).await.unwrap();
            tokens.push(token);
        }

        // Measure policy evaluation performance
        let start = std::time::Instant::now();
        for token in &tokens {
            let context = PolicyContext::new(token.clone(), "path5/data".to_string(), "read".to_string());
            engine.evaluate_policies(&context).await.unwrap();
        }
        let duration = start.elapsed();

        // Should complete 100 evaluations in reasonable time
        assert!(duration.as_millis() < 5000); // Less than 5 seconds

        // Check statistics
        let stats = engine.get_statistics().await;
        assert_eq!(stats.total_evaluations, 100);
        assert!(stats.avg_evaluation_time_ms < 50.0); // Average less than 50ms
    }
}
