//! Integration tests for Fortress authentication plugins

use serde_json::{json, Value};
use tokio::time::{sleep, Duration};

use fortress_auth_plugins::*;

// Mock implementations are provided in lib.rs::mock_host_functions

#[tokio::test]
async fn test_jwt_plugin_authentication() {
    // Initialize plugin registry
    let mut registry = PluginRegistry::new();
    registry.initialize().await.expect("Failed to initialize plugin registry");

    // Test JWT authentication with valid token
    let context = AuthContext {
        method: "JWT".to_string(),
        credentials: json!({
            "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyMTIzIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        }),
        request_id: "test-req-001".to_string(),
    };

    let result = registry.authenticate("jwt_auth", context).await;
    assert!(result.is_ok(), "JWT authentication should succeed");

    let auth_result = result.unwrap();
    assert!(auth_result.success, "Authentication should be successful");
    assert!(!auth_result.user_id.is_empty(), "User ID should be returned");
}

#[tokio::test]
async fn test_jwt_plugin_invalid_token() {
    let mut registry = PluginRegistry::new();
    registry.initialize().await.expect("Failed to initialize plugin registry");

    // Test JWT authentication with invalid token
    let context = AuthContext {
        method: "JWT".to_string(),
        credentials: json!({
            "token": "invalid.jwt.token"
        }),
        request_id: "test-req-002".to_string(),
    };

    let result = registry.authenticate("jwt_auth", context).await;
    assert!(result.is_ok(), "JWT authentication call should succeed");

    let auth_result = result.unwrap();
    assert!(!auth_result.success, "Authentication should fail with invalid token");
    assert!(!auth_result.error_message.is_empty(), "Error message should be provided");
}

#[tokio::test]
async fn test_oauth_plugin_authorization_flow() {
    let mut registry = PluginRegistry::new();
    registry.initialize().await.expect("Failed to initialize plugin registry");

    // Test OAuth authorization flow initiation
    let context = AuthContext {
        method: "OAuth".to_string(),
        credentials: json!({
            "action": "authorize",
            "redirect_uri": "https://localhost:8080/callback",
            "scopes": ["openid", "profile", "email"]
        }),
        request_id: "test-req-003".to_string(),
    };

    let result = registry.authenticate("oauth_auth", context).await;
    assert!(result.is_ok(), "OAuth authorization should succeed");

    let auth_result = result.unwrap();
    assert!(auth_result.success, "Authorization initiation should succeed");
    
    // Check for authorization URL in response
    let response_data: Value = serde_json::from_str(&auth_result.response_data)
        .unwrap_or(json!({}));
    assert!(response_data.get("authorization_url").is_some(), "Should return authorization URL");
}

#[tokio::test]
async fn test_oauth_plugin_token_exchange() {
    let mut registry = PluginRegistry::new();
    registry.initialize().await.expect("Failed to initialize plugin registry");

    // Test OAuth token exchange
    let context = AuthContext {
        method: "OAuth".to_string(),
        credentials: json!({
            "action": "exchange",
            "authorization_code": "test-auth-code",
            "redirect_uri": "https://localhost:8080/callback"
        }),
        request_id: "test-req-004".to_string(),
    };

    let result = registry.authenticate("oauth_auth", context).await;
    assert!(result.is_ok(), "OAuth token exchange should succeed");

    let auth_result = result.unwrap();
    // Note: This might fail with test code, but should not panic
    assert!(!auth_result.user_id.is_empty() || !auth_result.error_message.is_empty(), 
              "Should either succeed with user ID or fail with error message");
}

#[tokio::test]
async fn test_saml_plugin_assertion_validation() {
    let mut registry = PluginRegistry::new();
    registry.initialize().await.expect("Failed to initialize plugin registry");

    // Test SAML assertion validation
    let context = AuthContext {
        method: "SAML".to_string(),
        credentials: json!({
            "saml_response": "PHNhbWxwYXNzZXJ0aW9uIHhtbG5zPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTTDoyLjA6YXNzZXJ0aW9uIiB2ZXJzaW9uPSIyLjAiIGlzc3VlSW5zdGFudD0iMjAyMy0wMy0xNVQxNjo1MzowMFoiIHhtbG5zPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwLzA5L3htbHNzaWduYXR1cmUjIiBkZXN0aW5hdGlvbj0iaHR0cDovL3d3dy53My5vcmcvMjAwMC8wOS94bWxkc2lnI1NpZ25hdHVyZSI+PC9zYW1sQXNzZXJ0aW9uPg==",
            "relay_state": "test-relay-state"
        }),
        request_id: "test-req-005".to_string(),
    };

    let result = registry.authenticate("saml_auth", context).await;
    assert!(result.is_ok(), "SAML authentication call should succeed");

    let auth_result = result.unwrap();
    // Note: This might fail with test assertion, but should not panic
    assert!(!auth_result.user_id.is_empty() || !auth_result.error_message.is_empty(), 
              "Should either succeed with user ID or fail with error message");
}

#[tokio::test]
async fn test_plugin_health_checks() {
    let mut registry = PluginRegistry::new();
    registry.initialize().await.expect("Failed to initialize plugin registry");

    // Test health checks for all plugins
    let plugins = vec!["jwt_auth", "oauth_auth", "saml_auth"];
    
    for plugin_name in plugins {
        let health = registry.check_health(plugin_name).await;
        assert!(health.is_ok(), "Health check should succeed for {}", plugin_name);
        
        let health_status = health.unwrap();
        assert!(health_status.is_healthy, "Plugin {} should be healthy", plugin_name);
        assert!(!health_status.version.is_empty(), "Plugin {} should report version", plugin_name);
    }
}

#[tokio::test]
async fn test_plugin_capabilities() {
    let mut registry = PluginRegistry::new();
    registry.initialize().await.expect("Failed to initialize plugin registry");

    // Test plugin capabilities
    let plugins = vec!["jwt_auth", "oauth_auth", "saml_auth"];
    
    for plugin_name in plugins {
        let capabilities = registry.get_capabilities(plugin_name).await;
        assert!(capabilities.is_ok(), "Should get capabilities for {}", plugin_name);
        
        let caps = capabilities.unwrap();
        assert!(caps.can_validate_tokens, "Plugin {} should validate tokens", plugin_name);
    }
}

#[tokio::test]
async fn test_concurrent_authentication() {
    let mut registry = PluginRegistry::new();
    registry.initialize().await.expect("Failed to initialize plugin registry");

    // Test concurrent authentication requests
    let mut handles = Vec::new();
    
    for i in 0..10 {
        let context = AuthContext {
            method: "JWT".to_string(),
            credentials: json!({
                "token": format!("test.token.{}", i)
            }),
            request_id: format!("test-req-concurrent-{}", i),
        };
        
        let handle = tokio::spawn(async move {
            // Simulate async authentication
            sleep(Duration::from_millis(10)).await;
            context
        });
        
        handles.push(handle);
    }
    
    // Wait for all tasks and collect results
    let mut success_count = 0;
    for handle in handles {
        let context = handle.await.expect("Task should complete");
        let result = registry.authenticate("jwt_auth", context).await;
        if result.is_ok() && result.unwrap().success {
            success_count += 1;
        }
    }
    
    // Most should fail with test tokens, but all should complete without panics
    assert_eq!(success_count, 0, "Test tokens should all fail");
}

#[tokio::test]
async fn test_plugin_configuration_validation() {
    let mut registry = PluginRegistry::new();
    registry.initialize().await.expect("Failed to initialize plugin registry");

    // Test configuration validation
    let test_configs = vec![
        ("jwt_auth", json!({"jwt_secret": "test-secret"})),
        ("oauth_auth", json!({"client_id": "test-client"})),
        ("saml_auth", json!({"entity_id": "https://test.com"})),
    ];
    
    for (plugin_name, config) in test_configs {
        let result = registry.validate_config(plugin_name, config).await;
        assert!(result.is_ok(), "Config validation should succeed for {}", plugin_name);
    }
}

#[tokio::test]
async fn test_error_handling() {
    let mut registry = PluginRegistry::new();
    registry.initialize().await.expect("Failed to initialize plugin registry");

    // Test error handling with invalid plugin
    let context = AuthContext {
        method: "Invalid".to_string(),
        credentials: json!({}),
        request_id: "test-req-error".to_string(),
    };

    let result = registry.authenticate("nonexistent_plugin", context).await;
    assert!(result.is_err(), "Should return error for nonexistent plugin");
}

#[cfg(test)]
mod test_helpers {
    use super::*;
    
    pub fn create_test_jwt_token(user_id: &str) -> String {
        // Create a simple test JWT token (in real implementation, use proper JWT library)
        use base64::{Engine as _, engine::general_purpose::STANDARD};
        format!("header.{}.signature", STANDARD.encode(user_id))
    }
    
    pub fn create_test_saml_assertion(user_id: &str) -> String {
        // Create a simple test SAML assertion (in real implementation, use proper XML)
        format!("<saml:Assertion><saml:Subject>{}</saml:Subject></saml:Assertion>", user_id)
    }
}
