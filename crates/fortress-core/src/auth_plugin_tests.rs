//! Plugin-Based Authentication Tests
//!
//! Comprehensive test suite for the plugin-based authentication system
//! including plugin loading, hot-swapping, and authentication flows.

use crate::auth_plugin::*;
use crate::auth_plugin_manager::*;
use crate::auth_service::*;
use crate::wasm_runtime::*;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tempfile::TempDir;
use tokio::time::{sleep, Duration};
use tracing::{info, warn, debug};

/// Test configuration for plugin system
#[derive(Debug, Clone)]
struct TestConfig {
    temp_dir: TempDir,
    plugin_directory: String,
}

impl TestConfig {
    fn new() -> Self {
        Self {
            temp_dir: TempDir::new().expect("Failed to create temp directory"),
            plugin_directory: Self::temp_dir.path().to_string_lossy().to_string(),
        }
    }
}

/// Mock authentication request builder
#[derive(Debug, Clone)]
struct AuthRequestBuilder {
    method: AuthMethod,
    username: Option<String>,
    password: Option<String>,
    token: Option<String>,
    authorization_code: Option<String>,
    state: Option<String>,
    redirect_uri: Option<String>,
    saml_assertion: Option<String>,
    ip_address: Option<String>,
    user_agent: Option<String>,
    device_fingerprint: Option<String>,
}

impl AuthRequestBuilder {
    fn new() -> Self {
        Self {
            method: AuthMethod::JWT,
            username: None,
            password: None,
            token: None,
            authorization_code: None,
            state: None,
            redirect_uri: None,
            saml_assertion: None,
            ip_address: None,
            user_agent: None,
            device_fingerprint: None,
        }
    }

    fn with_method(mut self, method: AuthMethod) -> Self {
        self.method = method;
        self
    }

    fn with_credentials(mut self, username: &str, password: &str) -> Self {
        self.username = Some(username.to_string());
        self.password = Some(password.to_string());
        self
    }

    fn with_token(mut self, token: &str) -> Self {
        self.token = Some(token.to_string());
        self
    }

    fn with_oauth_code(mut self, code: &str, state: &str, redirect_uri: &str) -> Self {
        self.method = AuthMethod::OAuth;
        self.authorization_code = Some(code.to_string());
        self.state = Some(state.to_string());
        self.redirect_uri = Some(redirect_uri.to_string());
        self
    }

    fn with_saml_assertion(mut self, assertion: &str) -> Self {
        self.method = AuthMethod::SAML;
        self.saml_assertion = Some(assertion.to_string());
        self
    }

    fn with_context(mut self, ip_address: &str, user_agent: &str, device_fingerprint: &str) -> Self {
        self.ip_address = Some(ip_address.to_string());
        self.user_agent = Some(user_agent.to_string());
        self.device_fingerprint = Some(device_fingerprint.to_string());
        self
    }

    fn build(self) -> AuthRequest {
        AuthRequest {
            method: self.method.clone(),
            credentials: AuthCredentials {
                username: self.username.clone(),
                password: self.password.clone(),
                token: self.token.clone(),
                authorization_code: self.authorization_code.clone(),
                state: self.state.clone(),
                redirect_uri: self.redirect_uri.clone(),
                saml_assertion: self.saml_assertion.clone(),
                api_key: None,
                additional_data: HashMap::new(),
            },
            context: AuthContext {
                ip_address: self.ip_address.clone(),
                user_agent: self.user_agent.clone(),
                timestamp: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs(),
                device_fingerprint: self.device_fingerprint.clone(),
                request_id: uuid::Uuid::new_v4().to_string(),
            },
        }
    }
}

/// Test plugin metadata
fn create_test_plugin_metadata(name: &str, methods: Vec<AuthMethod>) -> AuthPluginMetadata {
    AuthPluginMetadata {
        name: name.to_string(),
        version: "1.0.0".to_string(),
        description: format!("Test {} plugin", name),
        author: "Test Suite".to_string(),
        supported_methods: methods,
        required_config: vec!["test_config".to_string()],
        optional_config: vec!["test_option".to_string()],
        capabilities: AuthPluginCapabilities {
            can_generate_tokens: true,
            can_validate_tokens: true,
            can_refresh_tokens: true,
            can_logout: true,
            supports_mfa: false,
            supports_rbac: false,
            supports_tenants: false,
            supports_sessions: true,
        },
    }
}

/// Create mock JWT plugin for testing
fn create_mock_jwt_plugin() -> Vec<u8> {
    // Simplified WASM binary for testing
    // In a real implementation, this would be compiled from Rust
    vec![
        // Mock WASM header
        0x00, 0x61, 0x73, 0x6d, 0x00, 0x00, 0x00, // Magic number for WASM
        // Mock function exports
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        // Mock data section
        0x54, 0x65, 0x73, 0x74, 0x74, 0x69, 0x63, // "Test data"
        0x6f, 0x72, 0x6f, 0x72, 0x6f, 0x2e, 0x20, // "for testing"
    ]
}

/// Create mock OAuth plugin for testing
fn create_mock_oauth_plugin() -> Vec<u8> {
    vec![
        0x00, 0x61, 0x73, 0x6d, 0x00, 0x00, 0x00, 0x00,
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x54, 0x65, 0x73, 0x74, 0x74, 0x69, 0x63,
        0x6f, 0x72, 0x6f, 0x72, 0x6f, 0x2e, 0x20,
    ]
}

/// Create mock SAML plugin for testing
fn create_mock_saml_plugin() -> Vec<u8> {
    vec![
        0x00, 0x61, 0x73, 0x6d, 0x00, 0x00, 0x00, 0x00,
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x54, 0x65, 0x73, 0x74, 0x74, 0x69, 0x63,
        0x6f, 0x72, 0x6f, 0x72, 0x6f, 0x2e, 0x20,
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_plugin_manager_creation() {
        let config = TestConfig::new();
        let plugin_config = AuthPluginManagerConfig {
            plugin_directory: config.plugin_directory.clone(),
            default_method: AuthMethod::JWT,
            enable_hot_reload: false,
            health_check_interval: 30,
            max_plugins: 5,
        };

        let manager = HotSwappableAuthPluginManager::new(plugin_config).await;
        assert!(manager.is_ok());
    }

    #[tokio::test]
    async fn test_plugin_registration() {
        let config = TestConfig::new();
        let plugin_config = AuthPluginManagerConfig {
            plugin_directory: config.plugin_directory.clone(),
            default_method: AuthMethod::JWT,
            enable_hot_reload: false,
            health_check_interval: 30,
            max_plugins: 5,
        };

        let manager = HotSwappableAuthPluginManager::new(plugin_config).await.unwrap();
        
        // Create mock plugin files
        let jwt_plugin_path = format!("{}/jwt_plugin.wasm", config.plugin_directory);
        let oauth_plugin_path = format!("{}/oauth_plugin.wasm", config.plugin_directory);
        let saml_plugin_path = format!("{}/saml_plugin.wasm", config.plugin_directory);

        tokio::fs::write(&jwt_plugin_path, create_mock_jwt_plugin()).await.unwrap();
        tokio::fs::write(&oauth_plugin_path, create_mock_oauth_plugin()).await.unwrap();
        tokio::fs::write(&saml_plugin_path, create_mock_saml_plugin()).await.unwrap();

        // Create metadata files
        let jwt_metadata = create_test_plugin_metadata("jwt", vec![AuthMethod::JWT, AuthMethod::Basic]);
        let oauth_metadata = create_test_plugin_metadata("oauth", vec![AuthMethod::OAuth]);
        let saml_metadata = create_test_plugin_metadata("saml", vec![AuthMethod::SAML]);

        tokio::fs::write(
            format!("{}/jwt_plugin.json", config.plugin_directory),
            serde_json::to_string(&jwt_metadata).unwrap()
        ).await.unwrap();

        tokio::fs::write(
            format!("{}/oauth_plugin.json", config.plugin_directory),
            serde_json::to_string(&oauth_metadata).unwrap()
        ).await.unwrap();

        tokio::fs::write(
            format!("{}/saml_plugin.json", config.plugin_directory),
            serde_json::to_string(&saml_metadata).unwrap()
        ).await.unwrap();

        // Scan and load plugins
        sleep(Duration::from_millis(100)).await;
        
        let plugins = manager.list_registered_plugins().await;
        assert_eq!(plugins.len(), 3);

        let loaded_plugins = manager.list_loaded_plugins().await;
        assert_eq!(loaded_plugins.len(), 0); // Not loaded yet

        // Load JWT plugin
        let result = manager.load_plugin("jwt_plugin").await;
        assert!(result.is_ok());

        let loaded_plugins = manager.list_loaded_plugins().await;
        assert_eq!(loaded_plugins.len(), 1);
        assert!(loaded_plugins.contains(&"jwt_plugin".to_string()));
    }

    #[tokio::test]
    async fn test_jwt_authentication() {
        let config = TestConfig::new();
        let plugin_config = AuthPluginManagerConfig {
            plugin_directory: config.plugin_directory.clone(),
            default_method: AuthMethod::JWT,
            enable_hot_reload: false,
            health_check_interval: 30,
            max_plugins: 5,
        };

        let manager = HotSwappableAuthPluginManager::new(plugin_config).await.unwrap();
        
        // Setup JWT plugin
        let jwt_plugin_path = format!("{}/jwt_plugin.wasm", config.plugin_directory);
        tokio::fs::write(&jwt_plugin_path, create_mock_jwt_plugin()).await.unwrap();
        let jwt_metadata = create_test_plugin_metadata("jwt", vec![AuthMethod::JWT, AuthMethod::Basic]);
        tokio::fs::write(
            format!("{}/jwt_plugin.json", config.plugin_directory),
            serde_json::to_string(&jwt_metadata).unwrap()
        ).await.unwrap();

        manager.load_plugin("jwt_plugin").await.unwrap();

        // Test JWT authentication
        let request = AuthRequestBuilder::new()
            .with_method(AuthMethod::JWT)
            .with_credentials("testuser", "testpass")
            .with_context("127.0.0.1", "test-agent", "test-fingerprint")
            .build();

        let result = manager.authenticate(request).await;
        assert!(result.is_ok());
        
        let auth_result = result.unwrap();
        assert!(auth_result.success);
        assert!(auth_result.user_info.is_some());
        assert_eq!(auth_result.user_info.as_ref().unwrap().username, "testuser");
        assert!(auth_result.token.is_some());
    }

    #[tokio::test]
    async fn test_oauth_authentication() {
        let config = TestConfig::new();
        let plugin_config = AuthPluginManagerConfig {
            plugin_directory: config.plugin_directory.clone(),
            default_method: AuthMethod::OAuth,
            enable_hot_reload: false,
            health_check_interval: 30,
            max_plugins: 5,
        };

        let manager = HotSwappableAuthPluginManager::new(plugin_config).await.unwrap();
        
        // Setup OAuth plugin
        let oauth_plugin_path = format!("{}/oauth_plugin.wasm", config.plugin_directory);
        tokio::fs::write(&oauth_plugin_path, create_mock_oauth_plugin()).await.unwrap();
        let oauth_metadata = create_test_plugin_metadata("oauth", vec![AuthMethod::OAuth]);
        tokio::fs::write(
            format!("{}/oauth_plugin.json", config.plugin_directory),
            serde_json::to_string(&oauth_metadata).unwrap()
        ).await.unwrap();

        manager.load_plugin("oauth_plugin").await.unwrap();

        // Test OAuth authentication
        let request = AuthRequestBuilder::new()
            .with_method(AuthMethod::OAuth)
            .with_oauth_code("test-code", "test-state", "https://example.com/callback")
            .with_context("127.0.0.1", "test-agent", "test-fingerprint")
            .build();

        let result = manager.authenticate(request).await;
        assert!(result.is_ok());
        
        let auth_result = result.unwrap();
        assert!(auth_result.success);
        assert!(auth_result.user_info.is_some());
        assert!(auth_result.token.is_some());
    }

    #[tokio::test]
    async fn test_saml_authentication() {
        let config = TestConfig::new();
        let plugin_config = AuthPluginManagerConfig {
            plugin_directory: config.plugin_directory.clone(),
            default_method: AuthMethod::SAML,
            enable_hot_reload: false,
            health_check_interval: 30,
            max_plugins: 5,
        };

        let manager = HotSwappableAuthPluginManager::new(plugin_config).await.unwrap();
        
        // Setup SAML plugin
        let saml_plugin_path = format!("{}/saml_plugin.wasm", config.plugin_directory);
        tokio::fs::write(&saml_plugin_path, create_mock_saml_plugin()).await.unwrap();
        let saml_metadata = create_test_plugin_metadata("saml", vec![AuthMethod::SAML]);
        tokio::fs::write(
            format!("{}/saml_plugin.json", config.plugin_directory),
            serde_json::to_string(&saml_metadata).unwrap()
        ).await.unwrap();

        manager.load_plugin("saml_plugin").await.unwrap();

        // Test SAML authentication
        let request = AuthRequestBuilder::new()
            .with_method(AuthMethod::SAML)
            .with_saml_assertion("<saml_assertion>test</saml_assertion>")
            .with_context("127.0.0.1", "test-agent", "test-fingerprint")
            .build();

        let result = manager.authenticate(request).await;
        assert!(result.is_ok());
        
        let auth_result = result.unwrap();
        assert!(auth_result.success);
        assert!(auth_result.user_info.is_some());
        assert_eq!(auth_result.user_info.as_ref().unwrap().username, "testuser");
    }

    #[tokio::test]
    async fn test_token_validation() {
        let config = TestConfig::new();
        let plugin_config = AuthPluginManagerConfig {
            plugin_directory: config.plugin_directory.clone(),
            default_method: AuthMethod::JWT,
            enable_hot_reload: false,
            health_check_interval: 30,
            max_plugins: 5,
        };

        let manager = HotSwappableAuthPluginManager::new(plugin_config).await.unwrap();
        
        // Setup JWT plugin
        let jwt_plugin_path = format!("{}/jwt_plugin.wasm", config.plugin_directory);
        tokio::fs::write(&jwt_plugin_path, create_mock_jwt_plugin()).await.unwrap();
        let jwt_metadata = create_test_plugin_metadata("jwt", vec![AuthMethod::JWT, AuthMethod::Basic]);
        tokio::fs::write(
            format!("{}/jwt_plugin.json", config.plugin_directory),
            serde_json::to_string(&jwt_metadata).unwrap()
        ).await.unwrap();

        manager.load_plugin("jwt_plugin").await.unwrap();

        // Test token validation
        let result = manager.auth_service.validate_token("test-token", &AuthRequestBuilder::new()
            .with_context("127.0.0.1", "test-agent", "test-fingerprint")
            .build().context
        ).await;

        assert!(result.is_ok());
        
        let user_info = result.unwrap();
        assert_eq!(user_info.username, "testuser");
    }

    #[tokio::test]
    async fn test_plugin_hot_swapping() {
        let config = TestConfig::new();
        let plugin_config = AuthPluginManagerConfig {
            plugin_directory: config.plugin_directory.clone(),
            default_method: AuthMethod::JWT,
            enable_hot_reload: true,
            health_check_interval: 1, // Fast health checks
            max_plugins: 5,
        };

        let manager = HotSwappableAuthPluginManager::new(plugin_config).await.unwrap();
        
        // Setup initial JWT plugin
        let jwt_plugin_path = format!("{}/jwt_plugin.wasm", config.plugin_directory);
        tokio::fs::write(&jwt_plugin_path, create_mock_jwt_plugin()).await.unwrap();
        let jwt_metadata = create_test_plugin_metadata("jwt", vec![AuthMethod::JWT, AuthMethod::Basic]);
        tokio::fs::write(
            format!("{}/jwt_plugin.json", config.plugin_directory),
            serde_json::to_string(&jwt_metadata).unwrap()
        ).await.unwrap();

        manager.load_plugin("jwt_plugin").await.unwrap();

        // Test initial authentication
        let request = AuthRequestBuilder::new()
            .with_method(AuthMethod::JWT)
            .with_credentials("testuser", "testpass")
            .build();

        let result1 = manager.authenticate(request).await;
        assert!(result1.is_ok());
        assert!(result1.as_ref().unwrap().success);

        // Create updated plugin (new version)
        let updated_jwt_metadata = create_test_plugin_metadata("jwt", vec![AuthMethod::JWT, AuthMethod::Basic]);
        tokio::fs::write(
            format!("{}/jwt_plugin_v2.json", config.plugin_directory),
            serde_json::to_string(&updated_jwt_metadata).unwrap()
        ).await.unwrap();

        // Hot-swap plugin
        let reload_request = PluginReloadRequest {
            plugin_name: "jwt_plugin".to_string(),
            force: true,
            reason: "Testing hot-swap".to_string(),
        };

        let reload_result = manager.reload_plugin(reload_request).await;
        assert!(reload_result.is_ok());

        // Wait for reload to complete
        sleep(Duration::from_millis(100)).await;

        // Test authentication with new plugin
        let result2 = manager.authenticate(request).await;
        assert!(result2.is_ok());
        assert!(result2.as_ref().unwrap().success);
    }

    #[tokio::test]
    async fn test_service_integration() {
        let config = TestConfig::new();
        let plugin_config = AuthPluginManagerConfig {
            plugin_directory: config.plugin_directory.clone(),
            default_method: AuthMethod::JWT,
            enable_hot_reload: false,
            health_check_interval: 30,
            max_plugins: 5,
        };

        let manager = HotSwappableAuthPluginManager::new(plugin_config).await.unwrap();
        
        // Setup JWT plugin
        let jwt_plugin_path = format!("{}/jwt_plugin.wasm", config.plugin_directory);
        tokio::fs::write(&jwt_plugin_path, create_mock_jwt_plugin()).await.unwrap();
        let jwt_metadata = create_test_plugin_metadata("jwt", vec![AuthMethod::JWT, AuthMethod::Basic]);
        tokio::fs::write(
            format!("{}/jwt_plugin.json", config.plugin_directory),
            serde_json::to_string(&jwt_metadata).unwrap()
        ).await.unwrap();

        manager.load_plugin("jwt_plugin").await.unwrap();

        // Create auth service
        let service_config = AuthServiceConfig::default();
        let auth_service = Arc::new(PluginAuthService::new(service_config).await.unwrap());

        // Test authentication through service
        let request = AuthRequestBuilder::new()
            .with_method(AuthMethod::JWT)
            .with_credentials("testuser", "testpass")
            .build();

        let result = auth_service.authenticate(request, &AuthRequestBuilder::new()
            .with_context("127.0.0.1", "test-agent", "test-fingerprint")
            .build().context
        ).await;

        assert!(result.is_ok());
        
        let auth_result = result.unwrap();
        assert!(auth_result.success);
        assert!(auth_result.user_info.is_some());
        assert_eq!(auth_result.user_info.as_ref().unwrap().username, "testuser");
    }

    #[tokio::test]
    async fn test_api_endpoints() {
        let config = TestConfig::new();
        let plugin_config = AuthPluginManagerConfig {
            plugin_directory: config.plugin_directory.clone(),
            default_method: AuthMethod::JWT,
            enable_hot_reload: false,
            health_check_interval: 30,
            max_plugins: 5,
        };

        let manager = HotSwappableAuthPluginManager::new(plugin_config).await.unwrap();
        let api_config = AuthApiConfig::default();
        let api_manager = Arc::new(AuthApiManager::new(Arc::new(
            PluginAuthService::new(AuthServiceConfig::default()).await.unwrap()),
            api_config
        ));

        // Setup JWT plugin
        let jwt_plugin_path = format!("{}/jwt_plugin.wasm", config.plugin_directory);
        tokio::fs::write(&jwt_plugin_path, create_mock_jwt_plugin()).await.unwrap();
        let jwt_metadata = create_test_plugin_metadata("jwt", vec![AuthMethod::JWT, AuthMethod::Basic]);
        tokio::fs::write(
            format!("{}/jwt_plugin.json", config.plugin_directory),
            serde_json::to_string(&jwt_metadata).unwrap()
        ).await.unwrap();

        manager.load_plugin("jwt_plugin").await.unwrap();

        // Test API endpoints
        let plugins = api_manager.list_plugins().await;
        assert!(plugins.is_ok());
        assert_eq!(plugins.as_ref().unwrap().len(), 1);

        let loaded_plugins = api_manager.list_loaded_plugins().await;
        assert!(loaded_plugins.is_ok());
        assert_eq!(loaded_plugins.as_ref().unwrap().len(), 1);

        let stats = api_manager.get_service_stats().await;
        assert!(stats.is_ok());
        assert_eq!(stats.as_ref().unwrap().total_requests, 0);

        let health = api_manager.health_check().await;
        assert!(health.is_ok());
        assert_eq!(health.as_ref().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn test_error_handling() {
        let config = TestConfig::new();
        let plugin_config = AuthPluginManagerConfig {
            plugin_directory: config.plugin_directory.clone(),
            default_method: AuthMethod::JWT,
            enable_hot_reload: false,
            health_check_interval: 30,
            max_plugins: 5,
        };

        let manager = HotSwappableAuthPluginManager::new(plugin_config).await.unwrap();

        // Test loading non-existent plugin
        let result = manager.load_plugin("non_existent_plugin").await;
        assert!(result.is_err());

        // Test authentication with no plugin loaded
        let request = AuthRequestBuilder::new()
            .with_method(AuthMethod::JWT)
            .with_credentials("testuser", "testpass")
            .build();

        let result = manager.authenticate(request).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("No plugin found"));
    }

    #[tokio::test]
    async fn test_concurrent_authentication() {
        let config = TestConfig::new();
        let plugin_config = AuthPluginManagerConfig {
            plugin_directory: config.plugin_directory.clone(),
            default_method: AuthMethod::JWT,
            enable_hot_reload: false,
            health_check_interval: 30,
            max_plugins: 5,
        };

        let manager = Arc::new(HotSwappableAuthPluginManager::new(plugin_config).await.unwrap());

        // Setup JWT plugin
        let jwt_plugin_path = format!("{}/jwt_plugin.wasm", config.plugin_directory);
        tokio::fs::write(&jwt_plugin_path, create_mock_jwt_plugin()).await.unwrap();
        let jwt_metadata = create_test_plugin_metadata("jwt", vec![AuthMethod::JWT, AuthMethod::Basic]);
        tokio::fs::write(
            format!("{}/jwt_plugin.json", config.plugin_directory),
            serde_json::to_string(&jwt_metadata).unwrap()
        ).await.unwrap();

        manager.load_plugin("jwt_plugin").await.unwrap();

        // Create multiple concurrent authentication requests
        let mut handles = Vec::new();
        for i in 0..10 {
            let request = AuthRequestBuilder::new()
                .with_method(AuthMethod::JWT)
                .with_credentials(&format!("user{}", i), "testpass")
                .with_context("127.0.0.1", "test-agent", "test-fingerprint")
                .build();

            let manager_clone = manager.clone();
            let handle = tokio::spawn(async move {
                manager_clone.authenticate(request).await
            });
            
            handles.push(handle);
        }

        // Wait for all requests to complete
        for handle in handles {
            let result = handle.await.unwrap();
            assert!(result.is_ok());
            assert!(result.as_ref().unwrap().success);
        }

        // Check final statistics
        let stats = manager.get_plugin_stats().await;
        assert!(stats.total_requests >= 10);
        assert!(stats.successful_auths >= 10);
    }
}
