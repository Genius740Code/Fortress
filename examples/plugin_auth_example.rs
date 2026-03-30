//! Plugin-Based Authentication Example
//!
//! This example demonstrates how to use the hot-swappable authentication system
//! with JWT, OAuth, and SAML plugins.

use fortress_core::auth_service::{AuthService, AuthServiceConfig, ServiceContext};
use fortress_core::auth_plugin::*;
use fortress_core::auth_plugin_manager::*;
use tokio;
use tracing::{info, warn};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .init();

    info!("Starting Plugin-Based Authentication Example");

    // Create auth service configuration
    let config = AuthServiceConfig {
        plugin_directory: "./plugins/auth".to_string(),
        default_method: AuthMethod::JWT,
        enable_hot_reload: true,
        health_check_interval: 30,
        max_plugins: 10,
        session_timeout: 3600, // 1 hour
        token_expiration: 1800, // 30 minutes
        enable_device_fingerprinting: true,
        security_policies: Default::default(),
    };

    // Create auth service
    let auth_service = Arc::new(AuthService::new(config).await?);

    // Example 1: JWT Authentication
    println!("\n=== JWT Authentication Example ===");
    let jwt_request = AuthRequestBuilder::new()
        .with_method(AuthMethod::JWT)
        .with_credentials("testuser", "testpass123")
        .with_context("127.0.0.1", "test-agent", "test-fingerprint")
        .build();

    let result = auth_service.authenticate(jwt_request, &ServiceContext {
        ip_address: Some("127.0.0.1".to_string()),
        user_agent: Some("test-agent".to_string()),
        timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
        device_fingerprint: Some("test-fingerprint".to_string()),
        request_id: uuid::Uuid::new_v4().to_string(),
        metadata: HashMap::new(),
    }).await;

    match result {
        Ok(auth_result) => {
            println!("✅ JWT Authentication successful!");
            println!("User: {}", auth_result.user_info.as_ref().unwrap().username);
            if let Some(token) = &auth_result.token {
                println!("Token: {}", token);
            }
        }
        Err(e) => {
            println!("❌ JWT Authentication failed: {}", e);
        }
    }

    // Example 2: OAuth Authentication
    println!("\n=== OAuth Authentication Example ===");
    let oauth_request = AuthRequestBuilder::new()
        .with_method(AuthMethod::OAuth)
        .with_oauth_code("auth_code_123", "state_abc", "https://example.com/callback")
        .with_context("127.0.0.1", "test-agent", "test-fingerprint")
        .build();

    let result = auth_service.authenticate(oauth_request, &ServiceContext {
        ip_address: Some("127.0.0.1".to_string()),
        user_agent: Some("test-agent".to_string()),
        timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
        device_fingerprint: Some("test-fingerprint".to_string()),
        request_id: uuid::Uuid::new_v4().to_string(),
        metadata: HashMap::new(),
    }).await;

    match result {
        Ok(auth_result) => {
            println!("✅ OAuth Authentication successful!");
            println!("User: {}", auth_result.user_info.as_ref().unwrap().username);
            if let Some(token) = &auth_result.token {
                println!("Token: {}", token);
            }
        }
        Err(e) => {
            println!("❌ OAuth Authentication failed: {}", e);
        }
    }

    // Example 3: SAML Authentication
    println!("\n=== SAML Authentication Example ===");
    let saml_request = AuthRequestBuilder::new()
        .with_method(AuthMethod::SAML)
        .with_saml_assertion("<saml_assertion>test_user</saml_assertion>")
        .with_context("127.0.0.1", "test-agent", "test-fingerprint")
        .build();

    let result = auth_service.authenticate(saml_request, &ServiceContext {
        ip_address: Some("127.0.0.1".to_string()),
        user_agent: Some("test-agent".to_string()),
        timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
        device_fingerprint: Some("test-fingerprint".to_string()),
        request_id: uuid::Uuid::new_v4().to_string(),
        metadata: HashMap::new(),
    }).await;

    match result {
        Ok(auth_result) => {
            println!("✅ SAML Authentication successful!");
            println!("User: {}", auth_result.user_info.as_ref().username);
        }
        Err(e) => {
            println!("❌ SAML Authentication failed: {}", e);
        }
    }

    // Example 4: Token Validation
    println!("\n=== Token Validation Example ===");
    if let Some(token) = auth_result.token {
        let validation_result = auth_service.validate_token(&token, &ServiceContext {
            ip_address: Some("127.0.0.1".to_string()),
            user_agent: Some("test-agent".to_string()),
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            device_fingerprint: Some("test-fingerprint".to_string()),
            request_id: uuid::Uuid::new_v4().to_string(),
            metadata: HashMap::new(),
        }).await;

        match validation_result {
            Ok(user_info) => {
                println!("✅ Token validation successful!");
                println!("User: {}", user_info.username);
            }
            Err(e) => {
                println!("❌ Token validation failed: {}", e);
            }
        }
    }

    // Example 5: Get Available Methods
    println!("\n=== Available Authentication Methods ===");
    let methods = auth_service.get_available_methods().await;
    for method in methods {
        println!("Available: {:?}", method);
    }

    // Example 6: Get Statistics
    println!("\n=== Authentication Statistics ===");
    let stats = auth_service.get_stats().await;
    println!("Total requests: {}", stats.total_requests);
    println!("Successful auths: {}", stats.successful_auths);
    println!("Failed auths: {}", stats.failed_auths);
    println!("Average auth time: {:.2}ms", stats.avg_auth_time_ms);

    println!("\n🎉 Plugin-Based Authentication System Demo Complete! 🎉");

    Ok(())
}
