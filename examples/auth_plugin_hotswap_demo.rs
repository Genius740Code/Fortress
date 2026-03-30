//! Hot-Swappable Authentication Plugin Demo
//!
//! This example demonstrates the complete hot-swappable authentication plugin system,
//! showing how JWT, OAuth, and SAML plugins can be deployed, managed, and swapped
//! independently without system restart.

use fortress_core::{
    auth_plugin_integration::{AuthPluginIntegrationService, IntegrationConfig, DeploymentStrategy},
    error::Result,
};
use serde_json::json;
use std::time::Duration;
use tokio::time::sleep;
use tracing::{info, warn, error};
use tracing_subscriber;

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    tracing_subscriber::fmt::init();

    info!("🚀 Starting Fortress Authentication Plugin Hot-Swapping Demo");

    // Create integration service with hot-swapping enabled
    let config = IntegrationConfig {
        enable_hot_swapping: true,
        plugin_directory: "./target/wasm-plugins".to_string(),
        default_auth_method: "jwt".to_string(),
        enable_health_monitoring: true,
        health_check_interval: 10, // 10 seconds for demo
        auto_reload_on_failure: true,
        max_reload_attempts: 3,
    };

    let service = AuthPluginIntegrationService::new(config)?;

    // Initialize the service
    service.initialize().await?;
    info!("✅ Authentication plugin integration service initialized");

    // Step 1: Deploy JWT plugin with rolling strategy
    info!("\n📦 Step 1: Deploying JWT authentication plugin (Rolling Strategy)");
    let jwt_deployment = service.deploy_plugin(
        "jwt",
        "./target/wasm-plugins/jwt_plugin.wasm",
        DeploymentStrategy::Rolling,
    ).await?;

    // Wait for deployment to complete
    sleep(Duration::from_secs(2)).await;
    
    let jwt_status = service.get_deployment_status(&jwt_deployment).await;
    if let Some(status) = jwt_status {
        match status.status {
            fortress_core::auth_plugin_integration::DeploymentStatus::Completed => {
                info!("✅ JWT plugin deployed successfully");
            }
            _ => {
                warn!("⚠️ JWT plugin deployment status: {:?}", status.status);
            }
        }
    }

    // Step 2: Test JWT authentication
    info!("\n🔐 Step 2: Testing JWT authentication");
    let jwt_credentials = json!({
        "username": "admin",
        "password": "admin123"
    });

    match service.test_authentication("jwt", jwt_credentials).await {
        Ok(result) => {
            info!("✅ JWT authentication successful: {}", serde_json::to_string_pretty(&result)?);
        }
        Err(e) => {
            error!("❌ JWT authentication failed: {}", e);
        }
    }

    // Step 3: Deploy OAuth plugin with blue-green strategy
    info!("\n📦 Step 3: Deploying OAuth authentication plugin (Blue-Green Strategy)");
    let oauth_deployment = service.deploy_plugin(
        "oauth",
        "./target/wasm-plugins/oauth_plugin.wasm",
        DeploymentStrategy::BlueGreen,
    ).await?;

    // Wait for deployment to complete
    sleep(Duration::from_secs(2)).await;
    
    let oauth_status = service.get_deployment_status(&oauth_deployment).await;
    if let Some(status) = oauth_status {
        match status.status {
            fortress_core::auth_plugin_integration::DeploymentStatus::Completed => {
                info!("✅ OAuth plugin deployed successfully");
            }
            _ => {
                warn!("⚠️ OAuth plugin deployment status: {:?}", status.status);
            }
        }
    }

    // Step 4: Test OAuth authentication
    info!("\n🔐 Step 4: Testing OAuth authentication");
    let oauth_credentials = json!({
        "authorization_code": "sample_auth_code",
        "state": "sample_state",
        "redirect_uri": "http://localhost:8080/callback"
    });

    match service.test_authentication("oauth", oauth_credentials).await {
        Ok(result) => {
            info!("✅ OAuth authentication successful: {}", serde_json::to_string_pretty(&result)?);
        }
        Err(e) => {
            error!("❌ OAuth authentication failed: {}", e);
        }
    }

    // Step 5: Deploy SAML plugin with immediate strategy
    info!("\n📦 Step 5: Deploying SAML authentication plugin (Immediate Strategy)");
    let saml_deployment = service.deploy_plugin(
        "saml",
        "./target/wasm-plugins/saml_plugin.wasm",
        DeploymentStrategy::Immediate,
    ).await?;

    // Wait for deployment to complete
    sleep(Duration::from_secs(2)).await;
    
    let saml_status = service.get_deployment_status(&saml_deployment).await;
    if let Some(status) = saml_status {
        match status.status {
            fortress_core::auth_plugin_integration::DeploymentStatus::Completed => {
                info!("✅ SAML plugin deployed successfully");
            }
            _ => {
                warn!("⚠️ SAML plugin deployment status: {:?}", status.status);
            }
        }
    }

    // Step 6: Test SAML authentication
    info!("\n🔐 Step 6: Testing SAML authentication");
    let saml_credentials = json!({
        "saml_assertion": "sample_saml_assertion"
    });

    match service.test_authentication("saml", saml_credentials).await {
        Ok(result) => {
            info!("✅ SAML authentication successful: {}", serde_json::to_string_pretty(&result)?);
        }
        Err(e) => {
            error!("❌ SAML authentication failed: {}", e);
        }
    }

    // Step 7: Demonstrate hot-swapping (simulate plugin update)
    info!("\n🔄 Step 7: Demonstrating hot-swapping (JWT Plugin Update)");
    info!("Simulating JWT plugin update with new version...");
    
    // In a real scenario, you would have a new WASM file
    // For demo purposes, we'll use the same file
    let hot_swap_deployment = service.hot_swap_plugin(
        "jwt",
        "./target/wasm-plugins/jwt_plugin.wasm",
        DeploymentStrategy::Rolling,
    ).await?;

    // Wait for hot-swap to complete
    sleep(Duration::from_secs(2)).await;
    
    let hot_swap_status = service.get_deployment_status(&hot_swap_deployment).await;
    if let Some(status) = hot_swap_status {
        match status.status {
            fortress_core::auth_plugin_integration::DeploymentStatus::Completed => {
                info!("✅ JWT plugin hot-swapped successfully");
            }
            _ => {
                warn!("⚠️ JWT plugin hot-swap status: {:?}", status.status);
            }
        }
    }

    // Step 8: Test authentication after hot-swap
    info!("\n🔐 Step 8: Testing JWT authentication after hot-swap");
    let jwt_credentials_after = json!({
        "username": "admin",
        "password": "admin123"
    });

    match service.test_authentication("jwt", jwt_credentials_after).await {
        Ok(result) => {
            info!("✅ JWT authentication still works after hot-swap: {}", serde_json::to_string_pretty(&result)?);
        }
        Err(e) => {
            error!("❌ JWT authentication failed after hot-swap: {}", e);
        }
    }

    // Step 9: Show system health and metrics
    info!("\n📊 Step 9: System Health and Metrics");
    let health = service.get_health_status().await;
    info!("System Health: {}", serde_json::to_string_pretty(&health)?);

    let metrics = service.get_auth_method_metrics().await;
    info!("Authentication Method Metrics:");
    for metric in metrics {
        info!("  - {}: healthy={}, requests={}", metric.method, metric.plugin_healthy, metric.total_requests);
    }

    // Step 10: List all deployments
    info!("\n📋 Step 10: Deployment History");
    let deployments = service.list_deployments().await;
    info!("Total deployments: {}", deployments.len());
    
    for deployment in deployments {
        info!("Deployment: {} -> {} ({:?})", 
              deployment.plugin_name, 
              deployment.status,
              deployment.deployment_type);
    }

    // Step 11: Demonstrate canary deployment
    info!("\n🕊️ Step 11: Demonstrating Canary Deployment (OAuth Plugin)");
    let canary_deployment = service.deploy_plugin(
        "oauth",
        "./target/wasm-plugins/oauth_plugin.wasm",
        DeploymentStrategy::Canary { percentage: 10 },
    ).await?;

    // Wait for canary deployment
    sleep(Duration::from_secs(2)).await;
    
    let canary_status = service.get_deployment_status(&canary_deployment).await;
    if let Some(status) = canary_status {
        match status.status {
            fortress_core::auth_plugin_integration::DeploymentStatus::Completed => {
                info!("✅ OAuth canary deployment completed (10% traffic)");
            }
            _ => {
                warn!("⚠️ OAuth canary deployment status: {:?}", status.status);
            }
        }
    }

    // Final health check
    info!("\n🏁 Final System Health Check");
    let final_health = service.get_health_status().await;
    info!("Final Health Status: {}", serde_json::to_string_pretty(&final_health)?);

    info!("\n🎉 Fortress Authentication Plugin Hot-Swapping Demo Completed!");
    info!("📈 Key Features Demonstrated:");
    info!("  ✅ Plugin-based authentication architecture");
    info!("  ✅ Hot-swappable plugins without system restart");
    info!("  ✅ Multiple deployment strategies (Rolling, Blue-Green, Canary, Immediate)");
    info!("  ✅ Health monitoring and automatic recovery");
    info!("  ✅ Support for JWT, OAuth, and SAML authentication");
    info!("  ✅ Zero-downtime plugin updates");
    info!("  ✅ Comprehensive deployment tracking and metrics");

    Ok(())
}
