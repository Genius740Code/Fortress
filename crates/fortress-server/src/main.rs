//! Fortress Server Main Entry Point
//!
//! This is the main entry point for Fortress REST API server.
//! It sets up the HTTP server with basic endpoints.

use axum::{
    Router,
    routing::{get, post, put, delete},
    Json,
};
use std::net::SocketAddr;
use std::sync::Arc;
use tower::ServiceBuilder;
use tower_http::{
    cors::CorsLayer,
    trace::TraceLayer,
    compression::CompressionLayer,
};
use tracing::info;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing
    info!("Fortress server starting");

    // Create OpenAPI specification
    let openapi = fortress_server::handlers::create_openapi();

    // Create router with OpenAPI endpoints
    let app = create_router(openapi).await?;

    // Start server
    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
    info!("Fortress server listening on {}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

/// Create an application router with all endpoints
async fn create_router(_openapi: utoipa::openapi::OpenApi) -> Result<Router, Box<dyn std::error::Error>> {
    use fortress_server::handlers::*;
    
    // Create application state
    let state = create_app_state().await?;

    // Create base router with all endpoints
    let app = Router::new()
        // Health and API documentation
        .route("/health", get(health_check))
        .route("/openapi.json", get(openapi_handler))
        
        // Data operations
        .route("/api/v1/data", post(store_data))
        .route("/api/v1/data/:key", get(retrieve_data))
        .route("/api/v1/data/:key", put(update_data))
        .route("/api/v1/data/:key", delete(delete_data))
        .route("/api/v1/data", get(list_data))
        
        // Key management
        .route("/api/v1/keys", post(generate_key))
        
        // Tenant management (admin only)
        .route("/api/v1/tenants", post(create_tenant))
        .route("/api/v1/tenants", get(list_tenants))
        .route("/api/v1/tenants/:tenant_id/stats", get(get_tenant_stats))
        
        // Admin operations
        .route("/api/v1/admin/data", get(admin_list_data))
        
        // Middleware
        .layer(
            ServiceBuilder::new()
                .layer(TraceLayer::new_for_http())
                .layer(CompressionLayer::new())
                .layer(CorsLayer::permissive())
        )
        .with_state(state);

    Ok(app)
}

/// Create application state
async fn create_app_state() -> Result<Arc<fortress_server::handlers::AppState>, Box<dyn std::error::Error>> {
    use fortress_server::handlers::AppState;
    use fortress_core::tenant::{InMemoryTenantManager, GlobalResourceLimits};
    use fortress_server::config::FeatureFlags;
    use fortress_core::field_encryption_manager::DefaultFieldEncryptionManager;
    use chrono::Duration;
    
    // Initialize components
    let auth_manager = Arc::new(fortress_server::auth::AuthManager::new(
        "demo-jwt-secret", 
        Duration::seconds(3600), 
        Arc::new(fortress_server::auth::InMemoryUserStore::new())
    ));
    let metrics = Arc::new(fortress_server::metrics::MetricsCollector::new());
    let key_manager = Arc::new(fortress_core::key::InMemoryKeyManager::new());
    
    // Initialize storage (using filesystem for now)
    let storage = Arc::new(fortress_core::storage::FileSystemStorage::new("./data")?);
    
    // Initialize field encryption manager
    let field_encryption_manager = Arc::new(
        DefaultFieldEncryptionManager::new(key_manager.clone())
    );
    
    // Initialize health checker
    let health_checker = Arc::new(fortress_server::health::HealthChecker::new(
        FeatureFlags::default()
    ));

    // Initialize tenant manager with demo limits
    let global_limits = GlobalResourceLimits {
        max_total_databases: Some(100),
        max_total_storage: Some(10737418240), // 10GB
        max_total_connections: Some(1000),
        max_total_cpu: Some(80.0),
        max_total_memory: Some(80.0),
    };
    let tenant_manager = Arc::new(InMemoryTenantManager::with_global_limits(global_limits));

    let state = AppState {
        auth_manager,
        metrics,
        key_manager,
        field_encryption_manager,
        storage,
        health_checker,
        tenant_manager,
    };

    Ok(Arc::new(state))
}

/// Simple health check for testing
async fn _health_check() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "status": "healthy",
        "timestamp": chrono::Utc::now(),
        "version": "0.1.0"
    }))
}

/// Create OpenAPI specification with all documented endpoints
async fn openapi_handler() -> Json<utoipa::openapi::OpenApi> {
    Json(fortress_server::handlers::create_openapi())
}
