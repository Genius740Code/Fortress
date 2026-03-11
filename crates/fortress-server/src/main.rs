//! Fortress Server Main Entry Point
//!
//! This is the main entry point for Fortress REST API server.
//! It sets up the HTTP server with basic endpoints.

use axum::{
    Router,
    routing::{get, post},
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
use utoipa_swagger_ui::SwaggerUi;
use chrono::Utc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing
    info!("Starting Fortress server");

    // Create OpenAPI specification
    let openapi = fortress_server::handlers::create_openapi();

    // Create router with OpenAPI endpoints
    let app = create_router(openapi).await?;

    // Start server
    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
    info!("Server listening on {}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

/// Create an application router with all endpoints
async fn create_router(openapi: utoipa::openapi::OpenApi) -> Result<Router, Box<dyn std::error::Error>> {
    // Create application state
    let state = Arc::new(());

    // Create base router
    let app = Router::new()
        // Simple health check route for testing
        .route("/health", get(health_check))
        .route("/openapi.json", get(openapi_handler))
        
        // Middleware
        .layer(
            ServiceBuilder::new()
                .layer(TraceLayer::new_for_http())
                .layer(CompressionLayer::new())
                .layer(CorsLayer::permissive())
        );

    // For now, just return the basic router without Swagger UI
    // TODO: Fix Swagger UI integration
    Ok(app)
}

/// Simple health check for testing
async fn health_check() -> Json<serde_json::Value> {
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

/*
/// Create application state
async fn create_app_state() -> ServerResult<Arc<fortress_server::handlers::AppState>> {
    use fortress_server::handlers::AppState;
    
    // Initialize components
    let auth_manager = Arc::new(fortress_server::auth::AuthManager::new());
    let metrics = Arc::new(fortress_server::metrics::MetricsCollector::new());
    let key_manager = Arc::new(fortress_core::key::InMemoryKeyManager::new());
    
    // Initialize storage (using filesystem for now)
    let storage = Arc::new(fortress_core::storage::FileStorage::new("./data")?);
    
    // Initialize field encryption manager
    let field_encryption_manager = Arc::new(
        fortress_core::field_encryption::DefaultFieldEncryptionManager::new(key_manager.clone())
    );
    
    // Initialize health checker
    let health_checker = Arc::new(fortress_server::health::HealthChecker::new());

    let state = AppState {
        auth_manager,
        metrics,
        key_manager,
        field_encryption_manager,
        storage,
        health_checker,
    };

    Ok(Arc::new(state))
}
*/
