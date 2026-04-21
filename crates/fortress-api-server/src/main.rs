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
use axum::http::{header, Method, HeaderValue};
use chrono::Duration;
use tracing::info;

// Import from fortress_api_server instead of fortress_server
use fortress_api_server::handlers::{
    get_tenant_stats, admin_list_data, create_openapi, AppState,
    detailed_health_check, security_health_check,
    get_prometheus_metrics, get_security_events, get_blocked_requests,
    store_data, retrieve_data, update_data, delete_data, list_data,
    generate_key, create_tenant, list_tenants
};
use fortress_api_server::auth::{AuthManager, InMemoryUserStore};
use fortress_api_server::metrics::MetricsCollector;
use fortress_api_server::health::HealthChecker;
use fortress_api_server::graphql::{graphql_handler, graphql_playground};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing
    info!("Fortress server starting");

    // Create OpenAPI specification
    let openapi = create_openapi();

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
    
    // Create application state
    let state = create_app_state().await?;

    // Get allowed origins from environment or use secure defaults
    let allowed_origins_str = std::env::var("FORTRESS_ALLOWED_ORIGINS")
        .unwrap_or_else(|_| "https://fortress.example.com,http://localhost:3000,http://localhost:8080".to_string());
    let allowed_origins = allowed_origins_str
        .split(',')
        .map(|s| s.trim().to_string())
        .collect::<Vec<_>>();

    // Create base router with all endpoints
    let app = Router::new()
        // Health and API documentation
        .route("/health", get(health_check))
        .route("/health/detailed", get(detailed_health_check))
        .route("/health/security", get(security_health_check))
        .route("/openapi.json", get(openapi_handler))
        
        // Metrics and monitoring
        .route("/metrics", get(get_prometheus_metrics))
        
        // Security endpoints
        .route("/security/events", get(get_security_events))
        .route("/security/blocked-requests", get(get_blocked_requests))
        
        // GraphQL API
        .route("/graphql", get(graphql_handler).post(graphql_handler))
        .route("/graphql/playground", get(graphql_playground))
        
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
        // Middleware with restricted CORS
        .layer(
            ServiceBuilder::new()
                .layer(TraceLayer::new_for_http())
                .layer(CompressionLayer::new())
                // Restricted CORS
                .layer(
                    CorsLayer::new()
                        .allow_origin(allowed_origins_str.parse::<HeaderValue>().unwrap_or_else(|_| "https://fortress.example.com".parse().unwrap()))
                        .allow_methods([
                            Method::GET,
                            Method::POST,
                            Method::PUT,
                            Method::DELETE,
                            Method::PATCH,
                            Method::OPTIONS
                        ])
                        .allow_headers([
                            header::AUTHORIZATION,
                            header::ACCEPT,
                            header::CONTENT_TYPE,
                            header::ORIGIN,
                            header::ACCESS_CONTROL_REQUEST_METHOD,
                            header::ACCESS_CONTROL_REQUEST_HEADERS
                        ])
                        .allow_credentials(true)
                        .max_age(std::time::Duration::from_secs(3600))
                )
        )
        .with_state(state);

    Ok(app)
}

/// Create application state
async fn create_app_state() -> Result<Arc<AppState>, Box<dyn std::error::Error>> {
    use fortress_api_server::handlers::AppState;
    use fortress_core::tenant::{InMemoryTenantManager, GlobalResourceLimits};
    use fortress_api_server::config::FeatureFlags;
    use fortress_core::field_encryption_manager::DefaultFieldEncryptionManager;
    use chrono::Duration;
    
    // Initialize components with secure JWT secret from environment
    let jwt_secret = std::env::var("FORTRESS_JWT_SECRET")
        .map_err(|_| "FORTRESS_JWT_SECRET environment variable not set")?;
    
    if jwt_secret.len() < 32 {
        return Err("FORTRESS_JWT_SECRET must be at least 32 characters long".into());
    }
    
    let auth_manager = Arc::new(AuthManager::new(
        &jwt_secret,
        Duration::seconds(3600), 
        Arc::new(InMemoryUserStore::new())
    ));
    let metrics = Arc::new(MetricsCollector::new());
    let key_manager = Arc::new(fortress_core::key::InMemoryKeyManager::new());
    
    // Initialize storage with optimized connection pool
    let storage_config = fortress_core::storage::StorageConfig {
        backend_type: fortress_core::storage::StorageBackendType::FileSystem {
            base_path: "./data".to_string(),
        },
        config: std::collections::HashMap::new(),
        connection_pool_size: std::env::var("FORTRESS_DB_POOL_SIZE")
            .unwrap_or_else(|_| "10".to_string())
            .parse()
            .unwrap_or(10),
        connection_timeout: std::time::Duration::from_secs(30).as_secs(),
        max_connections: 100,
    };
    let storage = Arc::new(fortress_core::storage::FileSystemStorage::with_config("./data", storage_config)?);
    
    // Initialize field encryption manager
    let field_encryption_manager = Arc::new(
        DefaultFieldEncryptionManager::new(key_manager.clone())
    );
    
    // Initialize health checker
    let health_checker = Arc::new(HealthChecker::new(
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

    // Initialize dynamic secrets engine
    let dynamic_secrets = Arc::new(fortress_core::dynamic_secrets::DynamicSecretsEngine::new());

    let state = AppState {
        auth_manager,
        metrics,
        key_manager,
        field_encryption_manager,
        storage,
        health_checker,
        tenant_manager,
        dynamic_secrets,
    };

    Ok(Arc::new(state))
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
    Json(create_openapi())
}
