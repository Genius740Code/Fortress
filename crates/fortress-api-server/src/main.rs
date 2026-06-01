//! Fortress Server Main Entry Point
//!
//! This is the main entry point for Fortress REST API server.
//! It sets up the HTTP server with basic endpoints.

use axum::http::{header, HeaderValue, Method};
use axum::{
    middleware::from_fn_with_state,
    routing::{delete, get, post, put},
    Json, Router,
};
use std::net::SocketAddr;
use std::sync::Arc;
use tower::ServiceBuilder;
use tower_http::{compression::CompressionLayer, cors::CorsLayer, trace::TraceLayer};
use tracing::info;

// Import from fortress_api_server instead of fortress_server
use fortress_api_server::auth::{require_jwt_middleware, AuthManager, InMemoryUserStore};
use fortress_api_server::graphql::{graphql_handler, graphql_playground};
use fortress_api_server::handlers::{
    admin_list_data, authenticate, create_openapi, create_tenant, delete_data,
    detailed_health_check, generate_key, get_blocked_requests, get_prometheus_metrics,
    get_security_events, get_tenant_stats, list_data, list_tenants, refresh_token, retrieve_data,
    security_health_check, store_data, update_data, AppState,
};
use fortress_api_server::health::HealthChecker;
use fortress_api_server::metrics::MetricsCollector;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing
    info!("Fortress server starting");

    // Create OpenAPI specification
    let openapi = create_openapi();

    let state = create_app_state().await?;
    let app = create_router_with_state(state, openapi).await?;

    // Start server
    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
    info!("Fortress server listening on {}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

async fn create_router_with_state(
    state: Arc<AppState>,
    _openapi: utoipa::openapi::OpenApi,
) -> Result<Router, Box<dyn std::error::Error>> {
    // Get allowed origins from environment or use secure defaults
    let allowed_origins_str = std::env::var("FORTRESS_ALLOWED_ORIGINS").unwrap_or_else(|_| {
        "https://fortress.example.com,http://localhost:3000,http://localhost:8080".to_string()
    });
    let _allowed_origins = allowed_origins_str
        .split(',')
        .map(|s| s.trim().to_string())
        .collect::<Vec<_>>();

    let public_routes = Router::new()
        .route("/health", get(health_check))
        .route("/health/detailed", get(detailed_health_check))
        .route("/health/security", get(security_health_check))
        .route("/openapi.json", get(openapi_handler))
        .route("/metrics", get(get_prometheus_metrics))
        .route("/security/events", get(get_security_events))
        .route("/security/blocked-requests", get(get_blocked_requests))
        .route("/graphql", get(graphql_handler).post(graphql_handler))
        .route("/graphql/playground", get(graphql_playground))
        .route("/api/v1/auth/login", post(authenticate))
        .route("/api/v1/auth/refresh", post(refresh_token));

    let protected_routes = Router::new()
        .route("/api/v1/data", post(store_data))
        .route("/api/v1/data/:key", get(retrieve_data))
        .route("/api/v1/data/:key", put(update_data))
        .route("/api/v1/data/:key", delete(delete_data))
        .route("/api/v1/data", get(list_data))
        .route("/api/v1/keys", post(generate_key))
        .route("/api/v1/tenants", post(create_tenant))
        .route("/api/v1/tenants", get(list_tenants))
        .route("/api/v1/tenants/:tenant_id/stats", get(get_tenant_stats))
        .route("/api/v1/admin/data", get(admin_list_data))
        .layer(from_fn_with_state(state.clone(), require_jwt_middleware));

    let app = public_routes
        .merge(protected_routes)
        // Middleware with restricted CORS
        .layer(
            ServiceBuilder::new()
                .layer(TraceLayer::new_for_http())
                .layer(CompressionLayer::new())
                // Restricted CORS
                .layer(
                    CorsLayer::new()
                        .allow_origin({
                            let fallback_origin =
                                HeaderValue::from_static("https://fortress.example.com");
                            allowed_origins_str
                                .parse::<HeaderValue>()
                                .unwrap_or(fallback_origin)
                        })
                        .allow_methods([
                            Method::GET,
                            Method::POST,
                            Method::PUT,
                            Method::DELETE,
                            Method::PATCH,
                            Method::OPTIONS,
                        ])
                        .allow_headers([
                            header::AUTHORIZATION,
                            header::ACCEPT,
                            header::CONTENT_TYPE,
                            header::ORIGIN,
                            header::ACCESS_CONTROL_REQUEST_METHOD,
                            header::ACCESS_CONTROL_REQUEST_HEADERS,
                        ])
                        .allow_credentials(true)
                        .max_age(std::time::Duration::from_secs(3600)),
                ),
        )
        .with_state(state);

    Ok(app)
}

/// Create application state
async fn create_app_state() -> Result<Arc<AppState>, Box<dyn std::error::Error>> {
    use chrono::Duration;
    use fortress_api_server::config::FeatureFlags;
    use fortress_api_server::handlers::AppState;
    use fortress_core::field_encryption_manager::DefaultFieldEncryptionManager;
    use fortress_core::tenant::{GlobalResourceLimits, InMemoryTenantManager};

    // Initialize components with secure JWT secret from environment
    let jwt_secret = std::env::var("FORTRESS_JWT_SECRET")
        .map_err(|_| "FORTRESS_JWT_SECRET environment variable not set")?;

    if jwt_secret.len() < 32 {
        return Err("FORTRESS_JWT_SECRET must be at least 32 characters long".into());
    }

    let user_store = Arc::new(InMemoryUserStore::new()); // Wrap in Arc here

    if std::env::var("FORTRESS_BOOTSTRAP_DEFAULT_ADMIN")
        .ok()
        .as_deref()
        == Some("1")
    {
        let admin_password = std::env::var("FORTRESS_BOOTSTRAP_ADMIN_PASSWORD") // Password for default admin user
            .map_err(|_| "FORTRESS_BOOTSTRAP_ADMIN_PASSWORD environment variable not set for default admin bootstrap")?;
        let admin_user = fortress_api_server::auth::UserRecord {
            id: "admin".to_string(),
            username: "admin".to_string(),
            password_hash: fortress_api_server::auth::hash_password_secure(&admin_password)
                .expect("Failed to hash admin password for default user"),
            email: Some("admin@fortress-db.com".to_string()),
            roles: vec!["admin".to_string(), "user".to_string()],
            tenant_id: None,
            failed_login_attempts: 0,
            locked_until: None,
        };
        user_store.add_user(admin_user);
    }
    let auth_manager = Arc::new(AuthManager::new(
        &jwt_secret,
        Duration::seconds(3600),
        user_store.clone(), // Clone the Arc for AuthManager
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
    let storage = Arc::new(fortress_core::storage::FileSystemStorage::with_config(
        "./data",
        storage_config,
    )?);

    // Initialize field encryption manager
    let field_encryption_manager =
        Arc::new(DefaultFieldEncryptionManager::new(key_manager.clone()));

    // Initialize health checker
    let health_checker = Arc::new(HealthChecker::new(FeatureFlags::default()));

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
        in_memory_user_store: user_store, // Assign the Arc<InMemoryUserStore>
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
