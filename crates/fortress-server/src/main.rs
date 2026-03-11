//! Fortress Server Main Entry Point
//!
//! This is the main entry point for Fortress REST API server.
//! It sets up the HTTP server with basic endpoints.

use axum::{
    Router,
    routing::{get, post},
    response::Html,
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
use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing
    info!("Starting Fortress server");

    // Create OpenAPI specification
    let openapi = OpenApi::new("Fortress API", "1.0");

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
async fn create_router(openapi: OpenApi) -> Result<Router, Box<dyn std::error::Error>> {
    // Create application state
    let state = Arc::new(());

    // Create base router
    let app = Router::new()
        // API routes
        .route("/api/v1/data", post(store_data))
        .route("/api/v1/data/:id", get(retrieve_data))
        .route("/api/v1/data/:id", axum::routing::delete(delete_data))
        .route("/api/v1/data", get(list_data))
        
        // Authentication routes
        .route("/api/v1/auth/login", post(authenticate))
        .route("/api/v1/auth/refresh", post(refresh_token))
        
        // Health and metrics routes
        .route("/health", get(health_check))
        .route("/metrics", get(get_metrics))
        .route("/metrics/prometheus", get(crate::handlers::get_prometheus_metrics))
        
        // OpenAPI documentation routes
        .route("/openapi.json", get(openapi_handler))
        .merge(SwaggerUi::new("/api/docs").url("/openapi.json", openapi))
        
        // Application state
        .with_state(state)
        
        // Middleware
        .layer(
            ServiceBuilder::new()
                .layer(TraceLayer::new_for_http())
                .layer(CompressionLayer::new())
                .layer(CorsLayer::permissive())
        );

    Ok(app)
}

/// Create OpenAPI specification with all documented endpoints
#[utoipa::path(
    get,
    path = "/openapi.json",
    responses(
        (status = 200, description = "OpenAPI specification in JSON format", body = OpenApi)
    ),
    tag = "Documentation"
)]
async fn openapi_handler() -> Json<OpenApi> {
    Json(create_openapi())
}

/// Create complete OpenAPI specification
fn create_openapi() -> OpenApi {
    #[derive(OpenApi)]
    #[openapi(
        paths(
            crate::handlers::store_data,
            crate::handlers::retrieve_data,
            crate::handlers::delete_data,
            crate::handlers::list_data,
            crate::handlers::authenticate,
            crate::handlers::refresh_token,
            crate::handlers::health_check,
            crate::handlers::get_metrics,
            crate::handlers::get_prometheus_metrics,
        ),
        components(
            schemas(
                crate::handlers::StorageRecord,
                crate::handlers::StoreDataRequest,
                crate::handlers::StoreDataResponse,
                crate::handlers::RetrieveDataResponse,
                crate::handlers::ListDataResponse,
                crate::handlers::AuthRequest,
                crate::handlers::AuthResponse,
                crate::handlers::RefreshTokenRequest,
                crate::handlers::RefreshTokenResponse,
                crate::handlers::HealthResponse,
                crate::handlers::MetricsResponse,
                crate::handlers::ErrorResponse,
            )
        ),
        tags(
            (
                name = "data",
                description = "Data storage and retrieval operations"
            ),
            (
                name = "authentication",
                description = "Authentication and token management"
            ),
            (
                name = "health",
                description = "Health check and monitoring endpoints"
            ),
            (
                name = "documentation",
                description = "API documentation and specification"
            )
        ),
        info(
            title = "Fortress API",
            version = "1.0.0",
            description = "REST API for Fortress secure database system with end-to-end encryption",
            contact(
                name = "Fortress Team",
                email = "team@fortress-db.com"
            ),
            license(
                name = "Apache-2.0",
                url = "https://github.com/Genius740Code/Fortress/blob/main/LICENSE"
            )
        )
    )]
    struct ApiDoc;

    ApiDoc::openapi()
}

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
