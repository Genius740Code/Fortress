use crate::grpc::service::FortressGrpcService;
use crate::error::ServerError;
use fortress_core::{
    encryption::{EncryptionAlgorithm, Aegis256, ChaCha20Poly1305, Aes256Gcm},
    key::{KeyManager, SecureKey},
    storage::StorageBackend,
};
use std::net::SocketAddr;
use std::sync::Arc;
use axum::{
    routing::{get, post},
    extract::{Path, State},
    http::StatusCode,
    response::Json,
    Router,
};
use tracing::{info, error};

pub struct GrpcServer {
    addr: SocketAddr,
    service: Arc<FortressGrpcService>,
}

impl GrpcServer {
    pub fn new(addr: SocketAddr) -> Self {
        Self {
            addr,
            service: Arc::new(FortressGrpcService::new()),
        }
    }

    pub async fn start(self) -> Result<(), ServerError> {
        info!("Starting gRPC-compatible server on {}", self.addr);

        // Create HTTP routes that mimic gRPC endpoints using JSON
        let app = Router::new()
            .route("/grpc/health", get(health_handler))
            .route("/grpc/metrics", get(metrics_handler))
            .route("/grpc/databases", post(create_database_handler))
            .route("/grpc/databases/:id", get(get_database_handler))
            .route("/grpc/databases/:id", post(delete_database_handler))
            .route("/grpc/encrypt", post(encrypt_handler))
            .route("/grpc/decrypt", post(decrypt_handler))
            .with_state(self.service)
            .layer(tower_http::cors::CorsLayer::permissive());

        let listener = tokio::net::TcpListener::bind(self.addr).await
            .map_err(|e| ServerError::internal(e.to_string()))?;

        info!("gRPC-compatible server listening on {}", self.addr);
        
        axum::serve(listener, app).await
            .map_err(|e| {
                error!("Server error: {}", e);
                ServerError::internal(e.to_string())
            })?;

        Ok(())
    }

    pub fn service(&self) -> Arc<FortressGrpcService> {
        self.service.clone()
    }
}

// HTTP handlers that provide gRPC-like functionality over JSON
async fn health_handler(
    State(service): State<Arc<FortressGrpcService>>,
) -> Result<Json<crate::grpc::HealthResponse>, StatusCode> {
    match service.health_check().await {
        Ok(response) => Ok(Json(response)),
        Err(_) => Err(StatusCode::INTERNAL_SERVER_ERROR),
    }
}

async fn metrics_handler(
    State(service): State<Arc<FortressGrpcService>>,
) -> Result<Json<crate::grpc::MetricsResponse>, StatusCode> {
    match service.get_metrics().await {
        Ok(response) => Ok(Json(response)),
        Err(_) => Err(StatusCode::INTERNAL_SERVER_ERROR),
    }
}

async fn create_database_handler(
    State(service): State<Arc<FortressGrpcService>>,
    Json(request): Json<crate::grpc::CreateDatabaseRequest>,
) -> Result<Json<crate::grpc::DatabaseResponse>, StatusCode> {
    match service.create_database(request).await {
        Ok(response) => Ok(Json(response)),
        Err(_) => Err(StatusCode::INTERNAL_SERVER_ERROR),
    }
}

async fn get_database_handler(
    State(service): State<Arc<FortressGrpcService>>,
    Path(database_id): Path<String>,
) -> Result<Json<crate::grpc::DatabaseResponse>, StatusCode> {
    let request = crate::grpc::GetDatabaseRequest { database_id };
    match service.get_database(request).await {
        Ok(response) => Ok(Json(response)),
        Err(_) => Err(StatusCode::NOT_FOUND),
    }
}

async fn delete_database_handler(
    State(service): State<Arc<FortressGrpcService>>,
    Path(database_id): Path<String>,
) -> Result<StatusCode, StatusCode> {
    let request = crate::grpc::DeleteDatabaseRequest { database_id };
    match service.delete_database(request).await {
        Ok(()) => Ok(StatusCode::NO_CONTENT),
        Err(_) => Err(StatusCode::INTERNAL_SERVER_ERROR),
    }
}

async fn encrypt_handler(
    State(service): State<Arc<FortressGrpcService>>,
    Json(request): Json<crate::grpc::EncryptRequest>,
) -> Result<Json<crate::grpc::EncryptResponse>, StatusCode> {
    match service.encrypt_data(request).await {
        Ok(response) => Ok(Json(response)),
        Err(_) => Err(StatusCode::INTERNAL_SERVER_ERROR),
    }
}

async fn decrypt_handler(
    State(service): State<Arc<FortressGrpcService>>,
    Json(request): Json<crate::grpc::DecryptRequest>,
) -> Result<Json<crate::grpc::DecryptResponse>, StatusCode> {
    match service.decrypt_data(request).await {
        Ok(response) => Ok(Json(response)),
        Err(_) => Err(StatusCode::INTERNAL_SERVER_ERROR),
    }
}
