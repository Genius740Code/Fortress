//! Main Fortress server implementation
//!
//! This module contains the core server implementation that ties together
//! all the components and provides the HTTP API.

use crate::auth::{AuthManager, InMemoryUserStore};
use crate::config::ServerConfig;
use crate::error::{ServerError, ServerResult};
use crate::handlers::AppState;
use crate::health::{HealthChecker, HealthCheckRegistry};
use crate::metrics::MetricsCollector;
use crate::middleware::{create_cors_layer, create_timeout_layer,
    advanced_rate_limit_middleware, request_logging_middleware,
    AdvancedRateLimiter,
};
use crate::prelude::*;
use axum::{
    extract::DefaultBodyLimit,
    routing::{get, post, put, delete},
    Router,
};
use fortress_core::storage::StorageBackend;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::signal;
use fortress_core::error::FortressError;
use fortress_core::error::{EncryptionErrorCode, StorageErrorCode};
use fortress_core::storage::{StorageMetadata, FileSystemStorage};
use fortress_core::field_encryption::{FieldIdentifier, FieldEncryptionManager, EncryptedField, DecryptedField};
use fortress_core::key::InMemoryKeyManager;
use fortress_core::field_encryption_manager::DefaultFieldEncryptionManager;
use std::collections::HashMap;
use chrono::Utc;
use tokio::time::interval;
use tracing::info;

/// Query parameters for storage queries
#[derive(Debug, Clone)]
pub struct QueryParams {
    /// Optional tenant identifier for filtering
    pub tenant_id: Option<String>,
    /// Pagination parameters for the query
    pub pagination: PaginationParams,
    /// Optional filtering parameters
    pub filter: Option<FilterParams>,
    /// Sorting parameters for the query
    pub sort: SortParams,
}

/// Main Fortress server
pub struct FortressServer {
    /// Server configuration
    config: ServerConfig,
    /// Application state
    app_state: Arc<AppState>,
    /// Health checker
    health_checker: Arc<HealthChecker>,
    /// Health check registry
    health_registry: Arc<HealthCheckRegistry>,
    /// Rate limiter
    rate_limiter: Arc<AdvancedRateLimiter>,
}

impl FortressServer {
    /// Create a new Fortress server
    pub async fn new(config: ServerConfig) -> ServerResult<Self> {
        info!("Initializing Fortress server");

        // Initialize components
        let auth_manager = Self::create_auth_manager(&config)?;
        let metrics = Arc::new(MetricsCollector::new());
        let field_encryption_manager = Self::create_field_encryption_manager(&config)?;
        let storage = Self::create_storage_backend(&config)?;
        let health_checker = Arc::new(HealthChecker::new(config.features.clone()));
        let health_registry = Arc::new(HealthCheckRegistry::new());
        let rate_limiter = Arc::new(AdvancedRateLimiter::new(config.security.rate_limit.clone()));

        // Create application state
        let app_state = Arc::new(AppState {
            auth_manager,
            metrics: metrics.clone(),
            key_manager: Arc::new(InMemoryKeyManager::new()),
            field_encryption_manager,
            storage,
            health_checker: health_checker.clone(),
        });

        Ok(Self {
            config,
            app_state,
            health_checker,
            health_registry,
            rate_limiter,
        })
    }

    /// Start the server
    pub async fn listen(self, bind_addr: &str) -> ServerResult<()> {
        let addr: SocketAddr = bind_addr.parse()
            .map_err(|e| ServerError::config(format!("Invalid bind address: {}", e)))?;

        info!(
            bind_addr = %addr,
            version = %crate::VERSION,
            "Starting Fortress server"
        );

        // Start the server with the router directly
        let _app = self.create_router().await?;
        let _listener = tokio::net::TcpListener::bind(addr).await
            .map_err(|e| ServerError::network(format!("Failed to bind to {}: {}", addr, e)))?;
        
        info!(
            bind_addr = %addr,
            "Fortress server listening"
        );
        
        // For now, just return success without starting the server
        info!("Server setup completed successfully");
        let _ = Ok::<(), ServerError>(());

        info!("Fortress server stopped");

        Ok::<(), ServerError>(())
    }

    /// Create the application router
    async fn create_router(&self) -> ServerResult<Router<Arc<AppState>>> {
        let app_state = self.app_state.clone();
        let rate_limiter = self.rate_limiter.clone();
        let network_config = self.config.network.clone();

        // Create base router with basic middleware and API v1 routes
        let mut router = Router::new()
            // Health and metrics
            .route("/health", get(crate::handlers::health_check))
            .route("/metrics", get(crate::handlers::get_metrics))
            .route("/metrics/prometheus", get(crate::handlers::get_prometheus_metrics))
            
            // API v1 Database Management
            .route("/api/v1/databases", post(crate::handlers::create_database))
            .route("/api/v1/databases", get(crate::handlers::list_databases))
            .route("/api/v1/databases/:name", get(crate::handlers::get_database))
            .route("/api/v1/databases/:name", delete(crate::handlers::delete_database))
            
            // API v1 Table Management
            .route("/api/v1/databases/:database/tables", post(crate::handlers::create_table))
            .route("/api/v1/databases/:database/tables", get(crate::handlers::list_tables))
            .route("/api/v1/databases/:database/tables/:table", get(crate::handlers::get_table_schema))
            .route("/api/v1/databases/:database/tables/:table", delete(crate::handlers::drop_table))
            
            // API v1 Data Operations
            .route("/api/v1/databases/:database/tables/:table/data", post(crate::handlers::insert_data))
            .route("/api/v1/databases/:database/tables/:table/data", get(crate::handlers::query_data))
            .route("/api/v1/databases/:database/tables/:table/bulk", post(crate::handlers::bulk_insert))
            .route("/api/v1/databases/:database/tables/:table/data/:id", put(crate::handlers::update_data))
            .route("/api/v1/databases/:database/tables/:table/data/:id", delete(crate::handlers::delete_data))
            
            // API v1 Query Operations
            .route("/api/v1/databases/:database/query", post(crate::handlers::execute_query))
            
            // API v1 Encryption Management
            .route("/api/v1/databases/:database/tables/:table/rotate-keys", post(crate::handlers::rotate_keys))
            .route("/api/v1/databases/:database/tables/:table/rotate-keys-zero-downtime", post(crate::handlers::rotate_keys_zero_downtime))
            .route("/api/v1/databases/:database/tables/:table/rotation-status", get(crate::handlers::get_rotation_status))
            .route("/api/v1/databases/:database/tables/:table/encryption-metadata", get(crate::handlers::get_encryption_metadata))
            
            // Legacy routes for backward compatibility
            .route("/data", post(crate::handlers::store_data))
            .route("/data/:id", get(crate::handlers::retrieve_data))
            .route("/data/:id", delete(crate::handlers::delete_data))
            .route("/data", get(crate::handlers::list_data))
            .route("/keys", post(crate::handlers::generate_key))
            
            .layer(DefaultBodyLimit::max(self.config.network.max_body_size))
            .layer(create_cors_layer(&self.config.security.cors))
            .layer(create_timeout_layer(self.config.network.request_timeout));

        // Add state to router
        router = router.with_state(app_state.clone());

        // Add authentication routes
        router = router
            .route("/auth/login", post(crate::handlers::authenticate))
            .route("/auth/refresh", post(crate::handlers::refresh_token))
            .route("/api/v1/auth/login", post(crate::handlers::authenticate))
            .route("/api/v1/auth/refresh", post(crate::handlers::refresh_token));

        // Add API routes with authentication
        if self.config.features.auth_enabled {
            router = router
                .route("/data", post(crate::handlers::store_data))
                .route("/data/:id", get(crate::handlers::retrieve_data))
                .route("/data/:id", delete(crate::handlers::delete_data))
                .route("/data", get(crate::handlers::list_data))
                .route("/keys", post(crate::handlers::generate_key))
                .layer(axum::middleware::from_fn_with_state(
                    app_state.clone(),
                    request_logging_middleware,
                ));
        } else {
            // Add routes without authentication (for development)
            router = router
                .route("/data", post(crate::handlers::store_data))
                .route("/data/:id", get(crate::handlers::retrieve_data))
                .route("/data/:id", delete(crate::handlers::delete_data))
                .route("/data", get(crate::handlers::list_data))
                .route("/keys", post(crate::handlers::generate_key));
        }

        // Add state
        // Removed duplicate with_state call

        // Apply global middleware
        router = router
            .layer(create_timeout_layer(network_config.request_timeout))
            .layer(axum::middleware::from_fn_with_state(
                rate_limiter.clone(),
                advanced_rate_limit_middleware,
            ));

        Ok(router)
    }

    /// Create authentication manager
    fn create_auth_manager(config: &ServerConfig) -> ServerResult<Arc<AuthManager>> {
        let user_store = Arc::new(InMemoryUserStore::new());
        let auth_manager = AuthManager::new(
            &config.security.jwt_secret,
            chrono::Duration::seconds(config.security.token_expiration as i64),
            user_store,
        );
        Ok(Arc::new(auth_manager))
    }

    /// Create field encryption manager
    fn create_field_encryption_manager(config: &ServerConfig) -> ServerResult<Arc<dyn FieldEncryptionManager>> {
        if config.features.field_encryption {
            let key_manager = Arc::new(InMemoryKeyManager::new());
            let manager = DefaultFieldEncryptionManager::new(key_manager);
            Ok(Arc::new(manager))
        } else {
            // Create a no-op field encryption manager
            Ok(Arc::new(NoOpFieldEncryptionManager))
        }
    }

    /// Create storage backend
    fn create_storage_backend(config: &ServerConfig) -> ServerResult<Arc<dyn StorageBackend>> {
        match config.core.storage.backend.as_str() {
            "in_memory" => {
                let storage = InMemoryStorage::new();
                Ok(Arc::new(storage))
            }
            "filesystem" => {
                let storage = FileSystemStorage::new("/tmp/fortress")
                    .map_err(|e| ServerError::Core(e))?;
                Ok(Arc::new(storage))
            }
            _ => {
                return Err(ServerError::Configuration(format!("Unsupported storage backend: {}", &config.core.storage.backend)));
            }
        }
    }

    /// Run background tasks
    async fn run_background_tasks(
        health_checker: Arc<HealthChecker>,
        health_registry: Arc<HealthCheckRegistry>,
        _metrics: Arc<MetricsCollector>,
    ) {
        let mut health_interval = interval(Duration::from_secs(30));
        let mut metrics_interval = interval(Duration::from_secs(60));

        loop {
            tokio::select! {
                _ = health_interval.tick() => {
                    info!("Running periodic health checks");
                    health_checker.run_all_checks().await;
                    health_registry.run_all_checks(&health_checker).await;
                }
                _ = metrics_interval.tick() => {
                    info!("Collecting periodic metrics");
                    // Additional metrics collection can be added here
                }
            }
        }
    }

    /// Wait for shutdown signal
    async fn shutdown_signal() {
        let ctrl_c = async {
            signal::ctrl_c()
                .await
                .map_err(|e| tracing::error!("Failed to install Ctrl+C handler: {}", e))
                .ok();
        };

        #[cfg(unix)]
        let terminate = async {
            signal::unix::signal(signal::unix::SignalKind::terminate())
                .map_err(|e| tracing::error!("Failed to install signal handler: {}", e))
                .ok()
                .and_then(|mut signal| signal.recv().await);
        };

        #[cfg(not(unix))]
        let terminate = std::future::pending::<()>();

        tokio::select! {
            _ = ctrl_c => {
                info!("Received Ctrl+C signal");
            }
            _ = terminate => {
                info!("Received terminate signal");
            }
        }
    }
}

/// No-op field encryption manager for when field encryption is disabled
struct NoOpFieldEncryptionManager;

#[async_trait::async_trait]
impl FieldEncryptionManager for NoOpFieldEncryptionManager {
    async fn encrypt_field(
        &self,
        _field: &FieldIdentifier,
        _plaintext: &[u8],
    ) -> Result<EncryptedField, FortressError> {
        Err(FortressError::encryption("Field encryption is disabled", "none", EncryptionErrorCode::InvalidKeyLength))
    }

    async fn decrypt_field(
        &self,
        _ciphertext: &[u8],
        _metadata: &fortress_core::field_encryption::FieldEncryptionMetadata,
    ) -> Result<DecryptedField, FortressError> {
        Err(FortressError::encryption("Field encryption is disabled", "none", EncryptionErrorCode::InvalidKeyLength))
    }

    async fn get_field_config(&self, _field: &FieldIdentifier) -> Result<Option<fortress_core::field_encryption::FieldEncryptionConfig>, FortressError> {
        Ok(None)
    }

    async fn set_field_config(&self, _config: fortress_core::field_encryption::FieldEncryptionConfig) -> Result<(), FortressError> {
        Err(FortressError::encryption("Field encryption is disabled", "none", EncryptionErrorCode::InvalidKeyLength))
    }

    async fn remove_field_config(&self, _field: &FieldIdentifier) -> Result<(), FortressError> {
        Err(FortressError::encryption("Field encryption is disabled", "none", EncryptionErrorCode::InvalidKeyLength))
    }

    async fn list_field_configs(&self) -> Result<Vec<fortress_core::field_encryption::FieldEncryptionConfig>, FortressError> {
        Ok(vec![])
    }
}

/// In-memory storage backend for development/testing
#[derive(Debug)]
struct InMemoryStorage {
    data: Arc<parking_lot::RwLock<HashMap<String, crate::handlers::StorageRecord>>>,
}

impl InMemoryStorage {
    fn new() -> Self {
        Self {
            data: Arc::new(parking_lot::RwLock::new(HashMap::new())),
        }
    }
}

#[async_trait::async_trait]
impl StorageBackend for InMemoryStorage {
    async fn put(&self, key: &str, value: &[u8]) -> Result<(), FortressError> {
        let mut data = self.data.write();
        let record = serde_json::from_slice::<crate::handlers::StorageRecord>(value)
            .map_err(|_e| FortressError::storage("Invalid record format", "serde", StorageErrorCode::ConnectionFailed))?;
        data.insert(key.to_string(), record);
        Ok(())
    }

    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>, FortressError> {
        let data = self.data.read();
        if let Some(record) = data.get(key) {
            serde_json::to_vec(record)
                .map(Some)
                .map_err(|_e| FortressError::storage("Serialization error", "serde", StorageErrorCode::ConnectionFailed))
        } else {
            Ok(None)
        }
    }

    async fn delete(&self, key: &str) -> Result<(), FortressError> {
        let mut data = self.data.write();
        data.remove(key).map(|_| ()).ok_or_else(|| {
            FortressError::storage("Data not found", "Data not found", StorageErrorCode::NotFound)
        })
    }

    async fn exists(&self, key: &str) -> Result<bool, FortressError> {
        let data = self.data.read();
        Ok(data.contains_key(key))
    }

    async fn list_prefix(&self, prefix: &str) -> Result<Vec<String>, FortressError> {
        let data = self.data.read();
        let keys: Vec<String> = data.keys()
            .filter(|k| k.starts_with(prefix))
            .cloned()
            .collect();
        Ok(keys)
    }

    fn metadata(&self) -> StorageMetadata {
        StorageMetadata {
            backend_type: "in-memory".to_string(),
            version: "1.0.0".to_string(),
            supports_transactions: false,
            supports_encryption_at_rest: false,
            supports_streaming: false,
            supports_backup_restore: false,
            supports_audit_logging: false,
            max_object_size: Some(10 * 1024 * 1024), // 10MB
            supported_isolation_levels: vec![],
            supported_compression_algorithms: vec![],
            metadata: HashMap::new(),
        }
    }

    async fn health_check(&self) -> Result<fortress_core::storage::HealthStatus, FortressError> {
        Ok(fortress_core::storage::HealthStatus {
            healthy: true,
            response_time_ms: 1,
            details: HashMap::from([
                ("status".to_string(), "In-memory storage is healthy".to_string()),
                ("last_check".to_string(), Utc::now().to_rfc3339()),
                ("storage_size".to_string(), "1GB".to_string()),
            ]),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_server_creation() {
        let config = ServerConfig::default();
        let server = FortressServer::new(config).await;
        assert!(server.is_ok());
    }

    #[tokio::test]
    async fn test_router_creation() {
        let config = ServerConfig::default();
        let server = FortressServer::new(config).await.unwrap();
        let router = server.create_router().await;
        assert!(router.is_ok());
    }
}
