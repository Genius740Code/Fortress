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
use crate::middleware::{
    create_cors_layer, create_timeout_layer, create_trace_layer,
    auth_middleware, advanced_rate_limit_middleware, request_logging_middleware,
    request_size_middleware, security_headers_middleware, tenant_isolation_middleware,
    AdvancedRateLimiter, MiddlewareStack,
};
use crate::prelude::*;
use axum::{
    extract::DefaultBodyLimit,
    http::Method,
    routing::{get, post, delete},
    Router,
};
use fortress_core::prelude::*;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::signal;
use tower::ServiceBuilder;
use tower_http::compression::CompressionLayer;
use tracing::{info, warn, error};

/// Query parameters for storage queries
#[derive(Debug, Clone)]
pub struct QueryParams {
    pub tenant_id: Option<String>,
    pub pagination: PaginationParams,
    pub filter: Option<FilterParams>,
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

        // Create the router
        let app = self.create_router().await?;

        // Start background tasks
        let health_checker = self.health_checker.clone();
        let health_registry = self.health_registry.clone();
        let metrics = self.app_state.metrics.clone();

        tokio::spawn(async move {
            Self::run_background_tasks(health_checker, health_registry, metrics).await;
        });

        // Start the server
        let listener = tokio::net::TcpListener::bind(addr).await
            .map_err(|e| ServerError::network(format!("Failed to bind to {}: {}", addr, e)))?;

        info!(
            bind_addr = %addr,
            "Fortress server listening"
        );

        axum::serve(listener, app)
            .with_graceful_shutdown(Self::shutdown_signal())
            .await
            .map_err(|e| ServerError::network(format!("Server error: {}", e)))?;

        info!("Fortress server stopped");

        Ok(())
    }

    /// Create the application router
    async fn create_router(&self) -> ServerResult<Router<Arc<AppState>>> {
        let app_state = self.app_state.clone();
        let rate_limiter = self.rate_limiter.clone();
        let network_config = self.config.network.clone();

        // Build middleware stack
        let middleware_stack = MiddlewareStack::new()
            .add_layer(create_trace_layer())
            .add_layer(create_cors_layer(&self.config.security.cors))
            .add_layer(create_timeout_layer(self.config.network.request_timeout))
            .add_layer(CompressionLayer::new())
            .add_layer(ServiceBuilder::new()
                .layer(axum::middleware::from_fn_with_state(
                    app_state.clone(),
                    request_logging_middleware,
                ))
                .layer(axum::middleware::from_fn_with_state(
                    rate_limiter.clone(),
                    advanced_rate_limit_middleware,
                ))
                .layer(axum::middleware::from_fn_with_state(
                    network_config,
                    request_size_middleware,
                ))
                .layer(axum::middleware::from_fn(
                    security_headers_middleware,
                ))
                .layer(axum::middleware::from_fn(
                    tenant_isolation_middleware,
                ))
            )
            .add_layer(DefaultBodyLimit::max(self.config.network.max_body_size));

        // Create base router
        let mut router = Router::new()
            .route("/health", get(crate::handlers::health_check))
            .route("/metrics", get(crate::handlers::get_metrics))
            .route("/metrics/prometheus", get(crate::handlers::get_prometheus_metrics))
            .layer(middleware_stack.build());

        // Add authentication routes
        router = router
            .route("/auth/login", post(crate::handlers::authenticate))
            .route("/auth/refresh", post(crate::handlers::refresh_token));

        // Add API routes with authentication
        if self.config.features.auth_enabled {
            router = router
                .route("/data", post(crate::handlers::store_data))
                .route("/data/:id", get(crate::handlers::retrieve_data))
                .route("/data/:id", delete(crate::handlers::delete_data))
                .route("/data", get(crate::handlers::list_data))
                .route("/keys", post(crate::handlers::generate_key))
                .layer(axum::middleware::from_fn_with_state(
                    app_state.auth_manager.clone(),
                    auth_middleware,
                ))
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
        router = router.with_state(app_state);

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
    fn create_storage_backend(_config: &ServerConfig) -> ServerResult<Arc<dyn StorageBackend>> {
        // For now, use an in-memory storage backend
        // In production, this would be configurable (PostgreSQL, SQLite, etc.)
        let storage = InMemoryStorage::new();
        Ok(Arc::new(storage))
    }

    /// Run background tasks
    async fn run_background_tasks(
        health_checker: Arc<HealthChecker>,
        health_registry: Arc<HealthCheckRegistry>,
        metrics: Arc<MetricsCollector>,
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
                .expect("failed to install Ctrl+C handler");
        };

        #[cfg(unix)]
        let terminate = async {
            signal::unix::signal(signal::unix::SignalKind::terminate())
                .expect("failed to install signal handler")
                .recv()
                .await;
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
        _field_id: &FieldIdentifier,
        _data: &serde_json::Value,
        _config: &FieldEncryptionConfig,
    ) -> Result<EncryptedField, FortressError> {
        Err(FortressError::encryption("Field encryption is disabled", "none", EncryptionErrorCode::NotSupported))
    }

    async fn decrypt_field(
        &self,
        _field_id: &FieldIdentifier,
        _encrypted_field: &EncryptedField,
    ) -> Result<DecryptedField, FortressError> {
        Err(FortressError::encryption("Field encryption is disabled", "none", EncryptionErrorCode::NotSupported))
    }

    async fn get_field_metadata(
        &self,
        _field_id: &FieldIdentifier,
    ) -> Result<Option<FieldEncryptionMetadata>, FortressError> {
        Ok(None)
    }

    async fn update_field_config(
        &self,
        _field_id: &FieldIdentifier,
        _config: &FieldEncryptionConfig,
    ) -> Result<(), FortressError> {
        Err(FortressError::encryption("Field encryption is disabled", "none", EncryptionErrorCode::NotSupported))
    }

    async fn delete_field_config(
        &self,
        _field_id: &FieldIdentifier,
    ) -> Result<(), FortressError> {
        Err(FortressError::encryption("Field encryption is disabled", "none", EncryptionErrorCode::NotSupported))
    }

    async fn list_encrypted_fields(
        &self,
        _tenant_id: Option<&str>,
    ) -> Result<Vec<FieldIdentifier>, FortressError> {
        Ok(vec![])
    }
}

/// In-memory storage backend for development/testing
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
    async fn store(&self, record: StorageRecord) -> Result<(), FortressError> {
        let mut data = self.data.write();
        data.insert(record.id.clone(), crate::handlers::StorageRecord {
            id: record.id,
            key_id: record.key_id,
            data: record.data,
            algorithm: record.algorithm,
            created_at: record.created_at,
            metadata: record.metadata,
            tenant_id: record.tenant_id,
            field_metadata: record.field_metadata,
        });
        Ok(())
    }

    async fn retrieve(&self, id: &str) -> Result<StorageRecord, FortressError> {
        let data = self.data.read();
        data.get(id).cloned().ok_or_else(|| {
            FortressError::storage("Data not found", "Data not found", StorageErrorCode::NotFound)
        })
    }

    async fn delete(&self, id: &str, _soft_delete: bool) -> Result<(), FortressError> {
        let mut data = self.data.write();
        data.remove(id).ok_or_else(|| {
            FortressError::storage("Data not found", "Data not found", StorageErrorCode::NotFound)
        })?;
        Ok(())
    }

    async fn query(&self, params: crate::handlers::QueryParams) -> Result<crate::handlers::QueryResults, FortressError> {
        let data = self.data.read();
        let mut records: Vec<crate::handlers::StorageRecord> = data.values().cloned().collect();

        // Apply filters
        // Filter by tenant_id from the QueryParams itself
        if let Some(ref tenant_id) = params.tenant_id {
            records.retain(|r| r.tenant_id.as_ref() == Some(tenant_id));
        }
        
        if let Some(filter) = &params.filter {
            if let Some(ref algorithm) = filter.algorithm {
                records.retain(|r| r.algorithm == *algorithm);
            }
            if let Some(ref date_range) = filter.date_range {
                if let Some(start) = date_range.start {
                    records.retain(|r| r.created_at >= start);
                }
                if let Some(end) = date_range.end {
                    records.retain(|r| r.created_at <= end);
                }
            }
        }

        // Apply sorting
        match params.sort.field.as_str() {
            "created_at" => {
                records.sort_by(|a, b| {
                    match params.sort.direction {
                        crate::models::SortDirection::Asc => a.created_at.cmp(&b.created_at),
                        crate::models::SortDirection::Desc => b.created_at.cmp(&a.created_at),
                    }
                });
            }
            _ => {
                // Default sort by created_at descending
                records.sort_by(|a, b| b.created_at.cmp(&a.created_at));
            }
        }

        // Apply pagination
        let total_count = records.len() as u64;
        let page = params.pagination.page.unwrap_or(1);
        let page_size = params.pagination.page_size.unwrap_or(50);
        let start = ((page - 1) * page_size) as usize;
        let end = std::cmp::min(start + page_size as usize, records.len());
        
        let paginated_records = if start < records.len() {
            records[start..end].to_vec()
        } else {
            vec![]
        };

        Ok(crate::handlers::QueryResults {
            records: paginated_records,
            total_count,
        })
    }

    async fn list_tenants(&self) -> Result<Vec<String>, FortressError> {
        let data = self.data.read();
        let mut tenants = std::collections::HashSet::<String>::new();
        for record in data.values() {
            if let Some(ref tenant_id) = record.tenant_id {
                tenants.insert(tenant_id.clone());
            }
        }
        Ok(tenants.into_iter().collect())
    }

    async fn get_tenant_stats(&self, _tenant_id: &str) -> Result<TenantStats, FortressError> {
        // Simplified implementation
        Ok(TenantStats {
            database_count: 0,
            storage_used: 0,
            active_connections: 0,
            cpu_usage: 0.0,
            memory_usage: 0.0,
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
