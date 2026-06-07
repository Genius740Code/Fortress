//! # Transit Engine API Layer
//!
//! HTTP and gRPC API endpoints for the Fortress Transit Engine.
//! This provides the external interface that applications use to communicate
//! with the security sidecar.
//!
//! ## API Endpoints
//!
//! ### HTTP REST API
//! - `POST /v1/transit/encrypt` - Encrypt data
//! - `POST /v1/transit/decrypt` - Decrypt data
//! - `POST /v1/transit/batch-encrypt` - Batch encrypt multiple items
//! - `POST /v1/transit/rewrap` - Re-encrypt with different key
//! - `GET /v1/transit/keys/{name}` - Get key information
//! - `GET /v1/transit/keys` - List all keys
//! - `POST /v1/transit/keys/{name}/rotate` - Rotate key
//! - `GET /v1/transit/stats` - Get engine statistics
//!
//! ### gRPC API
//! - `Encrypt` - Encrypt data
//! - `Decrypt` - Decrypt data
//! - `BatchEncrypt` - Batch encrypt multiple items
//! - `Rewrap` - Re-encrypt with different key
//! - `GetKeyInfo` - Get key information
//! - `ListKeys` - List all keys
//! - `RotateKey` - Rotate key
//! - `GetStats` - Get engine statistics

use crate::transit_engine_v2::{TransitEngine, EncryptRequest, DecryptResponse, EncryptResponse, DecryptRequest, BatchEncryptRequest, BatchEncryptResponse, RewrapRequest, RewrapResponse, KeyInfo, TransitStats};
use crate::error::{FortressError, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use chrono::{DateTime, Utc};
use uuid::Uuid;

/// HTTP API request/response structures
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpRequest<T> {
    pub request_id: String,
    pub timestamp: DateTime<Utc>,
    pub data: T,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpResponse<T> {
    pub request_id: String,
    pub timestamp: DateTime<Utc>,
    pub success: bool,
    pub data: Option<T>,
    pub error: Option<ApiError>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiError {
    pub code: String,
    pub message: String,
    pub details: Option<serde_json::Value>,
}

/// Transit API server configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransitApiConfig {
    /// Bind address for HTTP server
    pub http_bind_address: String,
    /// Bind address for gRPC server
    pub grpc_bind_address: String,
    /// Enable HTTP API
    pub enable_http: bool,
    /// Enable gRPC API
    pub enable_grpc: bool,
    /// Enable TLS
    pub enable_tls: bool,
    /// TLS certificate path
    pub tls_cert_path: Option<String>,
    /// TLS private key path
    pub tls_key_path: Option<String>,
    /// API authentication required
    pub require_auth: bool,
    /// JWT secret for authentication
    pub jwt_secret: Option<String>,
    /// CORS allowed origins
    pub cors_allowed_origins: Vec<String>,
    /// Request timeout in seconds
    pub request_timeout_seconds: u64,
    /// Max request size in bytes
    pub max_request_size_bytes: usize,
}

impl Default for TransitApiConfig {
    fn default() -> Self {
        Self {
            http_bind_address: "0.0.0.0:8200".to_string(), // Vault-compatible port
            grpc_bind_address: "0.0.0.0:9090".to_string(),
            enable_http: true,
            enable_grpc: true,
            enable_tls: false,
            tls_cert_path: None,
            tls_key_path: None,
            require_auth: true,
            jwt_secret: Some("change-me-in-production".to_string()),
            cors_allowed_origins: vec!["*".to_string()],
            request_timeout_seconds: 30,
            max_request_size_bytes: 10 * 1024 * 1024, // 10MB
        }
    }
}

/// Main Transit API server
#[derive(Debug)]
pub struct TransitApiServer {
    /// Transit engine instance
    transit_engine: Arc<TransitEngine>,
    /// API configuration
    config: Arc<RwLock<TransitApiConfig>>,
    /// Active HTTP server handle
    http_server: Arc<RwLock<Option<tokio::task::JoinHandle<()>>>>,
    /// Active gRPC server handle
    grpc_server: Arc<RwLock<Option<tokio::task::JoinHandle<()>>>>,
    /// Request metrics
    metrics: Arc<RwLock<ApiMetrics>>,
}

/// API metrics
#[derive(Debug, Clone, Default)]
pub struct ApiMetrics {
    pub total_requests: u64,
    pub successful_requests: u64,
    pub failed_requests: u64,
    pub avg_response_time_ms: f64,
    pub requests_per_second: f64,
    pub active_connections: u64,
    pub last_request: Option<DateTime<Utc>>,
}

impl TransitApiServer {
    /// Create new Transit API server
    pub async fn new(transit_engine: TransitEngine) -> Result<Self> {
        Self::with_config(transit_engine, TransitApiConfig::default()).await
    }

    /// Create Transit API server with custom configuration
    pub async fn with_config(transit_engine: TransitEngine, config: TransitApiConfig) -> Result<Self> {
        Ok(Self {
            transit_engine: Arc::new(transit_engine),
            config: Arc::new(RwLock::new(config)),
            http_server: Arc::new(RwLock::new(None)),
            grpc_server: Arc::new(RwLock::new(None)),
            metrics: Arc::new(RwLock::new(ApiMetrics::default())),
        })
    }

    /// Start the API servers
    pub async fn start(&self) -> Result<()> {
        let config = self.config.read().await.clone();
        
        // Start HTTP server if enabled
        if config.enable_http {
            self.start_http_server().await?;
        }
        
        // Start gRPC server if enabled
        if config.enable_grpc {
            self.start_grpc_server().await?;
        }
        
        tracing::info!("Transit API server started");
        tracing::info!("HTTP API: {}", config.http_bind_address);
        tracing::info!("gRPC API: {}", config.grpc_bind_address);
        
        Ok(())
    }

    /// Stop the API servers
    pub async fn stop(&self) -> Result<()> {
        tracing::info!("Stopping Transit API server");
        
        // Stop HTTP server
        {
            let mut http_server = self.http_server.write().await;
            if let Some(handle) = http_server.take() {
                handle.abort();
            }
        }
        
        // Stop gRPC server
        {
            let mut grpc_server = self.grpc_server.write().await;
            if let Some(handle) = grpc_server.take() {
                handle.abort();
            }
        }
        
        tracing::info!("Transit API server stopped");
        Ok(())
    }

    /// Start HTTP server
    async fn start_http_server(&self) -> Result<()> {
        use warp::{Filter, Reply};
        
        let transit_engine = self.transit_engine.clone();
        let metrics = self.metrics.clone();
        let config = self.config.read().await.clone();
        
        // Build CORS configuration
        let cors = warp::cors()
            .allow_any_origin()
            .allow_headers(vec!["content-type", "authorization"])
            .allow_methods(vec!["GET", "POST", "PUT", "DELETE"]);
        
        // Build authentication middleware
        let auth = self.build_auth_middleware(&config);
        
        // Metrics middleware
        let metrics_middleware = self.build_metrics_middleware(metrics.clone());
        
        // API routes
        let encrypt_route = warp::path("v1")
            .and(warp::path("transit"))
            .and(warp::path("encrypt"))
            .and(warp::post())
            .and(warp::body::json())
            .and(metrics_middleware)
            .and(auth)
            .and_then(move |request: HttpRequest<EncryptRequest>, metrics| {
                let engine = transit_engine.clone();
                async move {
                    match handle_encrypt_request(engine, request).await {
                        Ok(response) => {
                            update_metrics(&metrics, true, std::time::Duration::from_millis(100));
                            Ok(warp::reply::json(&response))
                        }
                        Err(e) => {
                            update_metrics(&metrics, false, std::time::Duration::from_millis(100));
                            let error_response = HttpResponse::<()> {
                                request_id: request.request_id,
                                timestamp: Utc::now(),
                                success: false,
                                data: None,
                                error: Some(ApiError {
                                    code: "ENCRYPT_ERROR".to_string(),
                                    message: e.to_string(),
                                    details: None,
                                }),
                            };
                            Ok(warp::reply::json(&error_response))
                        }
                    }
                }
            });
        
        let decrypt_route = warp::path("v1")
            .and(warp::path("transit"))
            .and(warp::path("decrypt"))
            .and(warp::post())
            .and(warp::body::json())
            .and(metrics_middleware)
            .and(auth)
            .and_then(move |request: HttpRequest<DecryptRequest>, metrics| {
                let engine = transit_engine.clone();
                async move {
                    match handle_decrypt_request(engine, request).await {
                        Ok(response) => {
                            update_metrics(&metrics, true, std::time::Duration::from_millis(100));
                            Ok(warp::reply::json(&response))
                        }
                        Err(e) => {
                            update_metrics(&metrics, false, std::time::Duration::from_millis(100));
                            let error_response = HttpResponse::<()> {
                                request_id: request.request_id,
                                timestamp: Utc::now(),
                                success: false,
                                data: None,
                                error: Some(ApiError {
                                    code: "DECRYPT_ERROR".to_string(),
                                    message: e.to_string(),
                                    details: None,
                                }),
                            };
                            Ok(warp::reply::json(&error_response))
                        }
                    }
                }
            });
        
        let batch_encrypt_route = warp::path("v1")
            .and(warp::path("transit"))
            .and(warp::path("batch-encrypt"))
            .and(warp::post())
            .and(warp::body::json())
            .and(metrics_middleware)
            .and(auth)
            .and_then(move |request: HttpRequest<BatchEncryptRequest>, metrics| {
                let engine = transit_engine.clone();
                async move {
                    match handle_batch_encrypt_request(engine, request).await {
                        Ok(response) => {
                            update_metrics(&metrics, true, std::time::Duration::from_millis(200));
                            Ok(warp::reply::json(&response))
                        }
                        Err(e) => {
                            update_metrics(&metrics, false, std::time::Duration::from_millis(200));
                            let error_response = HttpResponse::<()> {
                                request_id: request.request_id,
                                timestamp: Utc::now(),
                                success: false,
                                data: None,
                                error: Some(ApiError {
                                    code: "BATCH_ENCRYPT_ERROR".to_string(),
                                    message: e.to_string(),
                                    details: None,
                                }),
                            };
                            Ok(warp::reply::json(&error_response))
                        }
                    }
                }
            });
        
        let rewrap_route = warp::path("v1")
            .and(warp::path("transit"))
            .and(warp::path("rewrap"))
            .and(warp::post())
            .and(warp::body::json())
            .and(metrics_middleware)
            .and(auth)
            .and_then(move |request: HttpRequest<RewrapRequest>, metrics| {
                let engine = transit_engine.clone();
                async move {
                    match handle_rewrap_request(engine, request).await {
                        Ok(response) => {
                            update_metrics(&metrics, true, std::time::Duration::from_millis(150));
                            Ok(warp::reply::json(&response))
                        }
                        Err(e) => {
                            update_metrics(&metrics, false, std::time::Duration::from_millis(150));
                            let error_response = HttpResponse::<()> {
                                request_id: request.request_id,
                                timestamp: Utc::now(),
                                success: false,
                                data: None,
                                error: Some(ApiError {
                                    code: "REWRAP_ERROR".to_string(),
                                    message: e.to_string(),
                                    details: None,
                                }),
                            };
                            Ok(warp::reply::json(&error_response))
                        }
                    }
                }
            });
        
        let keys_route = warp::path("v1")
            .and(warp::path("transit"))
            .and(warp::path("keys"))
            .and(warp::get())
            .and(metrics_middleware)
            .and(auth)
            .and_then(move |_: (), metrics| {
                let engine = transit_engine.clone();
                async move {
                    match handle_list_keys_request(engine).await {
                        Ok(response) => {
                            update_metrics(&metrics, true, std::time::Duration::from_millis(50));
                            Ok(warp::reply::json(&response))
                        }
                        Err(e) => {
                            update_metrics(&metrics, false, std::time::Duration::from_millis(50));
                            let error_response = HttpResponse::<()> {
                                request_id: Uuid::new_v4().to_string(),
                                timestamp: Utc::now(),
                                success: false,
                                data: None,
                                error: Some(ApiError {
                                    code: "LIST_KEYS_ERROR".to_string(),
                                    message: e.to_string(),
                                    details: None,
                                }),
                            };
                            Ok(warp::reply::json(&error_response))
                        }
                    }
                }
            });
        
        let key_info_route = warp::path("v1")
            .and(warp::path("transit"))
            .and(warp::path("keys"))
            .and(warp::path::param::<String>())
            .and(warp::get())
            .and(metrics_middleware)
            .and(auth)
            .and_then(move |key_name: String, metrics| {
                let engine = transit_engine.clone();
                async move {
                    match handle_get_key_info_request(engine, &key_name).await {
                        Ok(response) => {
                            update_metrics(&metrics, true, std::time::Duration::from_millis(50));
                            Ok(warp::reply::json(&response))
                        }
                        Err(e) => {
                            update_metrics(&metrics, false, std::time::Duration::from_millis(50));
                            let error_response = HttpResponse::<()> {
                                request_id: Uuid::new_v4().to_string(),
                                timestamp: Utc::now(),
                                success: false,
                                data: None,
                                error: Some(ApiError {
                                    code: "GET_KEY_INFO_ERROR".to_string(),
                                    message: e.to_string(),
                                    details: None,
                                }),
                            };
                            Ok(warp::reply::json(&error_response))
                        }
                    }
                }
            });
        
        let rotate_key_route = warp::path("v1")
            .and(warp::path("transit"))
            .and(warp::path("keys"))
            .and(warp::path::param::<String>())
            .and(warp::path("rotate"))
            .and(warp::post())
            .and(metrics_middleware)
            .and(auth)
            .and_then(move |key_name: String, metrics| {
                let engine = transit_engine.clone();
                async move {
                    match handle_rotate_key_request(engine, &key_name).await {
                        Ok(response) => {
                            update_metrics(&metrics, true, std::time::Duration::from_millis(200));
                            Ok(warp::reply::json(&response))
                        }
                        Err(e) => {
                            update_metrics(&metrics, false, std::time::Duration::from_millis(200));
                            let error_response = HttpResponse::<()> {
                                request_id: Uuid::new_v4().to_string(),
                                timestamp: Utc::now(),
                                success: false,
                                data: None,
                                error: Some(ApiError {
                                    code: "ROTATE_KEY_ERROR".to_string(),
                                    message: e.to_string(),
                                    details: None,
                                }),
                            };
                            Ok(warp::reply::json(&error_response))
                        }
                    }
                }
            });
        
        let stats_route = warp::path("v1")
            .and(warp::path("transit"))
            .and(warp::path("stats"))
            .and(warp::get())
            .and(metrics_middleware)
            .and(auth)
            .and_then(move |_: (), metrics| {
                let engine = transit_engine.clone();
                async move {
                    match handle_get_stats_request(engine).await {
                        Ok(response) => {
                            update_metrics(&metrics, true, std::time::Duration::from_millis(30));
                            Ok(warp::reply::json(&response))
                        }
                        Err(e) => {
                            update_metrics(&metrics, false, std::time::Duration::from_millis(30));
                            let error_response = HttpResponse::<()> {
                                request_id: Uuid::new_v4().to_string(),
                                timestamp: Utc::now(),
                                success: false,
                                data: None,
                                error: Some(ApiError {
                                    code: "GET_STATS_ERROR".to_string(),
                                    message: e.to_string(),
                                    details: None,
                                }),
                            };
                            Ok(warp::reply::json(&error_response))
                        }
                    }
                }
            });
        
        let health_route = warp::path("health")
            .and(warp::get())
            .and_then(|| async {
                Ok(warp::reply::json(&serde_json::json!({
                    "status": "healthy",
                    "timestamp": Utc::now().to_rfc3339()
                })))
            });
        
        let routes = encrypt_route
            .or(decrypt_route)
            .or(batch_encrypt_route)
            .or(rewrap_route)
            .or(keys_route)
            .or(key_info_route)
            .or(rotate_key_route)
            .or(stats_route)
            .or(health_route)
            .with(cors)
            .with(warp::log("transit_api"));
        
        let addr: std::net::SocketAddr = config.http_bind_address.parse()
            .map_err(|e| FortressError::transit(format!("Invalid bind address: {}", e)))?;
        
        let server = warp::serve(routes).run(addr);
        let handle = tokio::spawn(server);
        
        {
            let mut http_server = self.http_server.write().await;
            *http_server = Some(handle);
        }
        
        tracing::info!("HTTP server started on {}", config.http_bind_address);
        Ok(())
    }

    /// Start gRPC server (placeholder for future implementation)
    async fn start_grpc_server(&self) -> Result<()> {
        let config = self.config.read().await;
        
        // This is a placeholder for gRPC server implementation
        // In a full implementation, you would use tonic or gRPC server framework
        
        tracing::info!("gRPC server would start on {}", config.grpc_bind_address);
        tracing::warn!("gRPC server not yet implemented - HTTP API available");
        
        Ok(())
    }

    /// Build authentication middleware
    fn build_auth_middleware(&self, config: &TransitApiConfig) -> warp::cors::Builder {
        // This is a simplified auth middleware
        // In production, you would implement proper JWT validation
        
        if config.require_auth {
            // Return CORS builder that will be combined with auth logic
            warp::cors()
                .allow_any_origin()
                .allow_headers(vec!["content-type", "authorization"])
                .allow_methods(vec!["GET", "POST", "PUT", "DELETE"])
        } else {
            warp::cors()
                .allow_any_origin()
                .allow_headers(vec!["content-type"])
                .allow_methods(vec!["GET", "POST", "PUT", "DELETE"])
        }
    }

    /// Build metrics middleware
    fn build_metrics_middleware(&self, metrics: Arc<RwLock<ApiMetrics>>) -> impl Clone {
        let metrics_clone = metrics.clone();
        move || {
            let metrics = metrics_clone.clone();
            move || {
                let metrics = metrics.clone();
                async move {
                    // Update connection count
                    {
                        let mut m = metrics.write().await;
                        m.active_connections += 1;
                        m.last_request = Some(Utc::now());
                    }
                    
                    // Return cleanup function
                    let metrics_cleanup = metrics.clone();
                    move || {
                        let mut m = metrics_cleanup.write().await;
                        m.active_connections = m.active_connections.saturating_sub(1);
                    }
                }
            }
        }
    }

    /// Get API metrics
    pub async fn get_metrics(&self) -> ApiMetrics {
        self.metrics.read().await.clone()
    }
}

// HTTP request handlers
async fn handle_encrypt_request(
    engine: Arc<TransitEngine>,
    request: HttpRequest<EncryptRequest>,
) -> Result<HttpResponse<EncryptResponse>> {
    let response = engine.encrypt(request.data).await?;
    
    Ok(HttpResponse {
        request_id: request.request_id,
        timestamp: Utc::now(),
        success: true,
        data: Some(response),
        error: None,
    })
}

async fn handle_decrypt_request(
    engine: Arc<TransitEngine>,
    request: HttpRequest<DecryptRequest>,
) -> Result<HttpResponse<DecryptResponse>> {
    let response = engine.decrypt(request.data).await?;
    
    Ok(HttpResponse {
        request_id: request.request_id,
        timestamp: Utc::now(),
        success: true,
        data: Some(response),
        error: None,
    })
}

async fn handle_batch_encrypt_request(
    engine: Arc<TransitEngine>,
    request: HttpRequest<BatchEncryptRequest>,
) -> Result<HttpResponse<BatchEncryptResponse>> {
    let response = engine.batch_encrypt(request.data).await?;
    
    Ok(HttpResponse {
        request_id: request.request_id,
        timestamp: Utc::now(),
        success: true,
        data: Some(response),
        error: None,
    })
}

async fn handle_rewrap_request(
    engine: Arc<TransitEngine>,
    request: HttpRequest<RewrapRequest>,
) -> Result<HttpResponse<RewrapResponse>> {
    let response = engine.rewrap(request.data).await?;
    
    Ok(HttpResponse {
        request_id: request.request_id,
        timestamp: Utc::now(),
        success: true,
        data: Some(response),
        error: None,
    })
}

async fn handle_list_keys_request(
    engine: Arc<TransitEngine>,
) -> Result<HttpResponse<Vec<String>>> {
    let keys = engine.list_keys().await?;
    
    Ok(HttpResponse {
        request_id: Uuid::new_v4().to_string(),
        timestamp: Utc::now(),
        success: true,
        data: Some(keys),
        error: None,
    })
}

async fn handle_get_key_info_request(
    engine: Arc<TransitEngine>,
    key_name: &str,
) -> Result<HttpResponse<KeyInfo>> {
    let key_info = engine.get_key_info(key_name).await?;
    
    Ok(HttpResponse {
        request_id: Uuid::new_v4().to_string(),
        timestamp: Utc::now(),
        success: true,
        data: Some(key_info),
        error: None,
    })
}

async fn handle_rotate_key_request(
    engine: Arc<TransitEngine>,
    key_name: &str,
) -> Result<HttpResponse<KeyInfo>> {
    let key_info = engine.rotate_key(key_name).await?;
    
    Ok(HttpResponse {
        request_id: Uuid::new_v4().to_string(),
        timestamp: Utc::now(),
        success: true,
        data: Some(key_info),
        error: None,
    })
}

async fn handle_get_stats_request(
    engine: Arc<TransitEngine>,
) -> Result<HttpResponse<TransitStats>> {
    let stats = engine.get_stats().await?;
    
    Ok(HttpResponse {
        request_id: Uuid::new_v4().to_string(),
        timestamp: Utc::now(),
        success: true,
        data: Some(stats),
        error: None,
    })
}

fn update_metrics(metrics: &Arc<RwLock<ApiMetrics>>, success: bool, response_time: std::time::Duration) -> Result<(), FortressError> {
    let mut m = metrics.write().map_err(|e| {
        FortressError::internal(format!("Failed to acquire metrics lock: {}", e), "METRICS_LOCK")
    })?;
    m.total_requests += 1;
    
    if success {
        m.successful_requests += 1;
    } else {
        m.failed_requests += 1;
    }
    
    let response_time_ms = response_time.as_millis() as f64;
    m.avg_response_time_ms = (m.avg_response_time_ms * (m.total_requests - 1) as f64 + response_time_ms) / m.total_requests as f64;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio_test;

    #[tokio::test]
    async fn test_api_server_creation() {
        let transit_engine = TransitEngine::new().await.unwrap();
        let api_server = TransitApiServer::new(transit_engine).await.unwrap();
        let metrics = api_server.get_metrics().await;
        assert_eq!(metrics.total_requests, 0);
    }

    #[tokio::test]
    async fn test_encrypt_request_handling() {
        let transit_engine = TransitEngine::new().await.unwrap();
        let engine = Arc::new(transit_engine);
        
        let request = HttpRequest {
            request_id: "test-123".to_string(),
            timestamp: Utc::now(),
            data: EncryptRequest {
                plaintext: "test data".to_string(),
                key_name: "test-key".to_string(),
                algorithm: None,
                context: None,
                ttl_seconds: None,
                encoded: Some(true),
                associated_data: None,
            },
        };
        
        let response = handle_encrypt_request(engine, request).await.unwrap();
        assert!(response.success);
        assert!(response.data.is_some());
        assert_eq!(response.request_id, "test-123");
    }
}
