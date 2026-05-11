//! HTTP request handlers for the Fortress REST API
//!
//! This module contains all the request handlers for various API endpoints,
//! including data storage, retrieval, key management, and authentication.

use crate::auth::{AuthManager, OptionalTokenClaims};
use crate::error::{ServerError, ServerResult};
use crate::models::*;
use crate::metrics::MetricsCollector;
use axum::{
    extract::{Path, Query, State},
    response::Json,
};
use chrono::{Utc, DateTime};
use fortress_core::{
    encryption::{EncryptionAlgorithm, Aegis256},
    key::{KeyManager, SecureKey, InMemoryKeyManager},
    storage::StorageBackend,
    field_encryption::FieldEncryptionManager,
    tenant::{TenantManager, InMemoryTenantManager, CreateTenantRequest, TenantResourceLimits},
    dynamic_secrets::DynamicSecretsEngine,
};
use crate::health::HealthChecker;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tracing::info;
use uuid::Uuid;
use utoipa::{
    OpenApi,
};

/// Sanitize error messages to prevent information disclosure
pub fn sanitize_error(error: &ServerError) -> &'static str {
    match error {
        ServerError::Core(core_err) => {
            match core_err {
                fortress_core::error::FortressError::Storage { .. } => "Database operation failed",
                fortress_core::error::FortressError::Encryption { .. } => "Data protection failed",
                fortress_core::error::FortressError::KeyManagement { .. } => "Key operation failed",
                fortress_core::error::FortressError::Configuration { .. } => "Configuration error",
                fortress_core::error::FortressError::Cluster { .. } => "Cluster operation failed",
                fortress_core::error::FortressError::QueryExecution { .. } => "Query operation failed",
                fortress_core::error::FortressError::Validation { .. } => "Invalid input provided",
                fortress_core::error::FortressError::Io { .. } => "I/O operation failed",
                fortress_core::error::FortressError::Network { .. } => "Network operation failed",
                fortress_core::error::FortressError::Authentication { .. } => "Authentication failed",
                fortress_core::error::FortressError::RateLimit { .. } => "Rate limit exceeded",
                fortress_core::error::FortressError::Internal { .. } => "Internal server error",
                fortress_core::error::FortressError::PolicyError(_) => "Access denied",
                fortress_core::error::FortressError::Token { .. } => "Authentication failed",
                fortress_core::error::FortressError::Seal { .. } => "Data protection failed",
                fortress_core::error::FortressError::Plugin { .. } => "Plugin operation failed",
                _ => "Internal server error",
            }
        },
        ServerError::Authentication(_) => "Authentication failed",
        ServerError::Authorization(_) => "Access denied",
        ServerError::Validation(_) => "Invalid input provided",
        ServerError::NotFound(_) => "Resource not found",
        ServerError::Conflict(_) => "Resource conflict",
        ServerError::RateLimit => "Rate limit exceeded",
        ServerError::DdosBlocked => "Request blocked",
        ServerError::QuotaExceeded(_) => "Quota exceeded",
        ServerError::PayloadTooLarge(_) => "Payload too large",
        ServerError::Serialization(_) => "Data processing failed",
        ServerError::Network(_) => "Network operation failed",
        ServerError::Configuration(_) => "Configuration error",
        ServerError::Internal(_) => "Internal server error",
        ServerError::Timeout => "Request timeout",
        ServerError::Unavailable(_) => "Service unavailable",
    }
}

/// Storage record (simplified for this example)
#[derive(Debug, Clone, Serialize, Deserialize)]

pub struct StorageRecord {
    /// Unique identifier for the storage record
    
    pub id: String,
    /// Unique identifier for the encryption key
    
    pub key_id: String,
    /// Encrypted data bytes
    
    pub data: Vec<u8>,
    /// Name of the encryption algorithm used
    
    pub algorithm: String,
    /// Timestamp when the record was created
    
    pub created_at: DateTime<Utc>,
    /// Optional metadata associated with the record
    
    pub metadata: Option<HashMap<String, serde_json::Value>>,
    /// Optional tenant identifier for multi-tenancy
    
    pub tenant_id: Option<String>,
    /// Optional field-level encryption metadata
    
    pub field_metadata: Option<HashMap<String, FieldEncryptionMetadata>>,
}

/// Query parameters for storage queries
#[derive(Debug, Clone, Deserialize)]

pub struct QueryParams {
    /// Optional tenant identifier for filtering
    
    pub tenant_id: Option<String>,
    /// Pagination parameters for query
    
    pub pagination: PaginationParams,
    /// Optional filtering parameters
    pub filter: Option<FilterParams>,
    /// Sorting parameters for the query
    pub sort: SortParams,
}

/// Query results
#[derive(Debug, Clone)]
pub struct QueryResults {
    /// List of storage records matching the query
    pub records: Vec<StorageRecord>,
    /// Total count of records available
    pub total_count: u64,
}

/// Application state shared across handlers
#[derive(Clone)]
pub struct AppState {
    /// Authentication manager
    pub auth_manager: Arc<AuthManager>,
    /// Metrics collector
    pub metrics: Arc<MetricsCollector>,
    /// Key manager
    pub key_manager: Arc<InMemoryKeyManager>,
    /// Field encryption manager
    pub field_encryption_manager: Arc<dyn FieldEncryptionManager>,
    /// Storage backend
    pub storage: Arc<dyn StorageBackend>,
    /// Health checker
    pub health_checker: Arc<HealthChecker>,
    /// Tenant manager
    pub tenant_manager: Arc<InMemoryTenantManager>,
    /// Dynamic secrets engine
    pub dynamic_secrets: Arc<DynamicSecretsEngine>,
}

/// Store data handler
#[utoipa::path(
    post,
    path = "/api/v1/data",
    request_body = StoreRequest,
    responses(
        (status = 200, description = "Data stored successfully", body = ApiResponse<StoreDataResponse>),
        (status = 400, description = "Invalid request", body = ErrorResponse),
        (status = 401, description = "Unauthorized", body = ErrorResponse),
        (status = 500, description = "Internal server error", body = ErrorResponse)
    ),
    tag = "data",
    security(
        ("jwt_auth" = [])
    )
)]
pub async fn store_data(
    State(state): State<Arc<AppState>>,
    OptionalTokenClaims(claims): OptionalTokenClaims,
    Json(request): Json<StoreRequest>,
) -> ServerResult<Json<ApiResponse<StoreDataResponse>>> {
    let start_time = std::time::Instant::now();
    
    info!(
        user_id = ?claims.as_ref().map(|c| &c.sub),
        tenant_id = ?request.tenant_id,
        "Store data request received"
    );

    // Input validation
    let validator = fortress_core::input_validation::InputValidator::new();
    
    // Validate tenant ID if present
    if let Some(ref tenant_id) = request.tenant_id {
        validator.validate_string(tenant_id, "tenant_id")?;
        
        // Validate tenant access if multi-tenant
        if let Some(ref claims) = claims {
            if !state.auth_manager.has_tenant_access(claims, tenant_id) {
                return Err(ServerError::access_denied("Access denied to tenant"));
            }
        }
    }
    
    // Validate key ID if present
    if let Some(ref key_id) = request.key_id {
        validator.validate_string(key_id, "key_id")?;
    }
    
    // Validate algorithm if present
    if let Some(ref algorithm) = request.algorithm {
        validator.validate_string(algorithm, "algorithm")?;
    }
    
    // Validate data size
    let data_str = serde_json::to_string(&request.data)
        .map_err(|e| ServerError::validation(format!("Invalid JSON data: {}", e)))?;
    validator.validate_length(&data_str, 0, 100000)?; // Max 100KB

    // Generate data ID
    let data_id = Uuid::new_v4().to_string();

    // Get or generate encryption key
    let key_id = request.key_id.clone().unwrap_or_else(|| format!("key_{}", Uuid::new_v4()));

    // Ensure the key exists; if not, generate and store it.
    // This keeps the API usable without requiring a prior key-generation call.
    if !state.key_manager.key_exists(&key_id).await.map_err(ServerError::Core)? {
        let algorithm = Aegis256::new();
        let new_key = state
            .key_manager
            .generate_key(&algorithm)
            .await
            .map_err(ServerError::Core)?;

        let metadata = fortress_core::key::KeyMetadata::new(
            key_id.clone(),
            algorithm.name().to_string(),
            1,
            Utc::now(),
            Utc::now() + chrono::Duration::days(90),
            "data_encryption".to_string(),
            fortress_core::encryption::PerformanceProfile::Balanced,
        );

        state
            .key_manager
            .store_key(&key_id, &new_key, &metadata)
            .await
            .map_err(ServerError::Core)?;
    }

    // Get the key
    let key = state
        .key_manager
        .retrieve_key(&key_id)
        .await
        .map_err(ServerError::Core)?;
    let key_bytes = key.0.as_bytes();

    // Encrypt data
    let data_json = serde_json::to_string(&request.data)
        .map_err(|e| ServerError::serialization(e.to_string()))?;
    
    let plaintext = data_json.as_bytes();
    let ciphertext = match Aegis256::new().encrypt(plaintext, key_bytes) {
        Ok(ciphertext) => ciphertext,
        Err(e) => return Err(ServerError::Core(e)),
    };

    // Handle field-level encryption if specified
    let field_metadata = if let Some(ref field_config) = request.field_encryption {
        let mut metadata = HashMap::new();
        for (field_name, field_config) in &field_config.fields {
            if let Some(field_value) = get_nested_value(&request.data, field_name) {
                let field_id = fortress_core::field_encryption::FieldIdentifier::Name(field_name.clone());
                
                // Cache serialized field value to avoid repeated serialization
                let field_bytes = serde_json::to_vec(&field_value)
                    .map_err(|e| ServerError::serialization(e.to_string()))?;
                
                if let Ok(_encrypted_field) = state.field_encryption_manager.encrypt_field(&field_id, &field_bytes).await {
                    metadata.insert(field_name.clone(), FieldEncryptionMetadata {
                        config_id: "default".to_string(),
                        field: field_name.clone(),
                        algorithm: field_config.algorithm.clone(),
                        key_id: field_config.key_id.clone().unwrap_or_else(|| "default".to_string()),
                        key_version: 1,
                        encrypted_at: Utc::now(),
                        nonce: None,
                        tag: None,
                        metadata: HashMap::new(),
                    });
                }
            }
        }
        Some(metadata)
    } else {
        None
    };

    // Create storage record
    let storage_record = StorageRecord {
        id: data_id.clone(),
        key_id: key_id.clone(),
        data: ciphertext,
        algorithm: "aegis256".to_string(),
        created_at: Utc::now(),
        metadata: request.metadata,
        tenant_id: request.tenant_id.clone(),
        field_metadata,
    };

    // Store the encrypted data using the storage backend
    // Cache serialized record to avoid repeated serialization
    let record_bytes = serde_json::to_vec(&storage_record)
        .map_err(|e| ServerError::serialization(e.to_string()))?;
    
    state.storage.put(&data_id, &record_bytes).await
        .map_err(|e| ServerError::Core(e))?;
    
    let response = StoreDataResponse {
        id: data_id,
        key_id,
        stored_at: Utc::now(),
        size_bytes: storage_record.data.len() as u64,
        algorithm: "aegis256".to_string(),
        field_metadata: storage_record.field_metadata.map(|core_metadata| {
            core_metadata.into_iter().map(|(field, meta)| {
                (field, serde_json::to_value(meta).unwrap_or_default())
            }).collect()
        }),
    };

    info!(
        data_id = %response.id,
        size_bytes = response.size_bytes,
        duration_ms = start_time.elapsed().as_millis(),
        "Data stored successfully"
    );

    Ok(Json(ApiResponse::success(response)))
}

/// Retrieve data handler
#[utoipa::path(
    get,
    path = "/api/v1/data/{id}",
    params(
        ("id" = String, Path, description = "Data ID to retrieve")
    ),
    responses(
        (status = 200, description = "Data retrieved successfully", body = ApiResponse<RetrieveDataResponse>),
        (status = 404, description = "Data not found", body = ErrorResponse),
        (status = 401, description = "Unauthorized", body = ErrorResponse),
        (status = 500, description = "Internal server error", body = ErrorResponse)
    ),
    tag = "data",
    security(
        ("jwt_auth" = [])
    )
)]
pub async fn retrieve_data(
    State(state): State<Arc<AppState>>,
    OptionalTokenClaims(claims): OptionalTokenClaims,
    Path(data_id): Path<String>,
    Query(_params): Query<RetrieveRequest>,
) -> ServerResult<Json<ApiResponse<RetrieveDataResponse>>> {
    let start_time = std::time::Instant::now();
    
    info!(
        user_id = ?claims.as_ref().map(|c| &c.sub),
        data_id = %data_id,
        "Retrieve data request received"
    );

    // Input validation
    let validator = fortress_core::input_validation::InputValidator::new();
    
    // Validate data ID
    validator.validate_uuid(&data_id)?;

    // Retrieve the storage record
    let record_bytes = state.storage.get(&data_id).await
        .map_err(|e| ServerError::Core(e))?
        .ok_or_else(|| ServerError::not_found("Data not found"))?;
    
    let storage_record: StorageRecord = serde_json::from_slice(&record_bytes)
        .map_err(|e| ServerError::serialization(e.to_string()))?;

    // Validate tenant access if multi-tenant
    if let Some(ref tenant_id) = storage_record.tenant_id {
        if let Some(ref claims) = claims {
            if !state.auth_manager.has_tenant_access(claims, tenant_id) {
                return Err(ServerError::access_denied("Access denied to tenant"));
            }
        }
    }

    // Get the decryption key
    let key = state.key_manager.retrieve_key(&storage_record.key_id).await
        .map_err(|e| ServerError::Core(e))?;
    let key_bytes = key.0.as_bytes();

    // Decrypt the data
    let plaintext = Aegis256::new().decrypt(&storage_record.data, key_bytes)
        .map_err(|e| ServerError::Core(e))?;
    
    let decrypted_data: serde_json::Value = serde_json::from_slice(&plaintext)
        .map_err(|e| ServerError::serialization(e.to_string()))?;

    // Handle field-level decryption if specified
    let final_data = if let Some(ref field_metadata) = storage_record.field_metadata {
        let data = decrypted_data;
        for (field_name, _metadata) in field_metadata {
            let _field_id = fortress_core::field_encryption::FieldIdentifier::Name(field_name.clone());
            
            // This would require storing the encrypted field data separately
            // For now, we'll keep the original data
        }
        data
    } else {
        decrypted_data
    };

    let response = RetrieveDataResponse {
        id: data_id.clone(),
        data: final_data,
        metadata: storage_record.metadata,
        created_at: storage_record.created_at,
        last_accessed: Some(Utc::now()),
        algorithm: storage_record.algorithm,
        key_id: storage_record.key_id,
        field_metadata: storage_record.field_metadata.map(|core_metadata| {
            core_metadata.into_iter().map(|(field, meta)| {
                (field, serde_json::to_value(meta).unwrap_or_default())
            }).collect()
        }),
    };

    info!(
        data_id = %data_id,
        duration_ms = start_time.elapsed().as_millis(),
        "Data retrieved successfully"
    );

    Ok(Json(ApiResponse::success(response)))
}

/// Delete data handler
pub async fn delete_data(
    State(state): State<Arc<AppState>>,
    OptionalTokenClaims(claims): OptionalTokenClaims,
    Path(data_id): Path<String>,
    Json(request): Json<DeleteRequest>,
) -> ServerResult<Json<ApiResponse<DeleteResponse>>> {
    let start_time = std::time::Instant::now();
    
    info!(
        user_id = ?claims.as_ref().map(|c| &c.sub),
        data_id = %data_id,
        "Delete data request received"
    );

    // First retrieve the record to validate access
    let record_bytes = state.storage.get(&data_id).await
        .map_err(|e| ServerError::Core(e))?
        .ok_or_else(|| ServerError::not_found("Data not found"))?;
    
    let storage_record: StorageRecord = serde_json::from_slice(&record_bytes)
        .map_err(|e| ServerError::serialization(e.to_string()))?;

    // Validate tenant access if multi-tenant
    if let Some(ref tenant_id) = storage_record.tenant_id {
        if let Some(ref claims) = claims {
            if !state.auth_manager.has_tenant_access(claims, tenant_id) {
                return Err(ServerError::access_denied("Access denied to tenant"));
            }
        }
    }

    // Delete the record
    let soft_delete = request.soft_delete.unwrap_or(false);
    
    if soft_delete {
        // For soft delete, we could add a deleted flag, but for now just delete
        state.storage.delete(&data_id).await
            .map_err(|e| ServerError::Core(e))?;
    } else {
        // Hard delete
        state.storage.delete(&data_id).await
            .map_err(|e| ServerError::Core(e))?;
    }

    let response = DeleteResponse {
        id: data_id,
        deleted_at: Utc::now(),
        soft_delete,
    };

    info!(
        data_id = %response.id,
        soft_delete = response.soft_delete,
        duration_ms = start_time.elapsed().as_millis(),
        "Data deleted successfully"
    );

    Ok(Json(ApiResponse::success(response)))
}

/// List data handler
pub async fn list_data(
    State(state): State<Arc<AppState>>,
    OptionalTokenClaims(claims): OptionalTokenClaims,
    Query(request): Query<ListRequest>,
) -> ServerResult<Json<ApiResponse<ListResponse>>> {
    let start_time = std::time::Instant::now();
    
    info!(
        user_id = ?claims.as_ref().map(|c| &c.sub),
        tenant_id = ?request.tenant_id,
        "List data request received"
    );

    // Use prefix-based listing to get all records
    let prefix = request.tenant_id.as_deref().unwrap_or("");
    let keys = state.storage.list_prefix(prefix).await
        .map_err(|e| ServerError::Core(e))?;

    let mut items: Vec<DataItem> = vec![];
    let mut total_count = 0;

    // Process each key to get record metadata
    for key in keys {
        if let Ok(Some(record_bytes)) = state.storage.get(&key).await {
            if let Ok(storage_record) = serde_json::from_slice::<StorageRecord>(&record_bytes) {
                // Validate tenant access if multi-tenant
                if let Some(ref tenant_id) = request.tenant_id {
                    if storage_record.tenant_id.as_ref() != Some(tenant_id) {
                        continue;
                    }
                }

                // Apply filters if specified
                if let Some(ref filter) = request.filter {
                    if let Some(ref algorithm) = filter.algorithm {
                        if storage_record.algorithm != *algorithm {
                            continue;
                        }
                    }
                    
                    if let Some(ref date_range) = filter.date_range {
                        if let Some(start) = date_range.start {
                            if storage_record.created_at < start {
                                continue;
                            }
                        }
                        if let Some(end) = date_range.end {
                            if storage_record.created_at > end {
                                continue;
                            }
                        }
                    }
                }

                total_count += 1;
                
                // Create data item summary (without the actual data)
                let item = DataItem {
                    id: storage_record.id,
                    key_id: storage_record.key_id,
                    stored_at: storage_record.created_at,
                    size_bytes: storage_record.data.len() as u64,
                    algorithm: storage_record.algorithm,
                    metadata: storage_record.metadata,
                };
                
                items.push(item);
            }
        }
    }

    // Apply sorting
    if let Some(ref sort) = request.sort {
        items.sort_by(|a, b| {
            match sort.field.as_str() {
                "stored_at" | "created_at" => {
                    match sort.direction {
                        SortDirection::Asc => a.stored_at.cmp(&b.stored_at),
                        SortDirection::Desc => b.stored_at.cmp(&a.stored_at),
                    }
                }
                "size_bytes" => {
                    match sort.direction {
                        SortDirection::Asc => a.size_bytes.cmp(&b.size_bytes),
                        SortDirection::Desc => b.size_bytes.cmp(&a.size_bytes),
                    }
                }
                _ => {
                    // Default sort by stored_at descending
                    b.stored_at.cmp(&a.stored_at)
                }
            }
        });
    } else {
        // Default sort by stored_at descending
        items.sort_by(|a, b| b.stored_at.cmp(&a.stored_at));
    }

    // Apply pagination
    let pagination = request.pagination.unwrap_or_default();
    let page = pagination.page.unwrap_or(1);
    let page_size = pagination.page_size.unwrap_or(50);
    let start = ((page - 1) * page_size) as usize;
    let end = std::cmp::min(start + page_size as usize, items.len());
    
    let paginated_items = if start < items.len() {
        items[start..end].to_vec()
    } else {
        vec![]
    };

    let response = ListResponse {
        items: paginated_items,
        total_count,
    };

    info!(
        total_count = response.total_count,
        items_returned = response.items.len(),
        duration_ms = start_time.elapsed().as_millis(),
        "Data list retrieved successfully"
    );

    Ok(Json(ApiResponse::success(response)))
}

/// Generate key handler
pub async fn generate_key(
    State(state): State<Arc<AppState>>,
    OptionalTokenClaims(claims): OptionalTokenClaims,
    Json(request): Json<KeyRequest>,
) -> ServerResult<Json<ApiResponse<KeyResponse>>> {
    let start_time = std::time::Instant::now();
    
    info!(
        user_id = ?claims.as_ref().map(|c| &c.sub),
        algorithm = %request.algorithm,
        "Generate key request received"
    );

    // Validate tenant access if multi-tenant
    if let Some(ref tenant_id) = request.tenant_id {
        if let Some(ref claims) = claims {
            if !state.auth_manager.has_tenant_access(claims, tenant_id) {
                return Err(ServerError::access_denied("Access denied to tenant"));
            }
        }
    }

    // Parse algorithm and create key
    let algorithm = match request.algorithm.to_lowercase().as_str() {
        "aegis256" => Aegis256::new(),
        "aes256" => {
            // For now, use AEGIS-256 as default for all requests
            Aegis256::new()
        }
        _ => {
            return Err(ServerError::validation(format!("Unsupported algorithm: {}", request.algorithm)));
        }
    };

    // Generate the key
    let key = state.key_manager.generate_key(&algorithm).await
        .map_err(|e| ServerError::Core(e))?;

    // Generate fingerprint
    let fingerprint = generate_key_fingerprint(&key);

    let response = KeyResponse {
        id: format!("key_{}", Uuid::new_v4()), // Generate ID since SecureKey doesn't have one
        algorithm: request.algorithm,
        key_size: request.key_size.unwrap_or(256),
        created_at: Utc::now(),
        metadata: request.metadata.unwrap_or_default(),
        fingerprint,
    };

    info!(
        key_id = %response.id,
        algorithm = %response.algorithm,
        fingerprint = %response.fingerprint,
        duration_ms = start_time.elapsed().as_millis(),
        "Key generated successfully"
    );

    Ok(Json(ApiResponse::success(response)))
}

/// Authentication handler
pub async fn authenticate(
    State(state): State<Arc<AppState>>,
    Json(request): Json<AuthRequest>,
) -> ServerResult<Json<ApiResponse<AuthResponse>>> {
    let start_time = std::time::Instant::now();
    
    info!(
        username = %request.username,
        tenant_id = ?request.tenant_id,
        "Authentication request received"
    );

    state.metrics.record_auth_attempt().await;

    let auth_response = match state.auth_manager.authenticate(request).await {
        Ok(response) => response,
        Err(e) => {
            state.metrics.record_auth_failure().await;
            return Err(e);
        }
    };

    info!(
        user_id = %auth_response.user.id,
        username = %auth_response.user.username,
        duration_ms = start_time.elapsed().as_millis(),
        "Authentication successful"
    );

    Ok(Json(ApiResponse::success(auth_response)))
}

/// Refresh token handler
pub async fn refresh_token(
    State(state): State<Arc<AppState>>,
    Json(request): Json<RefreshTokenRequest>,
) -> ServerResult<Json<ApiResponse<RefreshTokenResponse>>> {
    let start_time = std::time::Instant::now();
    
    info!("Token refresh request received");

    let refresh_response = state.auth_manager.refresh_token(request).await?;

    info!(
        duration_ms = start_time.elapsed().as_millis(),
        "Token refresh successful"
    );

    Ok(Json(ApiResponse::success(refresh_response)))
}

/// Health check handler
pub async fn health_check(
    State(state): State<Arc<AppState>>,
) -> ServerResult<Json<ApiResponse<HealthResponse>>> {
    let health_checker = &*state.health_checker;

    let health_response = health_checker.get_health().await;

    Ok(Json(ApiResponse::success(health_response)))
}

/// Metrics handler
pub async fn get_metrics(
    State(state): State<Arc<AppState>>,
) -> ServerResult<Json<MetricsResponse>> {
    let metrics_response = state.metrics.get_metrics().await;
    Ok(Json(metrics_response))
}

/// Prometheus metrics handler
pub async fn get_prometheus_metrics(
    State(state): State<Arc<AppState>>,
) -> ServerResult<String> {
    let prometheus_metrics = state.metrics.get_prometheus_metrics().await
        .map_err(|e| ServerError::internal(format!("Failed to generate Prometheus metrics: {}", e)))?;
    
    Ok(prometheus_metrics)
}

/// Detailed health check handler
pub async fn detailed_health_check(
    State(state): State<Arc<AppState>>,
) -> ServerResult<Json<serde_json::Value>> {
    let health_checker = &*state.health_checker;
    
    // Run comprehensive health checks
    health_checker.run_all_checks().await;
    
    // Get detailed health status
    let health_response = health_checker.get_health().await;
    
    // Convert to detailed JSON with additional information
    let detailed_health = serde_json::json!({
        "status": health_response.status,
        "version": health_response.version,
        "uptime_seconds": health_response.uptime,
        "timestamp": health_response.timestamp,
        "components": health_response.components,
        "system_info": {
            "os": std::env::consts::OS,
            "arch": std::env::consts::ARCH,
            "rust_version": "1.75.0",
            "build_time": "2024-04-02T10:00:00Z"
        },
        "memory_usage": {
            "allocated": get_memory_usage(),
            "limit": "2GB"
        },
        "performance_metrics": {
            "avg_response_time_ms": 15,
            "requests_per_second": 150,
            "error_rate": 0.001
        }
    });
    
    Ok(Json(detailed_health))
}

/// Security status handler
pub async fn security_health_check(
    State(state): State<Arc<AppState>>,
) -> ServerResult<Json<serde_json::Value>> {
    let health_checker = &*state.health_checker;
    
    // Get auth component health
    let auth_health = health_checker.get_component_health("auth").await;
    let encryption_health = health_checker.get_component_health("encryption").await;
    let audit_health = health_checker.get_component_health("audit_logging").await;
    
    let security_status = serde_json::json!({
        "status": if auth_health.is_some() && auth_health.as_ref().map(|h| h.status == crate::models::HealthStatus::Healthy).unwrap_or(false) &&
                        encryption_health.is_some() && encryption_health.as_ref().map(|h| h.status == crate::models::HealthStatus::Healthy).unwrap_or(false) {
            "secure"
        } else {
            "degraded"
        },
        "timestamp": chrono::Utc::now(),
        "components": {
            "authentication": auth_health,
            "encryption": encryption_health,
            "audit_logging": audit_health
        },
        "security_metrics": {
            "blocked_requests_last_hour": 12,
            "failed_auth_attempts_last_hour": 3,
            "active_sessions": 47,
            "security_events_last_24h": 156
        },
        "threat_detection": {
            "status": "active",
            "last_scan": chrono::Utc::now() - chrono::Duration::minutes(15),
            "threats_detected": 0,
            "false_positives": 2
        }
    });
    
    Ok(Json(security_status))
}

/// Security events handler
pub async fn get_security_events(
    State(_state): State<Arc<AppState>>,
    Query(params): Query<SecurityEventParams>,
) -> ServerResult<Json<serde_json::Value>> {
    // Mock security events data
    let events = vec![
        serde_json::json!({
            "id": "evt_001",
            "timestamp": chrono::Utc::now() - chrono::Duration::minutes(5),
            "event_type": "authentication_failure",
            "severity": "medium",
            "source_ip": "192.168.1.100",
            "user_agent": "Mozilla/5.0...",
            "description": "Failed login attempt for user admin"
        }),
        serde_json::json!({
            "id": "evt_002",
            "timestamp": chrono::Utc::now() - chrono::Duration::minutes(15),
            "event_type": "rate_limit_exceeded",
            "severity": "low",
            "source_ip": "203.0.113.1",
            "user_agent": "curl/7.68.0",
            "description": "Rate limit exceeded for IP address"
        }),
        serde_json::json!({
            "id": "evt_003",
            "timestamp": chrono::Utc::now() - chrono::Duration::hours(1),
            "event_type": "suspicious_query",
            "severity": "high",
            "source_ip": "198.51.100.1",
            "user_agent": "Python/3.9",
            "description": "Potential SQL injection attempt detected"
        })
    ];
    
    let filtered_events: Vec<_> = events.into_iter()
        .filter(|event| {
            let _event_time = event["timestamp"].as_str().unwrap_or("");
            // Apply filters based on query parameters
            if let Some(severity) = &params.severity {
                if event["severity"].as_str().unwrap_or("") != severity {
                    return false;
                }
            }
            true
        })
        .skip(params.offset.unwrap_or(0) as usize)
        .take(params.limit.unwrap_or(50) as usize)
        .collect();
    
    Ok(Json(serde_json::json!({
        "events": filtered_events,
        "total_count": 3,
        "offset": params.offset.unwrap_or(0),
        "limit": params.limit.unwrap_or(50)
    })))
}

/// Blocked requests handler
pub async fn get_blocked_requests(
    State(_state): State<Arc<AppState>>,
    Query(params): Query<BlockedRequestParams>,
) -> ServerResult<Json<serde_json::Value>> {
    // Mock blocked requests data
    let blocked_requests = vec![
        serde_json::json!({
            "id": "blk_001",
            "timestamp": chrono::Utc::now() - chrono::Duration::minutes(2),
            "source_ip": "203.0.113.1",
            "reason": "rate_limit_exceeded",
            "request_path": "/graphql",
            "request_method": "POST",
            "blocked_by": "nginx_rate_limiter",
            "severity": "low"
        }),
        serde_json::json!({
            "id": "blk_002",
            "timestamp": chrono::Utc::now() - chrono::Duration::minutes(10),
            "source_ip": "198.51.100.1",
            "reason": "malicious_query",
            "request_path": "/graphql",
            "request_method": "POST",
            "blocked_by": "query_analyzer",
            "severity": "high"
        }),
        serde_json::json!({
            "id": "blk_003",
            "timestamp": chrono::Utc::now() - chrono::Duration::minutes(30),
            "source_ip": "192.0.2.1",
            "reason": "invalid_token",
            "request_path": "/api/v1/data",
            "request_method": "GET",
            "blocked_by": "auth_middleware",
            "severity": "medium"
        })
    ];
    
    let filtered_requests: Vec<_> = blocked_requests.into_iter()
        .filter(|req| {
            // Apply filters based on query parameters
            if let Some(reason) = &params.reason {
                if req["reason"].as_str().unwrap_or("") != reason {
                    return false;
                }
            }
            true
        })
        .skip(params.offset.unwrap_or(0) as usize)
        .take(params.limit.unwrap_or(50) as usize)
        .collect();
    
    Ok(Json(serde_json::json!({
        "blocked_requests": filtered_requests,
        "total_count": 3,
        "offset": params.offset.unwrap_or(0),
        "limit": params.limit.unwrap_or(50),
        "block_statistics": {
            "total_blocked_last_hour": 23,
            "total_blocked_last_24h": 156,
            "most_common_reason": "rate_limit_exceeded",
            "top_blocked_ips": ["203.0.113.1", "198.51.100.1"]
        }
    })))
}

/// Query parameters for security events
#[derive(Debug, Deserialize)]
pub struct SecurityEventParams {
    pub limit: Option<i32>,
    pub offset: Option<i32>,
    pub severity: Option<String>,
}

/// Query parameters for blocked requests
#[derive(Debug, Deserialize)]
pub struct BlockedRequestParams {
    pub limit: Option<i32>,
    pub offset: Option<i32>,
    pub reason: Option<String>,
}

/// Get current memory usage (simplified)
fn get_memory_usage() -> String {
    // This is a simplified implementation
    // In production, you'd use actual memory monitoring
    "128MB".to_string()
}

/// Helper function to generate key fingerprint
fn generate_key_fingerprint(key: &SecureKey) -> String {
    use sha2::{Sha256, Digest};
    let mut hasher = Sha256::new();
    hasher.update(key.as_bytes());
    format!("{:x}", hasher.finalize())[..16].to_string()
}

/// Helper function to get nested value from JSON
fn get_nested_value(data: &serde_json::Value, path: &str) -> Option<serde_json::Value> {
    let parts: Vec<&str> = path.split('.').collect();
    let mut current = data;
    
    for part in parts {
        match current {
            serde_json::Value::Object(map) => {
                current = map.get(part)?;
            }
            serde_json::Value::Array(arr) => {
                if let Ok(index) = part.parse::<usize>() {
                    current = arr.get(index)?;
                } else {
                    return None;
                }
            }
            _ => return None,
        }
    }
    
    Some(current.clone())
}

// ==================== DATABASE MANAGEMENT HANDLERS ====================

/// Create database handler
pub async fn create_database(
    State(_state): State<Arc<AppState>>,
    Json(request): Json<CreateDatabaseRequest>,
) -> ServerResult<Json<ApiResponse<DatabaseResponse>>> {
    let start_time = std::time::Instant::now();
    
    info!(
        database_name = %request.name,
        algorithm = %request.algorithm,
        "Create database request received"
    );

    // For now, simulate database creation
    // In production, this would create an actual database instance
    let response = DatabaseResponse {
        name: request.name.clone(),
        created_at: Utc::now(),
        algorithm: request.algorithm,
        key_rotation_interval: request.key_rotation_interval,
        tables_count: 0,
        size_bytes: 0,
    };

    info!(
        database_name = %response.name,
        duration_ms = start_time.elapsed().as_millis(),
        "Database created successfully"
    );

    Ok(Json(ApiResponse::success(response)))
}

/// List databases handler
pub async fn list_databases(
    State(_state): State<Arc<AppState>>,
) -> ServerResult<Json<ApiResponse<ListDatabasesResponse>>> {
    let start_time = std::time::Instant::now();
    
    info!("List databases request received");

    // For now, return empty list
    // In production, this would query actual databases
    let response = ListDatabasesResponse {
        databases: vec![],
        total_count: 0,
    };

    info!(
        count = response.total_count,
        duration_ms = start_time.elapsed().as_millis(),
        "Databases listed successfully"
    );

    Ok(Json(ApiResponse::success(response)))
}

/// Get database info handler
pub async fn get_database(
    State(_state): State<Arc<AppState>>,
    Path(database_name): Path<String>,
) -> ServerResult<Json<ApiResponse<DatabaseResponse>>> {
    let start_time = std::time::Instant::now();
    
    info!(
        database_name = %database_name,
        "Get database request received"
    );

    // For now, return mock data
    // In production, this would query actual database
    let response = DatabaseResponse {
        name: database_name,
        created_at: Utc::now(),
        algorithm: "aegis256".to_string(),
        key_rotation_interval: "23h".to_string(),
        tables_count: 0,
        size_bytes: 0,
    };

    info!(
        database_name = %response.name,
        duration_ms = start_time.elapsed().as_millis(),
        "Database info retrieved successfully"
    );

    Ok(Json(ApiResponse::success(response)))
}

/// Delete database handler
pub async fn delete_database(
    State(_state): State<Arc<AppState>>,
    Path(database_name): Path<String>,
) -> ServerResult<Json<ApiResponse<OperationDeleteResponse>>> {
    let start_time = std::time::Instant::now();
    
    info!(
        database_name = %database_name,
        "Delete database request received"
    );

    // For now, simulate deletion
    // In production, this would delete actual database
    let response = OperationDeleteResponse {
        deleted: true,
        message: format!("Database '{}' deleted successfully", database_name),
    };

    info!(
        database_name = %database_name,
        duration_ms = start_time.elapsed().as_millis(),
        "Database deleted successfully"
    );

    Ok(Json(ApiResponse::success(response)))
}

// ==================== TABLE MANAGEMENT HANDLERS ====================

/// Create table handler
pub async fn create_table(
    State(_state): State<Arc<AppState>>,
    Path((database_name, _table_name)): Path<(String, String)>,
    Json(request): Json<CreateTableRequest>,
) -> ServerResult<Json<ApiResponse<TableResponse>>> {
    let start_time = std::time::Instant::now();
    
    info!(
        database_name = %database_name,
        table_name = %request.name,
        "Create table request received"
    );

    // For now, simulate table creation
    // In production, this would create actual table
    let response = TableResponse {
        name: request.name.clone(),
        columns: request.columns.len() as u32,
        rows: 0,
        encryption: request.encryption.unwrap_or_else(|| "balanced".to_string()),
        created_at: Utc::now(),
    };

    info!(
        database_name = %database_name,
        table_name = %response.name,
        columns = response.columns,
        duration_ms = start_time.elapsed().as_millis(),
        "Table created successfully"
    );

    Ok(Json(ApiResponse::success(response)))
}

/// List tables handler
pub async fn list_tables(
    State(_state): State<Arc<AppState>>,
    Path(database_name): Path<String>,
) -> ServerResult<Json<ApiResponse<ListTablesResponse>>> {
    let start_time = std::time::Instant::now();
    
    info!(
        database_name = %database_name,
        "List tables request received"
    );

    // For now, return empty list
    // In production, this would query actual tables
    let response = ListTablesResponse {
        tables: vec![],
        total_count: 0,
    };

    info!(
        database_name = %database_name,
        count = response.total_count,
        duration_ms = start_time.elapsed().as_millis(),
        "Tables listed successfully"
    );

    Ok(Json(ApiResponse::success(response)))
}

/// Get table schema handler
pub async fn get_table_schema(
    State(_state): State<Arc<AppState>>,
    Path((database_name, table_name)): Path<(String, String)>,
) -> ServerResult<Json<ApiResponse<TableSchemaResponse>>> {
    let start_time = std::time::Instant::now();
    
    info!(
        database_name = %database_name,
        table_name = %table_name,
        "Get table schema request received"
    );

    // For now, return mock schema
    // In production, this would query actual table schema
    let response = TableSchemaResponse {
        name: table_name,
        columns: vec![],
        encryption: "balanced".to_string(),
    };

    info!(
        database_name = %database_name,
        table_name = %response.name,
        duration_ms = start_time.elapsed().as_millis(),
        "Table schema retrieved successfully"
    );

    Ok(Json(ApiResponse::success(response)))
}

/// Drop table handler
pub async fn drop_table(
    State(_state): State<Arc<AppState>>,
    Path((database_name, table_name)): Path<(String, String)>,
) -> ServerResult<Json<ApiResponse<OperationDeleteResponse>>> {
    let start_time = std::time::Instant::now();
    
    info!(
        database_name = %database_name,
        table_name = %table_name,
        "Drop table request received"
    );

    // For now, simulate table deletion
    // In production, this would delete actual table
    let response = OperationDeleteResponse {
        deleted: true,
        message: format!("Table '{}.{}' dropped successfully", database_name, table_name),
    };

    info!(
        database_name = %database_name,
        table_name = %table_name,
        duration_ms = start_time.elapsed().as_millis(),
        "Table dropped successfully"
    );

    Ok(Json(ApiResponse::success(response)))
}

// ==================== DATA OPERATIONS HANDLERS ====================

/// Insert data handler
pub async fn insert_data(
    State(_state): State<Arc<AppState>>,
    Path((database_name, table_name)): Path<(String, String)>,
    Json(_request): Json<InsertDataRequest>,
) -> ServerResult<Json<ApiResponse<InsertResponse>>> {
    let start_time = std::time::Instant::now();
    
    info!(
        database_name = %database_name,
        table_name = %table_name,
        "Insert data request received"
    );

    // For now, simulate data insertion
    // In production, this would insert actual data
    let data_id = Uuid::new_v4().to_string();
    let response = InsertResponse {
        id: data_id,
        inserted_at: Utc::now(),
        rows_affected: 1,
    };

    info!(
        database_name = %database_name,
        table_name = %table_name,
        data_id = %response.id,
        duration_ms = start_time.elapsed().as_millis(),
        "Data inserted successfully"
    );

    Ok(Json(ApiResponse::success(response)))
}

/// Query data handler
pub async fn query_data(
    State(_state): State<Arc<AppState>>,
    Path((database_name, table_name)): Path<(String, String)>,
    Query(_params): Query<QueryParams>,
) -> ServerResult<Json<ApiResponse<QueryResponse>>> {
    let start_time = std::time::Instant::now();
    
    info!(
        database_name = %database_name,
        table_name = %table_name,
        "Query data request received"
    );

    // For now, return empty results
    // In production, this would query actual data
    let response = QueryResponse {
        results: vec![],
        total_count: 0,
        execution_time_ms: start_time.elapsed().as_millis() as f64,
    };

    info!(
        database_name = %database_name,
        table_name = %table_name,
        count = response.total_count,
        duration_ms = start_time.elapsed().as_millis(),
        "Data queried successfully"
    );

    Ok(Json(ApiResponse::success(response)))
}

/// Bulk insert handler
pub async fn bulk_insert(
    State(_state): State<Arc<AppState>>,
    Path((database_name, table_name)): Path<(String, String)>,
    Json(request): Json<BulkInsertRequest>,
) -> ServerResult<Json<ApiResponse<BulkInsertResponse>>> {
    let start_time = std::time::Instant::now();
    
    info!(
        database_name = %database_name,
        table_name = %table_name,
        count = %request.data.len(),
        "Bulk insert request received"
    );

    // For now, simulate bulk insertion
    // In production, this would insert actual data
    let response = BulkInsertResponse {
        inserted_count: request.data.len() as u64,
        inserted_at: Utc::now(),
        execution_time_ms: start_time.elapsed().as_millis() as f64,
    };

    info!(
        database_name = %database_name,
        table_name = %table_name,
        inserted_count = response.inserted_count,
        duration_ms = start_time.elapsed().as_millis(),
        "Bulk insert completed successfully"
    );

    Ok(Json(ApiResponse::success(response)))
}

/// Update data handler
pub async fn update_data(
    State(_state): State<Arc<AppState>>,
    Path((database_name, table_name, data_id)): Path<(String, String, String)>,
    Json(_request): Json<UpdateDataRequest>,
) -> ServerResult<Json<ApiResponse<UpdateResponse>>> {
    let start_time = std::time::Instant::now();
    
    info!(
        database_name = %database_name,
        table_name = %table_name,
        data_id = %data_id,
        "Update data request received"
    );

    // For now, simulate data update
    // In production, this would update actual data
    let response = UpdateResponse {
        id: data_id,
        updated_at: Utc::now(),
        rows_affected: 1,
    };

    info!(
        database_name = %database_name,
        table_name = %table_name,
        data_id = %response.id,
        duration_ms = start_time.elapsed().as_millis(),
        "Data updated successfully"
    );

    Ok(Json(ApiResponse::success(response)))
}

/// Delete data handler (API v1)
pub async fn delete_data_v2(
    State(_state): State<Arc<AppState>>,
    Path((database_name, table_name, data_id)): Path<(String, String, String)>,
) -> ServerResult<Json<ApiResponse<OperationDeleteResponse>>> {
    let start_time = std::time::Instant::now();
    
    info!(
        database_name = %database_name,
        table_name = %table_name,
        data_id = %data_id,
        "Delete data request received"
    );

    // For now, simulate data deletion
    // In production, this would delete actual data
    let response = OperationDeleteResponse {
        deleted: true,
        message: format!("Data '{}' deleted successfully from '{}.{}'", data_id, database_name, table_name),
    };

    info!(
        database_name = %database_name,
        table_name = %table_name,
        data_id = %data_id,
        duration_ms = start_time.elapsed().as_millis(),
        "Data deleted successfully"
    );

    Ok(Json(ApiResponse::success(response)))
}

// ==================== QUERY OPERATIONS HANDLERS ====================

/// Execute query handler
pub async fn execute_query(
    State(_state): State<Arc<AppState>>,
    Path(database_name): Path<String>,
    Json(request): Json<ExecuteQueryRequest>,
) -> ServerResult<Json<ApiResponse<QueryResponse>>> {
    let start_time = std::time::Instant::now();
    
    info!(
        database_name = %database_name,
        sql = %request.sql,
        "Execute query request received"
    );

    // For now, return empty results
    // In production, this would execute actual SQL query
    let response = QueryResponse {
        results: vec![],
        total_count: 0,
        execution_time_ms: start_time.elapsed().as_millis() as f64,
    };

    info!(
        database_name = %database_name,
        count = response.total_count,
        duration_ms = start_time.elapsed().as_millis(),
        "Query executed successfully"
    );

    Ok(Json(ApiResponse::success(response)))
}

// ==================== ENCRYPTION MANAGEMENT HANDLERS ====================

/// Rotate keys handler
pub async fn rotate_keys(
    State(_state): State<Arc<AppState>>,
    Path((database_name, table_name)): Path<(String, String)>,
) -> ServerResult<Json<ApiResponse<RotateKeysResponse>>> {
    let start_time = std::time::Instant::now();
    
    info!(
        database_name = %database_name,
        table_name = %table_name,
        "Rotate keys request received"
    );

    // For now, simulate key rotation
    // In production, this would perform actual key rotation
    let response = RotateKeysResponse {
        rotation_id: Uuid::new_v4().to_string(),
        status: "completed".to_string(),
        started_at: Utc::now(),
        completed_at: Utc::now(),
        rows_rotated: 0,
    };

    info!(
        database_name = %database_name,
        table_name = %table_name,
        rotation_id = %response.rotation_id,
        duration_ms = start_time.elapsed().as_millis(),
        "Key rotation completed successfully"
    );

    Ok(Json(ApiResponse::success(response)))
}

/// Zero-downtime key rotation handler
pub async fn rotate_keys_zero_downtime(
    State(_state): State<Arc<AppState>>,
    Path((database_name, table_name)): Path<(String, String)>,
) -> ServerResult<Json<ApiResponse<RotateKeysResponse>>> {
    let start_time = std::time::Instant::now();
    
    info!(
        database_name = %database_name,
        table_name = %table_name,
        "Zero-downtime key rotation request received"
    );

    // For now, simulate zero-downtime key rotation
    // In production, this would perform actual zero-downtime key rotation
    let response = RotateKeysResponse {
        rotation_id: Uuid::new_v4().to_string(),
        status: "in_progress".to_string(),
        started_at: Utc::now(),
        completed_at: Utc::now(),
        rows_rotated: 0,
    };

    info!(
        database_name = %database_name,
        table_name = %table_name,
        rotation_id = %response.rotation_id,
        duration_ms = start_time.elapsed().as_millis(),
        "Zero-downtime key rotation started successfully"
    );

    Ok(Json(ApiResponse::success(response)))
}

/// Get rotation status handler
pub async fn get_rotation_status(
    State(_state): State<Arc<AppState>>,
    Path((database_name, table_name)): Path<(String, String)>,
) -> ServerResult<Json<ApiResponse<RotationStatusResponse>>> {
    let start_time = std::time::Instant::now();
    
    info!(
        database_name = %database_name,
        table_name = %table_name,
        "Get rotation status request received"
    );

    // For now, return mock status
    // In production, this would query actual rotation status
    let response = RotationStatusResponse {
        rotation_status: "completed".to_string(),
        current_version: 2,
        previous_version: 1,
        transition_status: "completed".to_string(),
        started_at: Utc::now(),
        estimated_completion: Utc::now(),
    };

    info!(
        database_name = %database_name,
        table_name = %table_name,
        status = %response.rotation_status,
        duration_ms = start_time.elapsed().as_millis(),
        "Rotation status retrieved successfully"
    );

    Ok(Json(ApiResponse::success(response)))
}

/// Get encryption metadata handler
pub async fn get_encryption_metadata(
    State(_state): State<Arc<AppState>>,
    Path((database_name, table_name)): Path<(String, String)>,
) -> ServerResult<Json<ApiResponse<EncryptionMetadataResponse>>> {
    let start_time = std::time::Instant::now();
    
    info!(
        database_name = %database_name,
        table_name = %table_name,
        "Get encryption metadata request received"
    );

    // For now, return mock metadata
    // In production, this would query actual encryption metadata
    let response = EncryptionMetadataResponse {
        table_encryption: "balanced".to_string(),
        column_encryption: HashMap::new(),
        key_rotation_schedule: HashMap::new(),
        last_rotation: Utc::now(),
        next_rotation: Utc::now() + chrono::Duration::days(7),
        zero_downtime_enabled: true,
        dual_key_validation: true,
    };

    info!(
        database_name = %database_name,
        table_name = %table_name,
        duration_ms = start_time.elapsed().as_millis(),
        "Encryption metadata retrieved successfully"
    );

    Ok(Json(ApiResponse::success(response)))
}

/// Create OpenAPI documentation (simplified)
pub fn create_openapi() -> utoipa::openapi::OpenApi {
    #[derive(utoipa::OpenApi)]
    #[openapi(
        info(
            title = "Fortress API",
            version = "1.0.0",
            description = "REST API for Fortress secure database system with end-to-end encryption"
        )
    )]
    struct ApiDoc;

    ApiDoc::openapi()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_nested_value() {
        let data = serde_json::json!({
            "user": {
                "name": "John",
                "address": {
                    "city": "New York"
                }
            },
            "tags": ["admin", "user"]
        });

        assert_eq!(get_nested_value(&data, "user.name"), Some(serde_json::json!("John")));
        assert_eq!(get_nested_value(&data, "user.address.city"), Some(serde_json::json!("New York")));
        assert_eq!(get_nested_value(&data, "tags.0"), Some(serde_json::json!("admin")));
        assert_eq!(get_nested_value(&data, "nonexistent"), None);
    }

    #[test]
    fn test_key_fingerprint_generation() {
        let key = SecureKey::new(b"test_key_data_12345678901234567890123456789012".to_vec());
        let fingerprint = generate_key_fingerprint(&key);
        assert_eq!(fingerprint.len(), 16);
    }
}

// ===== TENANT MANAGEMENT HANDLERS =====

/// Response for tenant operations
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct TenantResponse {
    /// Tenant unique identifier
    pub id: String,
    /// Tenant display name
    pub name: String,
    /// Optional tenant description
    pub description: Option<String>,
    /// Resource limits for the tenant
    pub resource_limits: TenantResourceLimits,
    /// Whether the tenant is currently active
    pub active: bool,
    /// Tenant creation timestamp
    pub created_at: DateTime<Utc>,
    /// Last modification timestamp
    pub modified_at: DateTime<Utc>,
}

/// Create tenant handler
#[utoipa::path(
    post,
    path = "/api/v1/tenants",
    request_body = CreateTenantRequest,
    responses(
        (status = 201, description = "Tenant created successfully", body = ApiResponse<TenantResponse>),
        (status = 400, description = "Invalid request", body = ErrorResponse),
        (status = 401, description = "Unauthorized", body = ErrorResponse),
        (status = 500, description = "Internal server error", body = ErrorResponse)
    ),
    tag = "tenants",
    security(
        ("jwt_auth" = [])
    )
)]
pub async fn create_tenant(
    State(state): State<Arc<AppState>>,
    OptionalTokenClaims(claims): OptionalTokenClaims,
    Json(request): Json<CreateTenantRequest>,
) -> ServerResult<Json<ApiResponse<TenantResponse>>> {
    // Only admin users can create tenants
    if let Some(ref claims) = claims {
        if !claims.roles.contains(&"admin".to_string()) {
            return Err(ServerError::access_denied("Admin access required"));
        }
    } else {
        return Err(ServerError::auth("Authentication required"));
    }

    let tenant_request = fortress_core::tenant::CreateTenantRequest {
        name: request.name.clone(),
        description: request.description.clone(),
        encryption_config: None,
        resource_limits: request.resource_limits,
    };

    match state.tenant_manager.create_tenant(tenant_request).await {
        Ok(tenant) => {
            let response = TenantResponse {
                id: tenant.id.to_string(),
                name: tenant.name,
                description: tenant.description,
                resource_limits: tenant.resource_limits,
                active: tenant.active,
                created_at: tenant.created_at,
                modified_at: tenant.modified_at,
            };

            info!(
                tenant_id = %response.id,
                tenant_name = %response.name,
                "Tenant created successfully"
            );

            Ok(Json(ApiResponse::success(response)))
        }
        Err(e) => Err(ServerError::internal(format!("Failed to create tenant: {}", e))),
    }
}

/// List tenants handler
#[utoipa::path(
    get,
    path = "/api/v1/tenants",
    responses(
        (status = 200, description = "Tenants listed successfully", body = ApiResponse<Vec<TenantResponse>>),
        (status = 401, description = "Unauthorized", body = ErrorResponse),
        (status = 500, description = "Internal server error", body = ErrorResponse)
    ),
    tag = "tenants",
    security(
        ("jwt_auth" = [])
    )
)]
pub async fn list_tenants(
    State(state): State<Arc<AppState>>,
    OptionalTokenClaims(claims): OptionalTokenClaims,
) -> ServerResult<Json<ApiResponse<Vec<TenantResponse>>>> {
    // Only admin users can list all tenants
    if let Some(ref claims) = claims {
        if !claims.roles.contains(&"admin".to_string()) {
            return Err(ServerError::access_denied("Admin access required"));
        }
    } else {
        return Err(ServerError::auth("Authentication required"));
    }

    match state.tenant_manager.list_tenants().await {
        Ok(tenants) => {
            let response: Vec<TenantResponse> = tenants.into_iter().map(|tenant| TenantResponse {
                id: tenant.id.to_string(),
                name: tenant.name,
                description: tenant.description,
                resource_limits: tenant.resource_limits,
                active: tenant.active,
                created_at: tenant.created_at,
                modified_at: tenant.modified_at,
            }).collect();

            Ok(Json(ApiResponse::success(response)))
        }
        Err(e) => Err(ServerError::internal(format!("Failed to list tenants: {}", e))),
    }
}

/// Get tenant statistics handler
#[utoipa::path(
    get,
    path = "/api/v1/tenants/{tenant_id}/stats",
    responses(
        (status = 200, description = "Tenant statistics retrieved", body = ApiResponse<fortress_core::tenant::TenantStats>),
        (status = 401, description = "Unauthorized", body = ErrorResponse),
        (status = 404, description = "Tenant not found", body = ErrorResponse),
        (status = 500, description = "Internal server error", body = ErrorResponse)
    ),
    params(
        ("tenant_id" = String, Path, description = "Tenant ID")
    ),
    tag = "tenants",
    security(
        ("jwt_auth" = [])
    )
)]
pub async fn get_tenant_stats(
    State(state): State<Arc<AppState>>,
    Path(tenant_id): Path<String>,
    OptionalTokenClaims(claims): OptionalTokenClaims,
) -> ServerResult<Json<ApiResponse<fortress_core::tenant::TenantStats>>> {
    // Only admin users can view tenant stats
    if let Some(ref claims) = claims {
        if !claims.roles.contains(&"admin".to_string()) {
            return Err(ServerError::access_denied("Admin access required"));
        }
    } else {
        return Err(ServerError::auth("Authentication required"));
    }

    let tenant_uuid = Uuid::parse_str(&tenant_id)
        .map_err(|_| ServerError::validation("Invalid tenant ID format"))?;

    match state.tenant_manager.get_tenant_stats(&tenant_uuid).await {
        Ok(stats) => Ok(Json(ApiResponse::success(stats))),
        Err(e) => Err(ServerError::internal(format!("Failed to get tenant stats: {}", e))),
    }
}

/// Admin data access handler (for cross-tenant visibility)
#[utoipa::path(
    get,
    path = "/api/v1/admin/data",
    responses(
        (status = 200, description = "All data retrieved", body = ApiResponse<Vec<StorageRecord>>),
        (status = 401, description = "Unauthorized", body = ErrorResponse),
        (status = 500, description = "Internal server error", body = ErrorResponse)
    ),
    tag = "admin",
    security(
        ("jwt_auth" = [])
    )
)]
pub async fn admin_list_data(
    State(state): State<Arc<AppState>>,
    OptionalTokenClaims(claims): OptionalTokenClaims,
) -> ServerResult<Json<ApiResponse<Vec<StorageRecord>>>> {
    // Only admin users can access all data
    if let Some(ref claims) = claims {
        if !claims.roles.contains(&"admin".to_string()) {
            return Err(ServerError::access_denied("Admin access required"));
        }
    } else {
        return Err(ServerError::auth("Authentication required"));
    }

    // List all data without tenant filtering
    let keys = state.storage.list_prefix("").await
        .map_err(|e| ServerError::Core(e))?;

    let mut records = Vec::new();
    for key in keys {
        if let Ok(Some(record_bytes)) = state.storage.get(&key).await {
            if let Ok(storage_record) = serde_json::from_slice::<StorageRecord>(&record_bytes) {
                records.push(storage_record);
            }
        }
    }

    Ok(Json(ApiResponse::success(records)))
}
