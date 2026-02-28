//! HTTP request handlers for the Fortress REST API
//!
//! This module contains all the request handlers for the various API endpoints,
//! including data storage, retrieval, key management, and authentication.

use crate::auth::{AuthManager, TokenClaims};
use crate::error::{ServerError, ServerResult};
use crate::models::*;
use crate::metrics::MetricsCollector;
use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::Json,
};
use chrono::Utc;
use fortress_core::prelude::*;
use serde::Deserialize;
use std::collections::HashMap;
use std::sync::Arc;
use tracing::{info, warn, error};
use uuid::Uuid;

/// Storage record (simplified for this example)
#[derive(Debug, Clone)]
pub struct StorageRecord {
    pub id: String,
    pub key_id: String,
    pub data: Vec<u8>,
    pub algorithm: String,
    pub created_at: DateTime<Utc>,
    pub metadata: Option<HashMap<String, serde_json::Value>>,
    pub tenant_id: Option<String>,
    pub field_metadata: Option<HashMap<String, FieldEncryptionMetadata>>,
}

/// Query parameters for storage queries
#[derive(Debug, Clone)]
pub struct QueryParams {
    pub tenant_id: Option<String>,
    pub pagination: PaginationParams,
    pub filter: Option<FilterParams>,
    pub sort: SortParams,
}

/// Query results
#[derive(Debug, Clone)]
pub struct QueryResults {
    pub records: Vec<StorageRecord>,
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
}

/// Store data handler
pub async fn store_data(
    State(state): State<Arc<AppState>>,
    claims: Option<TokenClaims>,
    Json(request): Json<StoreRequest>,
) -> ServerResult<Json<ApiResponse<StoreResponse>>> {
    let start_time = std::time::Instant::now();
    
    info!(
        user_id = ?claims.as_ref().map(|c| &c.sub),
        tenant_id = ?request.tenant_id,
        "Store data request received"
    );

    // Validate tenant access if multi-tenant
    if let Some(ref tenant_id) = request.tenant_id {
        if let Some(ref claims) = claims {
            if !state.auth_manager.has_tenant_access(claims, tenant_id) {
                return Err(ServerError::access_denied("Access denied to tenant"));
            }
        }
    }

    // Generate data ID
    let data_id = Uuid::new_v4().to_string();

    // Get or generate encryption key
    let key_id = request.key_id.clone().unwrap_or_else(|| {
        let key = state.key_manager.generate_key(&Aegis256::new()).unwrap();
        key.id
    });

    // Get the key
    let key = state.key_manager.get_key(&key_id)
        .map_err(|e| ServerError::Core(e))?;

    // Encrypt the data
    let data_json = serde_json::to_string(&request.data)
        .map_err(|e| ServerError::serialization(e.to_string()))?;
    
    let plaintext = data_json.as_bytes();
    let ciphertext = Aegis256::new().encrypt(plaintext, &key)
        .map_err(|e| ServerError::Core(e))?;

    // Handle field-level encryption if specified
    let field_metadata = if let Some(ref field_config) = request.field_encryption {
        Some(encrypt_fields(field_config, &request.data, &state.field_encryption_manager).await?)
    } else {
        None
    };

    // Store the encrypted data
    let storage_record = StorageRecord {
        id: data_id.clone(),
        key_id: key_id.clone(),
        data: ciphertext,
        algorithm: "aegis256".to_string(),
        created_at: Utc::now(),
        metadata: request.metadata.clone(),
        tenant_id: request.tenant_id.clone(),
        field_metadata: field_metadata.clone(),
    };

    state.storage.store(storage_record)
        .await
        .map_err(|e| ServerError::Core(e))?;

    // Record metrics
    state.metrics.record_data_stored(ciphertext.len() as u64).await;
    state.metrics.record_encryption_operation().await;

    let response = StoreResponse {
        id: data_id,
        key_id,
        stored_at: Utc::now(),
        size_bytes: ciphertext.len() as u64,
        algorithm: "aegis256".to_string(),
        field_metadata,
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
pub async fn retrieve_data(
    State(state): State<Arc<AppState>>,
    claims: Option<TokenClaims>,
    Path(data_id): Path<String>,
    Query(params): Query<RetrieveRequest>,
) -> ServerResult<Json<ApiResponse<RetrieveResponse>>> {
    let start_time = std::time::Instant::now();
    
    info!(
        user_id = ?claims.as_ref().map(|c| &c.sub),
        data_id = %data_id,
        "Retrieve data request received"
    );

    // Retrieve the storage record
    let record = state.storage.retrieve(&data_id)
        .await
        .map_err(|e| ServerError::Core(e))?;

    // Validate tenant access if multi-tenant
    if let Some(ref tenant_id) = record.tenant_id {
        if let Some(ref claims) = claims {
            if !state.auth_manager.has_tenant_access(claims, tenant_id) {
                return Err(ServerError::access_denied("Access denied to tenant"));
            }
        }
    }

    // Get the decryption key
    let key_id = params.key_id.as_ref().unwrap_or(&record.key_id);
    let key = state.key_manager.get_key(key_id)
        .map_err(|e| ServerError::Core(e))?;

    // Decrypt the data
    let plaintext = Aegis256::new().decrypt(&record.data, &key)
        .map_err(|e| ServerError::Core(e))?;

    let data: serde_json::Value = serde_json::from_slice(&plaintext)
        .map_err(|e| ServerError::serialization(e.to_string()))?;

    // Handle field-level decryption if metadata exists
    let field_metadata = if let Some(ref field_meta) = record.field_metadata {
        Some(decrypt_fields(field_meta, &data, &state.field_encryption_manager).await?)
    } else {
        None
    };

    // Record metrics
    state.metrics.record_data_retrieved(record.data.len() as u64).await;
    state.metrics.record_decryption_operation().await;

    let response = RetrieveResponse {
        data,
        metadata: record.metadata,
        retrieved_at: Utc::now(),
        stored_at: record.created_at,
        algorithm: record.algorithm,
        key_id: key_id.clone(),
        encrypted_data: if params.include_encrypted.unwrap_or(false) {
            Some(base64::encode(&record.data))
        } else {
            None
        },
        field_metadata,
    };

    info!(
        data_id = %data_id,
        size_bytes = record.data.len(),
        duration_ms = start_time.elapsed().as_millis(),
        "Data retrieved successfully"
    );

    Ok(Json(ApiResponse::success(response)))
}

/// Delete data handler
pub async fn delete_data(
    State(state): State<Arc<AppState>>,
    claims: Option<TokenClaims>,
    Path(data_id): Path<String>,
    Json(request): Json<DeleteRequest>,
) -> ServerResult<Json<ApiResponse<DeleteResponse>>> {
    let start_time = std::time::Instant::now();
    
    info!(
        user_id = ?claims.as_ref().map(|c| &c.sub),
        data_id = %data_id,
        "Delete data request received"
    );

    // Retrieve the record first to validate access
    let record = state.storage.retrieve(&data_id)
        .await
        .map_err(|e| ServerError::Core(e))?;

    // Validate tenant access if multi-tenant
    if let Some(ref tenant_id) = record.tenant_id {
        if let Some(ref claims) = claims {
            if !state.auth_manager.has_tenant_access(claims, tenant_id) {
                return Err(ServerError::access_denied("Access denied to tenant"));
            }
        }
    }

    // Delete the data
    state.storage.delete(&data_id, request.soft_delete.unwrap_or(false))
        .await
        .map_err(|e| ServerError::Core(e))?;

    let response = DeleteResponse {
        id: data_id,
        deleted_at: Utc::now(),
        soft_delete: request.soft_delete.unwrap_or(false),
    };

    info!(
        data_id = %data_id,
        soft_delete = response.soft_delete,
        duration_ms = start_time.elapsed().as_millis(),
        "Data deleted successfully"
    );

    Ok(Json(ApiResponse::success(response)))
}

/// List data handler
pub async fn list_data(
    State(state): State<Arc<AppState>>,
    claims: Option<TokenClaims>,
    Query(request): Query<ListRequest>,
) -> ServerResult<Json<ApiResponse<ListResponse>>> {
    let start_time = std::time::Instant::now();
    
    info!(
        user_id = ?claims.as_ref().map(|c| &c.sub),
        tenant_id = ?request.tenant_id,
        "List data request received"
    );

    // Validate tenant access if multi-tenant
    if let Some(ref tenant_id) = request.tenant_id {
        if let Some(ref claims) = claims {
            if !state.auth_manager.has_tenant_access(claims, tenant_id) {
                return Err(ServerError::access_denied("Access denied to tenant"));
            }
        }
    }

    // Build query parameters
    let query_params = QueryParams {
        tenant_id: request.tenant_id.clone(),
        pagination: request.pagination.clone().unwrap_or_default(),
        filter: request.filter.clone(),
        sort: request.sort.clone().unwrap_or_default(),
    };

    // Query the storage
    let results = state.storage.query(query_params)
        .await
        .map_err(|e| ServerError::Core(e))?;

    let items: Vec<DataItem> = results.records.into_iter().map(|record| DataItem {
        id: record.id,
        key_id: record.key_id,
        stored_at: record.created_at,
        size_bytes: record.data.len() as u64,
        algorithm: record.algorithm,
        metadata: record.metadata,
    }).collect();

    let response = ListResponse {
        items,
        total_count: results.total_count,
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
    claims: Option<TokenClaims>,
    Json(request): Json<KeyRequest>,
) -> ServerResult<Json<ApiResponse<KeyResponse>>> {
    let start_time = std::time::Instant::now();
    
    info!(
        user_id = ?claims.as_ref().map(|c| &c.sub),
        algorithm = %request.algorithm,
        "Generate key request received"
    );

    // Validate user has permission to generate keys
    if let Some(ref claims) = claims {
        if !state.auth_manager.has_role(claims, "admin") && 
           !state.auth_manager.has_role(claims, "key_manager") {
            return Err(ServerError::access_denied("Insufficient permissions to generate keys"));
        }
    }

    // Create algorithm based on request
    let algorithm: Box<dyn EncryptionAlgorithm> = match request.algorithm.as_str() {
        "aegis256" => Box::new(Aegis256::new()),
        "chacha20poly1305" => Box::new(ChaCha20Poly1305::new()),
        "aes256gcm" => Box::new(Aes256Gcm::new()),
        _ => return Err(ServerError::validation("Unsupported encryption algorithm")),
    };

    // Generate the key
    let key = state.key_manager.generate_key(&*algorithm)
        .map_err(|e| ServerError::Core(e))?;

    // Generate fingerprint
    let fingerprint = generate_key_fingerprint(&key);

    let response = KeyResponse {
        id: key.id,
        algorithm: request.algorithm,
        key_size: request.key_size.unwrap_or(256),
        created_at: Utc::now(),
        metadata: request.metadata.unwrap_or_default(),
        fingerprint,
    };

    info!(
        key_id = %response.id,
        algorithm = %response.algorithm,
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

    let auth_response = state.auth_manager.authenticate(request).await.map_err(|e| {
        state.metrics.record_auth_failure().await;
        e
    })?;

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
    let health_checker = state.health_checker.as_ref()
        .ok_or_else(|| ServerError::internal("Health checker not available"))?;

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

/// Helper function to encrypt fields
async fn encrypt_fields(
    config: &FieldEncryptionConfig,
    data: &serde_json::Value,
    field_manager: &Arc<dyn FieldEncryptionManager>,
) -> ServerResult<HashMap<String, FieldEncryptionMetadata>> {
    let mut field_metadata = HashMap::new();

    for (field_path, field_config) in &config.fields {
        if let Some(field_value) = get_nested_value(data, field_path) {
            let field_id = FieldIdentifier::new(field_path);
            let encryption_config = FieldEncryptionConfig {
                fields: HashMap::from([(
                    field_path.clone(),
                    field_config.clone()
                )]),
            };

            let encrypted_field = field_manager.encrypt_field(
                &field_id,
                field_value,
                &encryption_config,
            ).await.map_err(|e| ServerError::Core(e))?;

            let metadata = FieldEncryptionMetadata {
                field: field_path.clone(),
                algorithm: field_config.algorithm.clone(),
                key_id: field_config.key_id.clone().unwrap_or("default".to_string()),
                size_bytes: encrypted_field.data.len() as u64,
            };

            field_metadata.insert(field_path.clone(), metadata);
        }
    }

    Ok(field_metadata)
}

/// Helper function to decrypt fields
async fn decrypt_fields(
    metadata: &HashMap<String, FieldEncryptionMetadata>,
    data: &serde_json::Value,
    field_manager: &Arc<dyn FieldEncryptionManager>,
) -> ServerResult<HashMap<String, FieldEncryptionMetadata>> {
    let mut decrypted_metadata = HashMap::new();

    for (field_path, field_meta) in metadata {
        let field_id = FieldIdentifier::new(field_path);
        
        // In a real implementation, we would decrypt the field here
        // For now, we'll just return the metadata
        
        decrypted_metadata.insert(field_path.clone(), field_meta.clone());
    }

    Ok(decrypted_metadata)
}

/// Helper function to get nested JSON value
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

/// Helper function to generate key fingerprint
fn generate_key_fingerprint(key: &SecureKey) -> String {
    use sha2::{Sha256, Digest};
    let mut hasher = Sha256::new();
    hasher.update(key.data());
    format!("{:x}", hasher.finalize())[..16].to_string()
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
        let key = SecureKey::new(b"test_key_data_12345678901234567890123456789012");
        let fingerprint = generate_key_fingerprint(&key);
        assert_eq!(fingerprint.len(), 16);
    }
}
