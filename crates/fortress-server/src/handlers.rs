//! HTTP request handlers for the Fortress REST API
//!
//! This module contains all the request handlers for the various API endpoints,
//! including data storage, retrieval, key management, and authentication.

use crate::auth::{AuthManager, TokenClaims, OptionalTokenClaims};
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
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tracing::{info, warn, error};
use uuid::Uuid;

/// Storage record (simplified for this example)
#[derive(Debug, Clone, Serialize, Deserialize)]
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
    OptionalTokenClaims(claims): OptionalTokenClaims,
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
        let algorithm = Aegis256::new();
        let key = state.key_manager.generate_key(&algorithm).unwrap();
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
        let mut metadata = HashMap::new();
        for (field_name, field_config) in &field_config.fields {
            if let Some(field_value) = get_nested_value(&request.data, field_name) {
                let field_id = FieldIdentifier {
                    name: field_name.clone(),
                    tenant_id: request.tenant_id.clone(),
                };
                
                let field_bytes = serde_json::to_vec(&field_value)
                    .map_err(|e| ServerError::serialization(e.to_string()))?;
                
                if let Ok(encrypted_field) = state.field_encryption_manager.encrypt_field(&field_id, &field_bytes).await {
                    metadata.insert(field_name.clone(), FieldEncryptionMetadata {
                        field: field_name.clone(),
                        algorithm: field_config.algorithm.clone(),
                        key_id: field_config.key_id.clone().unwrap_or_else(|| "default".to_string()),
                        size_bytes: encrypted_field.ciphertext.len() as u64,
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
    let record_bytes = serde_json::to_vec(&storage_record)
        .map_err(|e| ServerError::serialization(e.to_string()))?;
    
    state.storage.put(&data_id, &record_bytes).await
        .map_err(|e| ServerError::Core(e))?;
    
    let response = StoreResponse {
        id: data_id,
        key_id,
        stored_at: Utc::now(),
        size_bytes: storage_record.data.len() as u64,
        algorithm: "aegis256".to_string(),
        field_metadata: storage_record.field_metadata,
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
    OptionalTokenClaims(claims): OptionalTokenClaims,
    Path(data_id): Path<String>,
    Query(_params): Query<RetrieveRequest>,
) -> ServerResult<Json<ApiResponse<RetrieveResponse>>> {
    let start_time = std::time::Instant::now();
    
    info!(
        user_id = ?claims.as_ref().map(|c| &c.sub),
        data_id = %data_id,
        "Retrieve data request received"
    );

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
    let key = state.key_manager.get_key(&storage_record.key_id)
        .map_err(|e| ServerError::Core(e))?;

    // Decrypt the data
    let plaintext = Aegis256::new().decrypt(&storage_record.data, &key)
        .map_err(|e| ServerError::Core(e))?;
    
    let decrypted_data: serde_json::Value = serde_json::from_slice(&plaintext)
        .map_err(|e| ServerError::serialization(e.to_string()))?;

    // Handle field-level decryption if specified
    let final_data = if let Some(ref field_metadata) = storage_record.field_metadata {
        let mut data = decrypted_data;
        for (field_name, metadata) in field_metadata {
            let field_id = FieldIdentifier {
                name: field_name.clone(),
                tenant_id: storage_record.tenant_id.clone(),
            };
            
            // This would require storing the encrypted field data separately
            // For now, we'll keep the original data
        }
        data
    } else {
        decrypted_data
    };

    let response = RetrieveResponse {
        data: final_data,
        metadata: storage_record.metadata,
        retrieved_at: Utc::now(),
        stored_at: storage_record.created_at,
        algorithm: storage_record.algorithm,
        key_id: storage_record.key_id,
        encrypted_data: None, // Could include raw encrypted data if requested
        field_metadata: storage_record.field_metadata,
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
    let key = state.key_manager.generate_key(&algorithm)
        .map_err(|e| ServerError::Core(e))?;

    // Generate fingerprint
    let fingerprint = generate_key_fingerprint(&key);

    let response = KeyResponse {
        id: key.id.clone(),
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

/// Helper function to generate key fingerprint
fn generate_key_fingerprint(key: &SecureKey) -> String {
    use sha2::{Sha256, Digest};
    let mut hasher = Sha256::new();
    hasher.update(key.data());
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
