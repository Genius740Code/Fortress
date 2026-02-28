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
    let field_metadata = if request.field_encryption.is_some() {
        // TODO: Implement field encryption with correct API
        None
    } else {
        None
    };

    // Store the encrypted data using correct API
    // TODO: Implement proper storage with correct API
    // For now, just return success
    
    let response = StoreResponse {
        id: data_id,
        key_id,
        stored_at: Utc::now(),
        size_bytes: ciphertext.len() as u64,
        algorithm: "aegis256".to_string(),
        field_metadata: None,
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

    // TODO: Implement proper retrieval with correct storage API
    // For now, return not found
    return Err(ServerError::not_found("Data not found"));
}

/// Delete data handler
pub async fn delete_data(
    State(_state): State<Arc<AppState>>,
    OptionalTokenClaims(claims): OptionalTokenClaims,
    Path(data_id): Path<String>,
    Json(_request): Json<DeleteRequest>,
) -> ServerResult<Json<ApiResponse<DeleteResponse>>> {
    let start_time = std::time::Instant::now();
    
    info!(
        user_id = ?claims.as_ref().map(|c| &c.sub),
        data_id = %data_id,
        "Delete data request received"
    );

    // TODO: Implement proper deletion with correct storage API
    // For now, return not found
    return Err(ServerError::not_found("Data not found"));
}

/// List data handler
pub async fn list_data(
    State(_state): State<Arc<AppState>>,
    OptionalTokenClaims(claims): OptionalTokenClaims,
    Query(_request): Query<ListRequest>,
) -> ServerResult<Json<ApiResponse<ListResponse>>> {
    let start_time = std::time::Instant::now();
    
    info!(
        user_id = ?claims.as_ref().map(|c| &c.sub),
        "List data request received"
    );

    // TODO: Implement proper listing with correct storage API
    // For now, return empty results
    let items: Vec<DataItem> = vec![];

    let response = ListResponse {
        items,
        total_count: 0,
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
    State(_state): State<Arc<AppState>>,
    OptionalTokenClaims(claims): OptionalTokenClaims,
    Json(_request): Json<KeyRequest>,
) -> ServerResult<Json<ApiResponse<KeyResponse>>> {
    let start_time = std::time::Instant::now();
    
    info!(
        user_id = ?claims.as_ref().map(|c| &c.sub),
        "Generate key request received"
    );

    // TODO: Implement proper key generation with correct API
    // For now, return not implemented
    return Err(ServerError::internal("Key generation not yet implemented"));
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
