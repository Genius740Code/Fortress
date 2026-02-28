//! API models and data structures
//!
//! This module defines the request and response models used by the REST API,
//! including data transfer objects (DTOs) and validation structures.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;
use chrono::{DateTime, Utc};

/// API response wrapper
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiResponse<T> {
    /// Response data
    pub data: Option<T>,
    /// Success status
    pub success: bool,
    /// Response timestamp
    pub timestamp: DateTime<Utc>,
    /// Response metadata
    pub metadata: Option<ResponseMetadata>,
}

impl<T> ApiResponse<T> {
    /// Create a successful response
    pub fn success(data: T) -> Self {
        Self {
            data: Some(data),
            success: true,
            timestamp: Utc::now(),
            metadata: None,
        }
    }

    /// Create a successful response with metadata
    pub fn success_with_metadata(data: T, metadata: ResponseMetadata) -> Self {
        Self {
            data: Some(data),
            success: true,
            timestamp: Utc::now(),
            metadata: Some(metadata),
        }
    }

    /// Create an empty successful response
    pub fn empty() -> Self {
        Self {
            data: None,
            success: true,
            timestamp: Utc::now(),
            metadata: None,
        }
    }
}

/// Response metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseMetadata {
    /// Total count (for paginated responses)
    pub total_count: Option<u64>,
    /// Page information
    pub page: Option<PageInfo>,
    /// Rate limit information
    pub rate_limit: Option<RateLimitInfo>,
    /// Request ID
    pub request_id: Option<String>,
}

/// Page information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PageInfo {
    /// Current page number
    pub page: u32,
    /// Page size
    pub page_size: u32,
    /// Total pages
    pub total_pages: u32,
    /// Has next page
    pub has_next: bool,
    /// Has previous page
    pub has_previous: bool,
}

/// Rate limit information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitInfo {
    /// Requests remaining
    pub remaining: u32,
    /// Requests limit
    pub limit: u32,
    /// Reset time
    pub reset_at: DateTime<Utc>,
}

/// Data storage request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoreRequest {
    /// Data to store (will be automatically encrypted)
    pub data: serde_json::Value,
    /// Optional metadata
    pub metadata: Option<HashMap<String, serde_json::Value>>,
    /// Encryption algorithm (optional, uses default if not specified)
    pub algorithm: Option<String>,
    /// Key ID (optional, generates new key if not specified)
    pub key_id: Option<String>,
    /// Tenant ID (for multi-tenant setups)
    pub tenant_id: Option<String>,
    /// Field-level encryption configuration
    pub field_encryption: Option<FieldEncryptionConfig>,
}

/// Field-level encryption configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FieldEncryptionConfig {
    /// Fields to encrypt with specific algorithms
    pub fields: HashMap<String, FieldConfig>,
}

/// Field configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FieldConfig {
    /// Encryption algorithm for this field
    pub algorithm: String,
    /// Key ID for this field (optional)
    pub key_id: Option<String>,
    /// Field sensitivity level
    pub sensitivity: Option<String>,
}

/// Data storage response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoreResponse {
    /// ID of the stored data
    pub id: String,
    /// Key ID used for encryption
    pub key_id: String,
    /// Storage timestamp
    pub stored_at: DateTime<Utc>,
    /// Data size in bytes
    pub size_bytes: u64,
    /// Encryption algorithm used
    pub algorithm: String,
    /// Field encryption metadata
    pub field_metadata: Option<HashMap<String, FieldEncryptionMetadata>>,
}

/// Field encryption metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FieldEncryptionMetadata {
    /// Field name
    pub field: String,
    /// Algorithm used
    pub algorithm: String,
    /// Key ID used
    pub key_id: String,
    /// Encrypted size
    pub size_bytes: u64,
}

/// Data retrieval request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetrieveRequest {
    /// ID of the data to retrieve
    pub id: String,
    /// Key ID for decryption (optional, uses stored key if not specified)
    pub key_id: Option<String>,
    /// Tenant ID (for multi-tenant setups)
    pub tenant_id: Option<String>,
    /// Include raw encrypted data
    pub include_encrypted: Option<bool>,
}

/// Data retrieval response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetrieveResponse {
    /// Decrypted data
    pub data: serde_json::Value,
    /// Original metadata
    pub metadata: Option<HashMap<String, serde_json::Value>>,
    /// Retrieval timestamp
    pub retrieved_at: DateTime<Utc>,
    /// Storage timestamp
    pub stored_at: DateTime<Utc>,
    /// Encryption algorithm used
    pub algorithm: String,
    /// Key ID used
    pub key_id: String,
    /// Raw encrypted data (if requested)
    pub encrypted_data: Option<String>,
    /// Field decryption metadata
    pub field_metadata: Option<HashMap<String, FieldEncryptionMetadata>>,
}

/// Data deletion request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeleteRequest {
    /// ID of the data to delete
    pub id: String,
    /// Tenant ID (for multi-tenant setups)
    pub tenant_id: Option<String>,
    /// Soft delete (mark as deleted but keep data)
    pub soft_delete: Option<bool>,
}

/// Data deletion response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeleteResponse {
    /// ID of the deleted data
    pub id: String,
    /// Deletion timestamp
    pub deleted_at: DateTime<Utc>,
    /// Whether it was a soft delete
    pub soft_delete: bool,
}

/// List data request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListRequest {
    /// Tenant ID (for multi-tenant setups)
    pub tenant_id: Option<String>,
    /// Pagination parameters
    pub pagination: Option<PaginationParams>,
    /// Filter parameters
    pub filter: Option<FilterParams>,
    /// Sort parameters
    pub sort: Option<SortParams>,
}

/// Pagination parameters
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaginationParams {
    /// Page number (1-based)
    pub page: Option<u32>,
    /// Page size
    pub page_size: Option<u32>,
    /// Maximum items to return
    pub limit: Option<u32>,
}

/// Filter parameters
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FilterParams {
    /// Filter by metadata key-value pairs
    pub metadata: Option<HashMap<String, serde_json::Value>>,
    /// Filter by algorithm
    pub algorithm: Option<String>,
    /// Filter by date range
    pub date_range: Option<DateRange>,
    /// Filter by key ID
    pub key_id: Option<String>,
}

/// Date range filter
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DateRange {
    /// Start date (inclusive)
    pub start: Option<DateTime<Utc>>,
    /// End date (inclusive)
    pub end: Option<DateTime<Utc>>,
}

/// Sort parameters
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SortParams {
    /// Sort field
    pub field: String,
    /// Sort direction
    pub direction: SortDirection,
}

/// Sort direction
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SortDirection {
    /// Ascending order
    Asc,
    /// Descending order
    Desc,
}

/// List data response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListResponse {
    /// List of data items
    pub items: Vec<DataItem>,
    /// Total count
    pub total_count: u64,
}

/// Data item summary
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataItem {
    /// Data ID
    pub id: String,
    /// Key ID
    pub key_id: String,
    /// Storage timestamp
    pub stored_at: DateTime<Utc>,
    /// Data size in bytes
    pub size_bytes: u64,
    /// Algorithm used
    pub algorithm: String,
    /// Metadata
    pub metadata: Option<HashMap<String, serde_json::Value>>,
}

/// Key management request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyRequest {
    /// Key type/algorithm
    pub algorithm: String,
    /// Key size in bits (optional, uses algorithm default)
    pub key_size: Option<u32>,
    /// Metadata
    pub metadata: Option<HashMap<String, serde_json::Value>>,
    /// Tenant ID (for multi-tenant setups)
    pub tenant_id: Option<String>,
}

/// Key management response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyResponse {
    /// Key ID
    pub id: String,
    /// Key type/algorithm
    pub algorithm: String,
    /// Key size in bits
    pub key_size: u32,
    /// Creation timestamp
    pub created_at: DateTime<Utc>,
    /// Key metadata
    pub metadata: HashMap<String, serde_json::Value>,
    /// Key fingerprint (for verification)
    pub fingerprint: String,
}

/// Health check response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthResponse {
    /// Overall health status
    pub status: HealthStatus,
    /// Service version
    pub version: String,
    /// Uptime in seconds
    pub uptime: u64,
    /// Individual component health
    pub components: HashMap<String, ComponentHealth>,
    /// Timestamp
    pub timestamp: DateTime<Utc>,
}

/// Health status
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum HealthStatus {
    /// Healthy
    Healthy,
    /// Degraded performance
    Degraded,
    /// Unhealthy
    Unhealthy,
}

/// Component health information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComponentHealth {
    /// Component status
    pub status: HealthStatus,
    /// Status message
    pub message: Option<String>,
    /// Response time in milliseconds
    pub response_time_ms: Option<u64>,
    /// Last check timestamp
    pub last_check: DateTime<Utc>,
}

/// Metrics response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricsResponse {
    /// Metrics data
    pub metrics: HashMap<String, serde_json::Value>,
    /// Collection timestamp
    pub timestamp: DateTime<Utc>,
}

/// Authentication request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthRequest {
    /// Username or email
    pub username: String,
    /// Password
    pub password: String,
    /// Tenant ID (for multi-tenant setups)
    pub tenant_id: Option<String>,
}

/// Authentication response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthResponse {
    /// Access token
    pub access_token: String,
    /// Token type
    pub token_type: String,
    /// Token expiration in seconds
    pub expires_in: u64,
    /// Refresh token (optional)
    pub refresh_token: Option<String>,
    /// User information
    pub user: UserInfo,
}

/// User information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserInfo {
    /// User ID
    pub id: String,
    /// Username
    pub username: String,
    /// Email
    pub email: Option<String>,
    /// Roles
    pub roles: Vec<String>,
    /// Tenant ID
    pub tenant_id: Option<String>,
}

/// Token refresh request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RefreshTokenRequest {
    /// Refresh token
    pub refresh_token: String,
}

/// Token refresh response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RefreshTokenResponse {
    /// New access token
    pub access_token: String,
    /// Token type
    pub token_type: String,
    /// Token expiration in seconds
    pub expires_in: u64,
    /// New refresh token (optional)
    pub refresh_token: Option<String>,
}

impl Default for PaginationParams {
    fn default() -> Self {
        Self {
            page: Some(1),
            page_size: Some(50),
            limit: None,
        }
    }
}

impl Default for SortParams {
    fn default() -> Self {
        Self {
            field: "stored_at".to_string(),
            direction: SortDirection::Desc,
        }
    }
}
