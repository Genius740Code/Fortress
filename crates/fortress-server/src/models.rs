//! API models and data structures
//!
//! This module defines the request and response models used by the REST API,
//! including data transfer objects (DTOs) and validation structures.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
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
    /// Field configuration ID
    pub config_id: String,
    /// Field identifier
    pub field: String,
    /// Algorithm used for encryption
    pub algorithm: String,
    /// Key ID used
    pub key_id: String,
    /// Key version
    pub key_version: u32,
    /// When the field was encrypted
    pub encrypted_at: DateTime<Utc>,
    /// Nonce/IV used (if applicable)
    pub nonce: Option<Vec<u8>>,
    /// Authentication tag (if applicable)
    pub tag: Option<Vec<u8>>,
    /// Additional encryption metadata
    pub metadata: HashMap<String, String>,
}

/// Re-export from fortress_core to avoid conflicts
pub use fortress_core::field_encryption::FieldEncryptionMetadata as CoreFieldEncryptionMetadata;

/// Conversion from core metadata to API metadata
impl From<CoreFieldEncryptionMetadata> for FieldEncryptionMetadata {
    fn from(core: CoreFieldEncryptionMetadata) -> Self {
        Self {
            config_id: core.config_id.to_string(),
            field: match core.field {
                fortress_core::field_encryption::FieldIdentifier::Name(name) => name,
                fortress_core::field_encryption::FieldIdentifier::Path(path) => path.join("."),
                fortress_core::field_encryption::FieldIdentifier::Indexed { index, .. } => format!("[{}]", index),
            },
            algorithm: core.algorithm,
            key_id: core.key_id.to_string(),
            key_version: core.key_version,
            encrypted_at: core.encrypted_at,
            nonce: core.nonce,
            tag: core.tag,
            metadata: core.metadata,
        }
    }
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

// ==================== DATABASE MANAGEMENT MODELS ====================

/// Create database request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateDatabaseRequest {
    /// Database name
    pub name: String,
    /// Encryption algorithm
    pub algorithm: String,
    /// Key rotation interval
    pub key_rotation_interval: String,
    /// Storage path
    pub storage_path: String,
}

/// Database response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseResponse {
    /// Database name
    pub name: String,
    /// Creation timestamp
    pub created_at: DateTime<Utc>,
    /// Encryption algorithm
    pub algorithm: String,
    /// Key rotation interval
    pub key_rotation_interval: String,
    /// Number of tables
    pub tables_count: u32,
    /// Database size in bytes
    pub size_bytes: u64,
}

/// List databases response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListDatabasesResponse {
    /// List of databases
    pub databases: Vec<DatabaseInfo>,
    /// Total count
    pub total_count: u64,
}

/// Database information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseInfo {
    /// Database name
    pub name: String,
    /// Creation timestamp
    pub created_at: DateTime<Utc>,
    /// Number of tables
    pub tables_count: u32,
    /// Database size in bytes
    pub size_bytes: u64,
}

/// Operation delete response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperationDeleteResponse {
    /// Whether the operation was successful
    pub deleted: bool,
    /// Operation message
    pub message: String,
}

// ==================== TABLE MANAGEMENT MODELS ====================

/// Create table request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateTableRequest {
    /// Table name
    pub name: String,
    /// Table columns
    pub columns: Vec<ColumnDefinition>,
    /// Table encryption profile
    pub encryption: Option<String>,
    /// Column-specific encryption
    pub column_encryption: Option<HashMap<String, String>>,
}

/// Column definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ColumnDefinition {
    /// Column name
    pub name: String,
    /// Column type
    #[serde(rename = "type")]
    pub column_type: String,
    /// Whether it's a primary key
    pub primary_key: Option<bool>,
    /// Whether it's nullable
    pub nullable: Option<bool>,
    /// Encryption configuration
    pub encryption: Option<String>,
}

/// Table response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TableResponse {
    /// Table name
    pub name: String,
    /// Number of columns
    pub columns: u32,
    /// Number of rows
    pub rows: u64,
    /// Encryption profile
    pub encryption: String,
    /// Creation timestamp
    pub created_at: DateTime<Utc>,
}

/// List tables response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListTablesResponse {
    /// List of tables
    pub tables: Vec<TableInfo>,
    /// Total count
    pub total_count: u64,
}

/// Table information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TableInfo {
    /// Table name
    pub name: String,
    /// Number of columns
    pub columns: u32,
    /// Number of rows
    pub rows: u64,
    /// Encryption profile
    pub encryption: String,
    /// Creation timestamp
    pub created_at: DateTime<Utc>,
}

/// Table schema response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TableSchemaResponse {
    /// Table name
    pub name: String,
    /// Table columns
    pub columns: Vec<ColumnSchema>,
    /// Encryption profile
    pub encryption: String,
}

/// Column schema
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ColumnSchema {
    /// Column name
    pub name: String,
    /// Column type
    #[serde(rename = "type")]
    pub column_type: String,
    /// Whether it's a primary key
    pub primary_key: bool,
    /// Whether it's nullable
    pub nullable: bool,
    /// Whether it's encrypted
    pub encrypted: bool,
    /// Encryption algorithm (if encrypted)
    pub encryption_algorithm: Option<String>,
}

// ==================== DATA OPERATIONS MODELS ====================

/// Insert data request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InsertDataRequest {
    /// Data to insert (JSON object)
    #[serde(flatten)]
    pub data: serde_json::Value,
}

/// Insert response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InsertResponse {
    /// Inserted record ID
    pub id: String,
    /// Insert timestamp
    pub inserted_at: DateTime<Utc>,
    /// Number of rows affected
    pub rows_affected: u64,
}

/// Query response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryResponse {
    /// Query results
    pub results: Vec<serde_json::Value>,
    /// Total count
    pub total_count: u64,
    /// Execution time in milliseconds
    pub execution_time_ms: f64,
}

/// Bulk insert request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BulkInsertRequest {
    /// Data to insert (array of objects)
    pub data: Vec<serde_json::Value>,
}

/// Bulk insert response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BulkInsertResponse {
    /// Number of records inserted
    pub inserted_count: u64,
    /// Insert timestamp
    pub inserted_at: DateTime<Utc>,
    /// Execution time in milliseconds
    pub execution_time_ms: f64,
}

/// Update data request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateDataRequest {
    /// Data to update (JSON object with fields to update)
    #[serde(flatten)]
    pub data: serde_json::Value,
}

/// Update response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateResponse {
    /// Updated record ID
    pub id: String,
    /// Update timestamp
    pub updated_at: DateTime<Utc>,
    /// Number of rows affected
    pub rows_affected: u64,
}

// ==================== QUERY OPERATIONS MODELS ====================

/// Execute query request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecuteQueryRequest {
    /// SQL query
    pub sql: String,
    /// Query parameters
    pub parameters: Option<Vec<serde_json::Value>>,
    /// Query options
    pub options: Option<HashMap<String, String>>,
}

// ==================== ENCRYPTION MANAGEMENT MODELS ====================

/// Rotate keys response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RotateKeysResponse {
    /// Rotation operation ID
    pub rotation_id: String,
    /// Rotation status
    pub status: String,
    /// Start timestamp
    pub started_at: DateTime<Utc>,
    /// Completion timestamp
    pub completed_at: DateTime<Utc>,
    /// Number of rows rotated
    pub rows_rotated: u64,
}

/// Rotation status response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RotationStatusResponse {
    /// Rotation status
    pub rotation_status: String,
    /// Current key version
    pub current_version: u32,
    /// Previous key version
    pub previous_version: u32,
    /// Transition status
    pub transition_status: String,
    /// Start timestamp
    pub started_at: DateTime<Utc>,
    /// Estimated completion time
    pub estimated_completion: DateTime<Utc>,
}

/// Encryption metadata response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptionMetadataResponse {
    /// Table encryption profile
    pub table_encryption: String,
    /// Column-specific encryption
    pub column_encryption: HashMap<String, String>,
    /// Key rotation schedule
    pub key_rotation_schedule: HashMap<String, String>,
    /// Last rotation timestamp
    pub last_rotation: DateTime<Utc>,
    /// Next rotation timestamp
    pub next_rotation: DateTime<Utc>,
    /// Zero-downtime rotation enabled
    pub zero_downtime_enabled: bool,
    /// Dual key validation enabled
    pub dual_key_validation: bool,
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

// ==================== OPENAPI RESPONSE MODELS ====================

/// Store data response
#[derive(Debug, Clone, Serialize, Deserialize)]

pub struct StoreDataResponse {
    /// Unique identifier for stored data
    
    pub id: String,
    /// Key ID used for encryption
    
    pub key_id: String,
    /// Timestamp when data was stored
    
    pub stored_at: DateTime<Utc>,
    /// Size of stored data in bytes
    
    pub size_bytes: u64,
    /// Encryption algorithm used
    
    pub algorithm: String,
    /// Field-level encryption metadata
    
    pub field_metadata: Option<HashMap<String, serde_json::Value>>,
}

/// Retrieve data response
#[derive(Debug, Clone, Serialize, Deserialize)]

pub struct RetrieveDataResponse {
    /// Unique identifier for the data
    
    pub id: String,
    /// Decrypted data
    
    pub data: serde_json::Value,
    /// Metadata associated with the data
    
    pub metadata: Option<HashMap<String, serde_json::Value>>,
    /// Timestamp when data was created
    
    pub created_at: DateTime<Utc>,
    /// Last access timestamp
    
    pub last_accessed: Option<DateTime<Utc>>,
    /// Encryption algorithm used
    
    pub algorithm: String,
    /// Key ID used for encryption
    
    pub key_id: String,
    /// Field-level encryption metadata
    
    pub field_metadata: Option<HashMap<String, serde_json::Value>>,
}

/// List data response
#[derive(Debug, Clone, Serialize, Deserialize)]

pub struct ListDataResponse {
    /// List of storage records
    
    pub records: Vec<serde_json::Value>,
    /// Total count of records
    
    pub total_count: u64,
    /// Current page number
    
    pub page: u32,
    /// Page size
    
    pub page_size: u32,
    /// Total pages
    
    pub total_pages: u32,
}

/// Component status for health check
#[derive(Debug, Clone, Serialize, Deserialize)]

pub struct ComponentStatus {
    /// Component health status
    
    pub status: String,
    /// Response time in milliseconds
    
    pub response_time_ms: u64,
    /// Optional error message
    
    pub error: Option<String>,
}

/// Error response
#[derive(Debug, Clone, Serialize, Deserialize)]

pub struct ErrorResponse {
    /// Error code
    
    pub code: String,
    /// Error message
    
    pub message: String,
    /// Error details
    
    pub details: Option<HashMap<String, serde_json::Value>>,
    /// Timestamp
    
    pub timestamp: DateTime<Utc>,
    /// Request ID for tracing
    
    pub request_id: String,
}
