//! GraphQL type definitions
//!
//! Contains all GraphQL types, enums, and scalars used in the Fortress GraphQL API.

use async_graphql::{SimpleObject, InputObject, Enum};
use chrono::{DateTime, Utc};
use std::collections::HashMap;
use serde::{Serialize, Deserialize};

// ==================== Enums ====================

/// Database status
#[derive(Enum, Clone, Debug, Copy, PartialEq, Eq)]
pub enum DatabaseStatus {
    /// Database is active and ready
    Active,
    /// Database is being created
    Creating,
    /// Database is being deleted
    Deleting,
    /// Database is in maintenance mode
    Maintenance,
    /// Database is archived
    Archived,
}

/// Encryption algorithm
#[derive(Enum, Clone, Debug, Copy, PartialEq, Eq)]
pub enum EncryptionAlgorithm {
    /// AEGIS-256 (recommended)
    Aegis256,
    /// ChaCha20-Poly1305
    ChaCha20Poly1305,
    /// AES-256-GCM
    Aes256Gcm,
    /// RSA-2048
    Rsa2048,
    /// RSA-4096
    Rsa4096,
    /// ECDSA-P256
    EcdsaP256,
    /// ECDSA-P384
    EcdsaP384,
}

/// Field type
#[derive(Enum, Clone, Debug, Copy, PartialEq, Eq)]
pub enum FieldType {
    /// Text field
    Text,
    /// Integer field
    Integer,
    /// Float field
    Float,
    /// Boolean field
    Boolean,
    /// Date/time field
    DateTime,
    /// UUID field
    Uuid,
    /// JSON field
    Json,
    /// Binary field
    Binary,
    /// Encrypted field
    Encrypted,
}

/// Sort order
#[derive(Enum, Clone, Debug, Copy, PartialEq, Eq)]
pub enum SortOrder {
    /// Ascending order
    Asc,
    /// Descending order
    Desc,
}

/// Query operator
#[derive(Enum, Clone, Debug, Copy, PartialEq, Eq)]
pub enum QueryOperator {
    /// Equals
    Eq,
    /// Not equals
    Ne,
    /// Greater than
    Gt,
    /// Greater than or equal
    Gte,
    /// Less than
    Lt,
    /// Less than or equal
    Lte,
    /// Like (pattern matching)
    Like,
    /// In list
    In,
    /// Not in list
    NotIn,
    /// Is null
    IsNull,
    /// Is not null
    IsNotNull,
}

// ==================== Input Objects ====================

/// Input for creating a database
#[derive(InputObject)]
pub struct CreateDatabaseInput {
    /// Database name
    pub name: String,
    /// Description
    pub description: Option<String>,
    /// Default encryption algorithm
    pub encryption_algorithm: Option<EncryptionAlgorithm>,
    /// Tags
    pub tags: Option<Vec<String>>,
}

/// Input for creating a table
#[derive(InputObject)]
pub struct CreateTableInput {
    /// Table name
    pub name: String,
    /// Database name
    pub database: String,
    /// Table fields
    pub fields: Vec<CreateFieldInput>,
    /// Primary key fields
    pub primary_key: Vec<String>,
    /// Table description
    pub description: Option<String>,
}

/// Input for creating a field
#[derive(async_graphql::InputObject, Clone, Debug)]
pub struct CreateFieldInput {
    /// Field name
    pub name: String,
    /// Field type
    pub field_type: FieldType,
    /// Whether the field is required
    pub required: bool,
    /// Whether the field is encrypted
    pub encrypted: bool,
    /// Default value (if any)
    pub default_value: Option<String>,
    /// Field description
    pub description: Option<String>,
    /// Encryption algorithm for encrypted fields
    pub encryption_algorithm: Option<EncryptionAlgorithm>,
}

/// Input for inserting data
#[derive(InputObject)]
pub struct InsertDataInput {
    /// Database name
    pub database: String,
    /// Table name
    pub table: String,
    /// Data to insert
    pub data: async_graphql::Json<serde_json::Value>,
}

/// Input for updating data
#[derive(InputObject)]
pub struct UpdateDataInput {
    /// Database name
    pub database: String,
    /// Table name
    pub table: String,
    /// Record ID
    pub id: String,
    /// Data to update
    pub data: async_graphql::Json<serde_json::Value>,
}

/// Input for querying table data
#[derive(InputObject)]
pub struct TableQueryInput {
    /// Database name
    pub database: String,
    /// Table name
    pub table: String,
    /// Filter conditions
    pub filter: Option<Vec<FilterConditionInput>>,
    /// Sort conditions
    pub sort: Option<Vec<SortConditionInput>>,
    /// Pagination
    pub pagination: Option<PaginationInput>,
}

/// Input for querying data
#[derive(InputObject)]
pub struct QueryDataInput {
    /// Database name
    pub database: String,
    /// Table name
    pub table: String,
    /// Filter conditions
    pub filter: Option<Vec<FilterConditionInput>>,
    /// Sort conditions
    pub sort: Option<Vec<SortConditionInput>>,
    /// Pagination
    pub pagination: Option<PaginationInput>,
}

/// Input for filter conditions
#[derive(InputObject)]
pub struct FilterConditionInput {
    /// Field name
    pub field: String,
    /// Operator
    pub operator: QueryOperator,
    /// Value (for comparison operators)
    pub value: Option<async_graphql::Json<serde_json::Value>>,
    /// Values (for IN/NOT IN operators)
    pub values: Option<Vec<async_graphql::Json<serde_json::Value>>>,
}

/// Input for sort conditions
#[derive(InputObject)]
pub struct SortConditionInput {
    /// Field name
    pub field: String,
    /// Sort order
    pub order: SortOrder,
}

/// Input for pagination
#[derive(InputObject)]
pub struct PaginationInput {
    /// Page number (0-based)
    pub page: Option<i32>,
    /// Page size
    pub page_size: Option<i32>,
    /// Offset (alternative to page)
    pub offset: Option<i32>,
    /// Limit (alternative to page_size)
    pub limit: Option<i32>,
}

/// Input for key rotation
#[derive(InputObject)]
pub struct RotateKeysInput {
    /// Database name
    pub database: String,
    /// Table name
    pub table: String,
    /// New encryption algorithm
    pub algorithm: Option<EncryptionAlgorithm>,
    /// Whether to perform zero-downtime rotation
    pub zero_downtime: Option<bool>,
}

// ==================== Output Objects ====================

/// Database information
#[derive(SimpleObject, Clone, Debug)]
pub struct Database {
    /// Database ID
    pub id: String,
    /// Database name
    pub name: String,
    /// Description
    pub description: Option<String>,
    /// Status
    pub status: DatabaseStatus,
    /// Default encryption algorithm
    pub encryption_algorithm: EncryptionAlgorithm,
    /// Creation timestamp
    pub created_at: DateTime<Utc>,
    /// Last updated timestamp
    pub updated_at: DateTime<Utc>,
    /// Tags
    pub tags: Vec<String>,
    /// Number of tables
    pub table_count: i32,
    /// Storage size in bytes
    pub storage_size_bytes: i64,
}

/// Table information
#[derive(SimpleObject, Clone, Debug)]
pub struct Table {
    /// Table ID
    pub id: String,
    /// Table name
    pub name: String,
    /// Database name
    pub database: String,
    /// Description
    pub description: Option<String>,
    /// Table fields
    pub fields: Vec<Field>,
    /// Primary key fields
    pub primary_key: Vec<String>,
    /// Creation timestamp
    pub created_at: DateTime<Utc>,
    /// Last updated timestamp
    pub updated_at: DateTime<Utc>,
    /// Number of records
    pub record_count: i32,
    /// Whether encryption is enabled
    pub encryption_enabled: bool,
}

/// Field information
#[derive(SimpleObject, Clone, Debug)]
pub struct Field {
    /// Field name
    pub name: String,
    /// Field type
    pub field_type: FieldType,
    /// Whether the field is required
    pub required: bool,
    /// Description
    pub description: Option<String>,
    /// Default value
    pub default_value: Option<String>,
    /// Encryption algorithm (if encrypted)
    pub encryption_algorithm: Option<EncryptionAlgorithm>,
    /// Whether the field is encrypted
    pub encrypted: bool,
}

/// Data record
#[derive(SimpleObject, Clone, Debug, Serialize, Deserialize)]
pub struct DataRecord {
    /// Record ID
    pub id: String,
    /// Field data
    pub data: async_graphql::Json<serde_json::Value>,
    /// Creation timestamp
    pub created_at: DateTime<Utc>,
    /// Last updated timestamp
    pub updated_at: DateTime<Utc>,
    /// Encryption metadata for encrypted fields
    pub encryption_metadata: Option<async_graphql::Json<serde_json::Value>>,
}

/// Query result
#[derive(SimpleObject, Clone, Debug, Serialize, Deserialize)]
pub struct QueryResult {
    /// Records returned
    pub records: Vec<DataRecord>,
    /// Total number of records matching the query
    pub total_count: i32,
    /// Whether there are more records
    pub has_more: bool,
    /// Pagination information
    pub pagination: Option<PaginationInfo>,
}

/// Pagination information
#[derive(SimpleObject, Clone, Debug, Serialize, Deserialize)]
pub struct PaginationInfo {
    /// Current page number
    pub page: i32,
    /// Page size
    pub page_size: i32,
    /// Total number of pages
    pub total_pages: i32,
    /// Total number of records
    pub total_records: i32,
    /// Has next page
    pub has_next: bool,
    /// Has previous page
    pub has_previous: bool,
}

/// Key rotation status
#[derive(SimpleObject, Clone, Debug)]
pub struct KeyRotationStatus {
    /// Rotation ID
    pub id: String,
    /// Status
    pub status: String,
    /// Progress percentage
    pub progress_percentage: f64,
    /// Started at
    pub started_at: Option<DateTime<Utc>>,
    /// Completed at
    pub completed_at: Option<DateTime<Utc>>,
    /// Error message (if any)
    pub error_message: Option<String>,
    /// Records processed
    pub records_processed: i32,
    /// Total records to process
    pub total_records: i32,
}

/// Encryption metadata
#[derive(SimpleObject, Clone, Debug)]
pub struct EncryptionMetadata {
    /// Field name
    pub field_name: String,
    /// Encryption algorithm
    pub algorithm: EncryptionAlgorithm,
    /// Key ID
    pub key_id: String,
    /// Key version
    pub key_version: i32,
    /// Encryption timestamp
    pub encrypted_at: DateTime<Utc>,
}

/// API response wrapper
#[derive(SimpleObject, Clone, Debug)]
pub struct ApiResponse<T: async_graphql::OutputType + Send + Sync> {
    /// Whether the operation was successful
    pub success: bool,
    /// Response data (if successful)
    pub data: Option<T>,
    /// Error message (if failed)
    pub error_message: Option<String>,
    /// Error code (if any)
    pub error_code: Option<String>,
}

/// Health status
#[derive(SimpleObject, Clone, Debug)]
pub struct HealthStatus {
    /// Overall health
    pub healthy: bool,
    /// Service status
    pub services: HashMap<String, ServiceHealth>,
    /// Last check timestamp
    pub last_check: DateTime<Utc>,
}

/// Individual service health
#[derive(SimpleObject, Clone, Debug, serde::Serialize)]
pub struct ServiceHealth {
    /// Service name
    pub name: String,
    /// Whether the service is healthy
    pub healthy: bool,
    /// Response time in milliseconds
    pub response_time_ms: i32,
    /// Additional details
    pub details: HashMap<String, String>,
}
