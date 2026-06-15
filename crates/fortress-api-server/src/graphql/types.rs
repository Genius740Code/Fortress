//! GraphQL type definitions
//!
//! Contains all GraphQL types, enums, and scalars used in the Fortress GraphQL API.

use async_graphql::{Enum, InputObject, SimpleObject};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

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

// ==================== Dynamic Secrets Types ====================

/// Database type for dynamic credentials
#[derive(Enum, Clone, Debug, Copy, PartialEq, Eq)]
pub enum DynamicDatabaseType {
    /// PostgreSQL
    Postgresql,
    /// MySQL
    Mysql,
    /// SQL Server
    Sqlserver,
}

/// AWS IAM credential response
#[derive(SimpleObject, Clone, Debug)]
pub struct AwsCredential {
    /// Access key ID
    pub access_key_id: String,
    /// Secret access key (masked)
    pub secret_access_key: String,
    /// Session token (if any)
    pub session_token: Option<String>,
    /// Expiration time
    pub expires_at: DateTime<Utc>,
    /// IAM policy applied
    pub policy: serde_json::Value,
    /// Role assumed (if any)
    pub role: Option<String>,
    /// Lease ID for renewal/revocation
    pub lease_id: String,
    /// Time to live in seconds
    pub ttl: u64,
}

/// Database credential response
#[derive(SimpleObject, Clone, Debug)]
pub struct DatabaseCredential {
    /// Generated username
    pub username: String,
    /// Generated password (masked)
    pub password: String,
    /// Database type
    pub database_type: DynamicDatabaseType,
    /// Database name
    pub database: String,
    /// Connection string (password masked)
    pub connection_string: String,
    /// Granted permissions
    pub permissions: Vec<String>,
    /// Expiration time
    pub expires_at: DateTime<Utc>,
    /// Lease ID for renewal/revocation
    pub lease_id: String,
    /// Time to live in seconds
    pub ttl: u64,
    /// Database-specific metadata
    pub metadata: HashMap<String, String>,
}

/// Input for generating AWS IAM credentials
#[derive(InputObject)]
pub struct GenerateAwsCredentialInput {
    /// Path for the credential
    pub path: String,
    /// IAM policy document
    pub policy: serde_json::Value,
    /// Role to assume (optional)
    pub role: Option<String>,
    /// Time to live in seconds
    pub ttl: Option<u64>,
}

/// Input for generating database credentials
#[derive(InputObject)]
pub struct GenerateDatabaseCredentialInput {
    /// Path for the credential
    pub path: String,
    /// Database type
    pub database_type: DynamicDatabaseType,
    /// Database connection URL (admin)
    pub database_url: String,
    /// Permissions to grant
    pub permissions: Vec<String>,
    /// Time to live in seconds
    pub ttl: Option<u64>,
}

/// Input for configuring AWS integration
#[derive(InputObject)]
pub struct ConfigureAwsInput {
    /// AWS access key ID
    pub access_key_id: String,
    /// AWS secret access key
    pub secret_access_key: String,
    /// AWS region
    pub region: Option<String>,
    /// Default IAM role
    pub default_role: Option<String>,
}

/// Input for renewing a credential lease
#[derive(InputObject)]
pub struct RenewLeaseInput {
    /// Lease ID to renew
    pub lease_id: String,
    /// TTL increment in seconds
    pub increment: Option<u64>,
}

/// Dynamic secrets engine status
#[derive(SimpleObject, Clone, Debug)]
pub struct DynamicSecretsStatus {
    /// Engine name
    pub name: String,
    /// Whether the engine is initialized
    pub initialized: bool,
    /// Total active secrets
    pub total_secrets: u64,
    /// Active leases
    pub active_leases: u64,
    /// AWS configuration status
    pub aws_configured: bool,
    /// Supported database types
    pub supported_databases: Vec<DynamicDatabaseType>,
    /// Default TTL
    pub default_ttl: u64,
    /// Maximum TTL
    pub max_ttl: u64,
    /// Auto cleanup enabled
    pub auto_cleanup: bool,
}

/// Secret data response
#[derive(SimpleObject, Clone, Debug)]
pub struct SecretData {
    /// Secret data
    pub data: serde_json::Value,
    /// Creation timestamp
    pub created_at: DateTime<Utc>,
    /// Last update timestamp
    pub updated_at: Option<DateTime<Utc>>,
    /// Secret version
    pub version: i32,
    /// Lease information (if applicable)
    pub lease: Option<LeaseInfo>,
}

/// Lease information
#[derive(SimpleObject, Clone, Debug)]
pub struct LeaseInfo {
    /// Lease ID
    pub lease_id: String,
    /// Time to live in seconds
    pub ttl: u64,
    /// Creation timestamp
    pub created_at: DateTime<Utc>,
    /// Whether the lease is renewable
    pub renewable: bool,
    /// Maximum TTL
    pub max_ttl: Option<u64>,
}

impl From<fortress_core::secrets::LeaseInfo> for LeaseInfo {
    fn from(core_lease: fortress_core::secrets::LeaseInfo) -> Self {
        LeaseInfo {
            lease_id: core_lease.lease_id,
            ttl: core_lease.ttl,
            created_at: core_lease.created_at,
            renewable: core_lease.renewable,
            max_ttl: core_lease.max_ttl,
        }
    }
}

