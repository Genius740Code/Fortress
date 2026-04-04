// Basic gRPC types for Fortress - simplified implementation without protobuf compilation
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// Database types

/// Database information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Database {
    /// Unique database identifier
    pub id: String,
    /// Database name
    pub name: String,
    /// Database description
    pub description: String,
    /// When the database was created
    pub created_at: chrono::DateTime<chrono::Utc>,
    /// When the database was last updated
    pub updated_at: chrono::DateTime<chrono::Utc>,
    /// Database configuration
    pub config: DatabaseConfig,
}

/// Database configuration settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseConfig {
    /// Encryption algorithm to use
    pub encryption_algorithm: String,
    /// Key rotation interval in days
    pub key_rotation_interval_days: i32,
    /// Whether audit logging is enabled
    pub enable_audit_logging: bool,
    /// Custom configuration settings
    pub custom_settings: HashMap<String, String>,
}

impl Default for DatabaseConfig {
    fn default() -> Self {
        Self {
            encryption_algorithm: "aes-256-gcm".to_string(),
            key_rotation_interval_days: 30,
            enable_audit_logging: true,
            custom_settings: HashMap::new(),
        }
    }
}

// Request/Response types

/// Request to create a new database
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateDatabaseRequest {
    /// Name for the new database
    pub name: String,
    /// Description for the new database
    pub description: String,
    /// Optional configuration for the database
    pub config: Option<DatabaseConfig>,
}

/// Response containing database information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseResponse {
    /// The created/retrieved database
    pub database: Database,
}

/// Request to get a specific database
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetDatabaseRequest {
    /// ID of the database to retrieve
    pub database_id: String,
}

/// Request to list databases
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListDatabasesRequest {
    /// Number of items per page
    pub page_size: i32,
    /// Token for pagination
    pub page_token: String,
}

/// Response containing list of databases
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListDatabasesResponse {
    /// List of databases
    pub databases: Vec<Database>,
    /// Token for next page of results
    pub next_page_token: String,
}

/// Request to delete a database
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeleteDatabaseRequest {
    /// ID of the database to delete
    pub database_id: String,
}

// Encryption types

/// Request to encrypt data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptRequest {
    /// ID of the database to encrypt for
    pub database_id: String,
    /// Plaintext data to encrypt
    pub plaintext: Vec<u8>,
    /// Optional key ID to use for encryption
    pub key_id: Option<String>,
    /// Encryption metadata
    pub metadata: HashMap<String, String>,
}

/// Response containing encrypted data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptResponse {
    /// Encrypted ciphertext
    pub ciphertext: Vec<u8>,
    /// ID of the key used for encryption
    pub key_id: String,
    /// When the data was encrypted
    pub encrypted_at: chrono::DateTime<chrono::Utc>,
    /// Encryption metadata
    pub metadata: HashMap<String, String>,
}

/// Request to decrypt data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecryptRequest {
    /// ID of the database to decrypt for
    pub database_id: String,
    /// Ciphertext data to decrypt
    pub ciphertext: Vec<u8>,
    /// ID of the key to use for decryption
    pub key_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
/// Response containing decrypted data
pub struct DecryptResponse {
    /// Decrypted plaintext data
    pub plaintext: Vec<u8>,
    /// When the data was decrypted
    pub decrypted_at: chrono::DateTime<chrono::Utc>,
    /// Decryption metadata
    pub metadata: HashMap<String, String>,
}

// Health check types

/// Health check response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthResponse {
    /// Health status (1 = Healthy, 2 = Degraded, 3 = Unhealthy)
    pub status: i32,
    /// Service version
    pub version: String,
    /// When the health check was performed
    pub timestamp: chrono::DateTime<chrono::Utc>,
    /// Health status of individual components
    pub components: Vec<ComponentHealth>,
}

/// Component health information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComponentHealth {
    /// Component name
    pub name: String,
    /// Component status (1 = Healthy, 2 = Degraded, 3 = Unhealthy)
    pub status: i32,
    /// Status message
    pub message: String,
}

// Metrics types

/// Metrics response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricsResponse {
    /// When metrics were collected
    pub timestamp: chrono::DateTime<chrono::Utc>,
    /// Counter metrics
    pub counters: HashMap<String, f64>,
    /// Gauge metrics
    pub gauges: HashMap<String, f64>,
    /// Histogram metrics
    pub histograms: HashMap<String, HistogramData>,
}

/// Histogram data for metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HistogramData {
    /// Total count of values
    pub count: u64,
    /// Sum of all values
    pub sum: f64,
    /// Bucket boundaries
    pub buckets: Vec<f64>,
    /// Count of values in each bucket
    pub bucket_counts: Vec<u64>,
}

// Batch encryption types

/// Batch encryption request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchEncryptRequest {
    /// Database ID
    pub database_id: String,
    /// Items to encrypt
    pub items: Vec<BatchEncryptItem>,
}

/// Item to encrypt in batch
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchEncryptItem {
    /// Data to encrypt
    pub data: Vec<u8>,
    /// Key ID to use
    pub key_id: String,
    /// Encryption algorithm
    pub encryption_algorithm: Option<String>,
    /// Additional context
    pub context: HashMap<String, String>,
}

/// Batch encryption response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchEncryptResponse {
    /// Results for each item
    pub results: Vec<BatchEncryptResult>,
    /// Errors that occurred
    pub errors: Vec<BatchEncryptError>,
    /// Total number of items
    pub total_items: u32,
    /// Number of successful items
    pub successful_items: u32,
    /// Number of failed items
    pub failed_items: u32,
}

/// Result of batch encryption for a single item
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchEncryptResult {
    /// Item index
    pub index: u32,
    /// Encrypted data
    pub encrypted_data: String,
    /// Algorithm used
    pub algorithm: String,
    /// Key ID used
    pub key_id: String,
    /// Timestamp of encryption
    pub timestamp: chrono::DateTime<chrono::Utc>,
    /// Whether encryption was successful
    pub success: bool,
    /// Error message if failed
    pub error: Option<String>,
}

/// Error in batch encryption
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchEncryptError {
    /// Item index
    pub index: u32,
    /// Error message
    pub error: String,
}

/// Batch decryption request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchDecryptRequest {
    /// Database ID
    pub database_id: String,
    /// Items to decrypt
    pub items: Vec<BatchDecryptItem>,
}

/// Item to decrypt in batch
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchDecryptItem {
    /// Encrypted data
    pub encrypted_data: String,
    /// Key ID to use
    pub key_id: String,
    /// Encryption algorithm
    pub algorithm: Option<String>,
    /// Additional context
    pub context: HashMap<String, String>,
}

/// Batch decryption response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchDecryptResponse {
    /// Results for each item
    pub results: Vec<BatchDecryptResult>,
    /// Errors that occurred
    pub errors: Vec<BatchDecryptError>,
    /// Total number of items
    pub total_items: u32,
    /// Number of successful items
    pub successful_items: u32,
    /// Number of failed items
    pub failed_items: u32,
}

/// Result of batch decryption for a single item
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchDecryptResult {
    /// Item index
    pub index: u32,
    /// Decrypted data
    pub data: Vec<u8>,
    /// Algorithm used
    pub algorithm: String,
    /// Key ID used
    pub key_id: String,
    /// Timestamp of decryption
    pub timestamp: chrono::DateTime<chrono::Utc>,
    /// Whether decryption was successful
    pub success: bool,
    /// Error message if failed
    pub error: Option<String>,
}

/// Error in batch decryption
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchDecryptError {
    /// Item index
    pub index: u32,
    /// Error message
    pub error: String,
}
