// Basic gRPC types for Fortress - simplified implementation without protobuf compilation
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// Database types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Database {
    pub id: String,
    pub name: String,
    pub description: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
    pub config: DatabaseConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseConfig {
    pub encryption_algorithm: String,
    pub key_rotation_interval_days: i32,
    pub enable_audit_logging: bool,
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
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateDatabaseRequest {
    pub name: String,
    pub description: String,
    pub config: Option<DatabaseConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseResponse {
    pub database: Database,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetDatabaseRequest {
    pub database_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListDatabasesRequest {
    pub page_size: i32,
    pub page_token: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListDatabasesResponse {
    pub databases: Vec<Database>,
    pub next_page_token: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeleteDatabaseRequest {
    pub database_id: String,
}

// Encryption types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptRequest {
    pub database_id: String,
    pub plaintext: Vec<u8>,
    pub key_id: Option<String>,
    pub metadata: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptResponse {
    pub ciphertext: Vec<u8>,
    pub key_id: String,
    pub encrypted_at: chrono::DateTime<chrono::Utc>,
    pub metadata: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecryptRequest {
    pub database_id: String,
    pub ciphertext: Vec<u8>,
    pub key_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecryptResponse {
    pub plaintext: Vec<u8>,
    pub decrypted_at: chrono::DateTime<chrono::Utc>,
    pub metadata: HashMap<String, String>,
}

// Health types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthResponse {
    pub status: i32, // 1 = Healthy, 2 = Degraded, 3 = Unhealthy
    pub version: String,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub components: Vec<ComponentHealth>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComponentHealth {
    pub name: String,
    pub status: i32,
    pub message: String,
}

// Metrics types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricsResponse {
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub counters: HashMap<String, f64>,
    pub gauges: HashMap<String, f64>,
    pub histograms: HashMap<String, HistogramData>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HistogramData {
    pub count: u64,
    pub sum: f64,
    pub buckets: Vec<f64>,
    pub bucket_counts: Vec<u64>,
}
