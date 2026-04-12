//! Common types for secret engines

use chrono::{DateTime, Utc, Duration};
use serde::{Serialize, Deserialize};
use std::collections::HashMap;

/// Secret data structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Secret {
    pub data: serde_json::Value,
    pub metadata: SecretMetadata,
    pub lease_id: Option<String>,
    pub created_time: DateTime<Utc>,
    pub updated_time: DateTime<Utc>,
    pub version: u64,
}

/// Secret metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretMetadata {
    pub created_by: String,
    pub ttl: Option<Duration>,
    pub max_versions: Option<u64>,
    pub cas_required: bool,
    pub custom_metadata: HashMap<String, String>,
}

/// Request context for secret operations
#[derive(Debug, Clone)]
pub struct Context {
    pub token: crate::token::TokenInfo,
    pub request_path: String,
    pub operation: String,
    pub parameters: HashMap<String, serde_json::Value>,
    pub client_ip: Option<String>,
    pub user_agent: Option<String>,
    pub request_time: DateTime<Utc>,
}

/// Engine capabilities
#[derive(Debug, Clone)]
pub struct EngineCapabilities {
    pub supports_lease: bool,
    pub supports_rotation: bool,
    pub supports_dynamic_secrets: bool,
    pub supports_signing: bool,
    pub supports_encryption: bool,
    pub supported_operations: Vec<String>,
}

/// Engine configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EngineConfig {
    pub name: String,
    pub version: String,
    pub enabled: bool,
    pub mount_path: String,
    pub description: Option<String>,
    pub config: serde_json::Value,
}

/// Lease information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LeaseInfo {
    pub lease_id: String,
    pub renewable: bool,
    pub ttl: Duration,
    pub created_time: DateTime<Utc>,
    pub expires_time: DateTime<Utc>,
}

impl Default for SecretMetadata {
    fn default() -> Self {
        Self {
            created_by: "system".to_string(),
            ttl: None,
            max_versions: Some(10),
            cas_required: false,
            custom_metadata: HashMap::new(),
        }
    }
}

impl Default for EngineCapabilities {
    fn default() -> Self {
        Self {
            supports_lease: false,
            supports_rotation: false,
            supports_dynamic_secrets: false,
            supports_signing: false,
            supports_encryption: false,
            supported_operations: vec!["read".to_string(), "write".to_string(), "delete".to_string()],
        }
    }
}
