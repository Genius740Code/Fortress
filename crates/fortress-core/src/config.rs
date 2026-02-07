//! Configuration management for Fortress
//!
//! This module provides configuration loading, validation, and management
//! capabilities for Fortress.

use crate::error::{FortressError, Result, ConfigurationErrorCode};
use crate::encryption::{EncryptionProfile, PerformanceProfile};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;

/// Main Fortress configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Database configuration
    pub database: DatabaseConfig,
    /// Encryption configuration
    pub encryption: EncryptionConfig,
    /// Storage configuration
    pub storage: StorageConfig,
    /// API configuration
    pub api: Option<ApiConfig>,
    /// Monitoring configuration
    pub monitoring: Option<MonitoringConfig>,
}

impl Config {
    /// Load configuration from a file
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let content = std::fs::read_to_string(&path)
            .map_err(|e| FortressError::configuration(
                format!("Failed to read config file: {}", e),
                None,
                ConfigurationErrorCode::FileNotFound,
            ))?;

        let config = if path.as_ref().extension().and_then(|s| s.to_str()) == Some("toml") {
            toml::from_str(&content)
                .map_err(|e| FortressError::configuration(
                    format!("Failed to parse TOML config: {}", e),
                    None,
                    ConfigurationErrorCode::InvalidFormat,
                ))?
        } else {
            serde_json::from_str(&content)
                .map_err(|e| FortressError::configuration(
                    format!("Failed to parse JSON config: {}", e),
                    None,
                    ConfigurationErrorCode::InvalidFormat,
                ))?
        };

        // Validate configuration
        config.validate()?;
        Ok(config)
    }

    /// Load configuration from environment variables
    pub fn from_env() -> Result<Self> {
        let mut config = Config::default();

        // Database configuration
        if let Ok(path) = std::env::var("FORTRESS_DATABASE_PATH") {
            config.database.path = path;
        }

        // Encryption configuration
        if let Ok(algorithm) = std::env::var("FORTRESS_DEFAULT_ALGORITHM") {
            config.encryption.default_algorithm = algorithm;
        }

        if let Ok(interval) = std::env::var("FORTRESS_KEY_ROTATION_INTERVAL") {
            config.encryption.key_rotation_interval = parse_duration(&interval)?;
        }

        // API configuration
        if let Ok(port) = std::env::var("FORTRESS_API_PORT") {
            let mut api_config = config.api.unwrap_or_default();
            api_config.rest_port = port.parse()
                .map_err(|_| FortressError::configuration(
                    "Invalid API port".to_string(),
                    Some("api.rest_port".to_string()),
                    ConfigurationErrorCode::InvalidValue,
                ))?;
            config.api = Some(api_config);
        }

        config.validate()?;
        Ok(config)
    }

    /// Validate the configuration
    pub fn validate(&self) -> Result<()> {
        // Validate database configuration
        if self.database.path.is_empty() {
            return Err(FortressError::configuration(
                "Database path cannot be empty",
                Some("database.path".to_string()),
                ConfigurationErrorCode::MissingField,
            ));
        }

        // Validate encryption configuration
        if !["aegis256", "chacha20poly1305", "aes256gcm"].contains(&self.encryption.default_algorithm.as_str()) {
            return Err(FortressError::configuration(
                format!("Invalid default algorithm: {}", self.encryption.default_algorithm),
                Some("encryption.default_algorithm".to_string()),
                ConfigurationErrorCode::InvalidValue,
            ));
        }

        // Validate encryption profiles
        for (name, profile) in &self.encryption.profiles {
            if name != &profile.name {
                return Err(FortressError::configuration(
                    format!("Profile name mismatch: {} != {}", name, profile.name),
                    Some(format!("encryption.profiles.{}", name)),
                    ConfigurationErrorCode::InvalidValue,
                ));
            }
        }

        Ok(())
    }

    /// Save configuration to a file
    pub fn save_to_file<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        let content = if path.as_ref().extension().and_then(|s| s.to_str()) == Some("toml") {
            toml::to_string_pretty(self)
                .map_err(|e| FortressError::configuration(
                    format!("Failed to serialize TOML: {}", e),
                    None,
                    ConfigurationErrorCode::InvalidFormat,
                ))?
        } else {
            serde_json::to_string_pretty(self)
                .map_err(|e| FortressError::configuration(
                    format!("Failed to serialize JSON: {}", e),
                    None,
                    ConfigurationErrorCode::InvalidFormat,
                ))?
        };

        std::fs::write(path, content)
            .map_err(|e| FortressError::configuration(
                format!("Failed to write config file: {}", e),
                None,
                ConfigurationErrorCode::AccessDenied,
            ))?;

        Ok(())
    }

    /// Create a new configuration builder
    pub fn builder() -> ConfigBuilder {
        ConfigBuilder::new()
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            database: DatabaseConfig::default(),
            encryption: EncryptionConfig::default(),
            storage: StorageConfig::default(),
            api: None,
            monitoring: None,
        }
    }
}

/// Configuration builder
#[derive(Debug, Default)]
pub struct ConfigBuilder {
    config: Config,
}

impl ConfigBuilder {
    /// Create a new configuration builder
    pub fn new() -> Self {
        Self::default()
    }

    /// Set database configuration
    pub fn database(mut self, database: DatabaseConfig) -> Self {
        self.config.database = database;
        self
    }

    /// Set encryption configuration
    pub fn encryption(mut self, encryption: EncryptionConfig) -> Self {
        self.config.encryption = encryption;
        self
    }

    /// Set storage configuration
    pub fn storage(mut self, storage: StorageConfig) -> Self {
        self.config.storage = storage;
        self
    }

    /// Set API configuration
    pub fn api(mut self, api: ApiConfig) -> Self {
        self.config.api = Some(api);
        self
    }

    /// Set monitoring configuration
    pub fn monitoring(mut self, monitoring: MonitoringConfig) -> Self {
        self.config.monitoring = Some(monitoring);
        self
    }

    /// Build the configuration
    pub fn build(self) -> Result<Config> {
        self.config.validate()?;
        Ok(self.config)
    }
}

/// Database configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseConfig {
    /// Database path
    pub path: String,
    /// Maximum database size in bytes
    pub max_size: Option<u64>,
    /// Cache size in bytes
    pub cache_size: Option<u64>,
    /// Whether to enable WAL mode
    pub enable_wal: bool,
    /// Connection pool size
    pub pool_size: u32,
}

impl Default for DatabaseConfig {
    fn default() -> Self {
        Self {
            path: "./fortress.db".to_string(),
            max_size: Some(1024 * 1024 * 1024), // 1GB
            cache_size: Some(64 * 1024 * 1024),  // 64MB
            enable_wal: true,
            pool_size: 10,
        }
    }
}

/// Encryption configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptionConfig {
    /// Default encryption algorithm
    pub default_algorithm: String,
    /// Key rotation interval
    #[serde(with = "duration_serde")]
    pub key_rotation_interval: std::time::Duration,
    /// Master key rotation interval
    #[serde(with = "duration_serde")]
    pub master_key_rotation_interval: std::time::Duration,
    /// Encryption profiles
    pub profiles: HashMap<String, EncryptionProfile>,
    /// Key derivation configuration
    pub key_derivation: KeyDerivationConfig,
}

impl Default for EncryptionConfig {
    fn default() -> Self {
        let mut profiles = HashMap::new();
        profiles.insert("lightning".to_string(), EncryptionProfile::lightning("lightning".to_string()));
        profiles.insert("balanced".to_string(), EncryptionProfile::balanced("balanced".to_string()));
        profiles.insert("fortress".to_string(), EncryptionProfile::fortress("fortress".to_string()));

        Self {
            default_algorithm: "aegis256".to_string(),
            key_rotation_interval: humantime::Duration::from(std::time::Duration::from_secs(23 * 3600)), // 23 hours
            master_key_rotation_interval: humantime::Duration::from(std::time::Duration::from_secs(90 * 24 * 3600)), // 90 days
            profiles,
            key_derivation: KeyDerivationConfig::default(),
        }
    }
}

/// Key derivation configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyDerivationConfig {
    /// Key derivation function
    pub kdf: String,
    /// Memory cost for Argon2
    pub memory_cost: Option<u32>,
    /// Number of iterations
    pub iterations: Option<u32>,
    /// Parallelism factor
    pub parallelism: Option<u32>,
    /// Salt length
    pub salt_length: Option<usize>,
}

impl Default for KeyDerivationConfig {
    fn default() -> Self {
        Self {
            kdf: "argon2id".to_string(),
            memory_cost: Some(65536), // 64 MiB
            iterations: Some(3),
            parallelism: Some(4),
            salt_length: Some(32),
        }
    }
}

/// Storage configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageConfig {
    /// Storage backend type
    pub backend: String,
    /// Base path for file system storage
    pub base_path: Option<String>,
    /// AWS S3 configuration
    pub s3: Option<S3Config>,
    /// Azure Blob configuration
    pub azure_blob: Option<AzureBlobConfig>,
    /// Google Cloud Storage configuration
    pub gcs: Option<GcsConfig>,
    /// Compression settings
    pub compression: bool,
    /// Checksum settings
    pub checksum: String,
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            backend: "filesystem".to_string(),
            base_path: Some("./data".to_string()),
            s3: None,
            azure_blob: None,
            gcs: None,
            compression: true,
            checksum: "sha256".to_string(),
        }
    }
}

/// AWS S3 configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct S3Config {
    /// Bucket name
    pub bucket: String,
    /// Region
    pub region: String,
    /// Access key ID
    pub access_key_id: Option<String>,
    /// Secret access key
    pub secret_access_key: Option<String>,
    /// Prefix for objects
    pub prefix: Option<String>,
    /// Endpoint URL (for S3-compatible services)
    pub endpoint_url: Option<String>,
}

/// Azure Blob configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AzureBlobConfig {
    /// Container name
    pub container: String,
    /// Account name
    pub account_name: String,
    /// Account key
    pub account_key: Option<String>,
    /// Connection string
    pub connection_string: Option<String>,
}

/// Google Cloud Storage configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GcsConfig {
    /// Bucket name
    pub bucket: String,
    /// Service account key file
    pub service_account_key: Option<String>,
    /// Prefix for objects
    pub prefix: Option<String>,
}

/// API configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiConfig {
    /// REST API port
    pub rest_port: u16,
    /// gRPC port
    pub grpc_port: u16,
    /// Enable CORS
    pub enable_cors: bool,
    /// Enable WebAssembly
    pub enable_wasm: bool,
    /// API rate limiting
    pub rate_limit: Option<RateLimitConfig>,
    /// Authentication configuration
    pub authentication: Option<AuthenticationConfig>,
}

impl Default for ApiConfig {
    fn default() -> Self {
        Self {
            rest_port: 8080,
            grpc_port: 50051,
            enable_cors: true,
            enable_wasm: true,
            rate_limit: None,
            authentication: None,
        }
    }
}

/// Rate limiting configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitConfig {
    /// Requests per minute
    pub requests_per_minute: u32,
    /// Burst size
    pub burst_size: u32,
}

/// Authentication configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticationConfig {
    /// Authentication type
    pub auth_type: String,
    /// JWT secret
    pub jwt_secret: Option<String>,
    /// API key header
    pub api_key_header: Option<String>,
    /// LDAP configuration
    pub ldap: Option<LdapConfig>,
}

/// LDAP configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LdapConfig {
    /// LDAP server URL
    pub url: String,
    /// Bind DN
    pub bind_dn: String,
    /// Bind password
    pub bind_password: String,
    /// User search base
    pub user_search_base: String,
    /// User search filter
    pub user_search_filter: String,
}

/// Monitoring configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonitoringConfig {
    /// Enable metrics
    pub enable_metrics: bool,
    /// Metrics port
    pub metrics_port: u16,
    /// Enable tracing
    pub enable_tracing: bool,
    /// Jaeger endpoint
    pub jaeger_endpoint: Option<String>,
    /// Log level
    pub log_level: String,
}

impl Default for MonitoringConfig {
    fn default() -> Self {
        Self {
            enable_metrics: true,
            metrics_port: 9090,
            enable_tracing: false,
            jaeger_endpoint: None,
            log_level: "info".to_string(),
        }
    }
}

/// Parse duration string (e.g., "23h", "7d", "30m")
fn parse_duration(s: &str) -> Result<std::time::Duration> {
    humantime::parse_duration(s)
        .map_err(|_| FortressError::configuration(
            format!("Invalid duration format: {}", s),
            None,
            ConfigurationErrorCode::InvalidValue,
        ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    #[test]
    fn test_default_config() {
        let config = Config::default();
        assert!(config.validate().is_ok());
        assert_eq!(config.encryption.default_algorithm, "aegis256");
        assert_eq!(config.database.path, "./fortress.db");
    }

    #[test]
    fn test_config_builder() {
        let config = Config::builder()
            .database(DatabaseConfig {
                path: "/tmp/test.db".to_string(),
                ..Default::default()
            })
            .encryption(EncryptionConfig {
                default_algorithm: "chacha20poly1305".to_string(),
                ..Default::default()
            })
            .build()
            .unwrap();

        assert_eq!(config.database.path, "/tmp/test.db");
        assert_eq!(config.encryption.default_algorithm, "chacha20poly1305");
    }

    #[test]
    fn test_config_from_env() {
        std::env::set_var("FORTRESS_DATABASE_PATH", "/tmp/env_test.db");
        std::env::set_var("FORTRESS_DEFAULT_ALGORITHM", "aes256gcm");
        std::env::set_var("FORTRESS_API_PORT", "9000");

        let config = Config::from_env().unwrap();
        assert_eq!(config.database.path, "/tmp/env_test.db");
        assert_eq!(config.encryption.default_algorithm, "aes256gcm");
        assert_eq!(config.api.unwrap().rest_port, 9000);

        std::env::remove_var("FORTRESS_DATABASE_PATH");
        std::env::remove_var("FORTRESS_DEFAULT_ALGORITHM");
        std::env::remove_var("FORTRESS_API_PORT");
    }

    #[test]
    fn test_config_validation() {
        let mut config = Config::default();
        
        // Valid config should pass
        assert!(config.validate().is_ok());

        // Invalid algorithm should fail
        config.encryption.default_algorithm = "invalid".to_string();
        assert!(config.validate().is_err());

        // Empty database path should fail
        config.encryption.default_algorithm = "aegis256".to_string();
        config.database.path = "".to_string();
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_config_serialization() {
        let config = Config::default();
        
        // Test JSON serialization
        let json = serde_json::to_string_pretty(&config).unwrap();
        let deserialized: Config = serde_json::from_str(&json).unwrap();
        assert_eq!(config.database.path, deserialized.database.path);

        // Test TOML serialization
        let toml = toml::to_string_pretty(&config).unwrap();
        let deserialized: Config = toml::from_str(&toml).unwrap();
        assert_eq!(config.database.path, deserialized.database.path);
    }

    #[test]
    fn test_config_file_operations() {
        let config = Config::default();
        
        // Test JSON file
        let temp_file = NamedTempFile::new().unwrap();
        config.save_to_file(temp_file.path()).unwrap();
        let loaded_config = Config::from_file(temp_file.path()).unwrap();
        assert_eq!(config.database.path, loaded_config.database.path);

        // Test TOML file
        let temp_file = NamedTempFile::with_suffix(".toml").unwrap();
        config.save_to_file(temp_file.path()).unwrap();
        let loaded_config = Config::from_file(temp_file.path()).unwrap();
        assert_eq!(config.database.path, loaded_config.database.path);
    }

    #[test]
    fn test_parse_duration() {
        assert_eq!(parse_duration("23h").unwrap(), std::time::Duration::from_secs(23 * 3600));
        assert_eq!(parse_duration("7d").unwrap(), std::time::Duration::from_secs(7 * 24 * 3600));
        assert_eq!(parse_duration("30m").unwrap(), std::time::Duration::from_secs(30 * 60));
        
        assert!(parse_duration("invalid").is_err());
    }

    #[test]
    fn test_encryption_profiles() {
        let config = Config::default();
        assert_eq!(config.encryption.profiles.len(), 3);
        
        let lightning = config.encryption.profiles.get("lightning").unwrap();
        assert_eq!(lightning.algorithm, "aegis256");
        assert_eq!(lightning.performance_profile, PerformanceProfile::Lightning);
        
        let balanced = config.encryption.profiles.get("balanced").unwrap();
        assert_eq!(balanced.algorithm, "chacha20poly1305");
        assert_eq!(balanced.performance_profile, PerformanceProfile::Balanced);
        
        let fortress = config.encryption.profiles.get("fortress").unwrap();
        assert_eq!(fortress.algorithm, "aes256gcm");
        assert_eq!(fortress.performance_profile, PerformanceProfile::Fortress);
    }
}
