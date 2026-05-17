//! Server configuration management
//!
//! This module provides configuration structures for the Fortress server,
//! including network settings, security options, and feature flags.

use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::path::PathBuf;
use fortress_core::config::Config as CoreConfig;

/// Default server host
pub const DEFAULT_HOST: &str = "0.0.0.0";

/// Default server port
pub const DEFAULT_PORT: u16 = 8080;

/// Maximum request body size (default: 10MB)
pub const DEFAULT_MAX_BODY_SIZE: usize = 10 * 1024 * 1024;

/// Default request timeout in seconds
pub const DEFAULT_REQUEST_TIMEOUT: u64 = 30;

/// Default CORS origins
pub const DEFAULT_CORS_ORIGINS: &[&str] = &["*"];

/// Server configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    /// Network configuration
    pub network: NetworkConfig,
    
    /// Security configuration
    pub security: SecurityConfig,
    
    /// Core Fortress configuration
    pub core: CoreConfig,
    
    /// Feature flags
    pub features: FeatureFlags,
    
    /// Logging configuration
    pub logging: LoggingConfig,
    
    /// Metrics configuration
    pub metrics: MetricsConfig,
    
    /// Storage configuration
    pub storage: CoreConfig,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            network: NetworkConfig::default(),
            security: SecurityConfig::default(),
            core: CoreConfig::default(),
            features: FeatureFlags::default(),
            logging: LoggingConfig::default(),
            metrics: MetricsConfig::default(),
            storage: CoreConfig::default(),
        }
    }
}

/// Network configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    /// Server bind address
    pub host: String,
    
    /// Server port
    pub port: u16,
    
    /// Maximum request body size in bytes
    pub max_body_size: usize,
    
    /// Request timeout in seconds
    pub request_timeout: u64,
    
    /// Keep-alive timeout in seconds
    pub keep_alive: u64,
    
    /// Maximum concurrent connections
    pub max_connections: usize,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            host: DEFAULT_HOST.to_string(),
            port: DEFAULT_PORT,
            max_body_size: DEFAULT_MAX_BODY_SIZE,
            request_timeout: DEFAULT_REQUEST_TIMEOUT,
            keep_alive: 75,
            max_connections: 10000,
        }
    }
}

impl NetworkConfig {
    /// Get the full bind address
    pub fn bind_address(&self) -> std::result::Result<SocketAddr, std::net::AddrParseError> {
        format!("{}:{}", self.host, self.port).parse()
    }
}

/// Security configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityConfig {
    /// JWT secret for authentication
    pub jwt_secret: String,
    
    /// Token expiration time in seconds
    pub token_expiration: u64,
    
    /// CORS configuration
    pub cors: CorsConfig,
    
    /// Rate limiting
    pub rate_limit: RateLimitConfig,
    
    /// TLS configuration
    pub tls: Option<TlsConfig>,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            jwt_secret: generate_default_jwt_secret(),
            token_expiration: 3600, // 1 hour
            cors: CorsConfig::default(),
            rate_limit: RateLimitConfig::default(),
            tls: None,
        }
    }
}

/// CORS configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorsConfig {
    /// Allowed origins
    pub allowed_origins: Vec<String>,
    
    /// Allowed methods
    pub allowed_methods: Vec<String>,
    
    /// Allowed headers
    pub allowed_headers: Vec<String>,
    
    /// Allow credentials
    pub allow_credentials: bool,
}

impl Default for CorsConfig {
    fn default() -> Self {
        Self {
            allowed_origins: DEFAULT_CORS_ORIGINS.iter().map(|s| s.to_string()).collect(),
            allowed_methods: vec![
                "GET".to_string(),
                "POST".to_string(),
                "PUT".to_string(),
                "DELETE".to_string(),
                "PATCH".to_string(),
                "OPTIONS".to_string(),
            ],
            allowed_headers: vec![
                "Content-Type".to_string(),
                "Authorization".to_string(),
                "X-Requested-With".to_string(),
            ],
            allow_credentials: false,
        }
    }
}

/// Rate limiting configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitConfig {
    /// Enable rate limiting
    pub enabled: bool,
    
    /// Maximum requests per minute
    pub requests_per_minute: u32,
    
    /// Maximum requests per hour
    pub requests_per_hour: u32,
    
    /// Burst size
    pub burst_size: u32,
    
    /// Rate limiting algorithm
    #[serde(default = "default_rate_limit_algorithm")]
    pub algorithm: RateLimitAlgorithm,
    
    /// DDoS protection settings
    #[serde(default)]
    pub ddos_protection: DdosProtectionConfig,
}

/// Rate limiting algorithms
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum RateLimitAlgorithm {
    /// Token bucket algorithm (default)
    TokenBucket,
    /// Sliding window counter
    SlidingWindow,
    /// Fixed window counter
    FixedWindow,
    /// Leaky bucket
    LeakyBucket,
}

/// DDoS protection configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DdosProtectionConfig {
    /// Enable DDoS protection
    pub enabled: bool,
    
    /// Global requests per second threshold
    pub global_rps_threshold: Option<u32>,
    
    /// IP requests per second threshold
    pub ip_rps_threshold: Option<u32>,
    
    /// Auto-block threshold
    pub auto_block_threshold: Option<u32>,
    
    /// Block duration in seconds
    pub block_duration_seconds: u64,
    
    /// Reputation decay rate per hour
    pub reputation_decay_rate: u8,
}

fn default_rate_limit_algorithm() -> RateLimitAlgorithm {
    RateLimitAlgorithm::TokenBucket
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            requests_per_minute: 60,
            requests_per_hour: 1000,
            burst_size: 10,
            algorithm: RateLimitAlgorithm::TokenBucket,
            ddos_protection: DdosProtectionConfig::default(),
        }
    }
}

impl Default for DdosProtectionConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            global_rps_threshold: None,
            ip_rps_threshold: None,
            auto_block_threshold: None,
            block_duration_seconds: 300,
            reputation_decay_rate: 10,
        }
    }
}

/// TLS configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsConfig {
    /// Path to certificate file
    pub cert_path: PathBuf,
    
    /// Path to private key file
    pub key_path: PathBuf,
    
    /// CA certificate path (optional)
    pub ca_path: Option<PathBuf>,
}

/// OIDC configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OidcConfig {
    /// OIDC issuer URL
    pub issuer_url: String,
    
    /// Client ID
    pub client_id: String,
    
    /// Client secret
    pub client_secret: String,
    
    /// Redirect URI
    pub redirect_uri: String,
    
    /// Scopes to request
    pub scopes: Vec<String>,
    
    /// Enable PKCE
    pub enable_pkce: bool,
}

/// Feature flags
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeatureFlags {
    /// Enable authentication
    pub auth_enabled: bool,
    
    /// Enable audit logging
    pub audit_enabled: bool,
    
    /// Enable metrics collection
    pub metrics_enabled: bool,
    
    /// Enable health checks
    pub health_enabled: bool,
    
    /// Enable multi-tenant support
    pub multi_tenant: bool,
    
    /// Enable field-level encryption
    pub field_encryption: bool,
    
    /// Enable OIDC/OAuth2 authentication
    pub oidc_enabled: bool,
    
    /// OIDC provider configuration
    pub oidc_config: Option<OidcConfig>,
}

impl Default for FeatureFlags {
    fn default() -> Self {
        Self {
            auth_enabled: true,
            audit_enabled: true,
            metrics_enabled: true,
            health_enabled: true,
            multi_tenant: true,
            field_encryption: true,
            oidc_enabled: false,
            oidc_config: None,
        }
    }
}

/// Logging configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingConfig {
    /// Log level (trace, debug, info, warn, error)
    pub level: String,
    
    /// Enable JSON logging
    pub json_format: bool,
    
    /// Log file path (optional)
    pub file_path: Option<PathBuf>,
    
    /// Enable request logging
    pub log_requests: bool,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: "info".to_string(),
            json_format: false,
            file_path: None,
            log_requests: true,
        }
    }
}

/// Metrics configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricsConfig {
    /// Enable Prometheus metrics
    pub prometheus_enabled: bool,
    
    /// Metrics endpoint path
    pub metrics_path: String,
    
    /// Metrics collection interval in seconds
    pub collection_interval: u64,
}

impl Default for MetricsConfig {
    fn default() -> Self {
        Self {
            prometheus_enabled: true,
            metrics_path: "/metrics".to_string(),
            collection_interval: 60,
        }
    }
}

/// Generate a default JWT secret for development
fn generate_default_jwt_secret() -> String {
    use rand::Rng;
    let mut secret = String::with_capacity(64);
    let mut rng = rand::thread_rng();
    
    for _ in 0..64 {
        let chars = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        secret.push(chars[rng.gen_range(0..chars.len())] as char);
    }
    
    secret
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = ServerConfig::default();
        
        assert_eq!(config.network.host, DEFAULT_HOST);
        assert_eq!(config.network.port, DEFAULT_PORT);
        assert_eq!(config.security.token_expiration, 3600);
        assert!(config.features.auth_enabled);
        assert!(config.features.audit_enabled);
    }

    #[test]
    fn test_bind_address() {
        let network = NetworkConfig::default();
        let addr = network.bind_address().expect("Default bind address should be valid");
        assert_eq!(addr.port(), DEFAULT_PORT);
    }

    #[test]
    fn test_jwt_secret_generation() {
        let secret1 = generate_default_jwt_secret();
        let secret2 = generate_default_jwt_secret();
        
        assert_eq!(secret1.len(), 64);
        assert_eq!(secret2.len(), 64);
        assert_ne!(secret1, secret2);
    }
}
