//! Error types for Fortress operations
//!
//! This module defines comprehensive error types for all Fortress operations,
//! with a focus on security and clarity.

use std::fmt;
use thiserror::Error;

/// Result type alias for Fortress operations
pub type Result<T> = std::result::Result<T, FortressError>;

/// Main error type for Fortress operations
///
/// This enum represents all possible errors that can occur during Fortress operations.
/// Each variant provides specific context about the error and its cause.
#[derive(Error, Debug, Clone)]
pub enum FortressError {
    /// Encryption-related errors
    #[error("Encryption error: {message}")]
    Encryption {
        /// Error message
        message: String,
        /// Algorithm that caused the error
        algorithm: String,
        /// Error code for programmatic handling
        code: EncryptionErrorCode,
    },

    /// Key management errors
    #[error("Key management error: {message}")]
    KeyManagement {
        /// Error message
        message: String,
        /// Key ID if applicable
        key_id: Option<String>,
        /// Error code for programmatic handling
        code: KeyErrorCode,
    },

    /// Storage-related errors
    #[error("Storage error: {message}")]
    Storage {
        /// Error message
        message: String,
        /// Backend that caused the error
        backend: String,
        /// Error code for programmatic handling
        code: StorageErrorCode,
    },

    /// Configuration errors
    #[error("Configuration error: {message}")]
    Configuration {
        /// Error message
        message: String,
        /// Configuration field that caused the error
        field: Option<String>,
        /// Error code for programmatic handling
        code: ConfigurationErrorCode,
    },

    /// Query execution errors
    #[error("Query execution error: {message}")]
    QueryExecution {
        /// Error message
        message: String,
        /// Query that caused the error (if available)
        query: Option<String>,
        /// Error code for programmatic handling
        code: QueryErrorCode,
    },

    /// Validation errors
    #[error("Validation error: {message}")]
    Validation {
        /// Error message
        message: String,
        /// Field that failed validation
        field: Option<String>,
        /// Value that failed validation
        value: Option<String>,
    },

    /// I/O errors
    #[error("I/O error: {message}")]
    Io {
        /// Error message
        message: String,
        /// Path that caused the error (if applicable)
        path: Option<String>,
    },

    /// Network errors
    #[error("Network error: {message}")]
    Network {
        /// Error message
        message: String,
        /// Host or endpoint that caused the error
        endpoint: Option<String>,
    },

    /// Authentication/authorization errors
    #[error("Authentication error: {message}")]
    Authentication {
        /// Error message
        message: String,
        /// User or service that failed authentication
        principal: Option<String>,
    },

    /// Rate limiting errors
    #[error("Rate limit exceeded: {message}")]
    RateLimit {
        /// Error message
        message: String,
        /// Current rate limit
        current_limit: Option<u32>,
        /// Time until reset (in seconds)
        reset_time: Option<u64>,
    },

    /// Internal errors
    #[error("Internal error: {message}")]
    Internal {
        /// Error message
        message: String,
        /// Internal error code
        code: String,
    },

    /// Policy and authorization errors
    #[error("Policy error: {0}")]
    PolicyError(String),
}

/// Encryption error codes
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum EncryptionErrorCode {
    /// Invalid key length
    #[error("Invalid key length")]
    InvalidKeyLength,
    
    /// Invalid nonce length
    #[error("Invalid nonce length")]
    InvalidNonceLength,
    
    /// Authentication failed (tampered data)
    #[error("Authentication failed")]
    AuthenticationFailed,
    
    /// Algorithm not supported
    #[error("Algorithm not supported")]
    AlgorithmNotSupported,
    
    /// Buffer too small
    #[error("Buffer too small")]
    BufferTooSmall,
    
    /// Encryption operation failed
    #[error("Encryption failed")]
    EncryptionFailed,
    
    /// Decryption operation failed
    #[error("Decryption failed")]
    DecryptionFailed,
}

/// Key management error codes
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum KeyErrorCode {
    /// Key not found
    #[error("Key not found")]
    KeyNotFound,
    
    /// Key already exists
    #[error("Key already exists")]
    KeyAlreadyExists,
    
    /// Key rotation failed
    #[error("Key rotation failed")]
    RotationFailed,
    
    /// Key derivation failed
    #[error("Key derivation failed")]
    DerivationFailed,
    
    /// Key is expired
    #[error("Key is expired")]
    KeyExpired,
    
    /// Key is not yet valid
    #[error("Key is not yet valid")]
    KeyNotYetValid,
    
    /// Invalid key format
    #[error("Invalid key format")]
    InvalidKeyFormat,
    
    /// Key access denied
    #[error("Key access denied")]
    AccessDenied,
}

/// Storage error codes
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum StorageErrorCode {
    /// Connection failed
    #[error("Connection failed")]
    ConnectionFailed,
    
    /// Item not found
    #[error("Item not found")]
    NotFound,
    
    /// Item already exists
    #[error("Item already exists")]
    AlreadyExists,
    
    /// Permission denied
    #[error("Permission denied")]
    PermissionDenied,
    
    /// Quota exceeded
    #[error("Quota exceeded")]
    QuotaExceeded,
    
    /// Backend not available
    #[error("Backend not available")]
    BackendNotAvailable,
    
    /// Invalid operation
    #[error("Invalid operation")]
    InvalidOperation,
    
    /// Corrupted data
    #[error("Corrupted data")]
    CorruptedData,
}

/// Configuration error codes
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum ConfigurationErrorCode {
    /// Invalid configuration format
    #[error("Invalid configuration format")]
    InvalidFormat,
    
    /// Missing required field
    #[error("Missing required field")]
    MissingField,
    
    /// Invalid value for field
    #[error("Invalid value")]
    InvalidValue,
    
    /// Configuration file not found
    #[error("Configuration file not found")]
    FileNotFound,
    
    /// Permission denied for configuration file
    #[error("Configuration file access denied")]
    AccessDenied,
    
    /// Circular dependency in configuration
    #[error("Circular dependency")]
    CircularDependency,
}

/// Query error codes
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum QueryErrorCode {
    /// Invalid SQL syntax
    #[error("Invalid SQL syntax")]
    InvalidSyntax,
    
    /// Table not found
    #[error("Table not found")]
    TableNotFound,
    
    /// Column not found
    #[error("Column not found")]
    ColumnNotFound,
    
    /// Invalid parameter
    #[error("Invalid parameter")]
    InvalidParameter,
    
    /// Query timeout
    #[error("Query timeout")]
    Timeout,
    
    /// Query cancelled
    #[error("Query cancelled")]
    Cancelled,
    
    /// Insufficient permissions
    #[error("Insufficient permissions")]
    InsufficientPermissions,
}

impl FortressError {
    /// Create a new encryption error
    pub fn encryption<S: Into<String>>(
        message: S,
        algorithm: S,
        code: EncryptionErrorCode,
    ) -> Self {
        Self::Encryption {
            message: message.into(),
            algorithm: algorithm.into(),
            code,
        }
    }

    /// Create a new key management error
    pub fn key_management<S: Into<String>>(
        message: S,
        key_id: Option<String>,
        code: KeyErrorCode,
    ) -> Self {
        Self::KeyManagement {
            message: message.into(),
            key_id,
            code,
        }
    }

    /// Create a new storage error
    pub fn storage<S: Into<String>>(
        message: S,
        backend: S,
        code: StorageErrorCode,
    ) -> Self {
        Self::Storage {
            message: message.into(),
            backend: backend.into(),
            code,
        }
    }

    /// Create a new configuration error
    pub fn configuration<S: Into<String>>(
        message: S,
        field: Option<String>,
        code: ConfigurationErrorCode,
    ) -> Self {
        Self::Configuration {
            message: message.into(),
            field,
            code,
        }
    }

    /// Create a new query execution error
    pub fn query_execution<S: Into<String>>(
        message: S,
        query: Option<String>,
        code: QueryErrorCode,
    ) -> Self {
        Self::QueryExecution {
            message: message.into(),
            query,
            code,
        }
    }

    /// Create a new validation error
    pub fn validation<S: Into<String>>(
        message: S,
        field: Option<String>,
        value: Option<String>,
    ) -> Self {
        Self::Validation {
            message: message.into(),
            field,
            value,
        }
    }

    /// Create a new I/O error
    pub fn io<S: Into<String>>(message: S, path: Option<String>) -> Self {
        Self::Io {
            message: message.into(),
            path,
        }
    }

    /// Create a new network error
    pub fn network<S: Into<String>>(message: S, endpoint: Option<String>) -> Self {
        Self::Network {
            message: message.into(),
            endpoint,
        }
    }

    /// Create a new authentication error
    pub fn authentication<S: Into<String>>(message: S, principal: Option<String>) -> Self {
        Self::Authentication {
            message: message.into(),
            principal,
        }
    }

    /// Create a new rate limit error
    pub fn rate_limit<S: Into<String>>(
        message: S,
        current_limit: Option<u32>,
        reset_time: Option<u64>,
    ) -> Self {
        Self::RateLimit {
            message: message.into(),
            current_limit,
            reset_time,
        }
    }

    /// Create a new internal error
    pub fn internal<S: Into<String>>(message: S, code: S) -> Self {
        Self::Internal {
            message: message.into(),
            code: code.into(),
        }
    }

    /// Check if this error is retryable
    pub fn is_retryable(&self) -> bool {
        match self {
            Self::Network { .. } | Self::Storage { code: StorageErrorCode::ConnectionFailed, .. } => {
                true
            }
            Self::RateLimit { .. } => true,
            Self::Io { .. } => true,
            _ => false,
        }
    }

    /// Check if this error is a security-related error
    pub fn is_security_error(&self) -> bool {
        matches!(
            self,
            Self::Encryption { .. }
                | Self::KeyManagement { .. }
                | Self::Authentication { .. }
        )
    }

    /// Get the error category for logging/metrics
    pub fn category(&self) -> &'static str {
        match self {
            Self::Encryption { .. } => "encryption",
            Self::KeyManagement { .. } => "key_management",
            Self::Storage { .. } => "storage",
            Self::Configuration { .. } => "configuration",
            Self::QueryExecution { .. } => "query",
            Self::Validation { .. } => "validation",
            Self::Io { .. } => "io",
            Self::Network { .. } => "network",
            Self::Authentication { .. } => "authentication",
            Self::RateLimit { .. } => "rate_limit",
            Self::Internal { .. } => "internal",
            Self::PolicyError(_) => "policy",
        }
    }
}

// Implement conversions from standard error types
impl From<std::io::Error> for FortressError {
    fn from(err: std::io::Error) -> Self {
        Self::io(err.to_string(), None)
    }
}

impl From<serde_json::Error> for FortressError {
    fn from(err: serde_json::Error) -> Self {
        Self::configuration(
            format!("JSON serialization error: {}", err),
            None,
            ConfigurationErrorCode::InvalidFormat,
        )
    }
}

impl From<toml::de::Error> for FortressError {
    fn from(err: toml::de::Error) -> Self {
        Self::configuration(
            format!("TOML parsing error: {}", err),
            None,
            ConfigurationErrorCode::InvalidFormat,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_creation() {
        let err = FortressError::encryption(
            "Invalid key",
            "AEGIS-256",
            EncryptionErrorCode::InvalidKeyLength,
        );

        assert!(matches!(err, FortressError::Encryption { .. }));
        assert_eq!(err.category(), "encryption");
        assert!(!err.is_retryable());
        assert!(err.is_security_error());
    }

    #[test]
    fn test_retryable_errors() {
        let network_err = FortressError::network("Connection failed", Some("api.example.com".to_string()));
        assert!(network_err.is_retryable());

        let encryption_err = FortressError::encryption(
            "Failed",
            "AES",
            EncryptionErrorCode::EncryptionFailed,
        );
        assert!(!encryption_err.is_retryable());
    }

    #[test]
    fn test_security_errors() {
        let auth_err = FortressError::authentication("Invalid token", Some("user123".to_string()));
        assert!(auth_err.is_security_error());

        let io_err = FortressError::io("File not found", Some("/path/to/file".to_string()));
        assert!(!io_err.is_security_error());
    }

    #[test]
    fn test_error_categories() {
        let storage_err = FortressError::storage(
            "Not found",
            "local",
            StorageErrorCode::NotFound,
        );
        assert_eq!(storage_err.category(), "storage");

        let config_err = FortressError::configuration(
            "Missing field",
            Some("port".to_string()),
            ConfigurationErrorCode::MissingField,
        );
        assert_eq!(config_err.category(), "configuration");
    }

    #[test]
    fn test_error_display() {
        let err = FortressError::validation(
            "Value too long",
            Some("username".to_string()),
            Some("very_long_username".to_string()),
        );

        let display = format!("{}", err);
        assert!(display.contains("Validation error"));
        assert!(display.contains("Value too long"));
    }
}
