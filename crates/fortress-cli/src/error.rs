use thiserror::Error;
use serde::{Serialize, Deserialize};
use std::fmt;

#[derive(Error, Debug, Serialize, Deserialize)]
#[serde(tag = "error_type")]
pub enum FortressError {
    #[error("Encryption failed: {reason}")]
    EncryptionError {
        reason: String,
        #[serde(skip)]**License**: [![License: MIT](https://img.shields.io/badge/License-MIT--1.0-blue.svg)](https://opensource.org/licenses/MIT)
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
        #[serde(skip)]
        suggestion: Option<String>,
        error_code: String,
        help_text: String,
        related_docs: Vec<String>,
    },
    
    #[error("Database connection failed: {database}@{host}:{port}")]
    DatabaseError {
        database: String,
        host: String,
        port: u16,
        #[serde(skip)]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
        troubleshooting_steps: Vec<String>,
        error_code: String,
        help_text: String,
    },
    
    #[error("Configuration error: {field}")]
    ConfigurationError {
        field: String,
        value: String,
        expected_format: String,
        suggestion: String,
        error_code: String,
        help_text: String,
    },
    
    #[error("Authentication failed: {reason}")]
    AuthenticationError {
        reason: String,
        error_code: String,
        help_text: String,
        #[serde(skip)]
        suggestion: Option<String>,
    },
    
    #[error("Key management error: {operation}")]
    KeyError {
        operation: String,
        key_id: Option<String>,
        error_code: String,
        help_text: String,
        #[serde(skip)]
        suggestion: Option<String>,
    },
    
    #[error("Network error: {operation}")]
    NetworkError {
        operation: String,
        url: Option<String>,
        error_code: String,
        help_text: String,
        #[serde(skip)]
        suggestion: Option<String>,
    },
    
    #[error("Plugin error: {plugin_name}")]
    PluginError {
        plugin_name: String,
        operation: String,
        error_code: String,
        help_text: String,
        #[serde(skip)]
        suggestion: Option<String>,
    },
    
    #[error("Compliance error: {framework}")]
    ComplianceError {
        framework: String,
        requirement: String,
        error_code: String,
        help_text: String,
        #[serde(skip)]
        suggestion: Option<String>,
    },
    
    #[error("Cluster error: {operation}")]
    ClusterError {
        operation: String,
        node_id: Option<String>,
        error_code: String,
        help_text: String,
        #[serde(skip)]
        suggestion: Option<String>,
    },
    
    #[error("I/O error: {0}")]
    IoError(String),
    
    #[error("Validation error: {field}")]
    ValidationError {
        field: String,
        value: String,
        constraint: String,
        error_code: String,
        help_text: String,
    },
    
    #[error("Permission denied: {resource}")]
    PermissionError {
        resource: String,
        operation: String,
        error_code: String,
        help_text: String,
    },
    
    #[error("Resource not found: {resource_type} '{resource_id}'")]
    NotFoundError {
        resource_type: String,
        resource_id: String,
        error_code: String,
        help_text: String,
    },
    
    #[error("Operation timeout: {operation}")]
    TimeoutError {
        operation: String,
        timeout_seconds: u64,
        error_code: String,
        help_text: String,
    },
    
    #[error("Rate limit exceeded: {operation}")]
    RateLimitError {
        operation: String,
        limit: u32,
        window_seconds: u32,
        error_code: String,
        help_text: String,
    },
    
    #[error("Internal server error: {message}")]
    InternalError {
        message: String,
        error_code: String,
        help_text: String,
    },
}

impl FortressError {
    pub fn with_suggestion(mut self, suggestion: impl Into<String>) -> Self {
        match &mut self {
            FortressError::EncryptionError { suggestion: s, .. } => {
                *s = Some(suggestion.into());
            }
            FortressError::AuthenticationError { suggestion: s, .. } => {
                *s = Some(suggestion.into());
            }
            FortressError::KeyError { suggestion: s, .. } => {
                *s = Some(suggestion.into());
            }
            FortressError::NetworkError { suggestion: s, .. } => {
                *s = Some(suggestion.into());
            }
            FortressError::PluginError { suggestion: s, .. } => {
                *s = Some(suggestion.into());
            }
            FortressError::ComplianceError { suggestion: s, .. } => {
                *s = Some(suggestion.into());
            }
            FortressError::ClusterError { suggestion: s, .. } => {
                *s = Some(suggestion.into());
            }
            _ => {}
        }
        self
    }
    
    pub fn troubleshooting_steps(&self) -> Vec<String> {
        match self {
            FortressError::DatabaseError { troubleshooting_steps, .. } => troubleshooting_steps.clone(),
            FortressError::EncryptionError { suggestion: Some(s), .. } => vec![s.clone()],
            FortressError::AuthenticationError { suggestion: Some(s), .. } => vec![s.clone()],
            FortressError::KeyError { suggestion: Some(s), .. } => vec![s.clone()],
            FortressError::NetworkError { suggestion: Some(s), .. } => vec![s.clone()],
            FortressError::PluginError { suggestion: Some(s), .. } => vec![s.clone()],
            FortressError::ComplianceError { suggestion: Some(s), .. } => vec![s.clone()],
            FortressError::ClusterError { suggestion: Some(s), .. } => vec![s.clone()],
            FortressError::ConfigurationError { suggestion: s, .. } => vec![s.clone()],
            FortressError::ValidationError { help_text: h, .. } => vec![h.clone()],
            FortressError::PermissionError { help_text: h, .. } => vec![h.clone()],
            FortressError::NotFoundError { help_text: h, .. } => vec![h.clone()],
            FortressError::TimeoutError { help_text: h, .. } => vec![h.clone()],
            FortressError::RateLimitError { help_text: h, .. } => vec![h.clone()],
            FortressError::InternalError { help_text: h, .. } => vec![h.clone()],
            _ => vec![],
        }
    }
    
    pub fn error_code(&self) -> &str {
        match self {
            FortressError::EncryptionError { error_code, .. } => error_code,
            FortressError::DatabaseError { error_code, .. } => error_code,
            FortressError::ConfigurationError { error_code, .. } => error_code,
            FortressError::AuthenticationError { error_code, .. } => error_code,
            FortressError::KeyError { error_code, .. } => error_code,
            FortressError::NetworkError { error_code, .. } => error_code,
            FortressError::PluginError { error_code, .. } => error_code,
            FortressError::ComplianceError { error_code, .. } => error_code,
            FortressError::ClusterError { error_code, .. } => error_code,
            FortressError::ValidationError { error_code, .. } => error_code,
            FortressError::PermissionError { error_code, .. } => error_code,
            FortressError::NotFoundError { error_code, .. } => error_code,
            FortressError::TimeoutError { error_code, .. } => error_code,
            FortressError::RateLimitError { error_code, .. } => error_code,
            FortressError::InternalError { error_code, .. } => error_code,
            FortressError::IoError(_) => "IO001",
        }
    }
    
    pub fn help_text(&self) -> &str {
        match self {
            FortressError::EncryptionError { help_text, .. } => help_text,
            FortressError::DatabaseError { help_text, .. } => help_text,
            FortressError::ConfigurationError { help_text, .. } => help_text,
            FortressError::AuthenticationError { help_text, .. } => help_text,
            FortressError::KeyError { help_text, .. } => help_text,
            FortressError::NetworkError { help_text, .. } => help_text,
            FortressError::PluginError { help_text, .. } => help_text,
            FortressError::ComplianceError { help_text, .. } => help_text,
            FortressError::ClusterError { help_text, .. } => help_text,
            FortressError::ValidationError { help_text, .. } => help_text,
            FortressError::PermissionError { help_text, .. } => help_text,
            FortressError::NotFoundError { help_text, .. } => help_text,
            FortressError::TimeoutError { help_text, .. } => help_text,
            FortressError::RateLimitError { help_text, .. } => help_text,
            FortressError::InternalError { help_text, .. } => help_text,
            FortressError::IoError(_) => "An I/O operation failed. Check file permissions and disk space.",
        }
    }
    
    pub fn severity(&self) -> ErrorSeverity {
        match self {
            FortressError::EncryptionError { .. } => ErrorSeverity::High,
            FortressError::DatabaseError { .. } => ErrorSeverity::High,
            FortressError::ConfigurationError { .. } => ErrorSeverity::Medium,
            FortressError::AuthenticationError { .. } => ErrorSeverity::High,
            FortressError::KeyError { .. } => ErrorSeverity::High,
            FortressError::NetworkError { .. } => ErrorSeverity::Medium,
            FortressError::PluginError { .. } => ErrorSeverity::Medium,
            FortressError::ComplianceError { .. } => ErrorSeverity::High,
            FortressError::ClusterError { .. } => ErrorSeverity::High,
            FortressError::ValidationError { .. } => ErrorSeverity::Low,
            FortressError::PermissionError { .. } => ErrorSeverity::Medium,
            FortressError::NotFoundError { .. } => ErrorSeverity::Low,
            FortressError::TimeoutError { .. } => ErrorSeverity::Medium,
            FortressError::RateLimitError { .. } => ErrorSeverity::Low,
            FortressError::InternalError { .. } => ErrorSeverity::High,
            FortressError::IoError(_) => ErrorSeverity::Medium,
        }
    }
    
    pub fn is_recoverable(&self) -> bool {
        match self {
            FortressError::ValidationError { .. } => true,
            FortressError::ConfigurationError { .. } => true,
            FortressError::NotFoundError { .. } => true,
            FortressError::TimeoutError { .. } => true,
            FortressError::RateLimitError { .. } => true,
            FortressError::PermissionError { .. } => true,
            FortressError::NetworkError { .. } => true,
            FortressError::IoError(_) => true,
            _ => false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ErrorSeverity {
    Low,
    Medium,
    High,
    Critical,
}

impl fmt::Display for ErrorSeverity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ErrorSeverity::Low => write!(f, "🟡 Low"),
            ErrorSeverity::Medium => write!(f, "🟠 Medium"),
            ErrorSeverity::High => write!(f, "🔴 High"),
            ErrorSeverity::Critical => write!(f, "🔴 Critical"),
        }
    }
}

// Error constructors with helpful defaults
impl FortressError {
    pub fn encryption_failed(reason: impl Into<String>) -> Self {
        Self::EncryptionError {
            reason: reason.into(),
            source: None,
            suggestion: None,
            error_code: "ENC001".to_string(),
            help_text: "Encryption operations require valid keys and properly formatted data".to_string(),
            related_docs: vec![
                "https://docs.fortress.security/encryption/overview".to_string(),
                "https://docs.fortress.security/troubleshooting/encryption".to_string(),
            ],
        }
    }
    
    pub fn database_connection_failed(database: &str, host: &str, port: u16) -> Self {
        Self::DatabaseError {
            database: database.to_string(),
            host: host.to_string(),
            port,
            source: None,
            troubleshooting_steps: vec![
                format!("1. Verify database server is running at {}:{}/{}", host, port, database),
                "2. Check network connectivity to the database server".to_string(),
                "3. Verify database credentials in configuration".to_string(),
                "4. Ensure database user has necessary permissions".to_string(),
                "5. Check if firewall is blocking the connection".to_string(),
            ],
            error_code: "DB001".to_string(),
            help_text: "Database connection failures are usually caused by incorrect configuration or network issues".to_string(),
        }
    }
    
    pub fn configuration_error(field: &str, value: &str, expected: &str) -> Self {
        Self::ConfigurationError {
            field: field.to_string(),
            value: value.to_string(),
            expected_format: expected.to_string(),
            suggestion: format!("Check the configuration file and ensure '{}' has a valid {}", field, expected),
            error_code: "CFG001".to_string(),
            help_text: "Configuration errors prevent Fortress from starting properly".to_string(),
        }
    }
    
    pub fn authentication_failed(reason: impl Into<String>) -> Self {
        Self::AuthenticationError {
            reason: reason.into(),
            error_code: "AUTH001".to_string(),
            help_text: "Authentication failed due to invalid credentials or expired tokens".to_string(),
            suggestion: None,
        }
    }
    
    pub fn key_operation_failed(operation: &str, key_id: Option<&str>) -> Self {
        Self::KeyError {
            operation: operation.to_string(),
            key_id: key_id.map(|id| id.to_string()),
            error_code: "KEY001".to_string(),
            help_text: "Key management operations require valid key IDs and proper permissions".to_string(),
            suggestion: None,
        }
    }
    
    pub fn network_operation_failed(operation: &str, url: Option<&str>) -> Self {
        Self::NetworkError {
            operation: operation.to_string(),
            url: url.map(|u| u.to_string()),
            error_code: "NET001".to_string(),
            help_text: "Network operations require internet connectivity and valid URLs".to_string(),
            suggestion: None,
        }
    }
    
    pub fn plugin_operation_failed(plugin_name: &str, operation: &str) -> Self {
        Self::PluginError {
            plugin_name: plugin_name.to_string(),
            operation: operation.to_string(),
            error_code: "PLUGIN001".to_string(),
            help_text: "Plugin operations require the plugin to be properly installed and configured".to_string(),
            suggestion: None,
        }
    }
    
    pub fn compliance_check_failed(framework: &str, requirement: &str) -> Self {
        Self::ComplianceError {
            framework: framework.to_string(),
            requirement: requirement.to_string(),
            error_code: "COMP001".to_string(),
            help_text: "Compliance checks failed. Review the requirements and update your configuration".to_string(),
            suggestion: None,
        }
    }
    
    pub fn cluster_operation_failed(operation: &str, node_id: Option<&str>) -> Self {
        Self::ClusterError {
            operation: operation.to_string(),
            node_id: node_id.map(|id| id.to_string()),
            error_code: "CLUSTER001".to_string(),
            help_text: "Cluster operations require all nodes to be properly configured and connected".to_string(),
            suggestion: None,
        }
    }
    
    pub fn validation_error(field: &str, value: &str, constraint: &str) -> Self {
        Self::ValidationError {
            field: field.to_string(),
            value: value.to_string(),
            constraint: constraint.to_string(),
            error_code: "VALID001".to_string(),
            help_text: format!("Field '{}' must satisfy: {}", field, constraint),
        }
    }
    
    pub fn permission_denied(resource: &str, operation: &str) -> Self {
        Self::PermissionError {
            resource: resource.to_string(),
            operation: operation.to_string(),
            error_code: "PERM001".to_string(),
            help_text: "You don't have permission to perform this operation on this resource".to_string(),
        }
    }
    
    pub fn not_found(resource_type: &str, resource_id: &str) -> Self {
        Self::NotFoundError {
            resource_type: resource_type.to_string(),
            resource_id: resource_id.to_string(),
            error_code: "NOTFOUND001".to_string(),
            help_text: format!("The requested {} '{}' does not exist", resource_type, resource_id),
        }
    }
    
    pub fn timeout(operation: &str, timeout_seconds: u64) -> Self {
        Self::TimeoutError {
            operation: operation.to_string(),
            timeout_seconds,
            error_code: "TIMEOUT001".to_string(),
            help_text: format!("Operation '{}' timed out after {} seconds", operation, timeout_seconds),
        }
    }
    
    pub fn rate_limit_exceeded(operation: &str, limit: u32, window_seconds: u32) -> Self {
        Self::RateLimitError {
            operation: operation.to_string(),
            limit,
            window_seconds,
            error_code: "RATE001".to_string(),
            help_text: format!("Rate limit exceeded for '{}'. Limit: {} per {} seconds", operation, limit, window_seconds),
        }
    }
    
    pub fn internal_error(message: impl Into<String>) -> Self {
        Self::InternalError {
            message: message.into(),
            error_code: "INTERNAL001".to_string(),
            help_text: "An internal error occurred. Please contact support if this persists".to_string(),
        }
    }
}

// Conversion from common error types
impl From<std::io::Error> for FortressError {
    fn from(err: std::io::Error) -> Self {
        FortressError::IoError(format!("I/O error: {}", err))
    }
}

impl From<serde_json::Error> for FortressError {
    fn from(err: serde_json::Error) -> Self {
        FortressError::ConfigurationError {
            field: "JSON".to_string(),
            value: "unknown".to_string(),
            expected_format: "valid JSON".to_string(),
            suggestion: "Check the JSON syntax and structure".to_string(),
            error_code: "JSON001".to_string(),
            help_text: format!("JSON parsing failed: {}", err),
        }
    }
}

impl From<toml::de::Error> for FortressError {
    fn from(err: toml::de::Error) -> Self {
        FortressError::ConfigurationError {
            field: "TOML".to_string(),
            value: "unknown".to_string(),
            expected_format: "valid TOML".to_string(),
            suggestion: "Check the TOML syntax and structure".to_string(),
            error_code: "TOML001".to_string(),
            help_text: format!("TOML parsing failed: {}", err),
        }
    }
}

impl From<reqwest::Error> for FortressError {
    fn from(err: reqwest::Error) -> Self {
        FortressError::NetworkError {
            operation: "HTTP request".to_string(),
            url: err.url().map(|u| u.to_string()),
            error_code: "HTTP001".to_string(),
            help_text: format!("HTTP request failed: {}", err),
            suggestion: None,
        }
    }
}
