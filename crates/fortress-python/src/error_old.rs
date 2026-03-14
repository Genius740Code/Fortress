//! Error handling for Python bindings

use pyo3::prelude::*;
use pyo3::exceptions::{PyRuntimeError, PyValueError, PyIOError, PyKeyError};
use std::collections::HashMap;

use fortress_core::error::{FortressError, ErrorKind, StorageErrorCode};

/// Python wrapper for FortressError
#[pyclass]
pub struct FortressError {
    error: FortressError,
}

#[pymethods]
impl FortressError {
    /// Get error message
    fn message(&self) -> String {
        self.error.to_string()
    }

    /// Get error kind
    fn kind(&self) -> String {
        format!("{:?}", self.error.kind())
    }

    /// Get error code
    fn code(&self) -> String {
        self.error.code().to_string()
    }

    /// Get error details as dictionary
    fn details(&self) -> HashMap<String, String> {
        let mut details = HashMap::new();
        details.insert("message".to_string(), self.error.to_string());
        details.insert("kind".to_string(), format!("{:?}", self.error.kind()));
        details.insert("code".to_string(), self.error.code().to_string());
        
        if let Some(source) = self.error.source() {
            details.insert("source".to_string(), source.to_string());
        }
        
        details
    }

    /// Check if error is retryable
    fn is_retryable(&self) -> bool {
        self.error.is_retryable()
    }

    /// Check if error is temporary
    fn is_temporary(&self) -> bool {
        self.error.is_temporary()
    }

    fn __repr__(&self) -> String {
        format!("FortressError({})", self.error.to_string())
    }

    fn __str__(&self) -> String {
        self.error.to_string()
    }
}

/// Convert FortressError to Python exceptions
impl From<FortressError> for PyErr {
    fn from(error: FortressError) -> Self {
        match error.kind() {
            ErrorKind::Encryption => PyRuntimeError::new_err(error.to_string()),
            ErrorKind::KeyManagement => PyKeyError::new_err(error.to_string()),
            ErrorKind::Storage => match error.storage_error_code() {
                Some(StorageErrorCode::NotFound) => PyKeyError::new_err(error.to_string()),
                Some(StorageErrorCode::PermissionDenied) => PyValueError::new_err(error.to_string()),
                Some(StorageErrorCode::SerializationError) => PyValueError::new_err(error.to_string()),
                _ => PyIOError::new_err(error.to_string()),
            },
            ErrorKind::Configuration => PyValueError::new_err(error.to_string()),
            ErrorKind::Validation => PyValueError::new_err(error.to_string()),
            ErrorKind::Policy => PyValueError::new_err(error.to_string()),
            ErrorKind::Audit => PyRuntimeError::new_err(error.to_string()),
            ErrorKind::Tenant => PyValueError::new_err(error.to_string()),
            ErrorKind::Cluster => PyRuntimeError::new_err(error.to_string()),
            ErrorKind::Backup => PyRuntimeError::new_err(error.to_string()),
            ErrorKind::Hsm => PyRuntimeError::new_err(error.to_string()),
            ErrorKind::Network => PyRuntimeError::new_err(error.to_string()),
            ErrorKind::Authentication => PyValueError::new_err(error.to_string()),
            ErrorKind::Authorization => PyValueError::new_err(error.to_string()),
            ErrorKind::RateLimit => PyRuntimeError::new_err(error.to_string()),
            ErrorKind::Timeout => PyRuntimeError::new_err(error.to_string()),
            ErrorKind::Internal => PyRuntimeError::new_err(error.to_string()),
        }
    }
}

/// Error utilities
#[pyfunction]
fn is_retryable_error(error_message: String) -> bool {
    // Simple heuristic for retryable errors
    let retryable_patterns = [
        "timeout",
        "connection",
        "network",
        "temporary",
        "rate limit",
        "service unavailable",
    ];
    
    let message_lower = error_message.to_lowercase();
    retryable_patterns.iter().any(|pattern| message_lower.contains(pattern))
}

#[pyfunction]
fn is_temporary_error(error_message: String) -> bool {
    // Simple heuristic for temporary errors
    let temporary_patterns = [
        "timeout",
        "temporary",
        "service unavailable",
        "connection refused",
        "network unreachable",
    ];
    
    let message_lower = error_message.to_lowercase();
    temporary_patterns.iter().any(|pattern| message_lower.contains(pattern))
}

#[pyfunction]
fn get_error_kind(error_message: String) -> String {
    // Simple heuristic to determine error kind from message
    let message_lower = error_message.to_lowercase();
    
    if message_lower.contains("encryption") || message_lower.contains("decrypt") {
        "Encryption".to_string()
    } else if message_lower.contains("key") {
        "KeyManagement".to_string()
    } else if message_lower.contains("storage") || message_lower.contains("file") {
        "Storage".to_string()
    } else if message_lower.contains("config") {
        "Configuration".to_string()
    } else if message_lower.contains("policy") {
        "Policy".to_string()
    } else if message_lower.contains("audit") {
        "Audit".to_string()
    } else if message_lower.contains("tenant") {
        "Tenant".to_string()
    } else if message_lower.contains("cluster") {
        "Cluster".to_string()
    } else if message_lower.contains("backup") {
        "Backup".to_string()
    } else if message_lower.contains("hsm") {
        "Hsm".to_string()
    } else if message_lower.contains("network") || message_lower.contains("connection") {
        "Network".to_string()
    } else if message_lower.contains("auth") {
        "Authentication".to_string()
    } else if message_lower.contains("permission") {
        "Authorization".to_string()
    } else if message_lower.contains("rate limit") {
        "RateLimit".to_string()
    } else if message_lower.contains("timeout") {
        "Timeout".to_string()
    } else {
        "Internal".to_string()
    }
}

/// Create a custom Fortress error
#[pyfunction]
fn create_fortress_error(message: String, kind: String, code: Option<String>) -> FortressError {
    let error_kind = match kind.as_str() {
        "Encryption" => ErrorKind::Encryption,
        "KeyManagement" => ErrorKind::KeyManagement,
        "Storage" => ErrorKind::Storage,
        "Configuration" => ErrorKind::Configuration,
        "Validation" => ErrorKind::Validation,
        "Policy" => ErrorKind::Policy,
        "Audit" => ErrorKind::Audit,
        "Tenant" => ErrorKind::Tenant,
        "Cluster" => ErrorKind::Cluster,
        "Backup" => ErrorKind::Backup,
        "Hsm" => ErrorKind::Hsm,
        "Network" => ErrorKind::Network,
        "Authentication" => ErrorKind::Authentication,
        "Authorization" => ErrorKind::Authorization,
        "RateLimit" => ErrorKind::RateLimit,
        "Timeout" => ErrorKind::Timeout,
        "Internal" => ErrorKind::Internal,
        _ => ErrorKind::Internal,
    };

    let error_code = code.unwrap_or_else(|| "UNKNOWN".to_string());
    FortressError::new(error_kind, message, error_code)
}
