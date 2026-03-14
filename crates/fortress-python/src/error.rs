//! Error handling for Python bindings

use pyo3::prelude::*;
use fortress_core::error::FortressError;

/// Python wrapper for FortressError
#[pyclass]
pub struct FortressError {
    error: ErrorWrapper,
}

enum ErrorWrapper {
    Encryption(String),
    KeyManagement(String),
    Storage(String),
    Validation(String),
    Network(String),
    Config(String),
    Internal(String),
}

impl From<FortressError> for FortressError {
    fn from(error: FortressError) -> Self {
        let wrapper = match error {
            FortressError::encryption(msg) => ErrorWrapper::Encryption(msg),
            FortressError::key_management(msg) => ErrorWrapper::KeyManagement(msg),
            FortressError::storage(msg) => ErrorWrapper::Storage(msg),
            FortressError::validation(msg) => ErrorWrapper::Validation(msg),
            FortressError::network(msg) => ErrorWrapper::Network(msg),
            FortressError::config(msg) => ErrorWrapper::Config(msg),
            FortressError::internal(msg) => ErrorWrapper::Internal(msg),
        };
        Self { error: wrapper }
    }
}

#[pymethods]
impl FortressError {
    /// Get error message
    fn message(&self) -> String {
        match &self.error {
            ErrorWrapper::Encryption(msg) => msg.clone(),
            ErrorWrapper::KeyManagement(msg) => msg.clone(),
            ErrorWrapper::Storage(msg) => msg.clone(),
            ErrorWrapper::Validation(msg) => msg.clone(),
            ErrorWrapper::Network(msg) => msg.clone(),
            ErrorWrapper::Config(msg) => msg.clone(),
            ErrorWrapper::Internal(msg) => msg.clone(),
        }
    }

    /// Get error type
    fn error_type(&self) -> String {
        match &self.error {
            ErrorWrapper::Encryption(_) => "encryption".to_string(),
            ErrorWrapper::KeyManagement(_) => "key_management".to_string(),
            ErrorWrapper::Storage(_) => "storage".to_string(),
            ErrorWrapper::Validation(_) => "validation".to_string(),
            ErrorWrapper::Network(_) => "network".to_string(),
            ErrorWrapper::Config(_) => "config".to_string(),
            ErrorWrapper::Internal(_) => "internal".to_string(),
        }
    }

    /// Get string representation
    fn __str__(&self) -> String {
        self.message()
    }

    /// Get representation
    fn __repr__(&self) -> String {
        format!("FortressError(type: {}, message: {})", self.error_type(), self.message())
    }
}
