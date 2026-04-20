//! Server error types and handling
//!
//! This module provides comprehensive error handling for the Fortress server,
//! including HTTP status code mapping and error response formatting.

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;
use thiserror::Error;
use fortress_core::error::FortressError;

/// Server result type
pub type ServerResult<T> = Result<T, ServerError>;

/// Server error types
#[derive(Error, Debug)]
pub enum ServerError {
    /// Core Fortress error
    #[error("Fortress core error: {0}")]
    Core(#[from] FortressError),

    /// Authentication error
    #[error("Authentication failed: {0}")]
    Authentication(String),

    /// Authorization error
    #[error("Access denied: {0}")]
    Authorization(String),

    /// Validation error
    #[error("Validation failed: {0}")]
    Validation(String),

    /// Not found error
    #[error("Resource not found: {0}")]
    NotFound(String),

    /// Conflict error
    #[error("Resource conflict: {0}")]
    Conflict(String),

    /// Rate limit error
    #[error("Rate limit exceeded")]
    RateLimit,

    /// DDoS protection blocked
    #[error("Request blocked by DDoS protection")]
    DdosBlocked,

    /// Quota exceeded error
    #[error("Quota exceeded: {0}")]
    QuotaExceeded(String),

    /// Serialization error
    #[error("Serialization error: {0}")]
    Serialization(String),

    /// Network error
    #[error("Network error: {0}")]
    Network(String),

    /// Configuration error
    #[error("Configuration error: {0}")]
    Configuration(String),

    /// Internal server error
    #[error("Internal server error: {0}")]
    Internal(String),

    /// Service unavailable
    #[error("Service unavailable: {0}")]
    Unavailable(String),

    /// Timeout error
    #[error("Request timeout")]
    Timeout,

    /// Payload too large
    #[error("Payload too large: {0}")]
    PayloadTooLarge(String),
}

impl ServerError {
    /// Get the HTTP status code for this error
    pub fn status_code(&self) -> StatusCode {
        match self {
            ServerError::Authentication(_) => StatusCode::UNAUTHORIZED,
            ServerError::Authorization(_) => StatusCode::FORBIDDEN,
            ServerError::Validation(_) => StatusCode::BAD_REQUEST,
            ServerError::NotFound(_) => StatusCode::NOT_FOUND,
            ServerError::Conflict(_) => StatusCode::CONFLICT,
            ServerError::RateLimit => StatusCode::TOO_MANY_REQUESTS,
            ServerError::DdosBlocked => StatusCode::TOO_MANY_REQUESTS,
            ServerError::QuotaExceeded(_) => StatusCode::PAYLOAD_TOO_LARGE,
            ServerError::PayloadTooLarge(_) => StatusCode::PAYLOAD_TOO_LARGE,
            ServerError::Timeout => StatusCode::REQUEST_TIMEOUT,
            ServerError::Unavailable(_) => StatusCode::SERVICE_UNAVAILABLE,
            
            // Core Fortress errors need special handling
            ServerError::Core(core_err) => match core_err {
                FortressError::Encryption { .. } => StatusCode::INTERNAL_SERVER_ERROR,
                FortressError::KeyManagement { .. } => StatusCode::INTERNAL_SERVER_ERROR,
                FortressError::Storage { .. } => StatusCode::INTERNAL_SERVER_ERROR,
                FortressError::Configuration { .. } => StatusCode::INTERNAL_SERVER_ERROR,
                FortressError::Cluster { .. } => StatusCode::SERVICE_UNAVAILABLE,
                FortressError::QueryExecution { .. } => StatusCode::INTERNAL_SERVER_ERROR,
                FortressError::Validation { .. } => StatusCode::BAD_REQUEST,
                FortressError::Io { .. } => StatusCode::INTERNAL_SERVER_ERROR,
                FortressError::Network { .. } => StatusCode::INTERNAL_SERVER_ERROR,
                FortressError::Authentication { .. } => StatusCode::UNAUTHORIZED,
                _ => StatusCode::INTERNAL_SERVER_ERROR,
            },
            
            // All other errors are internal server errors
            ServerError::Serialization(_)
            | ServerError::Network(_)
            | ServerError::Configuration(_)
            | ServerError::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    /// Get the error code for this error
    pub fn error_code(&self) -> &'static str {
        match self {
            ServerError::Authentication(_) => "AUTHENTICATION_FAILED",
            ServerError::Authorization(_) => "ACCESS_DENIED",
            ServerError::Validation(_) => "VALIDATION_FAILED",
            ServerError::NotFound(_) => "NOT_FOUND",
            ServerError::Conflict(_) => "CONFLICT",
            ServerError::RateLimit => "RATE_LIMIT_EXCEEDED",
            ServerError::DdosBlocked => "DDOS_BLOCKED",
            ServerError::QuotaExceeded(_) => "QUOTA_EXCEEDED",
            ServerError::PayloadTooLarge(_) => "PAYLOAD_TOO_LARGE",
            ServerError::Timeout => "TIMEOUT",
            ServerError::Unavailable(_) => "SERVICE_UNAVAILABLE",
            ServerError::Serialization(_) => "SERIALIZATION_ERROR",
            ServerError::Network(_) => "NETWORK_ERROR",
            ServerError::Configuration(_) => "CONFIGURATION_ERROR",
            ServerError::Internal(_) => "INTERNAL_ERROR",
            ServerError::Core(_) => "CORE_ERROR",
        }
    }

    /// Check if this error should be logged as an error
    pub fn should_log_error(&self) -> bool {
        matches!(
            self,
            ServerError::Internal(_)
                | ServerError::Core(_)
                | ServerError::Network(_)
                | ServerError::Configuration(_)
                | ServerError::Unavailable(_)
        )
    }

    /// Check if this error is client-related (4xx)
    pub fn is_client_error(&self) -> bool {
        let status = self.status_code();
        status.is_client_error()
    }

    /// Check if this error is server-related (5xx)
    pub fn is_server_error(&self) -> bool {
        let status = self.status_code();
        status.is_server_error()
    }
}

impl IntoResponse for ServerError {
    fn into_response(self) -> Response {
        let status = self.status_code();
        let error_code = self.error_code();
        
        // Use sanitized error message to prevent information disclosure
        let message = crate::handlers::sanitize_error(&self);

        let error_response = json!({
            "error": {
                "code": error_code,
                "message": message,
                "timestamp": chrono::Utc::now().to_rfc3339(),
                "status": status.as_u16()
            }
        });

        tracing::error!(
            error_code = error_code,
            status = status.as_u16(),
            message = %self, // Log full error for debugging but sanitize for client
            "Server error occurred"
        );

        (status, Json(error_response)).into_response()
    }
}

/// Convenience functions for creating common errors
impl ServerError {
    /// Create an authentication error
    pub fn auth<S: Into<String>>(message: S) -> Self {
        Self::Authentication(message.into())
    }

    /// Create an authorization error
    pub fn access_denied<S: Into<String>>(message: S) -> Self {
        Self::Authorization(message.into())
    }

    /// Create a validation error
    pub fn validation<S: Into<String>>(message: S) -> Self {
        Self::Validation(message.into())
    }

    /// Create a not found error
    pub fn not_found<S: Into<String>>(resource: S) -> Self {
        Self::NotFound(resource.into())
    }

    /// Create a conflict error
    pub fn conflict<S: Into<String>>(message: S) -> Self {
        Self::Conflict(message.into())
    }

    /// Create an internal error
    pub fn internal<S: Into<String>>(message: S) -> Self {
        Self::Internal(message.into())
    }

    /// Create a configuration error
    pub fn config<S: Into<String>>(message: S) -> Self {
        Self::Configuration(message.into())
    }

    /// Create a network error
    pub fn network<S: Into<String>>(message: S) -> Self {
        Self::Network(message.into())
    }

    /// Create a serialization error
    pub fn serialization<S: Into<String>>(message: S) -> Self {
        Self::Serialization(message.into())
    }

    /// Create a quota exceeded error
    pub fn quota_exceeded<S: Into<String>>(message: S) -> Self {
        Self::QuotaExceeded(message.into())
    }

    /// Create a payload too large error
    pub fn payload_too_large<S: Into<String>>(message: S) -> Self {
        Self::PayloadTooLarge(message.into())
    }

    /// Create a service unavailable error
    pub fn unavailable<S: Into<String>>(message: S) -> Self {
        Self::Unavailable(message.into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_status_codes() {
        assert_eq!(ServerError::auth("test").status_code(), StatusCode::UNAUTHORIZED);
        assert_eq!(ServerError::access_denied("test").status_code(), StatusCode::FORBIDDEN);
        assert_eq!(ServerError::validation("test").status_code(), StatusCode::BAD_REQUEST);
        assert_eq!(ServerError::not_found("test").status_code(), StatusCode::NOT_FOUND);
        assert_eq!(ServerError::conflict("test").status_code(), StatusCode::CONFLICT);
        assert_eq!(ServerError::RateLimit.status_code(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(ServerError::Timeout.status_code(), StatusCode::REQUEST_TIMEOUT);
        assert_eq!(ServerError::internal("test").status_code(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[test]
    fn test_error_codes() {
        assert_eq!(ServerError::auth("test").error_code(), "AUTHENTICATION_FAILED");
        assert_eq!(ServerError::access_denied("test").error_code(), "ACCESS_DENIED");
        assert_eq!(ServerError::validation("test").error_code(), "VALIDATION_FAILED");
        assert_eq!(ServerError::not_found("test").error_code(), "NOT_FOUND");
        assert_eq!(ServerError::internal("test").error_code(), "INTERNAL_ERROR");
    }

    #[test]
    fn test_error_classification() {
        assert!(ServerError::auth("test").is_client_error());
        assert!(ServerError::validation("test").is_client_error());
        assert!(ServerError::not_found("test").is_client_error());
        
        assert!(ServerError::internal("test").is_server_error());
        assert!(ServerError::network("test").is_server_error());
        assert!(ServerError::config("test").is_server_error());
    }

    #[test]
    fn test_error_logging() {
        assert!(ServerError::internal("test").should_log_error());
        assert!(ServerError::network("test").should_log_error());
        assert!(ServerError::config("test").should_log_error());
        
        assert!(!ServerError::auth("test").should_log_error());
        assert!(!ServerError::validation("test").should_log_error());
        assert!(!ServerError::not_found("test").should_log_error());
    }
}
