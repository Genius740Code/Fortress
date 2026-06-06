//! Validation utilities and constants
//!
//! Provides centralized validation rules and constants for input length
//! and other validation requirements.

pub const MAX_USERNAME_LENGTH: usize = 64;
pub const MAX_PASSWORD_LENGTH: usize = 128;
pub const MAX_SECRET_PATH_LENGTH: usize = 256;
pub const MAX_REQUEST_SIZE: usize = 1024 * 1024; // 1MB
pub const MAX_QUERY_DEPTH: usize = 10;
pub const MAX_QUERY_COMPLEXITY: usize = 1000;
