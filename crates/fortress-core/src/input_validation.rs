//! Input Validation Module
//!
//! Provides comprehensive input validation for all API endpoints and user input processing.
//! This module prevents injection attacks and data corruption by validating all incoming data.

use crate::error::FortressError;
use regex::Regex;
use std::collections::HashSet;

/// Maximum allowed input lengths
const MAX_INPUT_LENGTH: usize = 10000;
const MAX_USERNAME_LENGTH: usize = 255;
const MAX_PASSWORD_LENGTH: usize = 1024;
const MAX_EMAIL_LENGTH: usize = 320;
const MAX_URL_LENGTH: usize = 2048;
const MAX_QUERY_LENGTH: usize = 4000;

/// Dangerous characters and patterns
const DANGEROUS_CHARS: &[char] = &[';', '-', '\'', '"', '\\', '|', '&', '<', '>', '$', '`'];
const SQL_INJECTION_PATTERNS: &[&str] = &[
    "union",
    "select",
    "insert",
    "update",
    "delete",
    "drop",
    "create",
    "alter",
    "exec",
    "execute",
    "sp_executesql",
    "xp_cmdshell",
    "cmdshell",
];

/// Valid characters for different input types
const USERNAME_ALLOWED_CHARS: &str =
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-.";
const EMAIL_ALLOWED_PATTERN: &str = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$";

lazy_static::lazy_static! {
    static ref EMAIL_REGEX: Regex = Regex::new(EMAIL_ALLOWED_PATTERN).unwrap();
    static ref UUID_REGEX: Regex = Regex::new(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$").unwrap();
    static ref ALPHANUMERIC_REGEX: Regex = Regex::new(r"^[a-zA-Z0-9]+$").unwrap();
}

/// Input validation result
#[derive(Debug, Clone)]
pub struct ValidationResult {
    pub is_valid: bool,
    pub sanitized_input: String,
    pub error_message: Option<String>,
}

impl ValidationResult {
    pub fn valid(input: String) -> Self {
        Self {
            is_valid: true,
            sanitized_input: input,
            error_message: None,
        }
    }

    pub fn invalid(error: String) -> Self {
        Self {
            is_valid: false,
            sanitized_input: String::new(),
            error_message: Some(error),
        }
    }
}

/// Comprehensive input validator
pub struct InputValidator {
    dangerous_patterns: HashSet<String>,
}

impl InputValidator {
    pub fn new() -> Self {
        let mut dangerous_patterns = HashSet::new();
        for pattern in SQL_INJECTION_PATTERNS {
            dangerous_patterns.insert(pattern.to_lowercase());
        }

        Self { dangerous_patterns }
    }

    /// Validate general user input
    pub fn validate_user_input(&self, input: &str) -> Result<String, FortressError> {
        // Check length
        if input.len() > MAX_INPUT_LENGTH {
            return Err(FortressError::validation(
                "Input too long",
                Some("max_length".to_string()),
                Some(MAX_INPUT_LENGTH.to_string()),
            ));
        }

        // Check for dangerous characters
        for char in input.chars() {
            if DANGEROUS_CHARS.contains(&char) {
                return Err(FortressError::validation(
                    "Invalid characters detected",
                    Some("dangerous_chars".to_string()),
                    None,
                ));
            }
        }

        // Check for SQL injection patterns
        let lower_input = input.to_lowercase();
        for pattern in &self.dangerous_patterns {
            if lower_input.contains(pattern) {
                return Err(FortressError::validation(
                    "Potential SQL injection detected",
                    Some("sql_injection".to_string()),
                    None,
                ));
            }
        }

        // Sanitize input by removing potentially dangerous characters
        let sanitized = input
            .chars()
            .filter(|c| !DANGEROUS_CHARS.contains(c))
            .collect();

        Ok(sanitized)
    }

    /// Validate username
    pub fn validate_username(&self, username: &str) -> Result<String, FortressError> {
        if username.len() > MAX_USERNAME_LENGTH {
            return Err(FortressError::validation(
                "Username too long",
                Some("max_length".to_string()),
                Some(MAX_USERNAME_LENGTH.to_string()),
            ));
        }

        if username.len() < 3 {
            return Err(FortressError::validation(
                "Username too short",
                Some("min_length".to_string()),
                Some("3".to_string()),
            ));
        }

        // Check allowed characters
        for char in username.chars() {
            if !USERNAME_ALLOWED_CHARS.contains(char) {
                return Err(FortressError::validation(
                    "Invalid characters in username",
                    Some("invalid_chars".to_string()),
                    None,
                ));
            }
        }

        // Check for dangerous patterns
        self.validate_user_input(username)?;

        Ok(username.to_string())
    }

    /// Validate email address
    pub fn validate_email(&self, email: &str) -> Result<String, FortressError> {
        if email.len() > MAX_EMAIL_LENGTH {
            return Err(FortressError::validation(
                "Email too long",
                Some("max_length".to_string()),
                Some(MAX_EMAIL_LENGTH.to_string()),
            ));
        }

        if !EMAIL_REGEX.is_match(email) {
            return Err(FortressError::validation(
                "Invalid email format",
                Some("invalid_format".to_string()),
                None,
            ));
        }

        Ok(email.to_string())
    }

    /// Validate password
    pub fn validate_password(&self, password: &str) -> Result<String, FortressError> {
        if password.len() > MAX_PASSWORD_LENGTH {
            return Err(FortressError::validation(
                "Password too long",
                Some("max_length".to_string()),
                Some(MAX_PASSWORD_LENGTH.to_string()),
            ));
        }

        if password.len() < 8 {
            return Err(FortressError::validation(
                "Password too short",
                Some("min_length".to_string()),
                Some("8".to_string()),
            ));
        }

        // Check for common weak passwords
        let weak_passwords = vec![
            "password",
            "123456",
            "12345678",
            "qwerty",
            "abc123",
            "password123",
            "admin",
            "root",
            "letmein",
        ];

        if weak_passwords.contains(&password.to_lowercase().as_str()) {
            return Err(FortressError::validation(
                "Password is too common",
                Some("weak_password".to_string()),
                None,
            ));
        }

        Ok(password.to_string())
    }

    /// Validate UUID
    pub fn validate_uuid(&self, uuid: &str) -> Result<String, FortressError> {
        if !UUID_REGEX.is_match(uuid) {
            return Err(FortressError::validation(
                "Invalid UUID format",
                Some("invalid_format".to_string()),
                None,
            ));
        }

        Ok(uuid.to_string())
    }

    /// Validate database query parameters
    pub fn validate_query_param(&self, param: &str) -> Result<String, FortressError> {
        if param.len() > MAX_QUERY_LENGTH {
            return Err(FortressError::validation(
                "Query parameter too long",
                Some("max_length".to_string()),
                Some(MAX_QUERY_LENGTH.to_string()),
            ));
        }

        // Check for SQL injection
        self.validate_user_input(param)?;

        // Additional query-specific validation
        if param.contains("/*") || param.contains("*/") {
            return Err(FortressError::validation(
                "Invalid query characters",
                Some("sql_comment".to_string()),
                None,
            ));
        }

        Ok(param.to_string())
    }

    /// Validate URL
    pub fn validate_url(&self, url: &str) -> Result<String, FortressError> {
        if url.len() > MAX_URL_LENGTH {
            return Err(FortressError::validation(
                "URL too long",
                Some("max_length".to_string()),
                Some(MAX_URL_LENGTH.to_string()),
            ));
        }

        // Basic URL validation
        if !url.starts_with("http://") && !url.starts_with("https://") {
            return Err(FortressError::validation(
                "Invalid URL protocol",
                Some("invalid_protocol".to_string()),
                None,
            ));
        }

        Ok(url.to_string())
    }

    /// Validate file path
    pub fn validate_file_path(&self, path: &str) -> Result<String, FortressError> {
        // Check for path traversal
        if path.contains("..") || path.contains("\\..") {
            return Err(FortressError::validation(
                "Path traversal detected",
                Some("path_traversal".to_string()),
                None,
            ));
        }

        // Check for absolute paths in sensitive areas
        let sensitive_paths = vec![
            "/etc",
            "/sys",
            "/proc",
            "/dev",
            "/root",
            "/var",
            "C:\\Windows",
            "C:\\Program Files",
            "C:\\Users",
        ];

        for sensitive_path in sensitive_paths {
            if path
                .to_lowercase()
                .starts_with(&sensitive_path.to_lowercase())
            {
                return Err(FortressError::validation(
                    "Access to sensitive path not allowed",
                    Some("sensitive_path".to_string()),
                    None,
                ));
            }
        }

        Ok(path.to_string())
    }

    /// Validate JSON input
    pub fn validate_json(&self, json_str: &str) -> Result<String, FortressError> {
        // Try to parse as JSON to ensure validity
        match serde_json::from_str::<serde_json::Value>(json_str) {
            Ok(_) => Ok(json_str.to_string()),
            Err(e) => Err(FortressError::validation(
                &format!("Invalid JSON: {}", e),
                Some("invalid_json".to_string()),
                None,
            )),
        }
    }

    /// Validate API key
    pub fn validate_api_key(&self, api_key: &str) -> Result<String, FortressError> {
        if api_key.len() < 16 || api_key.len() > 256 {
            return Err(FortressError::validation(
                "API key length invalid",
                Some("invalid_length".to_string()),
                None,
            ));
        }

        // Check for alphanumeric characters only
        if !ALPHANUMERIC_REGEX.is_match(api_key) {
            return Err(FortressError::validation(
                "API key contains invalid characters",
                Some("invalid_chars".to_string()),
                None,
            ));
        }

        Ok(api_key.to_string())
    }

    /// Validate pagination parameters
    pub fn validate_pagination(
        &self,
        page: u32,
        page_size: u32,
    ) -> Result<(u32, u32), FortressError> {
        if page == 0 {
            return Err(FortressError::validation(
                "Page number must be greater than 0",
                Some("invalid_page".to_string()),
                None,
            ));
        }

        if page_size == 0 || page_size > 1000 {
            return Err(FortressError::validation(
                "Page size must be between 1 and 1000",
                Some("invalid_page_size".to_string()),
                Some("1-1000".to_string()),
            ));
        }

        Ok((page, page_size))
    }

    /// Validate general string input
    pub fn validate_string(&self, input: &str, field_name: &str) -> Result<String, FortressError> {
        if input.is_empty() {
            return Err(FortressError::validation(
                &format!("{} cannot be empty", field_name),
                Some("empty_field".to_string()),
                None,
            ));
        }

        if input.len() > MAX_INPUT_LENGTH {
            return Err(FortressError::validation(
                &format!("{} is too long", field_name),
                Some("max_length".to_string()),
                Some(MAX_INPUT_LENGTH.to_string()),
            ));
        }

        // Check for dangerous characters and patterns
        self.validate_user_input(input)?;
        Ok(input.to_string())
    }

    /// Validate input length
    pub fn validate_length(
        &self,
        input: &str,
        min: usize,
        max: usize,
    ) -> Result<String, FortressError> {
        if input.len() < min {
            return Err(FortressError::validation(
                &format!("Input too short (minimum {} characters)", min),
                Some("min_length".to_string()),
                Some(min.to_string()),
            ));
        }

        if input.len() > max {
            return Err(FortressError::validation(
                &format!("Input too long (maximum {} characters)", max),
                Some("max_length".to_string()),
                Some(max.to_string()),
            ));
        }

        Ok(input.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_username() {
        let validator = InputValidator::new();

        // Valid username
        assert!(validator.validate_username("testuser123").is_ok());

        // Too short
        assert!(validator.validate_username("ab").is_err());

        // Too long
        let long_username = "a".repeat(256);
        assert!(validator.validate_username(&long_username).is_err());

        // Invalid characters
        assert!(validator.validate_username("test@user").is_err());
    }

    #[test]
    fn test_validate_email() {
        let validator = InputValidator::new();

        // Valid email
        assert!(validator.validate_email("test@example.com").is_ok());

        // Invalid format
        assert!(validator.validate_email("invalid-email").is_err());
    }

    #[test]
    fn test_validate_password() {
        let validator = InputValidator::new();

        // Valid password
        assert!(validator.validate_password("SecurePass123!").is_ok());

        // Too short
        assert!(validator.validate_password("short").is_err());

        // Weak password
        assert!(validator.validate_password("password").is_err());
    }

    #[test]
    fn test_sql_injection_detection() {
        let validator = InputValidator::new();

        // SQL injection attempts
        assert!(validator
            .validate_user_input("'; DROP TABLE users; --")
            .is_err());
        assert!(validator
            .validate_user_input("UNION SELECT * FROM users")
            .is_err());
        assert!(validator.validate_user_input("' OR '1'='1").is_err());
    }

    #[test]
    fn test_path_traversal_detection() {
        let validator = InputValidator::new();

        // Path traversal attempts
        assert!(validator.validate_file_path("../../../etc/passwd").is_err());
        assert!(validator
            .validate_file_path("..\\..\\windows\\system32")
            .is_err());
        assert!(validator.validate_file_path("/etc/passwd").is_err());
    }
}
