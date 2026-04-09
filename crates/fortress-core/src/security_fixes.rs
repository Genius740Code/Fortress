//! Security Fixes Module
//! 
//! This module contains additional security improvements and fixes
//! for the Fortress security system.

use crate::error::{FortressError, Result};
use std::time::{SystemTime, UNIX_EPOCH};
use sha2::{Sha256, Digest};

/// Secure session ID generator using cryptographically secure random numbers
pub struct SecureSessionGenerator {
    /// Entropy source for session ID generation
    entropy_source: SessionEntropySource,
}

impl SecureSessionGenerator {
    /// Create a new secure session generator
    pub fn new() -> Self {
        Self {
            entropy_source: SessionEntropySource::default(),
        }
    }
    
    /// Generate a cryptographically secure session ID
    pub fn generate_session_id(&mut self) -> Result<String> {
        // Use TRNG for secure random number generation
        let random_bytes = crate::trng::random_bytes(32)?;
        
        let mut hasher = Sha256::new();
        hasher.update(&random_bytes);
        hasher.update(&SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos().to_be_bytes());
        hasher.update(b"fortress_session_id");
        
        let session_id = format!("session_{:x}", hasher.finalize());
        Ok(session_id)
    }
    
    /// Generate a secure CSRF token
    pub fn generate_csrf_token(&mut self) -> Result<String> {
        let random_bytes = crate::trng::random_bytes(32)?;
        
        let mut hasher = Sha256::new();
        hasher.update(&random_bytes);
        hasher.update(b"fortress_csrf_token");
        
        Ok(format!("csrf_{:x}", hasher.finalize()))
    }
}

impl Default for SecureSessionGenerator {
    fn default() -> Self {
        Self::new()
    }
}

/// Session entropy source for secure random number generation
#[derive(Debug, Clone)]
pub struct SessionEntropySource {
    /// Last entropy collection time
    last_collection: u64,
    /// Entropy pool
    entropy_pool: Vec<u8>,
}

impl Default for SessionEntropySource {
    fn default() -> Self {
        Self {
            last_collection: 0,
            entropy_pool: Vec::new(),
        }
    }
}

/// Security headers for HTTP responses
#[derive(Debug, Clone)]
pub struct SecurityHeaders {
    /// Content Security Policy
    pub content_security_policy: String,
    /// X-Frame-Options
    pub x_frame_options: String,
    /// X-Content-Type-Options
    pub x_content_type_options: String,
    /// X-XSS-Protection
    pub x_xss_protection: String,
    /// Strict-Transport-Security
    pub strict_transport_security: String,
    /// Referrer Policy
    pub referrer_policy: String,
}

impl SecurityHeaders {
    /// Create default security headers
    pub fn default() -> Self {
        Self {
            content_security_policy: "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none';".to_string(),
            x_frame_options: "DENY".to_string(),
            x_content_type_options: "nosniff".to_string(),
            x_xss_protection: "1; mode=block".to_string(),
            strict_transport_security: "max-age=31536000; includeSubDomains; preload".to_string(),
            referrer_policy: "strict-origin-when-cross-origin".to_string(),
        }
    }
    
    /// Get headers as a map
    pub fn as_map(&self) -> std::collections::HashMap<String, String> {
        let mut headers = std::collections::HashMap::new();
        headers.insert("Content-Security-Policy".to_string(), self.content_security_policy.clone());
        headers.insert("X-Frame-Options".to_string(), self.x_frame_options.clone());
        headers.insert("X-Content-Type-Options".to_string(), self.x_content_type_options.clone());
        headers.insert("X-XSS-Protection".to_string(), self.x_xss_protection.clone());
        headers.insert("Strict-Transport-Security".to_string(), self.strict_transport_security.clone());
        headers.insert("Referrer-Policy".to_string(), self.referrer_policy.clone());
        headers
    }
}

impl Default for SecurityHeaders {
    fn default() -> Self {
        Self::default()
    }
}

/// CSRF protection utilities
pub struct CsrfProtection {
    /// Session generator
    session_generator: SecureSessionGenerator,
    /// Token storage (in production, use secure store)
    token_storage: std::collections::HashMap<String, String>,
}

impl CsrfProtection {
    /// Create new CSRF protection
    pub fn new() -> Self {
        Self {
            session_generator: SecureSessionGenerator::new(),
            token_storage: std::collections::HashMap::new(),
        }
    }
    
    /// Generate and store CSRF token for session
    pub fn generate_token(&mut self, session_id: &str) -> Result<String> {
        let token = self.session_generator.generate_csrf_token()?;
        self.token_storage.insert(session_id.to_string(), token.clone());
        Ok(token)
    }
    
    /// Validate CSRF token
    pub fn validate_token(&self, session_id: &str, token: &str) -> bool {
        match self.token_storage.get(session_id) {
            Some(stored_token) => {
                // Use constant-time comparison
                crate::utils::constant_time_eq(stored_token.as_bytes(), token.as_bytes())
            }
            None => false,
        }
    }
    
    /// Remove CSRF token for session
    pub fn remove_token(&mut self, session_id: &str) {
        self.token_storage.remove(session_id);
    }
}

impl Default for CsrfProtection {
    fn default() -> Self {
        Self::new()
    }
}

/// Input validation utilities
pub struct InputValidator;

impl InputValidator {
    /// Validate and sanitize email addresses
    pub fn validate_email(email: &str) -> Result<String> {
        if email.is_empty() || email.len() > 254 {
            return Err(FortressError::validation("Invalid email format", None, None));
        }
        
        // Basic email validation
        if !email.contains('@') || !email.contains('.') {
            return Err(FortressError::validation("Invalid email format", None, None));
        }
        
        // Check for dangerous patterns
        let dangerous_patterns = ["<script", "javascript:", "data:", "vbscript:"];
        let email_lower = email.to_lowercase();
        for pattern in &dangerous_patterns {
            if email_lower.contains(pattern) {
                return Err(FortressError::validation("Invalid email format", None, None));
            }
        }
        
        Ok(email.to_string())
    }
    
    /// Validate and sanitize URLs
    pub fn validate_url(url: &str) -> Result<String> {
        if url.is_empty() || url.len() > 2048 {
            return Err(FortressError::validation("Invalid URL format", None, None));
        }
        
        // Check for dangerous protocols
        let dangerous_protocols = ["javascript:", "data:", "vbscript:", "file:", "ftp:"];
        let url_lower = url.to_lowercase();
        for protocol in &dangerous_protocols {
            if url_lower.starts_with(protocol) {
                return Err(FortressError::validation("Invalid URL protocol", None, None));
            }
        }
        
        Ok(url.to_string())
    }
    
    /// Validate and sanitize file names
    pub fn validate_filename(filename: &str) -> Result<String> {
        if filename.is_empty() || filename.len() > 255 {
            return Err(FortressError::validation("Invalid filename", None, None));
        }
        
        // Check for dangerous patterns
        let dangerous_patterns = ["..", "\\", "/", ":", "*", "?", "\"", "<", ">", "|"];
        for pattern in &dangerous_patterns {
            if filename.contains(pattern) {
                return Err(FortressError::validation("Invalid filename", None, None));
            }
        }
        
        Ok(filename.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_secure_session_generation() {
        let mut generator = SecureSessionGenerator::new();
        let session_id1 = generator.generate_session_id().unwrap();
        let session_id2 = generator.generate_session_id().unwrap();
        
        assert_ne!(session_id1, session_id2);
        assert!(session_id1.starts_with("session_"));
        assert!(session_id2.starts_with("session_"));
    }
    
    #[test]
    fn test_csrf_protection() {
        let mut csrf = CsrfProtection::new();
        let session_id = "test_session";
        
        let token = csrf.generate_token(session_id).unwrap();
        assert!(csrf.validate_token(session_id, &token));
        assert!(!csrf.validate_token(session_id, "invalid_token"));
        assert!(!csrf.validate_token("other_session", &token));
    }
    
    #[test]
    fn test_email_validation() {
        assert!(InputValidator::validate_email("test@example.com").is_ok());
        assert!(InputValidator::validate_email("user.name+tag@domain.co.uk").is_ok());
        
        assert!(InputValidator::validate_email("").is_err());
        assert!(InputValidator::validate_email("invalid-email").is_err());
        assert!(InputValidator::validate_email("<script>alert('xss')</script>@example.com").is_err());
    }
    
    #[test]
    fn test_url_validation() {
        assert!(InputValidator::validate_url("https://example.com").is_ok());
        assert!(InputValidator::validate_url("http://localhost:8080").is_ok());
        
        assert!(InputValidator::validate_url("javascript:alert('xss')").is_err());
        assert!(InputValidator::validate_url("data:text/html,<script>alert(1)</script>").is_err());
    }
    
    #[test]
    fn test_filename_validation() {
        assert!(InputValidator::validate_filename("document.pdf").is_ok());
        assert!(InputValidator::validate_filename("image_123.jpg").is_ok());
        
        assert!(InputValidator::validate_filename("../etc/passwd").is_err());
        assert!(InputValidator::validate_filename("file\\name").is_err());
        assert!(InputValidator::validate_filename("file|pipe").is_err());
    }
}
