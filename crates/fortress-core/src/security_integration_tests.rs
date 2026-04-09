//! Security Integration Tests
//! 
//! Comprehensive integration tests to verify all security fixes work correctly
//! and to prevent regression of security vulnerabilities.

use crate::error::{FortressError, Result};
use crate::websocket::auth::{AuthManager, AuthConfig};
use crate::security_fixes::{SecureSessionGenerator, CsrfProtection, InputValidator};
use std::time::Duration;
use tokio::time::timeout;

/// Security integration test suite
pub struct SecurityIntegrationTests;

impl SecurityIntegrationTests {
    /// Test authentication system security
    pub async fn test_authentication_security() -> Result<()> {
        println!("Testing authentication system security...");
        
        let auth_config = AuthConfig {
            max_attempts_per_ip: 5,
            attempt_window_seconds: 300,
            lockout_duration_seconds: 900,
        };
        
        let auth_manager = AuthManager::new_with_config(auth_config);
        
        // Test 1: API key authentication with invalid key
        let client_ip = "192.168.1.100";
        let invalid_api_key = "invalid_key_12345";
        
        let result = auth_manager.authenticate_api_key(invalid_api_key, client_ip).await?;
        assert!(!result.success, "Invalid API key should fail authentication");
        assert!(result.user_id.is_none(), "Invalid authentication should not return user ID");
        
        // Test 2: Session token authentication with invalid token
        let invalid_session_token = "invalid_session_token";
        
        let result = auth_manager.authenticate_session(invalid_session_token, client_ip).await?;
        assert!(!result.success, "Invalid session token should fail authentication");
        assert!(result.user_id.is_none(), "Invalid authentication should not return user ID");
        
        // Test 3: Rate limiting enforcement
        let mut failed_attempts = 0;
        for _ in 0..6 {
            let result = auth_manager.authenticate_api_key("invalid_key", client_ip).await?;
            if !result.success {
                failed_attempts += 1;
            }
        }
        
        // Should be rate limited after 5 failed attempts
        let result = auth_manager.authenticate_api_key("another_invalid_key", client_ip).await?;
        assert!(result.error.as_ref().unwrap().contains("Rate limit exceeded"), 
               "Should be rate limited after multiple failed attempts");
        
        println!("Authentication security tests passed!");
        Ok(())
    }
    
    /// Test session generation and CSRF protection
    pub async fn test_session_and_csrf_security() -> Result<()> {
        println!("Testing session generation and CSRF protection...");
        
        let mut session_generator = SecureSessionGenerator::new();
        let mut csrf_protection = CsrfProtection::new();
        
        // Test 1: Secure session ID generation
        let session_id1 = session_generator.generate_session_id()?;
        let session_id2 = session_generator.generate_session_id()?;
        
        assert_ne!(session_id1, session_id2, "Session IDs should be unique");
        assert!(session_id1.starts_with("session_"), "Session ID should have correct prefix");
        assert!(session_id1.len() > 40, "Session ID should be sufficiently long");
        
        // Test 2: CSRF token generation and validation
        let session_id = "test_session_123";
        let csrf_token = csrf_protection.generate_token(session_id)?;
        
        assert!(csrf_protection.validate_token(session_id, &csrf_token), 
               "Valid CSRF token should pass validation");
        assert!(!csrf_protection.validate_token(session_id, "invalid_token"), 
               "Invalid CSRF token should fail validation");
        assert!(!csrf_protection.validate_token("other_session", &csrf_token), 
               "CSRF token should be session-specific");
        
        // Test 3: CSRF token removal
        csrf_protection.remove_token(session_id);
        assert!(!csrf_protection.validate_token(session_id, &csrf_token), 
               "Removed CSRF token should fail validation");
        
        println!("Session and CSRF security tests passed!");
        Ok(())
    }
    
    /// Test input validation security
    pub async fn test_input_validation_security() -> Result<()> {
        println!("Testing input validation security...");
        
        // Test 1: Email validation
        assert!(InputValidator::validate_email("test@example.com").is_ok(), 
               "Valid email should pass validation");
        assert!(InputValidator::validate_email("user.name+tag@domain.co.uk").is_ok(), 
               "Complex valid email should pass validation");
        
        assert!(InputValidator::validate_email("").is_err(), 
               "Empty email should fail validation");
        assert!(InputValidator::validate_email("invalid-email").is_err(), 
               "Invalid email format should fail validation");
        assert!(InputValidator::validate_email("<script>alert('xss')</script>@example.com").is_err(), 
               "Email with dangerous content should fail validation");
        
        // Test 2: URL validation
        assert!(InputValidator::validate_url("https://example.com").is_ok(), 
               "Valid HTTPS URL should pass validation");
        assert!(InputValidator::validate_url("http://localhost:8080").is_ok(), 
               "Valid HTTP URL should pass validation");
        
        assert!(InputValidator::validate_url("javascript:alert('xss')").is_err(), 
               "JavaScript URL should fail validation");
        assert!(InputValidator::validate_url("data:text/html,<script>alert(1)</script>").is_err(), 
               "Data URL should fail validation");
        
        // Test 3: Filename validation
        assert!(InputValidator::validate_filename("document.pdf").is_ok(), 
               "Valid filename should pass validation");
        assert!(InputValidator::validate_filename("image_123.jpg").is_ok(), 
               "Valid filename with numbers should pass validation");
        
        assert!(InputValidator::validate_filename("../etc/passwd").is_err(), 
               "Path traversal filename should fail validation");
        assert!(InputValidator::validate_filename("file\\name").is_err(), 
               "Filename with backslash should fail validation");
        assert!(InputValidator::validate_filename("file|pipe").is_err(), 
               "Filename with pipe should fail validation");
        
        println!("Input validation security tests passed!");
        Ok(())
    }
    
    /// Test rate limiting and lockout mechanisms
    pub async fn test_rate_limiting_security() -> Result<()> {
        println!("Testing rate limiting and lockout mechanisms...");
        
        let auth_config = AuthConfig {
            max_attempts_per_ip: 3,
            attempt_window_seconds: 60,
            lockout_duration_seconds: 120,
        };
        
        let auth_manager = AuthManager::new_with_config(auth_config);
        let client_ip = "192.168.1.200";
        
        // Test 1: Normal rate limiting
        let mut success_count = 0;
        for i in 0..5 {
            let result = auth_manager.authenticate_api_key("invalid_key", client_ip).await?;
            if result.success {
                success_count += 1;
            }
            println!("Attempt {}: Success={}", i+1, result.success);
        }
        
        assert_eq!(success_count, 0, "All attempts with invalid key should fail");
        
        // Test 2: Lockout enforcement
        let result = auth_manager.authenticate_api_key("another_invalid_key", client_ip).await?;
        assert!(result.error.as_ref().unwrap().contains("Rate limit exceeded"), 
               "Should be locked out after exceeding rate limit");
        
        // Test 3: Different IP should not be affected
        let different_ip = "192.168.1.201";
        let result = auth_manager.authenticate_api_key("invalid_key", different_ip).await?;
        assert!(!result.success, "Invalid key should still fail for different IP");
        assert!(!result.error.as_ref().unwrap().contains("Rate limit exceeded"), 
               "Different IP should not be rate limited");
        
        // Test 4: Statistics
        let stats = auth_manager.get_stats().await;
        assert!(stats.active_rate_limits > 0, "Should have active rate limits");
        assert!(stats.active_lockouts > 0, "Should have active lockouts");
        
        println!("Rate limiting security tests passed!");
        Ok(())
    }
    
    /// Test timeout and performance characteristics
    pub async fn test_timeout_and_performance() -> Result<()> {
        println!("Testing timeout and performance characteristics...");
        
        let auth_config = AuthConfig {
            max_attempts_per_ip: 10,
            attempt_window_seconds: 300,
            lockout_duration_seconds: 900,
        };
        
        let auth_manager = AuthManager::new_with_config(auth_config);
        
        // Test 1: Authentication should complete within reasonable time
        let start_time = std::time::Instant::now();
        
        let auth_future = auth_manager.authenticate_api_key("invalid_key", "127.0.0.1");
        let result = timeout(Duration::from_millis(100), auth_future).await??;
        
        let elapsed = start_time.elapsed();
        assert!(!result.success, "Invalid key should fail authentication");
        assert!(elapsed < Duration::from_millis(50), "Authentication should be fast");
        
        // Test 2: Session generation should be fast
        let start_time = std::time::Instant::now();
        let mut session_generator = SecureSessionGenerator::new();
        let session_id = session_generator.generate_session_id()?;
        let elapsed = start_time.elapsed();
        
        assert!(elapsed < Duration::from_millis(10), "Session generation should be very fast");
        assert!(session_id.len() > 40, "Session ID should be sufficiently long");
        
        // Test 3: CSRF operations should be fast
        let start_time = std::time::Instant::now();
        let mut csrf_protection = CsrfProtection::new();
        let token = csrf_protection.generate_token("test_session")?;
        let is_valid = csrf_protection.validate_token("test_session", &token);
        let elapsed = start_time.elapsed();
        
        assert!(is_valid, "CSRF token validation should work");
        assert!(elapsed < Duration::from_millis(5), "CSRF operations should be very fast");
        
        println!("Timeout and performance tests passed!");
        Ok(())
    }
    
    /// Test concurrent access safety
    pub async fn test_concurrent_access_safety() -> Result<()> {
        println!("Testing concurrent access safety...");
        
        let auth_config = AuthConfig {
            max_attempts_per_ip: 10,
            attempt_window_seconds: 300,
            lockout_duration_seconds: 900,
        };
        
        let auth_manager = std::sync::Arc::new(auth_manager);
        
        // Test 1: Concurrent authentication attempts
        let mut handles = vec![];
        for i in 0..10 {
            let auth_manager = auth_manager.clone();
            let handle = tokio::spawn(async move {
                let client_ip = format!("192.168.1.{}", i + 100);
                let result = auth_manager.authenticate_api_key("test_key", &client_ip).await;
                result.is_ok()
            });
            handles.push(handle);
        }
        
        let mut success_count = 0;
        for handle in handles {
            if handle.await.unwrap() {
                success_count += 1;
            }
        }
        
        assert_eq!(success_count, 10, "All concurrent authentication attempts should complete successfully");
        
        // Test 2: Concurrent session generation
        let mut handles = vec![];
        for _ in 0..20 {
            let handle = tokio::spawn(async move {
                let mut session_generator = SecureSessionGenerator::new();
                session_generator.generate_session_id().is_ok()
            });
            handles.push(handle);
        }
        
        let mut success_count = 0;
        for handle in handles {
            if handle.await.unwrap() {
                success_count += 1;
            }
        }
        
        assert_eq!(success_count, 20, "All concurrent session generations should succeed");
        
        println!("Concurrent access safety tests passed!");
        Ok(())
    }
    
    /// Run all security integration tests
    pub async fn run_all_tests() -> Result<()> {
        println!("Running comprehensive security integration tests...\n");
        
        Self::test_authentication_security().await?;
        Self::test_session_and_csrf_security().await?;
        Self::test_input_validation_security().await?;
        Self::test_rate_limiting_security().await?;
        Self::test_timeout_and_performance().await?;
        Self::test_concurrent_access_safety().await?;
        
        println!("\nAll security integration tests passed! Security fixes are working correctly.");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_security_integration_suite() {
        let result = SecurityIntegrationTests::run_all_tests().await;
        assert!(result.is_ok(), "All security integration tests should pass");
    }
    
    #[tokio::test]
    async fn test_authentication_security_individual() {
        let result = SecurityIntegrationTests::test_authentication_security().await;
        assert!(result.is_ok(), "Authentication security test should pass");
    }
    
    #[tokio::test]
    async fn test_session_and_csrf_security_individual() {
        let result = SecurityIntegrationTests::test_session_and_csrf_security().await;
        assert!(result.is_ok(), "Session and CSRF security test should pass");
    }
    
    #[tokio::test]
    async fn test_input_validation_security_individual() {
        let result = SecurityIntegrationTests::test_input_validation_security().await;
        assert!(result.is_ok(), "Input validation security test should pass");
    }
    
    #[tokio::test]
    async fn test_rate_limiting_security_individual() {
        let result = SecurityIntegrationTests::test_rate_limiting_security().await;
        assert!(result.is_ok(), "Rate limiting security test should pass");
    }
    
    #[tokio::test]
    async fn test_timeout_and_performance_individual() {
        let result = SecurityIntegrationTests::test_timeout_and_performance().await;
        assert!(result.is_ok(), "Timeout and performance test should pass");
    }
    
    #[tokio::test]
    async fn test_concurrent_access_safety_individual() {
        let result = SecurityIntegrationTests::test_concurrent_access_safety().await;
        assert!(result.is_ok(), "Concurrent access safety test should pass");
    }
}
