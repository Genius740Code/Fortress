# Fortress Security Developer Guide

## Overview

This guide provides comprehensive security best practices and guidelines for developers working on the Fortress security platform. It covers secure coding practices, authentication patterns, input validation, and security testing.

## Table of Contents

1. [Security Architecture](#security-architecture)
2. [Authentication & Authorization](#authentication--authorization)
3. [Input Validation & Sanitization](#input-validation--sanitization)
4. [Session Management](#session-management)
5. [Cryptographic Security](#cryptographic-security)
6. [Error Handling](#error-handling)
7. [Security Testing](#security-testing)
8. [Common Security Pitfalls](#common-security-pitfalls)
9. [Performance Considerations](#performance-considerations)
10. [Security Monitoring](#security-monitoring)

## Security Architecture

### Core Security Components

Fortress implements a layered security architecture:

```
Application Layer
    - Input Validation & Sanitization
    - CSRF Protection
    - Security Headers
Authentication Layer
    - API Key Authentication
    - Session Token Validation
    - Rate Limiting & Lockout
Cryptographic Layer
    - Secure Random Number Generation
    - Encryption & Decryption
    - Key Management
```

### Security Modules

- **`security_fixes`**: Core security utilities and enhancements
- **`websocket::auth`**: WebSocket authentication and authorization
- **`trng`**: True Random Number Generator
- **`encryption`**: Cryptographic operations
- **`auth`**: Core authentication system

## Authentication & Authorization

### API Key Authentication

```rust
use crate::websocket::auth::AuthManager;

// Secure API key authentication
let auth_manager = AuthManager::new();
let result = auth_manager.authenticate_api_key(api_key, client_ip).await?;

if result.success {
    // Authentication successful
    let user_id = result.user_id.unwrap();
    let roles = result.roles;
} else {
    // Authentication failed
    log_security_event("api_key_auth_failed", client_ip);
}
```

### Session Token Authentication

```rust
// Secure session token validation
let result = auth_manager.authenticate_session(session_token, client_ip).await?;

if result.success {
    let session_data = result.session_id.unwrap();
    // Process authenticated request
} else {
    // Return authentication error
}
```

### Rate Limiting

Rate limiting is automatically enforced by the `AuthManager`:

```rust
let auth_config = AuthConfig {
    max_attempts_per_ip: 10,
    attempt_window_seconds: 300,
    lockout_duration_seconds: 900,
};

let auth_manager = AuthManager::new_with_config(auth_config);
```

## Input Validation & Sanitization

### Using InputValidator

```rust
use crate::security_fixes::InputValidator;

// Email validation
let email = InputValidator::validate_email(user_input)?;
if email.is_ok() {
    // Email is valid and safe
}

// URL validation
let url = InputValidator::validate_url(user_input)?;

// Filename validation
let filename = InputValidator::validate_filename(user_input)?;
```

### Custom Input Validation

```rust
fn validate_custom_input(input: &str) -> Result<String> {
    // Length validation
    if input.is_empty() || input.len() > 100 {
        return Err(FortressError::validation("Invalid input length", None, None));
    }
    
    // Character validation
    if !input.chars().all(|c| c.is_alphanumeric() || c == '_' || c == '-') {
        return Err(FortressError::validation("Invalid characters", None, None));
    }
    
    // Dangerous pattern detection
    let dangerous_patterns = ["<script", "javascript:", "data:"];
    let input_lower = input.to_lowercase();
    for pattern in &dangerous_patterns {
        if input_lower.contains(pattern) {
            return Err(FortressError::validation("Dangerous pattern detected", None, None));
        }
    }
    
    Ok(input.to_string())
}
```

## Session Management

### Secure Session Generation

```rust
use crate::security_fixes::SecureSessionGenerator;

let mut session_generator = SecureSessionGenerator::new();
let session_id = session_generator.generate_session_id()?;

// Session ID format: "session_<64_char_hex>"
assert!(session_id.starts_with("session_"));
assert!(session_id.len() > 40);
```

### CSRF Protection

```rust
use crate::security_fixes::CsrfProtection;

let mut csrf_protection = CsrfProtection::new();

// Generate CSRF token for session
let session_id = "user_session_123";
let csrf_token = csrf_protection.generate_token(session_id)?;

// Validate CSRF token
if csrf_protection.validate_token(session_id, &csrf_token) {
    // Token is valid, proceed with request
} else {
    return Err(FortressError::authentication("Invalid CSRF token"));
}

// Clean up token when session ends
csrf_protection.remove_token(session_id);
```

### Security Headers

```rust
use crate::security_fixes::SecurityHeaders;

let headers = SecurityHeaders::default();
let header_map = headers.as_map();

// Apply headers to HTTP response
for (name, value) in header_map {
    response.headers_mut().insert(name, value.parse()?);
}
```

## Cryptographic Security

### Secure Random Number Generation

```rust
use crate::trng;

// Generate cryptographically secure random bytes
let random_bytes = trng::random_bytes(32)?;

// Use for session tokens, nonces, etc.
let nonce = trng::random_bytes(12)?;
```

### Encryption Operations

```rust
use crate::encryption::Aegis256;

let algorithm = Aegis256::new();
let key = SecureKey::new(32)?; // 256-bit key

// Encrypt data
let plaintext = b"Sensitive data";
let ciphertext = algorithm.encrypt(plaintext, &key)?;

// Decrypt data
let decrypted = algorithm.decrypt(&ciphertext, &key)?;
assert_eq!(plaintext, decrypted);
```

### Key Management

```rust
use crate::key::KeyManager;

let key_manager = KeyManager::new();

// Generate new key
let key = key_manager.generate_key(32)?;

// Store key securely
let key_id = key_manager.store_key(key.clone()).await?;

// Retrieve key
let retrieved_key = key_manager.get_key(&key_id).await?;

// Rotate key
let new_key = key_manager.rotate_key(&key_id).await?;
```

## Error Handling

### Security Error Types

```rust
use crate::error::FortressError;

// Authentication errors
return Err(FortressError::authentication("Invalid credentials"));

// Validation errors
return Err(FortressError::validation("Invalid input", None, None));

// Encryption errors
return Err(FortressError::encryption(
    "Encryption failed", 
    "Aegis256", 
    EncryptionErrorCode::EncryptionFailed
));

// Authorization errors
return Err(FortressError::authorization("Access denied"));
```

### Safe Error Handling Patterns

```rust
// NEVER use unwrap() in production code
// BAD:
let user_id = result.unwrap();

// GOOD:
let user_id = result.map_err(|e| {
    log_security_event("operation_failed", &e.to_string());
    FortressError::authentication("User lookup failed")
})?;

// Use ? operator for proper error propagation
let session_data = validate_session_token(session_token).await?;
```

### Constant-Time Operations

```rust
use crate::utils::constant_time_eq;

// Use constant-time comparison for sensitive data
if constant_time_eq(provided_hash, stored_hash) {
    // Authentication successful
} else {
    // Authentication failed (no timing difference)
}
```

## Security Testing

### Integration Tests

```rust
use crate::security_integration_tests::SecurityIntegrationTests;

#[tokio::test]
async fn test_security_integration() {
    SecurityIntegrationTests::run_all_tests().await.unwrap();
}
```

### Regression Tests

```rust
use crate::security_regression_tests::SecurityRegressionTests;

#[test]
fn test_security_regression() {
    SecurityRegressionTests::run_all_tests().unwrap();
}
```

### Performance Tests

```rust
use crate::security_performance_tests::SecurityPerformanceTests;

#[tokio::test]
async fn test_security_performance() {
    SecurityPerformanceTests::run_all_tests().await.unwrap();
}
```

### Unit Testing Security Components

```rust
#[cfg(test)]
mod security_tests {
    use super::*;
    
    #[test]
    fn test_input_validation() {
        assert!(InputValidator::validate_email("test@example.com").is_ok());
        assert!(InputValidator::validate_email("invalid-email").is_err());
        
        assert!(InputValidator::validate_url("https://example.com").is_ok());
        assert!(InputValidator::validate_url("javascript:alert('xss')").is_err());
    }
    
    #[test]
    fn test_csrf_protection() {
        let mut csrf = CsrfProtection::new();
        let session_id = "test_session";
        
        let token = csrf.generate_token(session_id).unwrap();
        assert!(csrf.validate_token(session_id, &token));
        assert!(!csrf.validate_token(session_id, "invalid_token"));
    }
}
```

## Common Security Pitfalls

### 1. Placeholder Authentication

**NEVER** use placeholder authentication patterns:

```rust
// BAD - Vulnerable
let user_id = format!("user_{}", &api_key[..8]);

// GOOD - Secure
let api_key_hash = hash_api_key(api_key)?;
if !is_valid_api_key(&api_key_hash).await? {
    return Err(FortressError::authentication("Invalid API key"));
}
let user_id = get_user_by_api_key(&api_key_hash).await?;
```

### 2. Weak Random Number Generation

**NEVER** use weak random number generators:

```rust
// BAD - Predictable
let mut rng = rand::thread_rng();
let random_bytes: Vec<u8> = (0..32).map(|_| rng.gen()).collect();

// GOOD - Cryptographically secure
let random_bytes = crate::trng::random_bytes(32)?;
```

### 3. Hardcoded Credentials

**NEVER** hardcode credentials:

```rust
// BAD - Security risk
auth.create_user("admin".to_string(), "password".to_string()).await.unwrap();

// GOOD - Secure credentials
let secure_password = crate::utils::generate_password(16);
auth.create_user("admin".to_string(), secure_password).await.unwrap();
```

### 4. Unsafe String Operations

**NEVER** use unsafe string operations for sensitive data:

```rust
// BAD - Potential timing attack
if provided_password == stored_password {
    // Authentication successful
}

// GOOD - Constant-time comparison
if constant_time_eq(provided_password.as_bytes(), stored_password.as_bytes()) {
    // Authentication successful
}
```

### 5. Information Disclosure

**NEVER** disclose sensitive information in error messages:

```rust
// BAD - Information disclosure
return Err(FortressError::authentication(format!("User {} not found", username)));

// GOOD - Generic error message
return Err(FortressError::authentication("Invalid credentials"));
```

## Performance Considerations

### Security vs Performance Balance

Security features should not significantly impact performance:

```rust
// Efficient session generation
let session_id = session_generator.generate_session_id()?; // < 5ms

// Fast input validation
let email = InputValidator::validate_email(input)?; // < 1ms

// Efficient rate limiting lookup
let result = auth_manager.authenticate_api_key(key, ip).await?; // < 10ms
```

### Caching Security Data

Cache frequently accessed security data:

```rust
// Cache user permissions
let cached_permissions = get_cached_permissions(&user_id);
if cached_permissions.is_none() {
    let permissions = fetch_permissions_from_db(&user_id).await?;
    cache_permissions(&user_id, &permissions);
}
```

### Batch Security Operations

Process security operations in batches:

```rust
// Batch session validation
let session_ids = vec!["session1", "session2", "session3"];
let valid_sessions = validate_sessions_batch(session_ids).await?;
```

## Security Monitoring

### Logging Security Events

```rust
fn log_security_event(event_type: &str, details: &str) {
    let log_entry = json!({
        "timestamp": chrono::Utc::now(),
        "event_type": event_type,
        "details": details,
        "severity": "security"
    });
    
    // Log to security monitoring system
    security_logger.log(&log_entry);
}
```

### Metrics Collection

```rust
use crate::observability::metrics;

// Track authentication attempts
metrics::counter("authentication_attempts_total", 
    &[("result", "success"), ("method", "api_key")]).inc();

// Track rate limiting
metrics::counter("rate_limit_blocks_total",
    &[("ip", client_ip), ("endpoint", "auth")]).inc();
```

### Alerting

```rust
fn check_security_alerts() {
    let failed_attempts = get_failed_auth_attempts_last_minute();
    
    if failed_attempts > 100 {
        send_security_alert("High rate of authentication failures", &failed_attempts.to_string());
    }
}
```

## Best Practices Summary

### DO:
- Use cryptographically secure random number generation
- Implement proper input validation and sanitization
- Use constant-time comparisons for sensitive data
- Implement rate limiting and account lockout
- Use secure session management
- Log security events appropriately
- Test security components thoroughly
- Follow the principle of least privilege

### DON'T:
- Use placeholder authentication patterns
- Hardcode credentials or secrets
- Use weak random number generators
- Disclose sensitive information in error messages
- Skip input validation
- Use `unwrap()` in production code
- Log sensitive information
- Ignore security warnings

## Security Checklist

Before deploying code to production:

- [ ] All authentication methods are secure
- [ ] Input validation is implemented for all user inputs
- [ ] CSRF protection is enabled for state-changing operations
- [ ] Rate limiting is configured appropriately
- [ ] Security headers are set
- [ ] Error messages don't disclose sensitive information
- [ ] Cryptographic operations use secure algorithms
- [ ] Session management is secure
- [ ] Security tests pass
- [ ] Performance impact is acceptable
- [ ] Security monitoring is configured

## Resources

- [Security Integration Tests](../crates/fortress-core/src/security_integration_tests.rs)
- [Security Regression Tests](../crates/fortress-core/src/security_regression_tests.rs)
- [Security Performance Tests](../crates/fortress-core/src/security_performance_tests.rs)
- [Security FixesModule](../crates/fortress-core/src/security_fixes.rs)
- [Authentication Module](../crates/fortress-core/src/websocket/auth.rs)

## Conclusion

Security is a continuous process. This guide provides the foundation for secure development practices in Fortress. Always stay updated on the latest security threats and best practices, and regularly review and update security measures.

For questions or concerns about security implementation, consult the security team or refer to the security documentation.
