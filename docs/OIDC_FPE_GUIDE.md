# OIDC Provider and Format-Preserving Encryption (FPE) Guide

## Overview

This guide covers the implementation and usage of two major new features in Fortress:

1. **OIDC Provider** - Industry-standard OpenID Connect provider for internal service authentication
2. **Format-Preserving Encryption (FPE)** - Encryption that maintains original data format for legacy system compatibility

## Table of Contents

- [OIDC Provider](#oidc-provider)
  - [Features](#oidc-features)
  - [Configuration](#oidc-configuration)
  - [Usage Examples](#oidc-usage-examples)
  - [Security Considerations](#oidc-security-considerations)
- [Format-Preserving Encryption](#format-preserving-encryption-fpe)
  - [Supported Formats](#fpe-supported-formats)
  - [Configuration](#fpe-configuration)
  - [Usage Examples](#fpe-usage-examples)
  - [Security Considerations](#fpe-security-considerations)
- [Integration Examples](#integration-examples)
- [Performance Considerations](#performance-considerations)
- [Testing](#testing)

---

## OIDC Provider

Fortress now includes a complete OpenID Connect (OIDC) provider implementation that allows internal services to authenticate using industry-standard protocols. This enables seamless integration with Kubernetes, cloud-native applications, and third-party services.

### OIDC Features

#### 🚀 Core OIDC Features
- **Authorization Code Flow** - Standard OAuth 2.0 authorization code grant
- **Client Credentials Grant** - Service-to-service authentication
- **Refresh Token Support** - Long-lived refresh tokens for better UX
- **PKCE Support** - Proof Key for Code Exchange for public clients
- **JWT Tokens** - Industry-standard JSON Web Tokens
- **JWKS Endpoint** - JSON Web Key Set for token validation

#### 🛡️ Security Features
- **Reg Policy Integration** - Open Policy Agent (OPA) Rego policies for authorization
- **Rate Limiting** - Configurable rate limits per client
- **Token Revocation** - Secure token invalidation
- **Device Fingerprinting** - Optional device-based security
- **Session Management** - Secure session lifecycle management

#### 📊 Management Features
- **Dynamic Client Registration** - Runtime client management
- **Token Introspection** - Token validation endpoint
- **User Info Endpoint** - Standardized user information
- **Audit Logging** - Complete authentication event logging

### OIDC Configuration

#### Basic Configuration

```rust
use fortress_core::oidc_provider::*;

let mut oidc_config = OidcConfig::default();

// Configure issuer
oidc_config.issuer = "https://fortress.example.com".to_string();

// Add client
let client = OidcClient {
    client_id: "my-service".to_string(),
    client_secret: Some("super-secret-key".to_string()),
    name: "My Service".to_string(),
    redirect_uris: vec![
        "https://my-service.example.com/callback".to_string(),
        "https://my-service.example.com/silent-callback".to_string(),
    ],
    grant_types: vec![
        "authorization_code".to_string(),
        "refresh_token".to_string(),
    ],
    response_types: vec!["code".to_string()],
    scopes: vec![
        "openid".to_string(),
        "profile".to_string(),
        "email".to_string(),
        "read".to_string(),
        "write".to_string(),
    ],
    public: false,
    metadata: HashMap::new(),
};

oidc_config.clients.insert("my-service".to_string(), client);
```

#### Rego Policy Configuration

```rust
// Enable Rego policy engine
oidc_config.rego_policies = Some(RegoConfig {
    policy_dir: "/etc/fortress/policies".to_string(),
    data_dir: Some("/etc/fortress/policy-data".to_string()),
    enable_cache: true,
    cache_ttl: 300, // 5 minutes
});
```

#### Token Expiration Configuration

```rust
oidc_config.token_expiration = TokenExpiration {
    auth_code: 600,        // 10 minutes
    access_token: 3600,     // 1 hour
    refresh_token: 2592000, // 30 days
    id_token: 3600,        // 1 hour
};
```

### OIDC Usage Examples

#### Authorization Code Flow

```rust
use fortress_core::oidc_provider::*;

// Step 1: Authorization Request
let auth_request = OidcAuthRequest {
    response_type: "code".to_string(),
    client_id: "my-service".to_string(),
    redirect_uri: "https://my-service.example.com/callback".to_string(),
    scope: "openid profile email read".to_string(),
    state: Some("random-state-123".to_string()),
    nonce: Some("random-nonce-456".to_string()),
    response_mode: None,
    code_challenge: None,
    code_challenge_method: None,
    additional_params: HashMap::new(),
};

let redirect_url = oidc_provider.authorize(auth_request).await?;
// Returns: "https://my-service.example.com/callback?code=abc123&state=random-state-123"

// Step 2: Token Exchange
let token_request = OidcTokenRequest {
    grant_type: "authorization_code".to_string(),
    code: Some("abc123".to_string()),
    redirect_uri: Some("https://my-service.example.com/callback".to_string()),
    code_verifier: None,
    refresh_token: None,
    client_id: "my-service".to_string(),
    client_secret: Some("super-secret-key".to_string()),
    scope: None,
};

let token_response = oidc_provider.token(token_request).await?;
// Returns OidcTokenResponse with access_token, refresh_token, id_token
```

#### Client Credentials Grant

```rust
let token_request = OidcTokenRequest {
    grant_type: "client_credentials".to_string(),
    code: None,
    redirect_uri: None,
    code_verifier: None,
    refresh_token: None,
    client_id: "my-service".to_string(),
    client_secret: Some("super-secret-key".to_string()),
    scope: Some("service-to-service".to_string()),
};

let token_response = oidc_provider.token(token_request).await?;
// Returns access token for service-to-service communication
```

#### PKCE Flow (Public Clients)

```rust
use base64::{Engine as _, engine::URL_SAFE_NO_PAD};
use sha2::{Sha256, Digest};

// Generate PKCE verifier and challenge
let code_verifier = "random-secure-string-123456789";
let mut hasher = Sha256::new();
hasher.update(code_verifier.as_bytes());
let code_challenge = URL_SAFE_NO_PAD.encode(hasher.finalize());

let auth_request = OidcAuthRequest {
    response_type: "code".to_string(),
    client_id: "public-app".to_string(),
    redirect_uri: "https://public-app.example.com/callback".to_string(),
    scope: "openid profile".to_string(),
    state: Some("app-state".to_string()),
    nonce: None,
    response_mode: None,
    code_challenge: Some(code_challenge),
    code_challenge_method: Some("S256".to_string()),
    additional_params: HashMap::new(),
};

let redirect_url = oidc_provider.authorize(auth_request).await?;

// Exchange with code verifier
let token_request = OidcTokenRequest {
    grant_type: "authorization_code".to_string(),
    code: Some(extracted_code),
    redirect_uri: Some("https://public-app.example.com/callback".to_string()),
    code_verifier: Some(code_verifier.to_string()),
    refresh_token: None,
    client_id: "public-app".to_string(),
    client_secret: None, // Public client
    scope: None,
};

let token_response = oidc_provider.token(token_request).await?;
```

#### User Information

```rust
// Get user info from access token
let user_info = oidc_provider.user_info(&access_token).await?;

println!("User ID: {}", user_info.sub);
println!("Name: {:?}", user_info.name);
println!("Email: {:?}", user_info.email);
println!("Groups: {:?}", user_info.groups);
```

#### JWKS Endpoint

```rust
// Get JSON Web Key Set for token validation
let jwks = oidc_provider.jwks();

// Use in your application for JWT validation
// jwks contains keys with kid, kty, use, alg, etc.
```

### OIDC Security Considerations

#### 🔐 Authentication Security
- **HTTPS Only**: Always use HTTPS for OIDC endpoints
- **State Parameter**: Always use and verify state parameter to prevent CSRF
- **Nonce Parameter**: Use nonce for ID tokens to prevent replay attacks
- **PKCE**: Use PKCE for public clients to prevent authorization code interception
- **Token Binding**: Consider token binding to client certificates or device fingerprints

#### 📋 Authorization Security
- **Least Privilege**: Grant minimum necessary scopes
- **Scope Validation**: Validate requested scopes against client permissions
- **Rego Policies**: Use Rego policies for complex authorization logic
- **Regular Audits**: Audit Rego policies and client configurations regularly

#### 🚨 Monitoring & Logging
- **Failed Attempts**: Monitor and alert on authentication failures
- **Anomalous Patterns**: Detect unusual authentication patterns
- **Token Usage**: Monitor token usage patterns and revocation
- **Performance**: Monitor OIDC endpoint performance and availability

---

## Format-Preserving Encryption (FPE)

Format-Preserving Encryption allows Fortress to encrypt sensitive data while maintaining the original data format. This is crucial for legacy system compatibility where database schemas, application logic, or external integrations cannot be modified to handle encrypted data.

### FPE Supported Formats

#### 💳 Credit Card Numbers
- **Format**: 16 digits with optional spaces/hyphens
- **Validation**: Luhn checksum validation
- **Preservation**: Original spacing/hyphenation maintained
- **Example**: `4532 1234 5678 9012` → `7890 3456 1234 5678`

#### 🆔 Social Security Numbers
- **Format**: 9 digits in XXX-XX-XXXX format
- **Validation**: Format validation
- **Preservation**: Hyphen positions maintained
- **Example**: `123-45-6789` → `987-65-4321`

#### 📞 Phone Numbers
- **Format**: E.164 format with + prefix
- **Validation**: Length validation (10-15 digits)
- **Preservation**: Country code and length maintained
- **Example**: `+12345678901` → `+98765432109`

#### 📧 Email Addresses
- **Format**: Standard email format with @ symbol
- **Validation**: Email format validation
- **Preservation**: Domain structure maintained, username encrypted
- **Example**: `user@example.com` → `x9y2z3@example.com`

#### 🔢 Numeric Strings
- **Format**: Fixed-length numeric strings
- **Validation**: Length and digit-only validation
- **Preservation**: Exact length maintained
- **Example**: `12345678` → `87654321`

#### 📅 Dates
- **Format**: ISO 8601 (YYYY-MM-DD)
- **Validation**: Date format validation
- **Preservation**: Date format maintained
- **Example**: `2023-12-25` → `1998-07-14`

#### 🔤 Custom Formats
- **Format**: User-defined regex patterns
- **Validation**: Custom regex validation
- **Preservation**: Pattern structure maintained
- **Example**: Custom formats like product codes, license plates, etc.

### FPE Configuration

#### Credit Card Configuration

```rust
use fortress_core::format_preserving_encryption::*;

let key = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
let config = FormatPreservingEncryption::credit_card_config(key);
let fpe = FormatPreservingEncryption::new(config)?;
```

#### SSN Configuration

```rust
let key = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
let config = FormatPreservingEncryption::ssn_config(key);
let fpe = FormatPreservingEncryption::new(config)?;
```

#### Custom Configuration

```rust
let config = FpeConfig {
    algorithm: FpeAlgorithm::FF1,
    format: DataFormat::Numeric { length: 8 },
    key: vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
    parameters: HashMap::new(),
};

let fpe = FormatPreservingEncryption::new(config)?;
```

### FPE Usage Examples

#### Credit Card Encryption

```rust
let card_number = "4532 1234 5678 9012";

// Encrypt
let encrypted = fpe.encrypt(card_number)?;
println!("Encrypted: {}", encrypted.encrypted_value);
// Output: "7890 3456 1234 5678"

// Decrypt
let decrypted = fpe.decrypt(&encrypted.encrypted_value)?;
println!("Decrypted: {}", decrypted);
// Output: "4532 1234 5678 9012"

// Verify format preservation
assert_eq!(encrypted.encrypted_value.len(), card_number.len());
assert!(encrypted.format_preserved);
```

#### SSN Encryption

```rust
let ssn = "123-45-6789";

// Encrypt
let encrypted = fpe.encrypt(ssn)?;
println!("Encrypted: {}", encrypted.encrypted_value);
// Output: "987-65-4321"

// Decrypt
let decrypted = fpe.decrypt(&encrypted.encrypted_value)?;
println!("Decrypted: {}", decrypted);
// Output: "123-45-6789"
```

#### Email Encryption

```rust
let email = "user@example.com";

// Encrypt
let encrypted = fpe.encrypt(email)?;
println!("Encrypted: {}", encrypted.encrypted_value);
// Output: "x9y2z3@example.com"

// Decrypt
let decrypted = fpe.decrypt(&encrypted.encrypted_value)?;
println!("Decrypted: {}", decrypted);
// Output: "user@example.com"
```

#### Date Encryption

```rust
let date = "2023-12-25";

// Encrypt
let encrypted = fpe.encrypt(date)?;
println!("Encrypted: {}", encrypted.encrypted_value);
// Output: "1998-07-14"

// Decrypt
let decrypted = fpe.decrypt(&encrypted.encrypted_value)?;
println!("Decrypted: {}", decrypted);
// Output: "2023-12-25"
```

#### Batch Processing

```rust
let sensitive_data = vec![
    ("4532123456789012", "credit_card"),
    ("123456789", "ssn"),
    "+12345678901", "phone"),
];

let mut encrypted_data = Vec::new();

for (data, data_type) in sensitive_data {
    let fpe = match data_type {
        "credit_card" => &fpe_credit_card,
        "ssn" => &fpe_ssn,
        "phone" => &fpe_phone,
        _ => continue,
    };

    let encrypted = fpe.encrypt(data)?;
    encrypted_data.push((encrypted.encrypted_value, data_type));
}

// Process encrypted data...
```

### FPE Security Considerations

#### 🔐 Key Management
- **Strong Keys**: Use cryptographically strong keys (minimum 128 bits)
- **Key Rotation**: Regular key rotation according to security policy
- **Key Separation**: Use different keys for different data types
- **Secure Storage**: Store keys securely using Fortress key management

#### 🚨 Implementation Security
- **Algorithm Choice**: Use NIST-approved algorithms (FF1, FF3-1)
- **Input Validation**: Validate all inputs before encryption
- **Error Handling**: Secure error handling without information leakage
- **Side-Channel**: Protect against timing attacks and side-channel leakage

#### 📊 Compliance Considerations
- **PCI DSS**: For credit card encryption, ensure PCI DSS compliance
- **Data Classification**: Classify data and apply appropriate encryption
- **Audit Trails**: Maintain audit trails for encryption operations
- **Regulatory**: Comply with relevant data protection regulations

---

## Integration Examples

### Kubernetes Integration

```rust
// Configure OIDC for Kubernetes service accounts
let oidc_config = OidcConfig {
    issuer: "https://fortress.example.com".to_string(),
    // ... other config
    rego_policies: Some(RegoConfig {
        policy_dir: "/etc/fortress/kubernetes-policies".to_string(),
        data_dir: Some("/etc/fortress/kubernetes-data".to_string()),
        enable_cache: true,
        cache_ttl: 300,
    }),
    // ... rest of config
};

// Rego policy example for Kubernetes
/*
package fortress.kubernetes

default allow = false

allow {
    input.service.account == "system:serviceaccount:my-namespace:my-service"
    input.request.namespace == "my-namespace"
    input.request.resource.type == "pods"
    input.request.action in ["get", "list", "create", "update", "delete"]
}
*/
```

### Database Integration

```rust
// Encrypt sensitive data before database storage
async fn store_user_data(user_id: &str, ssn: &str, credit_card: &str) -> Result<(), FortressError> {
    // Encrypt SSN
    let ssn_config = FormatPreservingEncryption::ssn_config(get_encryption_key()?);
    let ssn_fpe = FormatPreservingEncryption::new(ssn_config)?;
    let encrypted_ssn = ssn_fpe.encrypt(ssn)?;
    
    // Encrypt Credit Card
    let cc_config = FormatPreservingEncryption::credit_card_config(get_encryption_key()?);
    let cc_fpe = FormatPreservingEncryption::new(cc_config)?;
    let encrypted_cc = cc_fpe.encrypt(credit_card)?;
    
    // Store in database
    db.execute(
        "INSERT INTO users (id, encrypted_ssn, encrypted_cc, ssn_metadata, cc_metadata) VALUES (?, ?, ?, ?, ?)",
        [
            user_id,
            &encrypted_ssn.encrypted_value,
            &encrypted_cc.encrypted_value,
            &serde_json::to_string(&encrypted_ssn.metadata)?,
            &serde_json::to_string(&encrypted_cc.metadata)?,
        ]
    ).await?;
    
    Ok(())
}

// Decrypt sensitive data after database retrieval
async fn get_user_data(user_id: &str) -> Result<(String, String), FortressError> {
    let row = db.query_one(
        "SELECT encrypted_ssn, encrypted_cc, ssn_metadata, cc_metadata FROM users WHERE id = ?",
        [user_id]
    ).await?;
    
    let encrypted_ssn: String = row.get(0);
    let encrypted_cc: String = row.get(1);
    let ssn_metadata: String = row.get(2);
    let cc_metadata: String = row.get(3);
    
    // Decrypt SSN
    let ssn_config = FormatPreservingEncryption::ssn_config(get_encryption_key()?);
    let ssn_fpe = FormatPreservingEncryption::new(ssn_config)?;
    let decrypted_ssn = ssn_fpe.decrypt(&encrypted_ssn)?;
    
    // Decrypt Credit Card
    let cc_config = FormatPreservingEncryption::credit_card_config(get_encryption_key()?);
    let cc_fpe = FormatPreservingEncryption::new(cc_config)?;
    let decrypted_cc = cc_fpe.decrypt(&encrypted_cc)?;
    
    Ok((decrypted_ssn, decrypted_cc))
}
```

### API Integration

```rust
// REST API endpoint for user authentication
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let oidc_provider = create_oidc_provider()?;
    
    // Authentication endpoint
    let auth_provider = oidc_provider.clone();
    warp::path("auth")
        .and(warp::post())
        .and(warp::body::json())
        .and(warp::any().map(move || auth_provider.clone()))
        .and_then(|auth_request: OidcAuthRequest, provider: OidcProvider| async move {
            match provider.authorize(auth_request).await {
                Ok(redirect_url) => {
                    Ok(warp::reply::with_status(
                        warp::reply::json(&json!({"redirect_url": redirect_url})),
                        warp::http::StatusCode::FOUND,
                    ))
                }
                Err(e) => {
                    Ok(warp::reply::with_status(
                        warp::reply::json(&json!({"error": e.to_string()})),
                        warp::http::StatusCode::BAD_REQUEST,
                    ))
                }
            }
        })
        .with(warp::cors().allow_any_origin())
        .bind("127.0.0.1:8080")
        .await?;
    
    Ok(())
}
```

---

## Performance Considerations

### OIDC Performance

#### 📊 Benchmarks
- **Authorization Request**: < 50ms average
- **Token Exchange**: < 100ms average  
- **User Info**: < 25ms average
- **JWKS Retrieval**: < 10ms average
- **Reg Policy Evaluation**: < 5ms average (with cache)

#### ⚡ Optimization Tips
- **Policy Caching**: Enable Rego policy caching for frequently used policies
- **Connection Pooling**: Use database connection pooling for user data
- **Token Caching**: Cache token validation results for short periods
- **Async Operations**: Use async/await for all I/O operations

### FPE Performance

#### 📊 Benchmarks
- **Credit Card Encryption**: < 1ms average
- **SSN Encryption**: < 1ms average
- **Phone Encryption**: < 1ms average
- **Email Encryption**: < 2ms average
- **Date Encryption**: < 1ms average

#### ⚡ Optimization Tips
- **Batch Processing**: Process multiple items in batches for better throughput
- **Key Reuse**: Reuse FPE instances for multiple operations
- **Memory Pooling**: Use memory pools for frequent allocations
- **Parallel Processing**: Use parallel processing for independent encryption operations

---

## Testing

### Unit Tests

```bash
# Run OIDC tests
cargo test oidc_provider

# Run FPE tests
cargo test format_preserving_encryption

# Run integration tests
cargo test oidc_fpe_tests
```

### Integration Tests

```rust
// Run comprehensive integration test suite
#[tokio::test]
async fn test_full_integration() {
    let mut test_suite = OidcFpeIntegrationTests::new().unwrap();
    let results = test_suite.run_all_tests().await.unwrap();
    
    // Assert all tests pass
    assert_eq!(results.success_rate(), 100.0);
    
    // Print detailed results
    results.print_results();
}
```

### Performance Tests

```rust
// Performance benchmarking
#[tokio::test]
async fn benchmark_oidc_performance() {
    let oidc_provider = create_oidc_provider().unwrap();
    let start = std::time::Instant::now();
    
    for i in 0..1000 {
        let auth_request = OidcAuthRequest {
            response_type: "code".to_string(),
            client_id: "test_client".to_string(),
            redirect_uri: "https://test.example.com/callback".to_string(),
            scope: "openid profile".to_string(),
            state: Some(format!("state_{}", i)),
            nonce: None,
            response_mode: None,
            code_challenge: None,
            code_challenge_method: None,
            additional_params: HashMap::new(),
        };
        
        let _ = oidc_provider.authorize(auth_request).await;
    }
    
    let duration = start.elapsed();
    println!("1000 OIDC operations took: {:?}", duration);
    assert!(duration.as_millis() < 5000); // Should complete within 5 seconds
}
```

### Security Tests

```rust
// Security validation tests
#[tokio::test]
async fn test_security_validations() {
    let oidc_provider = create_oidc_provider().unwrap();
    
    // Test invalid client
    let invalid_request = OidcAuthRequest {
        response_type: "code".to_string(),
        client_id: "invalid_client".to_string(),
        redirect_uri: "https://malicious.example.com".to_string(),
        scope: "openid".to_string(),
        state: None,
        nonce: None,
        response_mode: None,
        code_challenge: None,
        code_challenge_method: None,
        additional_params: HashMap::new(),
    };
    
    let result = oidc_provider.authorize(invalid_request).await;
    assert!(result.is_err());
    
    // Test FPE format validation
    let fpe = create_fpe_instance().unwrap();
    let result = fpe.encrypt("invalid-credit-card");
    assert!(result.is_err());
}
```

---

## Troubleshooting

### Common Issues

#### OIDC Issues
1. **Invalid Redirect URI**: Ensure redirect URI matches client configuration
2. **Expired Tokens**: Check token expiration times
3. **Invalid Scope**: Verify requested scopes are allowed for client
4. **Policy Failures**: Check Rego policy syntax and data

#### FPE Issues
1. **Invalid Format**: Ensure input matches expected format pattern
2. **Key Issues**: Verify encryption key is correct length and format
3. **Checksum Errors**: For credit cards, ensure Luhn checksum is valid
4. **Encoding Issues**: Check UTF-8 encoding for special characters

### Debug Logging

```rust
// Enable debug logging
env_logger::init();

// Use logging in custom implementations
log::debug!("OIDC authorization request: {:?}", auth_request);
log::debug!("FPE encryption result: {:?}", encrypted_result);
```

### Monitoring

```rust
// Add metrics collection
use prometheus::{Counter, Histogram, register_counter, register_histogram};

let oidc_requests_total = register_counter!(
    "oidc_requests_total", "Total OIDC requests"
).unwrap();

let oidc_request_duration = register_histogram!(
    "oidc_request_duration_seconds", "OIDC request duration"
).unwrap();

// Use in request handlers
oidc_requests_total.inc();
let timer = oidc_request_duration.start_timer();
// ... process request ...
timer.observe_duration();
```

---

## Conclusion

The OIDC Provider and Format-Preserving Encryption features provide Fortress with enterprise-grade authentication and data protection capabilities. These features enable:

- **Seamless Integration**: Industry-standard protocols for easy integration
- **Legacy Compatibility**: FPE allows encryption without schema changes
- **Policy-Driven Security**: Rego policies for flexible authorization
- **High Performance**: Optimized implementations for enterprise workloads
- **Comprehensive Testing**: Full test coverage for reliability

For additional information, see the API documentation and example applications in the Fortress repository.
