# Transit Engine Migration Guide

## Overview

This guide helps you migrate from Fortress's invasive **Database Wrapper** approach to the non-invasive **Security Sidecar/Transit Engine** pattern.

## Why Migrate?

### Database Wrapper Problems (Old Approach)
- **Invasive**: Requires replacing database drivers and schemas
- **Tight Coupling**: Fortress becomes part of your data layer
- **Complex Migration**: Requires database schema changes
- **Language Specific**: Rust-only implementations
- **Performance Overhead**: Database emulation adds latency
- **Maintenance Burden**: Need to sync Fortress and database versions

### Transit Engine Benefits (New Approach)
- **Non-Invasive**: Applications keep existing databases and drivers
- **Loose Coupling**: Fortress is a separate service
- **Easy Migration**: Incremental adoption possible
- **Language Agnostic**: HTTP/gRPC APIs work with any language
- **Better Performance**: Optimized for crypto operations
- **Independent Updates**: Update Fortress without touching databases

## Architecture Comparison

### Before: Database Wrapper
```
┌─────────────────┐    ┌─────────────────┐
│   Application   │───▶│ Fortress DB     │───▶│   Database     │
│                │    │    Wrapper     │    │                │
│ - Custom DB    │    │ - Replaces     │    │ - Standard DB   │
│   Drivers      │    │   drivers      │    │ - Managed by   │
│ - Modified     │    │ - Schema       │    │   Fortress     │
│   Schemas     │    │   changes      │    │                │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

### After: Security Sidecar
```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   Application   │───▶│  Transit Engine  │───▶│   Database     │
│                │    │                  │    │                │
│ - Standard DB   │    │ - Encrypt data   │    │ - App manages  │
│   Drivers      │    │ - Manage keys    │    │   own data     │
│ - Original     │    │ - Field-level    │    │ - Standard DB   │
│   Schemas     │    │ - HTTP/gRPC API │    │                │
└─────────────────┘    └──────────────────┘    └─────────────────┘
```

## Migration Steps

### Step 1: Deploy Transit Engine

1. **Deploy Transit Engine as a separate service**
   ```bash
   # Using Docker (recommended)
   docker run -d \
     --name fortress-transit \
     -p 8200:8200 \
     -p 9090:9090 \
     fortress/transit-engine:latest
   
   # Or build from source
   cargo build --release --bin fortress-transit
   ./target/release/fortress-transit --config transit.yaml
   ```

2. **Configure Transit Engine**
   ```yaml
   # transit.yaml
   server:
     http_bind_address: "0.0.0.0:8200"
     grpc_bind_address: "0.0.0.0:9090"
     require_auth: true
     jwt_secret: "your-secret-key"
   
   transit:
     default_algorithm: "aes256-gcm"
     auto_key_rotation: true
     cache_ttl_seconds: 3600
   ```

### Step 2: Update Application Code

#### Option A: HTTP API Integration (Recommended)

**Python Example:**
```python
import requests
import base64
import json

class FortressTransitClient:
    def __init__(self, base_url="http://localhost:8200", token=None):
        self.base_url = base_url
        self.token = token
        self.session = requests.Session()
        
        if token:
            self.session.headers.update({
                'Authorization': f'Bearer {token}'
            })
    
    def encrypt(self, plaintext, key_name, context=None):
        """Encrypt data using Transit Engine"""
        url = f"{self.base_url}/v1/transit/encrypt"
        
        payload = {
            "plaintext": plaintext,
            "key_name": key_name,
            "encoded": True
        }
        
        if context:
            payload["context"] = context
        
        response = self.session.post(url, json=payload)
        response.raise_for_status()
        
        return response.json()["data"]
    
    def decrypt(self, ciphertext, key_name, context=None):
        """Decrypt data using Transit Engine"""
        url = f"{self.base_url}/v1/transit/decrypt"
        
        payload = {
            "ciphertext": ciphertext,
            "key_name": key_name
        }
        
        if context:
            payload["context"] = context
        
        response = self.session.post(url, json=payload)
        response.raise_for_status()
        
        return response.json()["data"]

# Usage
transit = FortressTransitClient("http://fortress-transit:8200")

# Encrypt sensitive field
encrypted_email = transit.encrypt(
    plaintext="user@example.com",
    key_name="user-data-key",
    context={"field": "email", "user_id": 12345}
)

# Store encrypted data in your database
user_record = {
    "id": 12345,
    "name": "John Doe",
    "email": encrypted_email["ciphertext"]  # Store encrypted value
}

# Later, decrypt when needed
decrypted_email = transit.decrypt(
    ciphertext=user_record["email"],
    key_name="user-data-key",
    context={"field": "email", "user_id": 12345}
)

print(f"Decrypted: {decrypted_email['plaintext']}")
```

**Node.js Example:**
```javascript
const axios = require('axios');

class FortressTransitClient {
    constructor(baseUrl = 'http://localhost:8200', token = null) {
        this.baseUrl = baseUrl;
        this.token = token;
        
        if (token) {
            axios.defaults.headers.common['Authorization'] = `Bearer ${token}`;
        }
    }
    
    async encrypt(plaintext, keyName, context = null) {
        const response = await axios.post(`${this.baseUrl}/v1/transit/encrypt`, {
            plaintext,
            key_name: keyName,
            encoded: true,
            ...(context && { context })
        });
        
        return response.data.data;
    }
    
    async decrypt(ciphertext, keyName, context = null) {
        const response = await axios.post(`${this.baseUrl}/v1/transit/decrypt`, {
            ciphertext,
            key_name: keyName,
            ...(context && { context })
        });
        
        return response.data.data;
    }
}

// Usage
const transit = new FortressTransitClient('http://fortress-transit:8200');

// Encrypt data
const encrypted = await transit.encrypt(
    'sensitive-data',
    'app-key',
    { user_id: 12345, field: 'ssn' }
);

// Store in database
await db.users.insert({
    id: 12345,
    name: 'John Doe',
    ssn: encrypted.ciphertext  // Store encrypted
});

// Decrypt when needed
const decrypted = await transit.decrypt(
    encrypted.ciphertext,
    'app-key',
    { user_id: 12345, field: 'ssn' }
);

console.log(`Decrypted: ${decrypted.plaintext}`);
```

**Go Example:**
```go
package main

import (
    "bytes"
    "encoding/json"
    "fmt"
    "net/http"
)

type TransitClient struct {
    BaseURL string
    Token   string
    Client  *http.Client
}

type EncryptRequest struct {
    Plaintext string                 `json:"plaintext"`
    KeyName   string                 `json:"key_name"`
    Context   map[string]interface{}   `json:"context,omitempty"`
    Encoded   bool                   `json:"encoded"`
}

type EncryptResponse struct {
    Ciphertext string `json:"ciphertext"`
    KeyName   string `json:"key_name"`
    KeyVersion uint32 `json:"key_version"`
}

func NewTransitClient(baseURL, token string) *TransitClient {
    return &TransitClient{
        BaseURL: baseURL,
        Token:   token,
        Client:  &http.Client{},
    }
}

func (c *TransitClient) Encrypt(plaintext, keyName string, context map[string]interface{}) (*EncryptResponse, error) {
    req := EncryptRequest{
        Plaintext: plaintext,
        KeyName:   keyName,
        Context:   context,
        Encoded:   true,
    }
    
    body, _ := json.Marshal(req)
    
    httpReq, _ := http.NewRequest("POST", c.BaseURL+"/v1/transit/encrypt", bytes.NewBuffer(body))
    httpReq.Header.Set("Content-Type", "application/json")
    
    if c.Token != "" {
        httpReq.Header.Set("Authorization", "Bearer "+c.Token)
    }
    
    resp, err := c.Client.Do(httpReq)
    if err != nil {
        return nil, err
    }
    defer resp.Body.Close()
    
    var result struct {
        Data EncryptResponse `json:"data"`
    }
    json.NewDecoder(resp.Body).Decode(&result)
    
    return &result.Data, nil
}

func main() {
    client := NewTransitClient("http://localhost:8200", "your-token")
    
    // Encrypt data
    encrypted, err := client.Encrypt(
        "sensitive-data",
        "app-key",
        map[string]interface{}{"user_id": 12345},
    )
    
    if err != nil {
        panic(err)
    }
    
    fmt.Printf("Encrypted: %s\n", encrypted.Ciphertext)
}
```

#### Option B: Direct Rust Integration

```rust
use fortress_core::transit_api::{TransitApiServer, TransitEngine};
use serde_json::json;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Start Transit Engine in-process (for testing)
    let transit_engine = TransitEngine::new().await?;
    let api_server = TransitApiServer::new(transit_engine).await?;
    
    // Start API server in background
    tokio::spawn(async move {
        if let Err(e) = api_server.start().await {
            eprintln!("API server error: {}", e);
        }
    });
    
    // Use Transit Engine directly
    let encrypt_request = fortress_core::transit_engine_v2::EncryptRequest {
        plaintext: "sensitive-data".to_string(),
        key_name: "app-key".to_string(),
        algorithm: Some("aes256-gcm".to_string()),
        context: Some(json!({"user_id": 12345})),
        ttl_seconds: None,
        encoded: Some(true),
        associated_data: None,
    };
    
    let encrypt_response = transit_engine.encrypt(encrypt_request).await?;
    println!("Encrypted: {}", encrypt_response.ciphertext);
    
    // Store encrypt_response.ciphertext in your database
    
    Ok(())
}
```

### Step 3: Database Schema Updates

#### Option A: Store Encrypted Data (Recommended)
```sql
-- Before: Plain text columns
CREATE TABLE users (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    email TEXT NOT NULL,        -- Plain text
    ssn TEXT NOT NULL          -- Plain text
);

-- After: Encrypted columns
CREATE TABLE users (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL,          -- Keep non-sensitive data plain
    email_encrypted TEXT NOT NULL, -- Encrypted email
    ssn_encrypted TEXT NOT NULL,   -- Encrypted SSN
    email_key_name TEXT,          -- Track which key was used
    ssn_key_name TEXT             -- Track which key was used
);
```

#### Option B: Hybrid Approach (Keep Some Data Plain)
```sql
-- Encrypt only highly sensitive fields
CREATE TABLE users (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL,          -- Keep plain (non-sensitive)
    email_encrypted TEXT,        -- Encrypt email
    phone TEXT NOT NULL,          -- Keep phone plain (less sensitive)
    ssn_encrypted TEXT NOT NULL,   -- Encrypt SSN (highly sensitive)
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

### Step 4: Application Logic Updates

#### Before: Direct Database Access
```python
# Old approach with database wrapper
def create_user(name, email, ssn):
    # Database wrapper handles encryption automatically
    user = fortress_db.users.create(
        name=name,
        email=email,      # Plain text
        ssn=ssn          # Plain text
    )
    return user
```

#### After: Manual Encryption
```python
# New approach with Transit Engine
def create_user(name, email, ssn):
    # Encrypt sensitive fields
    encrypted_email = transit.encrypt(email, "user-email-key")
    encrypted_ssn = transit.encrypt(ssn, "user-ssn-key")
    
    # Store encrypted data
    user = db.users.create(
        name=name,                    # Keep plain
        email_encrypted=encrypted_email["ciphertext"],
        ssn_encrypted=encrypted_ssn["ciphertext"],
        email_key_name="user-email-key",
        ssn_key_name="user-ssn-key"
    )
    return user

def get_user_email(user_id):
    user = db.users.get(user_id)
    
    # Decrypt email when needed
    decrypted_email = transit.decrypt(
        user.email_encrypted,
        user.email_key_name
    )
    
    return {
        "name": user.name,
        "email": decrypted_email["plaintext"]
    }
```

## Field-Level Encryption Patterns

### Pattern 1: Per-Field Keys
```python
# Different keys for different data types
keys = {
    "email": "user-email-key",
    "ssn": "user-ssn-key",
    "credit_card": "payment-credit-card-key",
    "phone": "user-phone-key"
}

def encrypt_user_data(user_data):
    encrypted = {}
    for field, value in user_data.items():
        if field in keys:
            encrypted[field] = transit.encrypt(value, keys[field])
        else:
            encrypted[field] = value  # Keep non-sensitive fields plain
    
    return encrypted
```

### Pattern 2: Context-Based Encryption
```python
def encrypt_with_context(data, user_id, record_id):
    context = {
        "user_id": user_id,
        "record_id": record_id,
        "field": data["field_name"]
    }
    
    return transit.encrypt(
        data["value"],
        "app-key",
        context=context
    )
```

### Pattern 3: Batch Encryption
```python
def encrypt_batch(records):
    batch_request = {
        "items": [
            {
                "plaintext": record["email"],
                "key_name": "user-email-key",
                "encoded": True
            }
            for record in records
        ]
    }
    
    return transit.batch_encrypt(batch_request)
```

## Performance Considerations

### Caching
- **Enable Transit Engine caching** for frequently accessed data
- **Application-side caching** of decrypted values (with security considerations)
- **Batch operations** for multiple encryptions/decryptions

### Network Optimization
- **Connection pooling** for HTTP clients
- **Local Transit Engine** for high-throughput applications
- **Asynchronous operations** to avoid blocking

### Key Management
- **Key rotation** during maintenance windows
- **Key versioning** for seamless transitions
- **Key access logging** for audit trails

## Security Best Practices

### Authentication
```python
# Always use authentication tokens
transit = FortressTransitClient(
    base_url="https://fortress.company.com",
    token=get_auth_token()  # JWT or API key
)
```

### Context Usage
```python
# Use context to bind encryption to specific records
transit.encrypt(
    plaintext="sensitive-data",
    key_name="record-key",
    context={
        "user_id": user.id,
        "record_type": "profile",
        "field": "email"
    }
)
```

### Error Handling
```python
try:
    encrypted = transit.encrypt(data, key_name)
except FortressError as e:
    logger.error(f"Encryption failed: {e}")
    # Fallback or retry logic
    raise
```

## Testing the Migration

### 1. Parallel Deployment
- Keep existing database wrapper running
- Deploy Transit Engine alongside
- Test with non-critical data first

### 2. Data Validation
```python
# Validate encryption/decryption roundtrip
original = "test@example.com"
encrypted = transit.encrypt(original, "test-key")
decrypted = transit.decrypt(encrypted["ciphertext"], "test-key")

assert original == decrypted["plaintext"]
```

### 3. Performance Testing
```python
import time

# Test encryption performance
start = time.time()
for i in range(1000):
    transit.encrypt(f"data-{i}", "perf-test-key")
end = time.time()

print(f"1000 encryptions took {end - start:.2f} seconds")
```

## Rollback Plan

If issues arise during migration:

### Immediate Rollback
1. **Stop writing encrypted data**
2. **Switch back to database wrapper**
3. **Decrypt any newly encrypted data**

### Data Recovery
```python
# Decrypt data written during migration
def rollback_encrypted_data():
    for record in db.users.all():
        if record.email_encrypted:
            record.email = transit.decrypt(
                record.email_encrypted,
                record.email_key_name
            )["plaintext"]
            record.save()
```

## Troubleshooting

### Common Issues

#### 1. Connection Errors
```python
# Handle network issues to Transit Engine
try:
    encrypted = transit.encrypt(data, key_name)
except requests.ConnectionError:
    # Implement retry logic
    time.sleep(1)
    transit.encrypt(data, key_name)
```

#### 2. Key Not Found
```python
# Ensure keys exist before encryption
try:
    encrypted = transit.encrypt(data, key_name)
except FortressError as e:
    if "Key not found" in str(e):
        # Create key first
        transit.create_key(key_name)
        encrypted = transit.encrypt(data, key_name)
```

#### 3. Performance Issues
- **Enable caching** in Transit Engine configuration
- **Use batch operations** for multiple items
- **Consider local Transit Engine** for high throughput

### Monitoring

#### Transit Engine Metrics
```bash
# Check Transit Engine health
curl http://localhost:8200/health

# Get performance metrics
curl http://localhost:8200/v1/transit/stats
```

#### Application Metrics
```python
# Track encryption/decryption performance
import time

def timed_encrypt(data, key_name):
    start = time.time()
    result = transit.encrypt(data, key_name)
    duration = time.time() - start
    
    # Log to monitoring system
    monitoring.log_metric("encrypt_duration", duration)
    
    return result
```

## Support

### Documentation
- [Transit Engine API Reference](./TRANSIT_API_REFERENCE.md)
- [Configuration Guide](./TRANSIT_CONFIGURATION.md)
- [Security Best Practices](./SECURITY_BEST_PRACTICES.md)

### Community
- GitHub Issues: [Fortress Issues](https://github.com/fortress/fortress/issues)
- Discord: [Fortress Community](https://discord.gg/fortress)
- Documentation: [Fortress Docs](https://docs.fortress.dev)
