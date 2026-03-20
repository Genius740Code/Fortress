# 📚 Fortress API Examples

## 🔐 Authentication

### Login and Get Token

```bash
curl -X POST http://localhost:8080/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "admin",
    "password": "your-password"
  }'
```

Response:
```json
{
  "success": true,
  "data": {
    "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "expires_in": 3600,
    "user": {
      "id": "user-123",
      "username": "admin",
      "roles": ["admin"]
    }
  }
}
```

---

## 🔑 Key Management

### Generate a New Key

```bash
curl -X POST http://localhost:8080/api/v1/keys \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "my-encryption-key",
    "algorithm": "aes256-gcm",
    "size": 256,
    "metadata": {
      "purpose": "data-encryption",
      "owner": "team-alpha"
    }
  }'
```

Response:
```json
{
  "success": true,
  "data": {
    "id": "key-456",
    "name": "my-encryption-key",
    "algorithm": "aes256-gcm",
    "size": 256,
    "created_at": "2024-01-15T10:30:00Z",
    "status": "active",
    "fingerprint": "a1b2c3d4e5f6...",
    "metadata": {
      "purpose": "data-encryption",
      "owner": "team-alpha"
    }
  }
}
```

### List All Keys

```bash
curl -X GET http://localhost:8080/api/v1/keys \
  -H "Authorization: Bearer YOUR_TOKEN"
```

Response:
```json
{
  "success": true,
  "data": [
    {
      "id": "key-456",
      "name": "my-encryption-key",
      "algorithm": "aes256-gcm",
      "status": "active",
      "created_at": "2024-01-15T10:30:00Z"
    },
    {
      "id": "key-789",
      "name": "signing-key",
      "algorithm": "rsa2048",
      "status": "active",
      "created_at": "2024-01-14T15:20:00Z"
    }
  ]
}
```

### Get Key Details

```bash
curl -X GET http://localhost:8080/api/v1/keys/key-456 \
  -H "Authorization: Bearer YOUR_TOKEN"
```

---

## 🔐 Encryption Operations

### Encrypt Data

```bash
curl -X POST http://localhost:8080/api/v1/encrypt \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "key_id": "key-456",
    "plaintext": "This is secret data that needs encryption",
    "algorithm": "aes256-gcm",
    "additional_data": "context-info"
  }'
```

Response:
```json
{
  "success": true,
  "data": {
    "ciphertext": "base64-encoded-encrypted-data...",
    "iv": "base64-encoded-iv...",
    "tag": "base64-encoded-auth-tag...",
    "algorithm": "aes256-gcm",
    "key_id": "key-456",
    "encrypted_at": "2024-01-15T11:00:00Z"
  }
}
```

### Decrypt Data

```bash
curl -X POST http://localhost:8080/api/v1/decrypt \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "key_id": "key-456",
    "ciphertext": "base64-encoded-encrypted-data...",
    "iv": "base64-encoded-iv...",
    "tag": "base64-encoded-auth-tag...",
    "algorithm": "aes256-gcm",
    "additional_data": "context-info"
  }'
```

Response:
```json
{
  "success": true,
  "data": {
    "plaintext": "This is secret data that needs encryption",
    "decrypted_at": "2024-01-15T11:05:00Z",
    "key_id": "key-456"
  }
}
```

---

## ✍️ Digital Signatures

### Sign Data

```bash
curl -X POST http://localhost:8080/api/v1/sign \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "key_id": "key-789",
    "data": "data-to-be-signed",
    "hash_algorithm": "sha256"
  }'
```

Response:
```json
{
  "success": true,
  "data": {
    "signature": "base64-encoded-signature...",
    "algorithm": "rsa2048",
    "hash_algorithm": "sha256",
    "key_id": "key-789",
    "signed_at": "2024-01-15T11:10:00Z"
  }
}
```

### Verify Signature

```bash
curl -X POST http://localhost:8080/api/v1/verify \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "key_id": "key-789",
    "data": "data-to-be-signed",
    "signature": "base64-encoded-signature...",
    "hash_algorithm": "sha256"
  }'
```

Response:
```json
{
  "success": true,
  "data": {
    "valid": true,
    "key_id": "key-789",
    "verified_at": "2024-01-15T11:15:00Z"
  }
}
```

---

## 💾 Storage Operations

### Store Encrypted Data

```bash
curl -X POST http://localhost:8080/api/v1/storage \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "key": "user:123:profile",
    "data": "encrypted-user-profile-data...",
    "encryption_key_id": "key-456",
    "metadata": {
      "content_type": "user-profile",
      "owner": "user-123",
      "tags": ["profile", "personal"]
    },
    "ttl_seconds": 86400
  }'
```

Response:
```json
{
  "success": true,
  "data": {
    "key": "user:123:profile",
    "stored_at": "2024-01-15T11:20:00Z",
    "size_bytes": 1024,
    "expires_at": "2024-01-16T11:20:00Z"
  }
}
```

### Retrieve Data

```bash
curl -X GET http://localhost:8080/api/v1/storage/user:123:profile \
  -H "Authorization: Bearer YOUR_TOKEN"
```

Response:
```json
{
  "success": true,
  "data": {
    "key": "user:123:profile",
    "data": "encrypted-user-profile-data...",
    "metadata": {
      "content_type": "user-profile",
      "owner": "user-123",
      "tags": ["profile", "personal"]
    },
    "retrieved_at": "2024-01-15T11:25:00Z"
  }
}
```

---

## 🗄️ Cache Operations

### Cache Data

```bash
curl -X POST http://localhost:8080/api/v1/cache \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "key": "session:user-456",
    "value": "cached-session-data...",
    "ttl_seconds": 3600,
    "tags": ["session", "user"]
  }'
```

Response:
```json
{
  "success": true,
  "data": {
    "key": "session:user-456",
    "cached_at": "2024-01-15T11:30:00Z",
    "ttl_seconds": 3600
  }
}
```

### Get Cached Data

```bash
curl -X GET http://localhost:8080/api/v1/cache/session:user-456 \
  -H "Authorization: Bearer YOUR_TOKEN"
```

Response:
```json
{
  "success": true,
  "data": {
    "key": "session:user-456",
    "value": "cached-session-data...",
    "cached_at": "2024-01-15T11:30:00Z",
    "expires_at": "2024-01-15T12:30:00Z",
    "hit_count": 5
  }
}
```

### Invalidate Cache

```bash
curl -X DELETE http://localhost:8080/api/v1/cache/session:user-456 \
  -H "Authorization: Bearer YOUR_TOKEN"
```

---

## 📊 Monitoring & Metrics

### Get System Metrics

```bash
curl -X GET http://localhost:8080/api/v1/metrics \
  -H "Authorization: Bearer YOUR_TOKEN"
```

Response:
```json
{
  "success": true,
  "data": {
    "system": {
      "uptime_seconds": 86400,
      "cpu_usage_percent": 25.5,
      "memory_usage_mb": 512,
      "disk_usage_percent": 45.2
    },
    "operations": {
      "total_requests": 1000000,
      "requests_per_second": 150.5,
      "avg_response_time_ms": 25.3,
      "error_rate_percent": 0.1
    },
    "caching": {
      "hit_ratio": 0.85,
      "total_entries": 50000,
      "cache_size_mb": 256,
      "evictions_per_hour": 100
    },
    "security": {
      "active_keys": 1250,
      "failed_authentications": 15,
      "rate_limit_violations": 5
    }
  }
}
```

### Health Check

```bash
curl -X GET http://localhost:8080/health
```

Response:
```json
{
  "status": "healthy",
  "timestamp": "2024-01-15T11:35:00Z",
  "version": "1.0.2",
  "checks": {
    "database": "healthy",
    "cache": "healthy",
    "encryption": "healthy",
    "storage": "healthy"
  }
}
```

---

## 👥 User Management

### Create User

```bash
curl -X POST http://localhost:8080/api/v1/users \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "newuser",
    "email": "newuser@example.com",
    "password": "secure-password",
    "roles": ["user"],
    "metadata": {
      "department": "engineering",
      "team": "platform"
    }
  }'
```

### List Users

```bash
curl -X GET http://localhost:8080/api/v1/users \
  -H "Authorization: Bearer YOUR_TOKEN"
```

---

## 🔍 Search & Query

### Search Keys

```bash
curl -X GET "http://localhost:8080/api/v1/keys/search?q=encryption&algorithm=aes256" \
  -H "Authorization: Bearer YOUR_TOKEN"
```

### Query Storage

```bash
curl -X GET "http://localhost:8080/api/v1/storage/search?tag=profile&owner=user-123" \
  -H "Authorization: Bearer YOUR_TOKEN"
```

---

## 📋 Batch Operations

### Batch Encrypt

```bash
curl -X POST http://localhost:8080/api/v1/batch/encrypt \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "key_id": "key-456",
    "items": [
      {"id": "item1", "data": "data1"},
      {"id": "item2", "data": "data2"},
      {"id": "item3", "data": "data3"}
    ]
  }'
```

Response:
```json
{
  "success": true,
  "data": {
    "results": [
      {"id": "item1", "ciphertext": "...", "success": true},
      {"id": "item2", "ciphertext": "...", "success": true},
      {"id": "item3", "ciphertext": "...", "success": true}
    ],
    "processed_count": 3,
    "failed_count": 0
  }
}
```

---

## 🚨 Error Handling

### Error Response Format

```json
{
  "success": false,
  "error": {
    "code": "INVALID_KEY_ID",
    "message": "The specified key ID does not exist",
    "details": {
      "key_id": "invalid-key-123",
      "timestamp": "2024-01-15T11:40:00Z"
    }
  }
}
```

### Common Error Codes

- `UNAUTHORIZED`: Invalid or missing authentication token
- `FORBIDDEN`: Insufficient permissions for the operation
- `INVALID_KEY_ID`: Specified key does not exist
- `ENCRYPTION_FAILED`: Encryption operation failed
- `DECRYPTION_FAILED`: Decryption operation failed
- `VALIDATION_ERROR`: Invalid request parameters
- `RATE_LIMIT_EXCEEDED`: Too many requests
- `INTERNAL_ERROR`: Server-side error

---

## 📝 SDK Examples

### Rust SDK

```rust
use fortress_sdk::{FortressClient, Config};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = Config::builder()
        .endpoint("http://localhost:8080")
        .token("your-token")
        .build();

    let client = FortressClient::new(config)?;

    // Generate a key
    let key = client.keys()
        .create("my-key", Algorithm::Aes256Gcm)
        .await?;

    // Encrypt data
    let encrypted = client.encrypt()
        .key_id(&key.id)
        .data(b"secret data")
        .await?;

    // Decrypt data
    let decrypted = client.decrypt()
        .key_id(&key.id)
        .ciphertext(&encrypted.ciphertext)
        .await?;

    println!("Decrypted: {:?}", String::from_utf8(decrypted.plaintext)?);

    Ok(())
}
```

### Python SDK

```python
from fortress_sdk import FortressClient, Algorithm

client = FortressClient(
    endpoint="http://localhost:8080",
    token="your-token"
)

# Generate a key
key = client.keys.create("my-key", Algorithm.AES256_GCM)

# Encrypt data
encrypted = client.encrypt.encrypt(
    key_id=key.id,
    data=b"secret data"
)

# Decrypt data
decrypted = client.decrypt.decrypt(
    key_id=key.id,
    ciphertext=encrypted.ciphertext
)

print(f"Decrypted: {decrypted.plaintext.decode()}")
```

---

## 🧪 Testing

### Load Testing Example

```bash
# Install hey (HTTP load testing tool)
go install github.com/rakyll/hey@latest

# Test encryption endpoint
hey -n 1000 -c 10 -m POST \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"key_id": "key-456", "plaintext": "test data"}' \
  http://localhost:8080/api/v1/encrypt

# Test cache endpoint
hey -n 5000 -c 20 \
  -H "Authorization: Bearer YOUR_TOKEN" \
  http://localhost:8080/api/v1/cache/test-key
```

---

## 📚 Additional Resources

- **OpenAPI Specification**: http://localhost:8080/openapi.json
- **Interactive API Docs**: http://localhost:8080/docs
- **SDK Documentation**: https://docs.fortress.security/sdk
- **Best Practices**: https://docs.fortress.security/best-practices

---

**🚀 These examples cover the most common Fortress API operations. For more advanced usage, refer to the complete API documentation.**
