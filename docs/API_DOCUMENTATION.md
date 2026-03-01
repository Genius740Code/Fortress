# Fortress REST API Documentation

## Overview

The Fortress REST API provides a secure, encrypted database interface with automatic encryption/decryption, key management, and comprehensive security features.

## Base URL

```
http://localhost:8080
```

## Authentication

The API supports JWT-based authentication. Include the token in the Authorization header:

```
Authorization: Bearer <your-jwt-token>
```

## Core Endpoints

### Health Check

Check if the server is running and healthy.

**GET** `/health`

**Response:**
```json
{
  "data": {
    "status": "healthy",
    "timestamp": "2024-01-01T00:00:00Z",
    "version": "0.1.0"
  },
  "success": true,
  "timestamp": "2024-01-01T00:00:00Z"
}
```

### Store Data

Store encrypted data in the database.

**POST** `/data`

**Request Body:**
```json
{
  "data": {
    "name": "John Doe",
    "email": "john@example.com",
    "age": 30,
    "address": {
      "street": "123 Main St",
      "city": "Anytown",
      "country": "USA"
    }
  },
  "metadata": {
    "source": "user-input",
    "version": "1.0"
  },
  "algorithm": "aegis256",
  "key_id": "optional-existing-key-id",
  "tenant_id": "optional-tenant-id",
  "field_encryption": {
    "fields": {
      "email": {
        "algorithm": "aes256gcm",
        "key_id": "email-key-id",
        "sensitivity": "high"
      },
      "ssn": {
        "algorithm": "aes256gcm",
        "key_id": "ssn-key-id",
        "sensitivity": "critical"
      }
    }
  }
}
```

**Response:**
```json
{
  "data": {
    "id": "uuid-generated-id",
    "key_id": "key-id-used",
    "stored_at": "2024-01-01T00:00:00Z",
    "size_bytes": 1024,
    "algorithm": "aegis256",
    "field_metadata": {
      "email": {
        "config_id": "default",
        "field": "email",
        "algorithm": "aes256gcm",
        "key_id": "email-key-id",
        "key_version": 1,
        "encrypted_at": "2024-01-01T00:00:00Z",
        "nonce": null,
        "tag": null,
        "metadata": {}
      }
    }
  },
  "success": true,
  "timestamp": "2024-01-01T00:00:00Z"
}
```

### Retrieve Data

Retrieve and decrypt data from the database.

**GET** `/data/{id}`

**Query Parameters:**
- `include_encrypted` (optional): Set to `true` to include raw encrypted data

**Response:**
```json
{
  "data": {
    "data": {
      "name": "John Doe",
      "email": "john@example.com",
      "age": 30,
      "address": {
        "street": "123 Main St",
        "city": "Anytown",
        "country": "USA"
      }
    },
    "metadata": {
      "source": "user-input",
      "version": "1.0"
    },
    "retrieved_at": "2024-01-01T00:00:00Z",
    "stored_at": "2024-01-01T00:00:00Z",
    "algorithm": "aegis256",
    "key_id": "key-id-used",
    "encrypted_data": null,
    "field_metadata": {
      "email": {
        "config_id": "default",
        "field": "email",
        "algorithm": "aes256gcm",
        "key_id": "email-key-id",
        "key_version": 1,
        "encrypted_at": "2024-01-01T00:00:00Z",
        "nonce": null,
        "tag": null,
        "metadata": {}
      }
    }
  },
  "success": true,
  "timestamp": "2024-01-01T00:00:00Z"
}
```

### List Data

List all stored data with optional filtering and pagination.

**GET** `/data`

**Query Parameters:**
- `tenant_id` (optional): Filter by tenant ID
- `page` (optional): Page number (default: 1)
- `page_size` (optional): Items per page (default: 50)
- `sort_by` (optional): Field to sort by
- `sort_order` (optional): `asc` or `desc` (default: `desc`)

**Response:**
```json
{
  "data": [
    {
      "id": "item-id-1",
      "key_id": "key-id-1",
      "created_at": "2024-01-01T00:00:00Z",
      "algorithm": "aegis256",
      "metadata": {}
    }
  ],
  "success": true,
  "timestamp": "2024-01-01T00:00:00Z",
  "metadata": {
    "total_count": 100,
    "page": {
      "page": 1,
      "page_size": 50,
      "total_pages": 2,
      "has_next": true,
      "has_previous": false
    }
  }
}
```

### Delete Data

Delete data from the database.

**DELETE** `/data/{id}`

**Request Body:**
```json
{
  "confirm": true
}
```

**Response:**
```json
{
  "data": {
    "id": "deleted-item-id",
    "deleted_at": "2024-01-01T00:00:00Z"
  },
  "success": true,
  "timestamp": "2024-01-01T00:00:00Z"
}
```

### Generate Key

Generate a new encryption key.

**POST** `/keys`

**Request Body:**
```json
{
  "algorithm": "aegis256",
  "metadata": {
    "purpose": "user-data-encryption",
    "created_by": "user-123"
  }
}
```

**Response:**
```json
{
  "data": {
    "key_id": "new-key-id",
    "algorithm": "aegis256",
    "created_at": "2024-01-01T00:00:00Z",
    "public_key": "base64-encoded-public-key",
    "fingerprint": "hex-encoded-fingerprint"
  },
  "success": true,
  "timestamp": "2024-01-01T00:00:00Z"
}
```

## Authentication Endpoints

### Login

Authenticate and obtain a JWT token.

**POST** `/auth/login`

**Request Body:**
```json
{
  "username": "john.doe",
  "password": "secure-password",
  "tenant_id": "optional-tenant-id"
}
```

**Response:**
```json
{
  "data": {
    "token": "jwt-token-string",
    "expires_at": "2024-01-01T01:00:00Z",
    "user": {
      "id": "user-123",
      "username": "john.doe",
      "email": "john@example.com",
      "roles": ["user", "admin"]
    }
  },
  "success": true,
  "timestamp": "2024-01-01T00:00:00Z"
}
```

### Refresh Token

Refresh an existing JWT token.

**POST** `/auth/refresh`

**Request Body:**
```json
{
  "token": "current-jwt-token"
}
```

**Response:**
```json
{
  "data": {
    "token": "new-jwt-token",
    "expires_at": "2024-01-01T01:00:00Z"
  },
  "success": true,
  "timestamp": "2024-01-01T00:00:00Z"
}
```

## Metrics Endpoints

### Get Metrics

Get application metrics in JSON format.

**GET** `/metrics`

**Response:**
```json
{
  "metrics": {
    "requests_total": 1000,
    "requests_success": 950,
    "requests_error": 50,
    "response_time_avg_ms": 150,
    "active_connections": 25,
    "storage_operations": 500,
    "encryption_operations": 750
  },
  "timestamp": "2024-01-01T00:00:00Z"
}
```

### Get Prometheus Metrics

Get metrics in Prometheus format for monitoring systems.

**GET** `/metrics/prometheus`

**Response:**
```
# HELP fortress_requests_total Total number of requests
# TYPE fortress_requests_total counter
fortress_requests_total{method="GET",status="200"} 950
fortress_requests_total{method="POST",status="200"} 45
fortress_requests_total{method="GET",status="404"} 5

# HELP fortress_response_time_ms Response time in milliseconds
# TYPE fortress_response_time_ms histogram
fortress_response_time_ms_bucket{le="10"} 100
fortress_response_time_ms_bucket{le="50"} 300
fortress_response_time_ms_bucket{le="100"} 450
fortress_response_time_ms_bucket{le="+Inf"} 500
```

## Error Responses

All endpoints return errors in the following format:

```json
{
  "success": false,
  "error": "Error message describing what went wrong",
  "error_code": "ERROR_CODE",
  "timestamp": "2024-01-01T00:00:00Z"
}
```

### Common Error Codes

- `UNAUTHORIZED` (401): Authentication required or invalid
- `FORBIDDEN` (403): Insufficient permissions
- `NOT_FOUND` (404): Resource not found
- `VALIDATION_ERROR` (400): Invalid request data
- `RATE_LIMITED` (429): Too many requests
- `INTERNAL_ERROR` (500): Server error

## Rate Limiting

The API implements rate limiting with the following defaults:

- **Requests per minute**: 60
- **Burst capacity**: 10
- **DDoS protection**: Enabled

Rate limit headers are included in responses:

```
X-RateLimit-Limit: 60
X-RateLimit-Remaining: 45
X-RateLimit-Reset: 1640995200
```

## Security Features

### Encryption

- **Default algorithm**: AEGIS-256
- **Supported algorithms**: AEGIS-256, AES-256-GCM, ChaCha20-Poly1305
- **Field-level encryption**: Supported for sensitive fields
- **Key management**: Automatic key generation and rotation

### Authentication

- **JWT tokens**: RS256 signed
- **Token expiration**: Configurable (default: 24 hours)
- **Multi-tenant support**: Isolated data per tenant

### DDoS Protection

- **Request rate limiting**: Multiple algorithms
- **IP-based blocking**: Automatic for suspicious patterns
- **Request size limits**: Configurable (default: 10MB)

## Usage Examples

### Python Example

```python
import requests
import json

# Base URL
BASE_URL = "http://localhost:8080"

# Store data
def store_data():
    data = {
        "data": {
            "name": "John Doe",
            "email": "john@example.com"
        },
        "metadata": {"source": "example"}
    }
    
    response = requests.post(f"{BASE_URL}/data", json=data)
    return response.json()

# Retrieve data
def retrieve_data(data_id):
    response = requests.get(f"{BASE_URL}/data/{data_id}")
    return response.json()

# Example usage
if __name__ == "__main__":
    # Store data
    result = store_data()
    print("Stored:", result)
    
    if result["success"]:
        data_id = result["data"]["id"]
        
        # Retrieve data
        retrieved = retrieve_data(data_id)
        print("Retrieved:", retrieved)
```

### JavaScript Example

```javascript
const BASE_URL = 'http://localhost:8080';

// Store data
async function storeData() {
    const data = {
        data: {
            name: 'John Doe',
            email: 'john@example.com'
        },
        metadata: { source: 'example' }
    };
    
    const response = await fetch(`${BASE_URL}/data`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify(data)
    });
    
    return await response.json();
}

// Retrieve data
async function retrieveData(dataId) {
    const response = await fetch(`${BASE_URL}/data/${dataId}`);
    return await response.json();
}

// Example usage
(async () => {
    // Store data
    const result = await storeData();
    console.log('Stored:', result);
    
    if (result.success) {
        const dataId = result.data.id;
        
        // Retrieve data
        const retrieved = await retrieveData(dataId);
        console.log('Retrieved:', retrieved);
    }
})();
```

### Rust Example

```rust
use reqwest;
use serde_json::json;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = reqwest::Client::new();
    let base_url = "http://localhost:8080";
    
    // Store data
    let data = json!({
        "data": {
            "name": "John Doe",
            "email": "john@example.com"
        },
        "metadata": {"source": "example"}
    });
    
    let response = client
        .post(&format!("{}/data", base_url))
        .json(&data)
        .send()
        .await?;
    
    let result: serde_json::Value = response.json().await?;
    println!("Stored: {}", result);
    
    if result["success"].as_bool().unwrap_or(false) {
        let data_id = result["data"]["id"].as_str().unwrap();
        
        // Retrieve data
        let retrieve_response = client
            .get(&format!("{}/data/{}", base_url, data_id))
            .send()
            .await?;
        
        let retrieved: serde_json::Value = retrieve_response.json().await?;
        println!("Retrieved: {}", retrieved);
    }
    
    Ok(())
}
```

## Configuration

The server can be configured with environment variables or configuration files:

### Environment Variables

```bash
# Server configuration
FORTRESS_HOST=0.0.0.0
FORTRESS_PORT=8080
FORTRESS_MAX_BODY_SIZE=10485760

# Security configuration
FORTRESS_JWT_SECRET=your-secret-key
FORTRESS_TOKEN_EXPIRATION=86400

# Rate limiting
FORTRESS_RATE_LIMIT_PER_MINUTE=60
FORTRESS_RATE_LIMIT_BURST=10

# Storage configuration
FORTRESS_STORAGE_TYPE=memory
FORTRESS_STORAGE_PATH=/data/fortress
```

### Configuration File

```json
{
  "network": {
    "host": "0.0.0.0",
    "port": 8080,
    "max_body_size": 10485760,
    "request_timeout": 30
  },
  "security": {
    "jwt_secret": "your-secret-key",
    "token_expiration": 86400,
    "rate_limit": {
      "algorithm": "token_bucket",
      "requests_per_minute": 60,
      "burst": 10
    }
  },
  "storage": {
    "backend_type": "memory"
  },
  "features": {
    "auth_enabled": true,
    "field_encryption_enabled": true
  }
}
```

## SDKs and Libraries

Official Fortress SDKs are available for:

- **Rust**: `fortress-core` crate
- **Python**: `fortress-python` package
- **JavaScript/TypeScript**: `fortress-js` package
- **Go**: `fortress-go` module

## Support

- **Documentation**: https://docs.fortress-db.com
- **GitHub**: https://github.com/Genius740Code/Fortress
- **Issues**: https://github.com/Genius740Code/Fortress/issues
- **Community**: https://discord.gg/fortress
