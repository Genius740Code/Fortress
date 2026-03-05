# Fortress API Documentation

## Table of Contents

1. [Overview](#overview)
2. [Authentication](#authentication)
3. [Core API Endpoints](#core-api-endpoints)
4. [Database Management](#database-management)
5. [Table Management](#table-management)
6. [Data Operations](#data-operations)
7. [Encryption Management](#encryption-management)
8. [Key Management](#key-management)
9. [Audit & Compliance](#audit--compliance)
10. [Cluster Operations](#cluster-operations)
11. [Tenant Management](#tenant-management)
12. [Plugin Management](#plugin-management)
13. [Monitoring & Health](#monitoring--health)
14. [Error Handling](#error-handling)
15. [Rate Limiting](#rate-limiting)
16. [SDK Examples](#sdk-examples)

## Overview

Fortress provides a comprehensive REST API for secure data storage with automatic encryption. The API is designed to be intuitive while providing enterprise-grade security features.

### Base URL
```
http://localhost:8080/api/v1
```

### Authentication Methods
- JWT Bearer Tokens
- API Keys
- Basic Authentication (development only)

### Response Format
All API responses follow a consistent format:

```json
{
  "data": { ... },
  "success": true,
  "timestamp": "2026-01-15T10:30:00Z",
  "metadata": {
    "request_id": "req_123456789",
    "version": "0.1.0"
  }
}
```

## Authentication

### Login
```http
POST /auth/login
Content-Type: application/json

{
  "username": "admin",
  "password": "secure-password",
  "tenant_id": "optional-tenant-id"
}
```

**Response:**
```json
{
  "data": {
    "token": "eyJhbGciOiJIUzI1NiIs...",
    "refresh_token": "eyJhbGciOiJIUzI1NiIs...",
    "expires_at": "2026-01-15T11:30:00Z",
    "user": {
      "id": "user_123",
      "username": "admin",
      "roles": ["admin"],
      "tenant_id": "tenant_456"
    }
  },
  "success": true
}
```

### Refresh Token
```http
POST /auth/refresh
Content-Type: application/json

{
  "refresh_token": "eyJhbGciOiJIUzI1NiIs..."
}
```

### Logout
```http
POST /auth/logout
Authorization: Bearer your-jwt-token
```

## Core API Endpoints

### Health Check
```http
GET /health
```

**Response:**
```json
{
  "status": "healthy",
  "version": "0.1.0",
  "uptime": 3600,
  "components": {
    "database": { "status": "healthy", "response_time_ms": 15 },
    "encryption": { "status": "healthy", "response_time_ms": 25 },
    "storage": { "status": "healthy", "response_time_ms": 10 }
  },
  "timestamp": "2026-01-15T10:30:00Z"
}
```

### Metrics
```http
GET /metrics
```

**Response:**
```json
{
  "metrics": {
    "requests_total": 15420,
    "requests_success": 15380,
    "requests_error": 40,
    "response_time_avg_ms": 125,
    "encryption_ops_total": 8920,
    "active_connections": 45,
    "storage_size_bytes": 1048576000
  },
  "timestamp": "2026-01-15T10:30:00Z"
}
```

## Database Management

### Create Database
```http
POST /databases
Authorization: Bearer your-jwt-token
Content-Type: application/json

{
  "name": "myapp_db",
  "algorithm": "aegis256",
  "key_rotation_interval": "24h",
  "storage_path": "./data/myapp_db",
  "encryption_profile": "balanced",
  "metadata": {
    "description": "Main application database",
    "owner": "app-team"
  }
}
```

**Response:**
```json
{
  "data": {
    "id": "db_123456",
    "name": "myapp_db",
    "status": "active",
    "created_at": "2026-01-15T10:30:00Z",
    "algorithm": "aegis256",
    "key_rotation_interval": "24h",
    "encryption_profile": "balanced"
  },
  "success": true
}
```

### List Databases
```http
GET /databases
Authorization: Bearer your-jwt-token
```

**Response:**
```json
{
  "data": [
    {
      "id": "db_123456",
      "name": "myapp_db",
      "status": "active",
      "created_at": "2026-01-15T10:30:00Z",
      "size_bytes": 1048576,
      "tables_count": 5
    }
  ],
  "success": true,
  "metadata": {
    "total": 1,
    "page": 1,
    "page_size": 50
  }
}
```

### Get Database Info
```http
GET /databases/{database_id}
Authorization: Bearer your-jwt-token
```

### Delete Database
```http
DELETE /databases/{database_id}
Authorization: Bearer your-jwt-token
```

## Table Management

### Create Table
```http
POST /databases/{database_id}/tables
Authorization: Bearer your-jwt-token
Content-Type: application/json

{
  "name": "users",
  "columns": [
    {
      "name": "id",
      "type": "uuid",
      "primary_key": true,
      "nullable": false
    },
    {
      "name": "name",
      "type": "text",
      "nullable": false,
      "max_length": 255
    },
    {
      "name": "email",
      "type": "text",
      "nullable": false,
      "unique": true
    },
    {
      "name": "password",
      "type": "encrypted",
      "encryption": "fortress",
      "sensitivity": "high"
    },
    {
      "name": "created_at",
      "type": "timestamp",
      "default": "now()"
    }
  ],
  "encryption": "balanced",
  "indexes": [
    {
      "name": "idx_email",
      "columns": ["email"],
      "unique": true
    }
  ]
}
```

**Response:**
```json
{
  "data": {
    "id": "table_789012",
    "name": "users",
    "status": "active",
    "created_at": "2026-01-15T10:30:00Z",
    "columns": [...],
    "encryption_metadata": {
      "algorithm": "aegis256",
      "field_encryption": {
        "password": {
          "algorithm": "aes256gcm",
          "key_id": "key_password_123"
        }
      }
    }
  },
  "success": true
}
```

### List Tables
```http
GET /databases/{database_id}/tables
Authorization: Bearer your-jwt-token
```

### Get Table Schema
```http
GET /databases/{database_id}/tables/{table_name}/schema
Authorization: Bearer your-jwt-token
```

### Drop Table
```http
DELETE /databases/{database_id}/tables/{table_name}
Authorization: Bearer your-jwt-token
```

## Data Operations

### Insert Data
```http
POST /databases/{database_id}/tables/{table_name}/data
Authorization: Bearer your-jwt-token
Content-Type: application/json

{
  "data": {
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "name": "Alice Johnson",
    "email": "alice@example.com",
    "password": "secure-password-123"
  },
  "returning": ["id", "name", "email"]
}
```

**Response:**
```json
{
  "data": {
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "name": "Alice Johnson",
    "email": "alice@example.com",
    "created_at": "2026-01-15T10:30:00Z"
  },
  "success": true
}
```

### Query Data
```http
GET /databases/{database_id}/tables/{table_name}/data?page=1&page_size=50&sort=created_at&order=desc&filter=name=Alice
Authorization: Bearer your-jwt-token
```

**Query Parameters:**
- `page`: Page number (default: 1)
- `page_size`: Items per page (default: 50, max: 1000)
- `sort`: Sort column
- `order`: Sort order (asc/desc)
- `filter`: Filter expression
- `fields`: Comma-separated fields to return

**Response:**
```json
{
  "data": [
    {
      "id": "550e8400-e29b-41d4-a716-446655440000",
      "name": "Alice Johnson",
      "email": "alice@example.com",
      "created_at": "2026-01-15T10:30:00Z"
    }
  ],
  "success": true,
  "metadata": {
    "total": 1,
    "page": 1,
    "page_size": 50,
    "has_next": false,
    "has_prev": false
  }
}
```

### Update Data
```http
PUT /databases/{database_id}/tables/{table_name}/data/{record_id}
Authorization: Bearer your-jwt-token
Content-Type: application/json

{
  "data": {
    "name": "Alice Smith",
    "email": "alice.smith@example.com"
  },
  "returning": ["id", "name", "email", "updated_at"]
}
```

### Delete Data
```http
DELETE /databases/{database_id}/tables/{table_name}/data/{record_id}
Authorization: Bearer your-jwt-token
Content-Type: application/json

{
  "soft_delete": true
}
```

### Bulk Insert
```http
POST /databases/{database_id}/tables/{table_name}/bulk
Authorization: Bearer your-jwt-token
Content-Type: application/json

{
  "data": [
    {
      "id": "550e8400-e29b-41d4-a716-446655440001",
      "name": "Bob Johnson",
      "email": "bob@example.com",
      "password": "secure-password-456"
    },
    {
      "id": "550e8400-e29b-41d4-a716-446655440002",
      "name": "Carol Davis",
      "email": "carol@example.com",
      "password": "secure-password-789"
    }
  ],
  "batch_size": 100
}
```

## Encryption Management

### Rotate Keys
```http
POST /databases/{database_id}/tables/{table_name}/rotate-keys
Authorization: Bearer your-jwt-token
Content-Type: application/json

{
  "strategy": "zero-downtime",
  "algorithm": "aegis256",
  "dry_run": false
}
```

**Response:**
```json
{
  "data": {
    "rotation_id": "rot_123456",
    "status": "in_progress",
    "estimated_completion": "2026-01-15T11:00:00Z",
    "records_to_update": 1500,
    "records_updated": 0
  },
  "success": true
}
```

### Get Rotation Status
```http
GET /databases/{database_id}/tables/{table_name}/rotation-status
Authorization: Bearer your-jwt-token
```

### Get Encryption Metadata
```http
GET /databases/{database_id}/tables/{table_name}/encryption-metadata
Authorization: Bearer your-jwt-token
```

**Response:**
```json
{
  "data": {
    "table_algorithm": "aegis256",
    "key_rotation_interval": "24h",
    "last_rotation": "2026-01-14T10:30:00Z",
    "next_rotation": "2026-01-15T10:30:00Z",
    "field_encryption": {
      "password": {
        "algorithm": "aes256gcm",
        "key_id": "key_password_123",
        "created_at": "2026-01-10T10:30:00Z",
        "sensitivity": "high"
      },
      "ssn": {
        "algorithm": "aes256gcm",
        "key_id": "key_ssn_456",
        "created_at": "2026-01-10T10:30:00Z",
        "sensitivity": "critical"
      }
    }
  },
  "success": true
}
```

## Key Management

### Generate Key
```http
POST /keys
Authorization: Bearer your-jwt-token
Content-Type: application/json

{
  "algorithm": "aegis256",
  "key_size": 256,
  "purpose": "data-encryption",
  "metadata": {
    "owner": "security-team",
    "description": "Key for user data encryption"
  }
}
```

**Response:**
```json
{
  "data": {
    "key_id": "key_123456",
    "algorithm": "aegis256",
    "key_size": 256,
    "status": "active",
    "created_at": "2026-01-15T10:30:00Z",
    "public_key": "base64-encoded-public-key"
  },
  "success": true
}
```

### List Keys
```http
GET /keys?status=active&algorithm=aegis256
Authorization: Bearer your-jwt-token
```

### Get Key Info
```http
GET /keys/{key_id}
Authorization: Bearer your-jwt-token
```

### Rotate Key
```http
POST /keys/{key_id}/rotate
Authorization: Bearer your-jwt-token
Content-Type: application/json

{
  "algorithm": "aegis256",
  "grace_period": "24h"
}
```

### Deactivate Key
```http
DELETE /keys/{key_id}
Authorization: Bearer your-jwt-token
Content-Type: application/json

{
  "grace_period": "72h"
}
```

## Audit & Compliance

### Get Audit Logs
```http
GET /audit/logs?start_time=2026-01-14T00:00:00Z&end_time=2026-01-15T00:00:00Z&event_type=data_access&page=1
Authorization: Bearer your-jwt-token
```

**Query Parameters:**
- `start_time`: ISO 8601 timestamp
- `end_time`: ISO 8601 timestamp
- `event_type`: Filter by event type
- `user_id`: Filter by user
- `resource`: Filter by resource
- `severity`: Filter by severity level

**Response:**
```json
{
  "data": [
    {
      "id": "audit_123456",
      "timestamp": "2026-01-15T10:30:00Z",
      "event_type": "data_access",
      "user_id": "user_789",
      "resource": "table/users",
      "action": "select",
      "outcome": "success",
      "ip_address": "192.168.1.100",
      "user_agent": "FortressClient/1.0",
      "details": {
        "query": "SELECT id, name FROM users WHERE id = ?",
        "records_returned": 1
      }
    }
  ],
  "success": true,
  "metadata": {
    "total": 150,
    "page": 1,
    "page_size": 50
  }
}
```

### Generate Compliance Report
```http
POST /compliance/reports
Authorization: Bearer your-jwt-token
Content-Type: application/json

{
  "standard": "gdpr",
  "period": {
    "start": "2026-01-01T00:00:00Z",
    "end": "2026-01-31T23:59:59Z"
  },
  "format": "pdf",
  "include_sections": ["data_processing", "security_measures", "user_rights"]
}
```

## Cluster Operations

### Get Cluster Status
```http
GET /cluster/status
Authorization: Bearer your-jwt-token
```

**Response:**
```json
{
  "data": {
    "cluster_id": "cluster_main",
    "status": "healthy",
    "nodes": [
      {
        "id": "node_1",
        "address": "192.168.1.10:8080",
        "status": "healthy",
        "role": "leader",
        "last_heartbeat": "2026-01-15T10:30:00Z"
      },
      {
        "id": "node_2",
        "address": "192.168.1.11:8080",
        "status": "healthy",
        "role": "follower",
        "last_heartbeat": "2026-01-15T10:29:55Z"
      }
    ],
    "replication_status": "synced",
    "election_term": 15
  },
  "success": true
}
```

### Add Node to Cluster
```http
POST /cluster/nodes
Authorization: Bearer your-jwt-token
Content-Type: application/json

{
  "address": "192.168.1.12:8080",
  "role": "follower"
}
```

### Remove Node from Cluster
```http
DELETE /cluster/nodes/{node_id}
Authorization: Bearer your-jwt-token
```

## Tenant Management

### Create Tenant
```http
POST /tenants
Authorization: Bearer your-jwt-token
Content-Type: application/json

{
  "name": "Acme Corp",
  "domain": "acme.com",
  "resource_limits": {
    "max_databases": 10,
    "max_storage_gb": 100,
    "max_users": 50
  },
  "encryption_config": {
    "default_algorithm": "aegis256",
    "key_rotation_interval": "24h"
  }
}
```

### List Tenants
```http
GET /tenants
Authorization: Bearer your-jwt-token
```

### Get Tenant Info
```http
GET /tenants/{tenant_id}
Authorization: Bearer your-jwt-token
```

### Update Tenant
```http
PUT /tenants/{tenant_id}
Authorization: Bearer your-jwt-token
Content-Type: application/json

{
  "resource_limits": {
    "max_databases": 20,
    "max_storage_gb": 200
  }
}
```

## Plugin Management

### Install Plugin
```http
POST /plugins/install
Authorization: Bearer your-jwt-token
Content-Type: multipart/form-data

{
  "file": "plugin.wasm",
  "config": {
    "enabled": true,
    "permissions": ["data_access", "key_management"]
  }
}
```

### List Plugins
```http
GET /plugins
Authorization: Bearer your-jwt-token
```

**Response:**
```json
{
  "data": [
    {
      "id": "plugin_audit_enhanced",
      "name": "Enhanced Audit Plugin",
      "version": "1.0.0",
      "status": "active",
      "capabilities": ["audit_logging", "real_time_monitoring"],
      "installed_at": "2026-01-15T10:30:00Z"
    }
  ],
  "success": true
}
```

### Enable/Disable Plugin
```http
POST /plugins/{plugin_id}/toggle
Authorization: Bearer your-jwt-token
Content-Type: application/json

{
  "enabled": false
}
```

### Uninstall Plugin
```http
DELETE /plugins/{plugin_id}
Authorization: Bearer your-jwt-token
```

## Monitoring & Health

### System Metrics
```http
GET /metrics/system
Authorization: Bearer your-jwt-token
```

**Response:**
```json
{
  "data": {
    "cpu_usage_percent": 45.2,
    "memory_usage_mb": 2048,
    "memory_usage_percent": 25.6,
    "disk_usage_mb": 10240,
    "disk_usage_percent": 60.0,
    "network_io": {
      "bytes_sent": 1048576,
      "bytes_received": 2097152
    },
    "active_connections": 45,
    "uptime_seconds": 86400
  },
  "success": true
}
```

### Performance Metrics
```http
GET /metrics/performance
Authorization: Bearer your-jwt-token
```

**Response:**
```json
{
  "data": {
    "encryption_ops_per_second": 1250,
    "decryption_ops_per_second": 1180,
    "avg_encryption_time_ms": 2.5,
    "avg_decryption_time_ms": 2.1,
    "query_response_time_avg_ms": 125,
    "cache_hit_rate_percent": 85.6,
    "key_rotation_progress": 75.0
  },
  "success": true
}
```

### Prometheus Metrics
```http
GET /metrics/prometheus
Authorization: Bearer your-jwt-token
```

Returns metrics in Prometheus format for integration with monitoring systems.

## Error Handling

### Error Response Format
```json
{
  "data": null,
  "success": false,
  "timestamp": "2026-01-15T10:30:00Z",
  "metadata": {
    "error": {
      "code": "VALIDATION_ERROR",
      "message": "Invalid request parameters",
      "details": {
        "field": "email",
        "reason": "Invalid email format"
      },
      "request_id": "req_123456789"
    }
  }
}
```

### Common Error Codes

| Code | HTTP Status | Description |
|------|-------------|-------------|
| `VALIDATION_ERROR` | 400 | Request validation failed |
| `UNAUTHORIZED` | 401 | Authentication required |
| `FORBIDDEN` | 403 | Insufficient permissions |
| `NOT_FOUND` | 404 | Resource not found |
| `CONFLICT` | 409 | Resource conflict |
| `RATE_LIMITED` | 429 | Too many requests |
| `INTERNAL_ERROR` | 500 | Server internal error |
| `SERVICE_UNAVAILABLE` | 503 | Service temporarily unavailable |
| `ENCRYPTION_ERROR` | 422 | Encryption/decryption failed |
| `KEY_NOT_FOUND` | 404 | Encryption key not found |
| `DATABASE_ERROR` | 500 | Database operation failed |

## Rate Limiting

### Rate Limit Headers
```http
X-RateLimit-Limit: 1000
X-RateLimit-Remaining: 999
X-RateLimit-Reset: 1642248600
X-RateLimit-Retry-After: 60
```

### Rate Limits by Endpoint

| Endpoint | Limit | Window |
|----------|-------|--------|
| Authentication | 10 requests | 1 minute |
| Data Operations | 1000 requests | 1 hour |
| Key Management | 100 requests | 1 hour |
| Admin Operations | 50 requests | 1 hour |

## SDK Examples

### Python SDK
```python
from fortress_client import FortressClient

# Initialize client
client = FortressClient(
    base_url="http://localhost:8080",
    api_key="your-api-key"
)

# Create database
db = client.create_database(
    name="myapp_db",
    algorithm="aegis256",
    key_rotation_interval="24h"
)

# Create table
table = client.create_table(
    database_id=db.id,
    name="users",
    columns=[
        {"name": "id", "type": "uuid", "primary_key": True},
        {"name": "name", "type": "text"},
        {"name": "email", "type": "text", "unique": True},
        {"name": "password", "type": "encrypted", "sensitivity": "high"}
    ]
)

# Insert data
user = client.insert_data(
    database_id=db.id,
    table_name="users",
    data={
        "id": uuid.uuid4(),
        "name": "Alice Johnson",
        "email": "alice@example.com",
        "password": "secure-password"
    }
)

# Query data
users = client.query_data(
    database_id=db.id,
    table_name="users",
    filter="name=Alice"
)
```

### JavaScript SDK
```javascript
const { FortressClient } = require('@fortress-db/client');

// Initialize client
const client = new FortressClient({
  baseURL: 'http://localhost:8080',
  apiKey: 'your-api-key'
});

// Create database
const db = await client.createDatabase({
  name: 'myapp_db',
  algorithm: 'aegis256',
  keyRotationInterval: '24h'
});

// Create table
const table = await client.createTable(db.id, {
  name: 'users',
  columns: [
    { name: 'id', type: 'uuid', primaryKey: true },
    { name: 'name', type: 'text' },
    { name: 'email', type: 'text', unique: true },
    { name: 'password', type: 'encrypted', sensitivity: 'high' }
  ]
});

// Insert data
const user = await client.insertData(db.id, 'users', {
  id: uuid.v4(),
  name: 'Alice Johnson',
  email: 'alice@example.com',
  password: 'secure-password'
});

// Query data
const users = await client.queryData(db.id, 'users', {
  filter: 'name=Alice'
});
```

### Rust SDK
```rust
use fortress_client::FortressClient;
use fortress_core::prelude::*;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize client
    let client = FortressClient::new("http://localhost:8080")
        .with_api_key("your-api-key");

    // Create database
    let db = client.create_database()
        .name("myapp_db")
        .algorithm("aegis256")
        .key_rotation_interval("24h")
        .send()
        .await?;

    // Create table
    let table = client.create_table(&db.id)
        .name("users")
        .column(|c| c.name("id").type_("uuid").primary_key(true))
        .column(|c| c.name("name").type_("text"))
        .column(|c| c.name("email").type_("text").unique(true))
        .column(|c| c.name("password").type_("encrypted").sensitivity("high"))
        .send()
        .await?;

    // Insert data
    let user = client.insert_data(&db.id, "users")
        .data(json!({
            "id": uuid::Uuid::new_v4(),
            "name": "Alice Johnson",
            "email": "alice@example.com",
            "password": "secure-password"
        }))
        .send()
        .await?;

    // Query data
    let users = client.query_data(&db.id, "users")
        .filter("name=Alice")
        .send()
        .await?;

    Ok(())
}
```

## WebSocket API

Fortress also provides a WebSocket API for real-time updates and streaming operations.

### Connect to WebSocket
```javascript
const ws = new WebSocket('ws://localhost:8080/ws');

// Authenticate
ws.send(JSON.stringify({
  type: 'auth',
  token: 'your-jwt-token'
}));

// Subscribe to events
ws.send(JSON.stringify({
  type: 'subscribe',
  events: ['data_change', 'key_rotation', 'audit_log']
}));

// Handle messages
ws.onmessage = (event) => {
  const message = JSON.parse(event.data);
  console.log('Received:', message);
};
```

### WebSocket Events

| Event | Description | Payload |
|-------|-------------|---------|
| `data_change` | Data modification | `{ table, operation, record_id }` |
| `key_rotation` | Key rotation progress | `{ rotation_id, progress, status }` |
| `audit_log` | New audit entry | `{ audit_entry }` |
| `system_health` | Health status updates | `{ component, status, metrics }` |

## GraphQL API

For complex queries, Fortress provides a GraphQL endpoint.

### GraphQL Endpoint
```
POST /graphql
```

### Example Query
```graphql
query GetUserWithAudit($userId: ID!) {
  user(id: $userId) {
    id
    name
    email
    createdAt
  }
  
  auditLogs(
    userId: $userId
    limit: 10
    orderBy: { timestamp: DESC }
  ) {
    id
    timestamp
    eventType
    action
    outcome
  }
}
```

## Best Practices

1. **Use HTTPS in production** - Always use TLS for API communication
2. **Implement proper error handling** - Check the `success` field in responses
3. **Use field-level encryption** - Encrypt sensitive data with appropriate algorithms
4. **Monitor rate limits** - Respect rate limiting headers
5. **Cache frequently accessed data** - Reduce API calls for static data
6. **Use appropriate algorithms** - AEGIS-256 for speed, AES-256-GCM for compatibility
7. **Implement retry logic** - Handle temporary failures gracefully
8. **Validate input** - Ensure data is properly formatted before sending
9. **Use pagination** - For large result sets, use pagination parameters
10. **Secure credentials** - Store API keys and tokens securely

## Support

- 📖 [Documentation](https://docs.fortress-db.com)
- 🐛 [Issue Tracker](https://github.com/Genius740Code/Fortress/issues)
- 💬 [Discussions](https://github.com/Genius740Code/Fortress/discussions)
- 📧 [Email Support](mailto:support@fortress-db.com)
