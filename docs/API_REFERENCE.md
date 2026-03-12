# Fortress API Documentation

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
  "timestamp": "2024-01-15T10:30:00Z",
  "metadata": {
    "request_id": "req_123456789",
    "version": "0.1.0"
  }
}
```

## Authentication

### Login with Credentials
```http
POST /api/v1/auth/login
Content-Type: application/json

{
  "username": "admin",
  "password": "secure-password"
}
```

**Response:**
```json
{
  "data": {
    "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "expires_in": 3600,
    "token_type": "Bearer"
  },
  "success": true,
  "timestamp": "2024-01-15T10:30:00Z"
}
```

### Refresh Token
```http
POST /api/v1/auth/refresh
Content-Type: application/json

{
  "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

### Create API Key
```http
POST /api/v1/auth/api-keys
Authorization: Bearer <jwt-token>
Content-Type: application/json

{
  "name": "production-api-key",
  "permissions": ["read", "write"],
  "expires_at": "2024-12-31T23:59:59Z"
}
```

## Database Management

### Create Database
```http
POST /api/v1/databases
Authorization: Bearer <token>
Content-Type: application/json

{
  "name": "myapp_db",
  "algorithm": "aegis256",
  "key_rotation_interval": "24h",
  "storage_backend": "local",
  "data_dir": "/var/lib/fortress/myapp_db"
}
```

**Response:**
```json
{
  "data": {
    "id": "db_123456789",
    "name": "myapp_db",
    "algorithm": "aegis256",
    "status": "active",
    "created_at": "2024-01-15T10:30:00Z",
    "key_id": "key_987654321",
    "storage_backend": "local"
  },
  "success": true,
  "timestamp": "2024-01-15T10:30:00Z"
}
```

### List Databases
```http
GET /api/v1/databases
Authorization: Bearer <token>
```

**Response:**
```json
{
  "data": {
    "databases": [
      {
        "id": "db_123456789",
        "name": "myapp_db",
        "algorithm": "aegis256",
        "status": "active",
        "created_at": "2024-01-15T10:30:00Z"
      }
    ],
    "total": 1,
    "page": 1,
    "per_page": 20
  },
  "success": true,
  "timestamp": "2024-01-15T10:30:00Z"
}
```

### Get Database Details
```http
GET /api/v1/databases/{database_id}
Authorization: Bearer <token>
```

### Delete Database
```http
DELETE /api/v1/databases/{database_id}
Authorization: Bearer <token>
```

## Table Management

### Create Table
```http
POST /api/v1/databases/{database_id}/tables
Authorization: Bearer <token>
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
      "nullable": false
    },
    {
      "name": "email",
      "type": "text",
      "unique": true,
      "nullable": false
    },
    {
      "name": "password",
      "type": "encrypted",
      "algorithm": "aes256gcm",
      "sensitivity": "high",
      "searchable": false
    },
    {
      "name": "created_at",
      "type": "timestamp",
      "default": "now()"
    }
  ]
}
```

**Response:**
```json
{
  "data": {
    "id": "table_123456789",
    "name": "users",
    "database_id": "db_123456789",
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
        "nullable": false
      },
      {
        "name": "email",
        "type": "text",
        "unique": true,
        "nullable": false
      },
      {
        "name": "password",
        "type": "encrypted",
        "algorithm": "aes256gcm",
        "sensitivity": "high",
        "searchable": false
      }
    ],
    "created_at": "2024-01-15T10:30:00Z"
  },
  "success": true,
  "timestamp": "2024-01-15T10:30:00Z"
}
```

### List Tables
```http
GET /api/v1/databases/{database_id}/tables
Authorization: Bearer <token>
```

### Get Table Schema
```http
GET /api/v1/databases/{database_id}/tables/{table_name}
Authorization: Bearer <token>
```

### Drop Table
```http
DELETE /api/v1/databases/{database_id}/tables/{table_name}
Authorization: Bearer <token>
```

## Data Operations

### Insert Data
```http
POST /api/v1/databases/{database_id}/tables/{table_name}/data
Authorization: Bearer <token>
Content-Type: application/json

{
  "data": {
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "name": "Alice Johnson",
    "email": "alice@example.com",
    "password": "secure-password"
  }
}
```

**Response:**
```json
{
  "data": {
    "id": "record_123456789",
    "inserted_at": "2024-01-15T10:30:00Z",
    "row_count": 1
  },
  "success": true,
  "timestamp": "2024-01-15T10:30:00Z"
}
```

### Get Data
```http
GET /api/v1/databases/{database_id}/tables/{table_name}/data/{record_id}
Authorization: Bearer <token>
```

**Response:**
```json
{
  "data": {
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "name": "Alice Johnson",
    "email": "alice@example.com",
    "password": "encrypted:base64data...",
    "created_at": "2024-01-15T10:30:00Z"
  },
  "success": true,
  "timestamp": "2024-01-15T10:30:00Z"
}
```

### Query Data
```http
POST /api/v1/databases/{database_id}/tables/{table_name}/query
Authorization: Bearer <token>
Content-Type: application/json

{
  "filter": {
    "email": "alice@example.com"
  },
  "select": ["id", "name", "email"],
  "limit": 10,
  "offset": 0,
  "order_by": "created_at",
  "order_direction": "desc"
}
```

### Update Data
```http
PUT /api/v1/databases/{database_id}/tables/{table_name}/data/{record_id}
Authorization: Bearer <token>
Content-Type: application/json

{
  "data": {
    "name": "Alice Smith",
    "email": "alice.smith@example.com"
  }
}
```

### Delete Data
```http
DELETE /api/v1/databases/{database_id}/tables/{table_name}/data/{record_id}
Authorization: Bearer <token>
```

### Bulk Operations

#### Bulk Insert
```http
POST /api/v1/databases/{database_id}/tables/{table_name}/bulk-insert
Authorization: Bearer <token>
Content-Type: application/json

{
  "data": [
    {
      "id": "550e8400-e29b-41d4-a716-446655440001",
      "name": "Bob Johnson",
      "email": "bob@example.com",
      "password": "password1"
    },
    {
      "id": "550e8400-e29b-41d4-a716-446655440002",
      "name": "Carol Williams",
      "email": "carol@example.com",
      "password": "password2"
    }
  ]
}
```

#### Bulk Update
```http
POST /api/v1/databases/{database_id}/tables/{table_name}/bulk-update
Authorization: Bearer <token>
Content-Type: application/json

{
  "filter": {
    "created_at": {
      "lt": "2024-01-01T00:00:00Z"
    }
  },
  "data": {
    "status": "archived"
  }
}
```

#### Bulk Delete
```http
POST /api/v1/databases/{database_id}/tables/{table_name}/bulk-delete
Authorization: Bearer <token>
Content-Type: application/json

{
  "filter": {
    "status": "inactive"
  }
}
```

## Encryption Management

### Get Encryption Info
```http
GET /api/v1/databases/{database_id}/encryption
Authorization: Bearer <token>
```

**Response:**
```json
{
  "data": {
    "algorithm": "aegis256",
    "key_id": "key_987654321",
    "key_version": 3,
    "key_rotation_interval": "24h",
    "last_rotation": "2024-01-14T10:30:00Z",
    "next_rotation": "2024-01-15T10:30:00Z",
    "field_encryption": {
      "users.password": {
        "algorithm": "aes256gcm",
        "sensitivity": "high",
        "searchable": false
      }
    }
  },
  "success": true,
  "timestamp": "2024-01-15T10:30:00Z"
}
```

### Rotate Encryption Key
```http
POST /api/v1/databases/{database_id}/encryption/rotate
Authorization: Bearer <token>
Content-Type: application/json

{
  "algorithm": "aegis256",
  "force": false,
  "background": true
}
```

### Update Encryption Settings
```http
PUT /api/v1/databases/{database_id}/encryption/settings
Authorization: Bearer <token>
Content-Type: application/json

{
  "key_rotation_interval": "48h",
  "auto_rotation": true,
  "encryption_algorithm": "aegis256"
}
```

## Key Management

### List Keys
```http
GET /api/v1/keys
Authorization: Bearer <token>
```

**Response:**
```json
{
  "data": {
    "keys": [
      {
        "id": "key_987654321",
        "database_id": "db_123456789",
        "algorithm": "aegis256",
        "version": 3,
        "status": "active",
        "created_at": "2024-01-01T00:00:00Z",
        "last_rotated": "2024-01-14T10:30:00Z"
      }
    ]
  },
  "success": true,
  "timestamp": "2024-01-15T10:30:00Z"
}
```

### Get Key Details
```http
GET /api/v1/keys/{key_id}
Authorization: Bearer <token>
```

### Rotate Key
```http
POST /api/v1/keys/{key_id}/rotate
Authorization: Bearer <token>
Content-Type: application/json

{
  "algorithm": "aegis256",
  "force": false
}
```

### Delete Key
```http
DELETE /api/v1/keys/{key_id}
Authorization: Bearer <token>
```

## Audit & Compliance

### Get Audit Logs
```http
GET /api/v1/audit/logs
Authorization: Bearer <token>
Query Parameters:
- start_time: ISO 8601 timestamp
- end_time: ISO 8601 timestamp
- event_type: authentication, data_access, key_operation
- user_id: Filter by user
- limit: Number of records (max 1000)
- offset: Pagination offset
```

**Response:**
```json
{
  "data": {
    "logs": [
      {
        "id": "audit_123456789",
        "timestamp": "2024-01-15T10:30:00Z",
        "event_type": "data_access",
        "user_id": "user_12345",
        "action": "read",
        "resource": "database:myapp_db.table:users",
        "ip_address": "192.168.1.100",
        "user_agent": "FortressClient/1.0.0",
        "outcome": "success",
        "details": {
          "record_count": 1,
          "fields_accessed": ["name", "email"]
        }
      }
    ],
    "total": 1,
    "page": 1,
    "per_page": 100
  },
  "success": true,
  "timestamp": "2024-01-15T10:30:00Z"
}
```

### Export Audit Logs
```http
POST /api/v1/audit/export
Authorization: Bearer <token>
Content-Type: application/json

{
  "start_time": "2024-01-01T00:00:00Z",
  "end_time": "2024-01-31T23:59:59Z",
  "format": "csv",
  "event_types": ["data_access", "authentication"]
}
```

### Compliance Report
```http
GET /api/v1/compliance/report
Authorization: Bearer <token>
Query Parameters:
- standard: gdpr, hipaa, pci_dss
- period: monthly, quarterly, yearly
```

## Cluster Operations

### Get Cluster Status
```http
GET /api/v1/cluster/status
Authorization: Bearer <token>
```

**Response:**
```json
{
  "data": {
    "cluster_id": "cluster_123456789",
    "status": "healthy",
    "nodes": [
      {
        "id": "node_123456789",
        "address": "192.168.1.100:8080",
        "status": "leader",
        "last_heartbeat": "2024-01-15T10:30:00Z"
      },
      {
        "id": "node_987654321",
        "address": "192.168.1.101:8080",
        "status": "follower",
        "last_heartbeat": "2024-01-15T10:29:55Z"
      }
    ],
    "term": 15,
    "leader": "node_123456789"
  },
  "success": true,
  "timestamp": "2024-01-15T10:30:00Z"
}
```

### Add Node to Cluster
```http
POST /api/v1/cluster/nodes
Authorization: Bearer <token>
Content-Type: application/json

{
  "address": "192.168.1.102:8080",
  "join_token": "join_token_123456789"
}
```

### Remove Node from Cluster
```http
DELETE /api/v1/cluster/nodes/{node_id}
Authorization: Bearer <token>
```

## Tenant Management

### Create Tenant
```http
POST /api/v1/tenants
Authorization: Bearer <token>
Content-Type: application/json

{
  "name": "Company A",
  "domain": "company-a.com",
  "admin_email": "admin@company-a.com",
  "resource_limits": {
    "max_databases": 10,
    "max_storage_gb": 1000,
    "max_api_calls_per_day": 100000
  }
}
```

### List Tenants
```http
GET /api/v1/tenants
Authorization: Bearer <token>
```

### Get Tenant Details
```http
GET /api/v1/tenants/{tenant_id}
Authorization: Bearer <token>
```

### Update Tenant Settings
```http
PUT /api/v1/tenants/{tenant_id}
Authorization: Bearer <token>
Content-Type: application/json

{
  "resource_limits": {
    "max_databases": 20,
    "max_storage_gb": 2000
  }
}
```

### Delete Tenant
```http
DELETE /api/v1/tenants/{tenant_id}
Authorization: Bearer <token>
```

## Plugin Management

### List Plugins
```http
GET /api/v1/plugins
Authorization: Bearer <token>
```

### Install Plugin
```http
POST /api/v1/plugins/install
Authorization: Bearer <token>
Content-Type: multipart/form-data

file: plugin.wasm
name: enhanced-audit
version: 1.0.0
```

### Enable Plugin
```http
POST /api/v1/plugins/{plugin_name}/enable
Authorization: Bearer <token>
```

### Disable Plugin
```http
POST /api/v1/plugins/{plugin_name}/disable
Authorization: Bearer <token>
```

### Uninstall Plugin
```http
DELETE /api/v1/plugins/{plugin_name}
Authorization: Bearer <token>
```

## Monitoring & Health

### Health Check
```http
GET /api/v1/health
```

**Response:**
```json
{
  "data": {
    "status": "healthy",
    "version": "0.1.0",
    "uptime": "72h 15m 30s",
    "checks": {
      "database": "healthy",
      "encryption": "healthy",
      "storage": "healthy",
      "cluster": "healthy"
    }
  },
  "success": true,
  "timestamp": "2024-01-15T10:30:00Z"
}
```

### Detailed Health Check
```http
GET /api/v1/health?detailed=true
```

### System Metrics
```http
GET /api/v1/metrics/system
Authorization: Bearer <token>
```

**Response:**
```json
{
  "data": {
    "cpu_usage": 25.5,
    "memory_usage": 45.2,
    "disk_usage": 60.8,
    "network_io": {
      "bytes_sent": 1048576,
      "bytes_received": 2097152
    },
    "connections": {
      "active": 150,
      "total": 1250
    }
  },
  "success": true,
  "timestamp": "2024-01-15T10:30:00Z"
}
```

### Performance Metrics
```http
GET /api/v1/metrics/performance
Authorization: Bearer <token>
```

**Response:**
```json
{
  "data": {
    "encryption_throughput": {
      "aegis256": 1500,
      "chacha20poly1305": 1200,
      "aes256gcm": 1000
    },
    "request_latency": {
      "p50": 5.2,
      "p95": 15.8,
      "p99": 45.6
    },
    "request_rate": 1250,
    "error_rate": 0.02
  },
  "success": true,
  "timestamp": "2024-01-15T10:30:00Z"
}
```

## Error Handling

### Error Response Format
```json
{
  "error": {
    "code": "VALIDATION_ERROR",
    "message": "Invalid input data",
    "details": {
      "field": "email",
      "reason": "Invalid email format"
    }
  },
  "success": false,
  "timestamp": "2024-01-15T10:30:00Z",
  "request_id": "req_123456789"
}
```

### Common Error Codes

| Error Code | HTTP Status | Description |
|------------|-------------|-------------|
| VALIDATION_ERROR | 400 | Invalid input data |
| UNAUTHORIZED | 401 | Authentication required |
| FORBIDDEN | 403 | Insufficient permissions |
| NOT_FOUND | 404 | Resource not found |
| CONFLICT | 409 | Resource already exists |
| RATE_LIMITED | 429 | Rate limit exceeded |
| INTERNAL_ERROR | 500 | Internal server error |
| SERVICE_UNAVAILABLE | 503 | Service temporarily unavailable |

### Specific Error Examples

#### Validation Error
```json
{
  "error": {
    "code": "VALIDATION_ERROR",
    "message": "Invalid database configuration",
    "details": {
      "errors": [
        {
          "field": "name",
          "message": "Database name must be alphanumeric"
        },
        {
          "field": "algorithm",
          "message": "Unsupported encryption algorithm"
        }
      ]
    }
  },
  "success": false,
  "timestamp": "2024-01-15T10:30:00Z"
}
```

#### Authentication Error
```json
{
  "error": {
    "code": "UNAUTHORIZED",
    "message": "Invalid or expired token",
    "details": {
      "token_expired": true,
      "expires_at": "2024-01-15T09:30:00Z"
    }
  },
  "success": false,
  "timestamp": "2024-01-15T10:30:00Z"
}
```

## Rate Limiting

### Rate Limit Headers
```http
X-RateLimit-Limit: 1000
X-RateLimit-Remaining: 999
X-RateLimit-Reset: 1642248600
```

### Rate Limit Exceeded
```json
{
  "error": {
    "code": "RATE_LIMITED",
    "message": "Rate limit exceeded",
    "details": {
      "limit": 1000,
      "window": "1h",
      "reset_at": "2024-01-15T11:30:00Z"
    }
  },
  "success": false,
  "timestamp": "2024-01-15T10:30:00Z"
}
```

## WebSocket API

### Connection
```javascript
const ws = new WebSocket('ws://localhost:8080/api/v1/ws');

// Authenticate
ws.send(JSON.stringify({
  type: 'auth',
  token: 'your-jwt-token'
}));
```

### Subscribe to Events
```javascript
ws.send(JSON.stringify({
  type: 'subscribe',
  events: ['data_change', 'key_rotation', 'system_alert']
}));
```

### Event Messages
```javascript
ws.onmessage = (event) => {
  const message = JSON.parse(event.data);
  
  switch (message.type) {
    case 'data_change':
      console.log('Data changed:', message.data);
      break;
    case 'key_rotation':
      console.log('Key rotated:', message.data);
      break;
    case 'system_alert':
      console.log('System alert:', message.data);
      break;
  }
};
```

## SDK Examples

### Python SDK
```python
from fortress_client import FortressClient

# Initialize client
client = FortressClient('http://localhost:8080')
client.authenticate('admin', 'secure-password')

# Create database
db = client.create_database('myapp_db', algorithm='aegis256')

# Create table
table = client.create_table('myapp_db', 'users', [
    {'name': 'id', 'type': 'uuid', 'primary_key': True},
    {'name': 'name', 'type': 'text'},
    {'name': 'email', 'type': 'text', 'unique': True},
    {'name': 'password', 'type': 'encrypted', 'sensitivity': 'high'}
])

# Insert data
user = client.insert_data('myapp_db', 'users', {
    'id': '550e8400-e29b-41d4-a716-446655440000',
    'name': 'Alice Johnson',
    'email': 'alice@example.com',
    'password': 'secure-password'
})
```

### JavaScript SDK
```javascript
const { FortressClient } = require('@fortress-db/client');

// Initialize client
const client = new FortressClient('http://localhost:8080');
await client.authenticate('admin', 'secure-password');

// Create database
const db = await client.createDatabase('myapp_db', { algorithm: 'aegis256' });

// Create table
const table = await client.createTable('myapp_db', 'users', [
    { name: 'id', type: 'uuid', primaryKey: true },
    { name: 'name', type: 'text' },
    { name: 'email', type: 'text', unique: true },
    { name: 'password', type: 'encrypted', sensitivity: 'high' }
]);

// Insert data
const user = await client.insertData('myapp_db', 'users', {
    id: '550e8400-e29b-41d4-a716-446655440000',
    name: 'Alice Johnson',
    email: 'alice@example.com',
    password: 'secure-password'
});
```

### Rust SDK
```rust
use fortress_client::FortressClient;
use fortress_client::prelude::*;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize client
    let client = FortressClient::new("http://localhost:8080");
    client.authenticate("admin", "secure-password").await?;

    // Create database
    let db = client.create_database("myapp_db", CreateDatabaseRequest {
        algorithm: "aegis256".to_string(),
        ..Default::default()
    }).await?;

    // Create table
    let table = client.create_table("myapp_db", CreateTableRequest {
        name: "users".to_string(),
        columns: vec![
            ColumnDefinition {
                name: "id".to_string(),
                column_type: "uuid".to_string(),
                primary_key: true,
                ..Default::default()
            },
            ColumnDefinition {
                name: "name".to_string(),
                column_type: "text".to_string(),
                ..Default::default()
            },
            ColumnDefinition {
                name: "email".to_string(),
                column_type: "text".to_string(),
                unique: true,
                ..Default::default()
            },
            ColumnDefinition {
                name: "password".to_string(),
                column_type: "encrypted".to_string(),
                sensitivity: Some("high".to_string()),
                ..Default::default()
            }
        ],
    }).await?;

    // Insert data
    let user = client.insert_data("myapp_db", "users", InsertDataRequest {
        data: serde_json::json!({
            "id": "550e8400-e29b-41d4-a716-446655440000",
            "name": "Alice Johnson",
            "email": "alice@example.com",
            "password": "secure-password"
        }),
    }).await?;

    Ok(())
}
```

This comprehensive API documentation provides all the information needed to integrate with Fortress and build secure applications.
