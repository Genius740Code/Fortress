# Fortress REST API Quick Start

This guide shows how to quickly get started with the Fortress REST API for your MS-like application.

## 🚀 Quick Start

### 1. Start the Server

```bash
cd crates/fortress-server
cargo run --bin simple_server
```

The server will start on `http://localhost:8080`

### 2. Run the Example Client

```bash
python examples/api_client_example.py
```

## 📚 API Endpoints

### Database Management
- `POST /api/v1/databases` - Create database
- `GET /api/v1/databases` - List databases  
- `GET /api/v1/databases/{name}` - Get database info
- `DELETE /api/v1/databases/{name}` - Delete database

### Table Management
- `POST /api/v1/databases/{db}/tables` - Create table
- `GET /api/v1/databases/{db}/tables` - List tables
- `GET /api/v1/databases/{db}/tables/{table}/schema` - Get table schema
- `DELETE /api/v1/databases/{db}/tables/{table}` - Drop table

### Data Operations
- `POST /api/v1/databases/{db}/tables/{table}/data` - Insert data
- `GET /api/v1/databases/{db}/tables/{table}/data` - Query data
- `POST /api/v1/databases/{db}/tables/{table}/bulk` - Bulk insert
- `PUT /api/v1/databases/{db}/tables/{table}/data/{id}` - Update data
- `DELETE /api/v1/databases/{db}/tables/{table}/data/{id}` - Delete data

### Query Operations
- `POST /api/v1/databases/{db}/query` - Execute SQL query

### Encryption Management
- `POST /api/v1/databases/{db}/tables/{table}/rotate-keys` - Rotate keys
- `POST /api/v1/databases/{db}/tables/{table}/rotate-keys-zero-downtime` - Zero-downtime rotation
- `GET /api/v1/databases/{db}/tables/{table}/rotation-status` - Get rotation status
- `GET /api/v1/databases/{db}/tables/{table}/encryption-metadata` - Get encryption metadata

### Authentication
- `POST /api/v1/auth/login` - Login
- `POST /api/v1/auth/refresh` - Refresh token

### Health & Metrics
- `GET /health` - Health check
- `GET /metrics` - Application metrics

## 🔧 Example Usage

### Create Database

```bash
curl -X POST http://localhost:8080/api/v1/databases \
  -H "Content-Type: application/json" \
  -d '{
    "name": "myapp_db",
    "algorithm": "aegis256",
    "key_rotation_interval": "23h",
    "storage_path": "./data/myapp_db"
  }'
```

### Create Table

```bash
curl -X POST http://localhost:8080/api/v1/databases/myapp_db/tables \
  -H "Content-Type: application/json" \
  -d '{
    "name": "users",
    "columns": [
      {"name": "id", "type": "uuid", "primary_key": true},
      {"name": "name", "type": "text"},
      {"name": "email", "type": "text"},
      {"name": "password", "type": "encrypted", "encryption": "fortress"}
    ],
    "encryption": "balanced"
  }'
```

### Insert Data

```bash
curl -X POST http://localhost:8080/api/v1/databases/myapp_db/tables/users/data \
  -H "Content-Type: application/json" \
  -d '{
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "name": "Alice Johnson",
    "email": "alice@example.com",
    "password": "super_secret_password"
  }'
```

### Query Data

```bash
curl "http://localhost:8080/api/v1/databases/myapp_db/tables/users/data"
```

### Execute SQL Query

```bash
curl -X POST http://localhost:8080/api/v1/databases/myapp_db/query \
  -H "Content-Type: application/json" \
  -d '{
    "sql": "SELECT name, email FROM users WHERE name = ?",
    "parameters": ["Alice Johnson"]
  }'
```

## 🔐 Authentication

If authentication is enabled, include an API key or JWT token:

```bash
# API Key Authentication
curl -H "X-API-Key: your-api-key" http://localhost:8080/api/v1/databases

# JWT Token Authentication  
curl -H "Authorization: Bearer your-jwt-token" http://localhost:8080/api/v1/databases
```

## 📊 Response Format

All API responses follow this format:

```json
{
  "data": { ... },
  "success": true,
  "timestamp": "2024-01-15T10:30:00Z",
  "metadata": { ... }
}
```

## 🚨 Error Handling

Errors return detailed information:

```json
{
  "data": null,
  "success": false,
  "timestamp": "2024-01-15T10:30:00Z",
  "metadata": {
    "error": {
      "code": "DATABASE_NOT_FOUND",
      "message": "Database does not exist",
      "details": { ... }
    }
  }
}
```

## 🐳 Docker Usage

```bash
# Build and run with Docker
docker build -t fortress-api .
docker run -p 8080:8080 fortress-api
```

## 📈 Integration Examples

### JavaScript/Node.js

```javascript
const FortressClient = require('./fortress-client');

const client = new FortressClient('http://localhost:8080');

// Create database
await client.createDatabase('myapp_db');

// Create table
await client.createTable('myapp_db', 'users', [
  {name: 'id', type: 'uuid', primary_key: true},
  {name: 'name', type: 'text'},
  {name: 'email', type: 'text'}
]);

// Insert data
await client.insertData('myapp_db', 'users', {
  id: uuid.v4(),
  name: 'John Doe',
  email: 'john@example.com'
});
```

### Python

```python
from fortress_client import FortressClient

client = FortressClient('http://localhost:8080')

# Create database
client.create_database('myapp_db')

# Create table
client.create_table('myapp_db', 'users', [
    {'name': 'id', 'type': 'uuid', 'primary_key': True},
    {'name': 'name', 'type': 'text'},
    {'name': 'email', 'type': 'text'}
])

# Insert data
client.insert_data('myapp_db', 'users', {
    'id': str(uuid.uuid4()),
    'name': 'John Doe',
    'email': 'john@example.com'
})
```

## 🔧 Configuration

The server can be configured via environment variables or config file:

```toml
[network]
port = 8080
host = "0.0.0.0"
max_body_size = 10485760

[security]
cors_origins = ["*"]
rate_limit = 1000

[features]
auth_enabled = true
metrics_enabled = true
health_enabled = true
```

## 📚 More Documentation

- [Full API Documentation](../docs/API.md)
- [Architecture Guide](../docs/ARCHITECTURE.md)
- [Security Best Practices](../docs/SECURITY.md)

## 🤝 Contributing

Contributions welcome! Please see [CONTRIBUTING.md](../CONTRIBUTING.md) for details.
