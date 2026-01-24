# Fortress API Documentation

## Overview

Fortress provides multiple API interfaces to suit different use cases:

- **Rust Library**: Native Rust integration
- **REST API**: HTTP/JSON interface for web applications
- **gRPC**: High-performance binary protocol
- **CLI**: Command-line interface for operations
- **WebAssembly**: Browser-compatible library

## Rust Library API

### Core Types

```rust
use fortress::{Fortress, Config, EncryptionProfile, DatabaseConfig};

// Configuration
let config = Config::builder()
    .database(DatabaseConfig::new("./data"))
    .default_algorithm("aegis256")
    .key_rotation_interval(Duration::from_secs(23 * 3600))
    .build()?;

// Database connection
let db = Fortress::connect(config).await?;
```

### Database Operations

#### Create Database
```rust
let db = Fortress::create("./mydb")
    .algorithm("aegis256")
    .key_rotation(Duration::from_secs(23 * 3600))
    .encryption_profile("lightning", EncryptionProfile {
        algorithm: "aegis256".to_string(),
        rotation_interval: Duration::from_secs(23 * 3600),
    })
    .await?;
```

#### Table Management
```rust
// Create table with schema
use fortress::{TableSchema, ColumnType, EncryptionRule};

let schema = TableSchema::builder()
    .column("id", ColumnType::UUID)
    .column("name", ColumnType::Text)
    .column("email", ColumnType::Text)
    .column("password", ColumnType::Encrypted)
    .encryption_rule("password", EncryptionRule::Fortress)
    .build()?;

db.create_table("users", schema).await?;

// List tables
let tables = db.list_tables().await?;
println!("Tables: {:?}", tables);

// Drop table
db.drop_table("users").await?;
```

#### Data Operations
```rust
use serde_json::json;

// Insert data
let user_data = json!({
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "name": "Alice Johnson",
    "email": "alice@example.com",
    "password": "super_secret_password"
});

db.insert("users", &user_data).await?;

// Insert multiple records
let users = vec![
    json!({"id": uuid::Uuid::new_v4(), "name": "Bob", "email": "bob@example.com"}),
    json!({"id": uuid::Uuid::new_v4(), "name": "Charlie", "email": "charlie@example.com"}),
];

db.insert_batch("users", &users).await?;

// Update data
db.update("users")
    .set("email", "alice.new@example.com")
    .where_eq("id", "550e8400-e29b-41d4-a716-446655440000")
    .await?;

// Delete data
db.delete("users")
    .where_eq("id", "550e8400-e29b-41d4-a716-446655440000")
    .await?;
```

#### Query Operations
```rust
// Simple query
let results = db.query("SELECT * FROM users").await?;

// Query with parameters
let results = db.query("SELECT * FROM users WHERE name = ?")
    .bind("Alice")
    .await?;

// Query builder
let results = db.select_from("users")
    .columns(&["id", "name", "email"])
    .where_eq("name", "Alice")
    .order_by("created_at", Order::Desc)
    .limit(10)
    .await?;

// Aggregation queries
let count = db.query_scalar::<i64>("SELECT COUNT(*) FROM users").await?;
let avg_age = db.query_scalar::<f64>("SELECT AVG(age) FROM users").await?;
```

#### Encryption Management
```rust
// Set encryption for table
db.set_table_encryption("users", "balanced").await?;

// Set encryption for specific column
db.set_column_encryption("users", "password", "fortress").await?;

// Rotate keys
db.rotate_keys("users").await?;

// Get encryption metadata
let metadata = db.get_encryption_metadata("users").await?;
```

### Transactions
```rust
// Begin transaction
let mut tx = db.begin().await?;

// Perform operations
tx.insert("users", &user_data).await?;
tx.insert("audit_log", &audit_data).await?;

// Commit or rollback
tx.commit().await?;
// or
tx.rollback().await?;
```

### Streaming Operations
```rust
use futures::TryStreamExt;

// Stream query results
let mut stream = db.stream_query("SELECT * FROM large_table").await?;
while let Some(row) = stream.try_next().await? {
    process_row(row).await?;
}

// Stream bulk insert
let data_stream = futures::stream::iter(large_dataset);
db.insert_stream("users", data_stream).await?;
```

## REST API

### Base URL
```
http://localhost:8080/api/v1
```

### Authentication
```bash
# API Key Authentication
curl -H "X-API-Key: your-api-key" http://localhost:8080/api/v1/tables

# JWT Token Authentication
curl -H "Authorization: Bearer your-jwt-token" http://localhost:8080/api/v1/tables
```

### Database Management

#### Create Database
```bash
curl -X POST http://localhost:8080/api/v1/databases \
  -H "Content-Type: application/json" \
  -d '{
    "name": "mydb",
    "algorithm": "aegis256",
    "key_rotation_interval": "23h",
    "storage_path": "./data/mydb"
  }'
```

#### Get Database Info
```bash
curl http://localhost:8080/api/v1/databases/mydb
```

Response:
```json
{
  "name": "mydb",
  "created_at": "2024-01-15T10:30:00Z",
  "algorithm": "aegis256",
  "key_rotation_interval": "23h",
  "tables_count": 5,
  "size_bytes": 1048576
}
```

### Table Management

#### Create Table
```bash
curl -X POST http://localhost:8080/api/v1/databases/mydb/tables \
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

#### List Tables
```bash
curl http://localhost:8080/api/v1/databases/mydb/tables
```

Response:
```json
{
  "tables": [
    {
      "name": "users",
      "columns": 4,
      "rows": 1250,
      "encryption": "balanced",
      "created_at": "2024-01-15T10:30:00Z"
    }
  ]
}
```

#### Get Table Schema
```bash
curl http://localhost:8080/api/v1/databases/mydb/tables/users/schema
```

Response:
```json
{
  "name": "users",
  "columns": [
    {
      "name": "id",
      "type": "uuid",
      "primary_key": true,
      "nullable": false,
      "encrypted": false
    },
    {
      "name": "name",
      "type": "text",
      "primary_key": false,
      "nullable": false,
      "encrypted": false
    },
    {
      "name": "email",
      "type": "text",
      "primary_key": false,
      "nullable": false,
      "encrypted": false
    },
    {
      "name": "password",
      "type": "encrypted",
      "primary_key": false,
      "nullable": false,
      "encrypted": true,
      "encryption_algorithm": "aes256gcm"
    }
  ],
  "encryption": "balanced"
}
```

### Data Operations

#### Insert Data
```bash
curl -X POST http://localhost:8080/api/v1/databases/mydb/tables/users/data \
  -H "Content-Type: application/json" \
  -d '{
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "name": "Alice Johnson",
    "email": "alice@example.com",
    "password": "super_secret_password"
  }'
```

#### Bulk Insert
```bash
curl -X POST http://localhost:8080/api/v1/databases/mydb/tables/users/bulk \
  -H "Content-Type: application/json" \
  -d '{
    "data": [
      {"id": "uuid1", "name": "Bob", "email": "bob@example.com"},
      {"id": "uuid2", "name": "Charlie", "email": "charlie@example.com"}
    ]
  }'
```

#### Query Data
```bash
# Simple query
curl "http://localhost:8080/api/v1/databases/mydb/tables/users/data"

# Query with filters
curl "http://localhost:8080/api/v1/databases/mydb/tables/users/data?name=Alice"

# Query with SQL
curl -X POST http://localhost:8080/api/v1/databases/mydb/query \
  -H "Content-Type: application/json" \
  -d '{
    "sql": "SELECT id, name, email FROM users WHERE name = ?",
    "parameters": ["Alice"]
  }'
```

Response:
```json
{
  "results": [
    {
      "id": "550e8400-e29b-41d4-a716-446655440000",
      "name": "Alice Johnson",
      "email": "alice@example.com"
    }
  ],
  "total_count": 1,
  "execution_time_ms": 2.5
}
```

#### Update Data
```bash
curl -X PUT http://localhost:8080/api/v1/databases/mydb/tables/users/data/550e8400-e29b-41d4-a716-446655440000 \
  -H "Content-Type: application/json" \
  -d '{
    "email": "alice.new@example.com"
  }'
```

#### Delete Data
```bash
curl -X DELETE http://localhost:8080/api/v1/databases/mydb/tables/users/data/550e8400-e29b-41d4-a716-446655440000
```

### Encryption Management

#### Rotate Keys
```bash
curl -X POST http://localhost:8080/api/v1/databases/mydb/tables/users/rotate-keys
```

#### Get Encryption Metadata
```bash
curl http://localhost:8080/api/v1/databases/mydb/tables/users/encryption-metadata
```

Response:
```json
{
  "table_encryption": "balanced",
  "column_encryption": {
    "password": "fortress"
  },
  "key_rotation_schedule": {
    "table": "7d",
    "password": "30d"
  },
  "last_rotation": "2024-01-15T10:30:00Z",
  "next_rotation": "2024-01-22T10:30:00Z"
}
```

## gRPC API

### Protocol Definition
```protobuf
syntax = "proto3";

package fortress;

service FortressService {
  rpc CreateDatabase(CreateDatabaseRequest) returns (DatabaseResponse);
  rpc GetDatabase(GetDatabaseRequest) returns (DatabaseResponse);
  rpc CreateTable(CreateTableRequest) returns (TableResponse);
  rpc ListTables(ListTablesRequest) returns (ListTablesResponse);
  rpc InsertData(InsertDataRequest) returns (InsertResponse);
  rpc QueryData(QueryRequest) returns (QueryResponse);
  rpc UpdateData(UpdateDataRequest) returns (UpdateResponse);
  rpc DeleteData(DeleteDataRequest) returns (DeleteResponse);
  rpc RotateKeys(RotateKeysRequest) returns (RotateKeysResponse);
}

message CreateDatabaseRequest {
  string name = 1;
  string algorithm = 2;
  string key_rotation_interval = 3;
  string storage_path = 4;
  map<string, EncryptionProfile> encryption_profiles = 5;
}

message CreateTableRequest {
  string database_name = 1;
  string table_name = 2;
  repeated ColumnDefinition columns = 3;
  string encryption = 4;
  map<string, string> column_encryption = 5;
}

message ColumnDefinition {
  string name = 1;
  ColumnType type = 2;
  bool primary_key = 3;
  bool nullable = 4;
  string encryption = 5;
}

enum ColumnType {
  UUID = 0;
  TEXT = 1;
  INTEGER = 2;
  FLOAT = 3;
  BOOLEAN = 4;
  BLOB = 5;
  ENCRYPTED = 6;
  TIMESTAMP = 7;
}

message QueryRequest {
  string database_name = 1;
  string sql = 2;
  repeated bytes parameters = 3;
  map<string, string> options = 4;
}

message QueryResponse {
  repeated Row rows = 1;
  int64 total_count = 2;
  double execution_time_ms = 3;
  QueryMetadata metadata = 4;
}

message Row {
  repeated Value values = 1;
}

message Value {
  oneof value {
    string string_value = 1;
    int64 int_value = 2;
    double float_value = 3;
    bool bool_value = 4;
    bytes bytes_value = 5;
    string null_value = 6;
  }
}
```

### Client Usage (Rust)
```rust
use fortress_grpc::fortress_service_client::FortressServiceClient;
use fortress_grpc::{CreateDatabaseRequest, DatabaseResponse};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut client = FortressServiceClient::connect("http://[::1]:50051").await?;
    
    let request = CreateDatabaseRequest {
        name: "mydb".to_string(),
        algorithm: "aegis256".to_string(),
        key_rotation_interval: "23h".to_string(),
        storage_path: "./data/mydb".to_string(),
        encryption_profiles: HashMap::new(),
    };
    
    let response = client.create_database(request).await?;
    println!("Database created: {:?}", response.into_inner());
    
    Ok(())
}
```

## CLI API

### Installation
```bash
cargo install fortress-cli
```

### Basic Commands

#### Database Operations
```bash
# Create database
fortress db create mydb --algorithm aegis256 --rotation 23h

# List databases
fortress db list

# Get database info
fortress db info mydb

# Delete database
fortress db delete mydb
```

#### Table Operations
```bash
# Create table
fortress table create mydb users \
  --columns "id:uuid,name:text,email:text,password:encrypted" \
  --encryption balanced \
  --column-encryption "password:fortress"

# List tables
fortress table list mydb

# Get table schema
fortress table schema mydb users

# Drop table
fortress table drop mydb users
```

#### Data Operations
```bash
# Insert data
fortress insert mydb users \
  --name "Alice" \
  --email "alice@example.com" \
  --password "secret123"

# Bulk insert from JSON file
fortress bulk-insert mydb users --file users.json

# Query data
fortress query mydb "SELECT * FROM users WHERE name = 'Alice'"

# Update data
fortress update mydb users \
  --set "email=alice.new@example.com" \
  --where "name='Alice'"

# Delete data
fortress delete mydb users --where "name='Alice'"
```

#### Encryption Operations
```bash
# Rotate keys
fortress rotate-keys mydb users

# Set encryption
fortress encryption set mydb users balanced

# Set column encryption
fortress encryption set-column mydb users password fortress

# Get encryption metadata
fortress encryption metadata mydb users
```

#### Configuration
```bash
# Show configuration
fortress config show

# Set configuration
fortress config set default.algorithm aegis256
fortress config set api.port 8080

# Export configuration
fortress config export > fortress.toml

# Import configuration
fortress config import fortress.toml
```

## WebAssembly API

### Browser Usage
```html
<!DOCTYPE html>
<html>
<head>
    <script src="https://unpkg.com/fortress-wasm@latest/dist/fortress.js"></script>
</head>
<body>
    <script>
        async function initDatabase() {
            const fortress = await Fortress.init();
            
            // Create in-memory database
            const db = await fortress.createDatabase({
                name: "mydb",
                algorithm: "aegis256",
                storage: "memory"
            });
            
            // Create table
            await db.createTable({
                name: "users",
                columns: [
                    {name: "id", type: "uuid"},
                    {name: "name", type: "text"},
                    {name: "email", type: "text"}
                ]
            });
            
            // Insert data
            await db.insert("users", {
                id: crypto.randomUUID(),
                name: "Alice",
                email: "alice@example.com"
            });
            
            // Query data
            const results = await db.query("SELECT * FROM users");
            console.log(results);
        }
        
        initDatabase();
    </script>
</body>
</html>
```

### Node.js Usage
```javascript
const Fortress = require('fortress-wasm');

async function main() {
    const fortress = await Fortress.init();
    
    const db = await fortress.connect({
        path: "./mydb",
        algorithm: "aegis256"
    });
    
    const results = await db.query("SELECT COUNT(*) FROM users");
    console.log(`Total users: ${results[0].count}`);
}

main().catch(console.error);
```

## Error Handling

### Error Response Format
```json
{
  "error": {
    "code": "ENCRYPTION_FAILED",
    "message": "Failed to encrypt data: invalid key length",
    "details": {
      "algorithm": "aegis256",
      "expected_key_length": 32,
      "actual_key_length": 16
    },
    "request_id": "req_123456789",
    "timestamp": "2024-01-15T10:30:00Z"
  }
}
```

### Common Error Codes
- `DATABASE_NOT_FOUND`: Database does not exist
- `TABLE_NOT_FOUND`: Table does not exist
- `ENCRYPTION_FAILED`: Encryption operation failed
- `KEY_ROTATION_FAILED`: Key rotation failed
- `INVALID_SQL`: SQL syntax error
- `PERMISSION_DENIED`: Insufficient permissions
- `RATE_LIMITED`: Too many requests

## Rate Limiting

### Default Limits
- **REST API**: 1000 requests/minute
- **gRPC**: 5000 requests/minute
- **CLI**: No limit (local operations)

### Rate Limit Headers
```http
X-RateLimit-Limit: 1000
X-RateLimit-Remaining: 999
X-RateLimit-Reset: 1642248600
```

## Pagination

### Query Pagination
```bash
curl "http://localhost:8080/api/v1/databases/mydb/tables/users/data?page=1&limit=50"
```

Response:
```json
{
  "results": [...],
  "pagination": {
    "page": 1,
    "limit": 50,
    "total_count": 1250,
    "total_pages": 25,
    "has_next": true,
    "has_prev": false
  }
}
```

## Streaming APIs

### Server-Sent Events
```bash
curl -H "Accept: text/event-stream" \
  "http://localhost:8080/api/v1/databases/mydb/tables/users/stream"
```

### WebSocket API
```javascript
const ws = new WebSocket('ws://localhost:8080/api/v1/ws');

ws.onopen = () => {
    ws.send(JSON.stringify({
        type: 'query',
        database: 'mydb',
        sql: 'SELECT * FROM users'
    }));
};

ws.onmessage = (event) => {
    const data = JSON.parse(event.data);
    console.log('Received:', data);
};
```

This comprehensive API documentation provides developers with all the necessary information to integrate Fortress into their applications, regardless of their preferred programming language or deployment environment.
