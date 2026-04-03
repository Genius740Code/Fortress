# Fortress Quick Start Guide

Get started with Fortress quickly with ecosystem-specific guides and examples.

## Table of Contents

- [What is Fortress?](#what-is-fortress)
- [Choose Your Ecosystem](#choose-your-ecosystem)
- [Rust Quick Start](#rust-quick-start)
- [Python Quick Start](#python-quick-start)
- [Node.js Quick Start](#nodejs-quick-start)
- [Go Quick Start](#go-quick-start)
- [Docker Quick Start](#docker-quick-start)
- [Web Dashboard Quick Start](#web-dashboard-quick-start)
- [Next Steps](#next-steps)

## What is Fortress?

Fortress is an enterprise security platform that provides:
- **Automatic Encryption**: All data encrypted before storage
- **Key Management**: Automatic key generation and rotation
- **Multi-Tenant Support**: Isolated data per organization
- **High Performance**: Optimized for speed and scalability
- **Multiple APIs**: REST, GraphQL, WebSocket, and gRPC

## Choose Your Ecosystem

Select your preferred programming language or platform:

| Ecosystem | Installation Time | Learning Curve | Best For |
|-----------|------------------|----------------|----------|
| [Rust](#rust-quick-start) | 2-5 min | Medium | High-performance applications |
| [Python](#python-quick-start) | 1-3 min | Low | Data science, web applications |
| [Node.js](#nodejs-quick-start) | 1-3 min | Low | JavaScript/TypeScript projects |
| [Go](#go-quick-start) | 2-4 min | Low | Microservices, cloud native |
| [Docker](#docker-quick-start) | 1-2 min | Low | Containerized deployments |

## Rust Quick Start

### Installation

```bash
# Install Fortress CLI
cargo install fortress-cli

# Verify installation
fortress --version
```

### Basic Usage

```rust
use fortress_core::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
struct User {
    id: String,
    name: String,
    email: String,
    ssn: String, // Will be encrypted
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize Fortress
    let fortress = Fortress::builder()
        .with_algorithm(Aegis256::new())
        .build()
        .await?;

    // Create encrypted database
    let db = fortress.create_database("myapp").await?;

    // Create table with encrypted fields
    let table = db.create_table("users", vec![
        FieldDefinition::new("id", FieldType::Text),
        FieldDefinition::new("name", FieldType::Text),
        FieldDefinition::new("email", FieldType::Text),
        FieldDefinition::new("ssn", FieldType::Encrypted),
    ]).await?;

    // Insert data (automatically encrypted)
    let user = User {
        id: "123".to_string(),
        name: "Alice Johnson".to_string(),
        email: "alice@example.com".to_string(),
        ssn: "123-45-6789".to_string(),
    };

    let result = table.insert(&user).await?;
    println!("User inserted with ID: {}", result.id);

    // Query data (automatically decrypted)
    let retrieved: User = table.get("123").await?;
    println!("Retrieved user: {} ({})", retrieved.name, retrieved.email);

    Ok(())
}
```

### CLI Operations

```bash
# Initialize Fortress
fortress init

# Start server
fortress server start

# Create encryption key
fortress key create --name app-key --algorithm aegis256

# Encrypt data
echo "secret data" | fortress encrypt --key-id app-key > encrypted.dat

# Decrypt data
fortress decrypt --key-id app-key --input encrypted.dat
```

### Cargo.toml

```toml
[dependencies]
fortress-core = "1.0.0"
tokio = { version = "1.0", features = ["full"] }
serde = { version = "1.0", features = ["derive"] }
```

## Python Quick Start

### Installation

```bash
# Install Fortress
pip install fortress-db

# Verify installation
python -c "import fortress; print(fortress.__version__)"
```

### Basic Usage

```python
from fortress import Fortress
from fortress.models import User
import asyncio

async def main():
    # Initialize Fortress
    fortress = Fortress(
        server_url="http://localhost:8080",
        api_key="your-api-key"
    )

    # Create database
    db = await fortress.create_database("myapp")

    # Create table with encrypted fields
    table = await db.create_table("users", [
        {"name": "id", "type": "text", "primary_key": True},
        {"name": "name", "type": "text"},
        {"name": "email", "type": "text", "unique": True},
        {"name": "ssn", "type": "encrypted", "sensitivity": "high"}
    ])

    # Insert data (automatically encrypted)
    user = await table.insert({
        "id": "123",
        "name": "Alice Johnson",
        "email": "alice@example.com",
        "ssn": "123-45-6789"  # This will be encrypted
    })

    print(f"User inserted: {user['name']}")

    # Query data (automatically decrypted)
    retrieved = await table.get("123")
    print(f"Retrieved: {retrieved['name']} ({retrieved['email']})")

    # Search with encrypted fields
    results = await table.search(
        filters={"name": "Alice Johnson"},
        include_encrypted=True
    )
    print(f"Found {len(results)} users")

# Run the async function
asyncio.run(main())
```

### CLI Operations

```bash
# Start Fortress server
fortress server start

# Create database and table
python -c "
import asyncio
from fortress import Fortress

async def setup():
    f = Fortress('http://localhost:8080')
    db = await f.create_database('myapp')
    table = await db.create_table('users', [
        {'name': 'id', 'type': 'text'},
        {'name': 'name', 'type': 'text'},
        {'name': 'ssn', 'type': 'encrypted'}
    ])
    print('Database and table created!')

asyncio.run(setup())
"
```

### Requirements.txt

```txt
fortress-db>=1.0.0
aiohttp>=3.8.0
pydantic>=1.10.0
```

## Node.js Quick Start

### Installation

```bash
# Install Fortress
npm install fortress-db

# Or globally for CLI
npm install -g fortress-cli
```

### Basic Usage

```javascript
const { Fortress } = require('fortress-db');

async function main() {
    // Initialize Fortress
    const fortress = new Fortress({
        serverUrl: 'http://localhost:8080',
        apiKey: 'your-api-key'
    });

    // Create database
    const db = await fortress.createDatabase('myapp');

    // Create table with encrypted fields
    const table = await db.createTable('users', [
        { name: 'id', type: 'text', primaryKey: true },
        { name: 'name', type: 'text' },
        { name: 'email', type: 'text', unique: true },
        { name: 'ssn', type: 'encrypted', sensitivity: 'high' }
    ]);

    // Insert data (automatically encrypted)
    const user = await table.insert({
        id: '123',
        name: 'Alice Johnson',
        email: 'alice@example.com',
        ssn: '123-45-6789'  // This will be encrypted
    });

    console.log(`User inserted: ${user.name}`);

    // Query data (automatically decrypted)
    const retrieved = await table.get('123');
    console.log(`Retrieved: ${retrieved.name} (${retrieved.email})`);

    // Search with encrypted fields
    const results = await table.search({
        filters: { name: 'Alice Johnson' },
        includeEncrypted: true
    });
    console.log(`Found ${results.length} users`);
}

main().catch(console.error);
```

### TypeScript Usage

```typescript
import { Fortress, User, TableSchema } from 'fortress-db';

interface AppUser {
    id: string;
    name: string;
    email: string;
    ssn: string;
}

async function main() {
    const fortress = new Fortress<AppUser>({
        serverUrl: 'http://localhost:8080',
        apiKey: 'your-api-key'
    });

    const db = await fortress.createDatabase('myapp');

    const schema: TableSchema = [
        { name: 'id', type: 'text', primaryKey: true },
        { name: 'name', type: 'text' },
        { name: 'email', type: 'text', unique: true },
        { name: 'ssn', type: 'encrypted', sensitivity: 'high' }
    ];

    const table = await db.createTable<AppUser>('users', schema);

    const user = await table.insert({
        id: '123',
        name: 'Alice Johnson',
        email: 'alice@example.com',
        ssn: '123-45-6789'
    });

    console.log(`User: ${user.name}`);
}

main();
```

### package.json

```json
{
  "name": "my-fortress-app",
  "version": "1.0.0",
  "dependencies": {
    "fortress-db": "^1.0.0"
  },
  "devDependencies": {
    "@types/node": "^18.0.0",
    "typescript": "^4.9.0"
  }
}
```

## Go Quick Start

### Installation

```bash
# Install Fortress Go module
go get github.com/fortress-security/fortress/fortress-go

# Install CLI tool
go install github.com/fortress-security/fortress/fortress-go/cmd/fortress-cli@latest
```

### Basic Usage

```go
package main

import (
    "context"
    "fmt"
    "log"

    "github.com/fortress-security/fortress/fortress-go"
    "github.com/fortress-security/fortress/fortress-go/models"
)

type User struct {
    ID    string `json:"id"`
    Name  string `json:"name"`
    Email string `json:"email"`
    SSN   string `json:"ssn"` // Will be encrypted
}

func main() {
    // Initialize Fortress client
    client, err := fortress.NewClient(&fortress.Config{
        ServerURL: "http://localhost:8080",
        APIKey:    "your-api-key",
    })
    if err != nil {
        log.Fatal(err)
    }

    ctx := context.Background()

    // Create database
    db, err := client.CreateDatabase(ctx, "myapp")
    if err != nil {
        log.Fatal(err)
    }

    // Create table with encrypted fields
    schema := []models.FieldDefinition{
        {Name: "id", Type: "text", PrimaryKey: true},
        {Name: "name", Type: "text"},
        {Name: "email", Type: "text", Unique: true},
        {Name: "ssn", Type: "encrypted", Sensitivity: "high"},
    }

    table, err := db.CreateTable(ctx, "users", schema)
    if err != nil {
        log.Fatal(err)
    }

    // Insert data (automatically encrypted)
    user := User{
        ID:    "123",
        Name:  "Alice Johnson",
        Email: "alice@example.com",
        SSN:   "123-45-6789", // This will be encrypted
    }

    result, err := table.Insert(ctx, user)
    if err != nil {
        log.Fatal(err)
    }

    fmt.Printf("User inserted: %s\n", result.Name)

    // Query data (automatically decrypted)
    var retrieved User
    err = table.Get(ctx, "123", &retrieved)
    if err != nil {
        log.Fatal(err)
    }

    fmt.Printf("Retrieved: %s (%s)\n", retrieved.Name, retrieved.Email)

    // Search with encrypted fields
    results, err := table.Search(ctx, &models.SearchOptions{
        Filters: map[string]interface{}{
            "name": "Alice Johnson",
        },
        IncludeEncrypted: true,
    })
    if err != nil {
        log.Fatal(err)
    }

    fmt.Printf("Found %d users\n", len(results))
}
```

### go.mod

```mod
module my-fortress-app

go 1.21

require (
    github.com/fortress-security/fortress/fortress-go v1.0.0
)
```

## Docker Quick Start

### Using Pre-built Images

```bash
# Pull the latest image
docker pull fortress-security/fortress:latest

# Run Fortress with default settings
docker run -d \
  --name fortress \
  -p 8080:8080 \
  -p 9090:9090 \
  fortress-security/fortress:latest

# Check if it's running
curl http://localhost:8080/health
```

### Docker Compose

Create a `docker-compose.yml` file:

```yaml
version: '3.8'

services:
  fortress:
    image: fortress-security/fortress:latest
    container_name: fortress
    restart: unless-stopped
    ports:
      - "8080:8080"
      - "9090:9090"
    volumes:
      - fortress_data:/var/lib/fortress
      - ./config.toml:/etc/fortress/config.toml:ro
    environment:
      - FORTRESS_LOG_LEVEL=info
      - FORTRESS_ENCRYPTION_DEFAULT_ALGORITHM=aegis256
    networks:
      - fortress-network

  redis:
    image: redis:7-alpine
    container_name: fortress-redis
    restart: unless-stopped
    ports:
      - "6379:6379"
    volumes:
      - redis_data:/data
    networks:
      - fortress-network

volumes:
  fortress_data:
  redis_data:

networks:
  fortress-network:
    driver: bridge
```

Start the services:

```bash
# Start all services
docker-compose up -d

# View logs
docker-compose logs -f fortress

# Stop services
docker-compose down
```

### Custom Configuration

Create a `config.toml` file:

```toml
[server]
host = "0.0.0.0"
port = 8080

[database]
default_algorithm = "aegis256"

[encryption]
auto_rotation = true
key_rotation_interval = "24h"

[cache]
backend = "redis"
url = "redis://redis:6379"
ttl = "1h"

[logging]
level = "info"
format = "json"
```

Then run with custom configuration:

```bash
docker run -d \
  --name fortress \
  -p 8080:8080 \
  -v $(pwd)/config.toml:/etc/fortress/config.toml \
  fortress-security/fortress:latest
```

## Web Dashboard Quick Start

### Accessing the Dashboard

1. **Start Fortress Server**:
   ```bash
   fortress server start
   ```

2. **Open Dashboard**:
   Navigate to [http://localhost:8080](http://localhost:8080) in your browser

3. **Login**:
   - Default username: `admin`
   - Default password: `admin123` (change immediately)

### Dashboard Features

- **Database Management**: Create and manage databases
- **Table Management**: Define schemas and encrypted fields
- **Key Management**: Generate and rotate encryption keys
- **User Management**: Manage users and permissions
- **Monitoring**: View performance metrics and logs
- **Audit Logs**: Track all security events

### API Explorer

The dashboard includes a built-in API explorer:

1. Navigate to `/api-explorer`
2. Test API endpoints directly
3. View request/response examples
4. Generate code snippets

## Next Steps

### Learning Resources

- **[Installation Guide](INSTALLATION_GUIDE.md)**: Detailed installation instructions
- **[API Reference](API_REFERENCE.md)**: Complete API documentation
- **[Security Guide](SECURITY.md)**: Security best practices
- **[Configuration Reference](CONFIGURATION_REFERENCE.md)**: All configuration options

### Common Use Cases

#### 1. Secure User Data
```rust
// Encrypt sensitive user information
let user = UserProfile {
    name: "Alice Johnson",
    email: "alice@example.com",
    ssn: "123-45-6789", // Automatically encrypted
    credit_card: "4111-1111-1111-1111", // Automatically encrypted
};
```

#### 2. API Key Management
```python
# Store API keys securely
api_keys = await table.insert({
    "service": "stripe",
    "key": "sk_test_...",  # Automatically encrypted
    "created_at": datetime.now()
})
```

#### 3. Configuration Secrets
```javascript
// Encrypt configuration values
const config = await table.insert({
    "database_url": "postgres://...",  // Automatically encrypted
    "jwt_secret": "your-secret-key",   // Automatically encrypted
    "encryption_key": "master-key"     // Automatically encrypted
});
```

### Production Deployment

For production deployments, consider:

1. **Security**:
   - Use strong authentication
   - Enable audit logging
   - Configure rate limiting

2. **Performance**:
   - Enable caching
   - Configure connection pooling
   - Set up monitoring

3. **Reliability**:
   - Enable clustering
   - Set up backups
   - Configure health checks

See the [Production Deployment Guide](PRODUCTION_DEPLOYMENT_GUIDE.md) for detailed instructions.

### Getting Help

- **Documentation**: [docs.fortress-security.org](https://docs.fortress-security.org)
- **Issues**: [GitHub Issues](https://github.com/fortress-security/fortress/issues)
- **Discussions**: [GitHub Discussions](https://github.com/fortress-security/fortress/discussions)
- **Community**: [Discord Server](https://discord.gg/fortress)

---

Welcome to Fortress! 🎉 You're now ready to build secure applications with automatic encryption.
