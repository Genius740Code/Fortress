# Fortress Server

[![Crates.io](https://img.shields.io/crates/v/fortress-server.svg)](https://crates.io/crates/fortress-server)
[![License: Fortress Sustainable Use License 1.0](https://img.shields.io/badge/License-Fortress%20Sustainable%20Use%20License%201.0-blue.svg)](../../LICENSE)

🛡️ **Fortress Server** - High-performance secure database server with enterprise-grade encryption, clustering, and REST/GraphQL APIs.

## Features

- **Automatic Encryption/Decryption**: All data is automatically encrypted before storage and decrypted after retrieval
- **RESTful API**: Standard HTTP methods with JSON payloads
- **JWT Authentication**: Token-based authentication with role-based authorization
- **Multi-tenant Support**: Isolated data per tenant/organization
- **Field-level Encryption**: Encrypt specific fields with different algorithms
- **Audit Logging**: Comprehensive security event logging
- **Health Monitoring**: Built-in health checks and metrics
- **Rate Limiting**: Configurable rate limiting and DDoS protection
- **CORS Support**: Cross-origin resource sharing configuration
- **Prometheus Metrics**: Export metrics for monitoring

## Quick Start

### Installation

Add the following to your `Cargo.toml`:

```toml
[dependencies]
fortress-server = "0.1.0"
tokio = { version = "1.35", features = ["full"] }
tracing-subscriber = "0.3"
```

### Basic Server

```rust
use fortress_server::prelude::*;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::from_default_env())
        .with(tracing_subscriber::fmt::layer())
        .init();

    // Create server configuration
    let config = ServerConfig::default();

    // Create and start the server
    let server = FortressServer::new(config).await?;
    server.listen("127.0.0.1:8080").await?;

    Ok(())
}
```

### Run the Example

```bash
cd crates/fortress-server
cargo run --example simple_server
```

## API Endpoints

### Authentication

#### Login
```http
POST /auth/login
Content-Type: application/json

{
  "username": "admin",
  "password": "admin123",
  "tenant_id": "optional-tenant-id"
}
```

#### Refresh Token
```http
POST /auth/refresh
Content-Type: application/json

{
  "refresh_token": "your-refresh-token"
}
```

### Data Management

#### Store Data
```http
POST /data
Authorization: Bearer your-jwt-token
Content-Type: application/json

{
  "data": {
    "message": "Hello, Fortress!",
    "user_id": 123,
    "sensitive_info": "secret data"
  },
  "metadata": {
    "category": "user-data",
    "priority": "high"
  },
  "algorithm": "aegis256",
  "field_encryption": {
    "fields": {
      "sensitive_info": {
        "algorithm": "aes256gcm",
        "sensitivity": "high"
      }
    }
  }
}
```

#### Retrieve Data
```http
GET /data/{data_id}
Authorization: Bearer your-jwt-token
```

#### List Data
```http
GET /data?page=1&page_size=50&sort=created_at&order=desc
Authorization: Bearer your-jwt-token
```

#### Delete Data
```http
DELETE /data/{data_id}
Authorization: Bearer your-jwt-token
Content-Type: application/json

{
  "soft_delete": false
}
```

### Key Management

#### Generate Key
```http
POST /keys
Authorization: Bearer your-jwt-token
Content-Type: application/json

{
  "algorithm": "aegis256",
  "key_size": 256,
  "metadata": {
    "purpose": "data-encryption",
    "owner": "security-team"
  }
}
```

### Monitoring

#### Health Check
```http
GET /health
```

#### Metrics (JSON)
```http
GET /metrics
```

#### Prometheus Metrics
```http
GET /metrics/prometheus
```

## Configuration

### Server Configuration

```rust
use fortress_server::config::*;

let config = ServerConfig {
    network: NetworkConfig {
        host: "0.0.0.0".to_string(),
        port: 8080,
        max_body_size: 10 * 1024 * 1024, // 10MB
        request_timeout: 30,
        ..Default::default()
    },
    security: SecurityConfig {
        jwt_secret: "your-secret-key".to_string(),
        token_expiration: 3600, // 1 hour
        cors: CorsConfig::default(),
        rate_limit: RateLimitConfig::default(),
        ..Default::default()
    },
    features: FeatureFlags {
        auth_enabled: true,
        audit_enabled: true,
        metrics_enabled: true,
        health_enabled: true,
        multi_tenant: true,
        field_encryption: true,
    },
    ..Default::default()
};
```

### Environment Variables

You can configure the server using environment variables:

```bash
export FORTRESS_HOST=0.0.0.0
export FORTRESS_PORT=8080
export FORTRESS_JWT_SECRET=your-secret-key
export FORTRESS_LOG_LEVEL=info
export FORTRESS_AUTH_ENABLED=true
export FORTRESS_METRICS_ENABLED=true
```

## Security Features

### Authentication & Authorization

- **JWT Tokens**: Secure token-based authentication
- **Role-based Access Control**: Fine-grained permissions
- **Multi-tenant Isolation**: Data separation per organization
- **Token Refresh**: Automatic token renewal

### Encryption

- **Automatic Encryption**: Data is encrypted before storage
- **Multiple Algorithms**: Support for AEGIS-256, ChaCha20-Poly1305, AES-256-GCM
- **Field-level Encryption**: Encrypt specific fields with different algorithms
- **Key Management**: Automatic key generation and rotation

### Rate Limiting

```rust
let rate_limit = RateLimitConfig {
    enabled: true,
    requests_per_minute: 60,
    requests_per_hour: 1000,
    burst_size: 10,
};
```

## Monitoring & Observability

### Health Checks

The server provides comprehensive health checks for all components:

```json
{
  "status": "healthy",
  "version": "0.1.0",
  "uptime": 3600,
  "components": {
    "auth": {
      "status": "healthy",
      "response_time_ms": 15,
      "last_check": "2026-01-01T12:00:00Z"
    },
    "encryption": {
      "status": "healthy",
      "response_time_ms": 25,
      "last_check": "2026-01-01T12:00:00Z"
    }
  },
  "timestamp": "2026-01-01T12:00:00Z"
}
```

### Metrics

Comprehensive metrics are available in both JSON and Prometheus formats:

- HTTP request counts and response times
- Authentication attempts and failures
- Data storage and retrieval metrics
- Encryption/decryption operations
- Rate limit violations
- Error counts by type

## Development

### Running Tests

```bash
cd crates/fortress-server
cargo test
```

### Building

```bash
cargo build --release
```

### Running with Features

```bash
# Enable all features
cargo run --example simple_server --all-features

# Enable specific features
cargo run --example simple_server --features "auth,metrics"
```

## Architecture

The Fortress server is built with a modular architecture:

- **Handlers**: HTTP request handlers for API endpoints
- **Middleware**: Authentication, logging, rate limiting, CORS
- **Authentication**: JWT-based auth with role-based authorization
- **Health Checks**: Component health monitoring
- **Metrics**: Comprehensive metrics collection and export
- **Configuration**: Flexible configuration management

## Production Deployment

### Docker

```dockerfile
FROM rust:1.70 as builder
WORKDIR /app
COPY . .
RUN cargo build --release

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/target/release/fortress-server /usr/local/bin/
EXPOSE 8080
CMD ["fortress-server"]
```

### Environment Configuration

For production, ensure you:

1. Set a strong JWT secret
2. Enable HTTPS/TLS
3. Configure proper rate limiting
4. Set up monitoring and alerting
5. Enable audit logging
6. Use a proper database backend

## License

This project is licensed under the **Fortress Sustainable Use License 1.0** - see the [LICENSE](../../LICENSE) file for details.

## Contributing

Please read [CONTRIBUTING.md](../../CONTRIBUTING.md) for details on our code of conduct and the process for submitting pull requests.

## Support

- 📖 [Documentation](https://docs.fortress-db.com)
- 🐛 [Issue Tracker](https://github.com/Genius740Code/Fortress/issues)
- 💬 [Discussions](https://github.com/Genius740Code/Fortress/discussions)
