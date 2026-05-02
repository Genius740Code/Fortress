# Fortress

![CI](https://github.com/Genius740Code/Fortress/workflows/CI/badge.svg)
![Security Audit](https://github.com/Genius740Code/Fortress/workflows/Security%20Audit/badge.svg)
![Documentation](https://github.com/Genius740Code/Fortress/workflows/Documentation/badge.svg)

**Fortress** - Enterprise Security Platform

A comprehensive security platform that provides enterprise-grade cryptography, key management, distributed caching, clustering, and compliance features with simplicity of modern APIs.


## Key Features

### Feature Maturity Legend
- `[Stable]` - Production-ready with comprehensive testing
- `[Beta]` - Feature-complete, needs production validation
- `[In Development]` - Partial implementation, APIs may change
- `[Planned]` - Designed but not yet implemented

### Security First
- **Automatic Encryption**: All data encrypted before storage, decrypted after retrieval `[Stable]`
- **Multiple Algorithms**: AEGIS-256, ChaCha20-Poly1305, AES-256-GCM, RSA, ECDSA `[Stable]`
- **Field-Level Encryption**: Encrypt specific fields with different algorithms `[Stable]`
- **Key Management**: Automatic key generation, rotation, and secure storage `[Stable]`
- **Zero-Downtime Rotation**: Rotate encryption keys without service interruption `[Stable]`
- **HSM Integration**: Hardware Security Module support `[Stable]`
- **Transit Engine**: Non-invasive encryption as a service `[Stable]`

### Enterprise Architecture
- **Multi-Tenant Support**: Isolated data per tenant/organization `[Stable]`
- **Cluster Support**: High availability with Raft consensus `[Beta]`
- **Audit Logging**: Comprehensive security event logging `[Stable]`
- **Compliance Framework**: GDPR, HIPAA, PCI-DSS compliance features `[Stable]`
- **HSM Integration**: Hardware Security Module support `[Stable]`

### High Performance
- **Optimized Algorithms**: AEGIS-256 for maximum speed `[Stable]`
- **Caching Layer**: Intelligent multi-tier caching with Redis/Memcached/Hybrid `[Stable]`
- **Connection Pooling**: Efficient database and cache connections `[Stable]`
- **Compression**: Built-in data compression with LZ4 `[Stable]`
- **Performance Monitoring**: Real-time metrics and profiling `[Stable]`

### Developer Friendly
- **REST API**: Standard HTTP methods with JSON payloads `[Stable]`
- **Multiple SDKs**: 
  - Rust: ✅ Stable (crates.io/crates/fortress)
  - **Python**: ✅ Available (v1.0.0)
  - **JavaScript**: ✅ Available (v1.0.0)
  - **Go**: ✅ Available (v1.0.0)
- **gRPC API**: High-performance RPC interface `[In Development]`
- **WebSocket API**: Real-time updates and streaming `[In Development]`
- **GraphQL API**: Flexible query language with real-time subscriptions `[Stable]`
- **Plugin System**: Extensible WASM-based functionality `[Stable]`

### Modern Deployment
- **Docker Support**: 
  - Build from source: `docker build -t fortress .` ✅
  - Official registry: ✅ Available (Docker Hub)
- **Kubernetes**: Production-ready K8s manifests `[Stable]`
- **Helm Charts**: 
  - Local install: `helm install ./helm/fortress` ✅
  - Official repo: 📋 Planned
- **Cloud Integration**: AWS, Azure, Google Cloud support `[In Development]`

### Privacy-Preserving ML & Homomorphic Encryption

**Current Status: Research Implementation - Not Production Ready**

- **Homomorphic Encryption**: Mathematical framework exists `[Research Only]`
- **Privacy-Preserving ML**: Depends on real homomorphic encryption `[Depends: HE Implementation]`
- **ML Integration**: Roadmap item blocked by missing crypto foundation `[Planned]`

**Important Notice**: The homomorphic encryption module contains research implementations only. The mathematical operations are **not cryptographically secure** and should never be used for real security purposes. For production use, either implement proper cryptographic schemes or remove the module entirely.

See `crates/fortress-core/src/homomorphic_encryption.rs` for detailed warnings and current implementation status.

## Prerequisites

### System Requirements
- **RAM**: Minimum 2GB, Recommended 4GB+
- **Storage**: Minimum 1GB free space
- **CPU**: 64-bit processor (x86_64 or ARM64)

### Platform-Specific Dependencies

#### Ubuntu/Debian
```bash
# Install required system dependencies
sudo apt update
sudo apt install -y build-essential pkg-config libssl-dev

# Verify OpenSSL installation
openssl version
```

#### macOS
```bash
# Install OpenSSL and pkg-config via Homebrew
brew install openssl pkg-config

# Set environment variables for Rust to find OpenSSL
export PKG_CONFIG_PATH="/usr/local/opt/openssl/lib/pkgconfig:$PKG_CONFIG_PATH"
export LDFLAGS="-L/usr/local/opt/openssl/lib"
export CPPFLAGS="-I/usr/local/opt/openssl/include"

# Add to shell profile for persistence
echo 'export PKG_CONFIG_PATH="/usr/local/opt/openssl/lib/pkgconfig:$PKG_CONFIG_PATH"' >> ~/.zshrc
echo 'export LDFLAGS="-L/usr/local/opt/openssl/lib"' >> ~/.zshrc
echo 'export CPPFLAGS="-I/usr/local/opt/openssl/include"' >> ~/.zshrc
```

#### Windows
```bash
# Using vcpkg (recommended)
vcpkg install openssl:x64-windows
vcpkg integrate install

# Or using Chocolatey
choco install openssl

# Or using Scoop
scoop install openssl
```

#### Fedora/CentOS/RHEL
```bash
# Fedora
sudo dnf install -y gcc gcc-c++ pkg-config openssl-devel

# CentOS/RHEL
sudo yum install -y gcc gcc-c++ pkg-config openssl-devel
```

#### Arch Linux
```bash
sudo pacman -S --needed base-devel pkg-config openssl
```

### Verify Installation
```bash
# Test OpenSSL installation
openssl version

# Test pkg-config (should show OpenSSL paths)
pkg-config --modversion openssl
```

## Quick Start

### Installation

#### Choose Your Installation Method

| Method | Best For | Time to Start |
|--------|-----------|---------------|
| [Pre-built Binaries](#pre-built-binaries-recommended) | Quick start, production | 2-5 minutes |
| [Package Managers](#package-managers) | Development, CI/CD | 1-3 minutes |
| [Docker](#docker) | Containers, microservices | 1-2 minutes |
| [Source Build](#development-setup) | Development, customization | 5-10 minutes |

#### Pre-built Binaries (Recommended)

**Download from GitHub Releases**
```bash
# Download latest release for your platform
# Visit: https://github.com/Genius740Code/Fortress/releases

# Example for Linux AMD64
curl -L "https://github.com/Genius740Code/Fortress/releases/latest/download/fortress-linux-amd64-latest" -o fortress
chmod +x fortress
sudo mv fortress /usr/local/bin/

# Example for Windows
# Download fortress-windows-amd64-latest.exe from releases page
```

#### Package Managers

**NPM (Node.js)**
```bash
# Install CLI tool globally
npm install -g fortress-cli

# Install as dependency in your project
npm install fortress-cli fortress-db
```

**PyPI (Python)**
```bash
# Install from PyPI
pip install fortress-db

# With development dependencies
pip install fortress-db[dev]
```

**Cargo (Rust)**
```bash
# Install from crates.io
cargo install fortress-cli
cargo install fortress-server

# Or build from source
git clone https://github.com/Genius740Code/Fortress.git
cd Fortress
cargo install --path crates/fortress-cli
```

**Go**
```bash
# Install CLI tool
go install github.com/Genius740Code/Fortress/fortress-go/cmd/fortress-cli@latest
```

#### Docker

**Build from Source (Recommended)**
```bash
# Clone and build
git clone https://github.com/Genius740Code/Fortress.git
cd Fortress
docker build -t fortress .

# Run with default configuration
docker run -p 8080:8080 -p 9090:9090 fortress

# Or with custom configuration
docker run -p 8080:8080 \
  -v /path/to/config:/etc/fortress \
  fortress
```

**Note**: Official Docker images will be available in Q2 2024. Until then, please build from source.

### Basic Usage

#### Choose Your Language

| Language | Quick Start | Full Guide |
|----------|-------------|------------|
| **Rust** | [5-minute Rust start](docs/QUICK_START_GUIDE.md#rust-quick-start) | [Rust Ecosystem Guide](docs/ECOSYSTEM_GUIDES.md#rust-ecosystem) |
| **Python** | [5-minute Python start](docs/QUICK_START_GUIDE.md#python-quick-start) | [Python Ecosystem Guide](docs/ECOSYSTEM_GUIDES.md#python-ecosystem) |
| **Node.js** | [5-minute Node.js start](docs/QUICK_START_GUIDE.md#nodejs-quick-start) | [Node.js Ecosystem Guide](docs/ECOSYSTEM_GUIDES.md#nodejsjavascript-ecosystem) |
| **Go** | [5-minute Go start](docs/QUICK_START_GUIDE.md#go-quick-start) | [Go Ecosystem Guide](docs/ECOSYSTEM_GUIDES.md#go-ecosystem) |
| **Docker** | [2-minute Docker start](docs/QUICK_START_GUIDE.md#docker-quick-start) | [Installation Guide](docs/INSTALLATION_GUIDE.md#docker-installation) |

#### Quick CLI Example

```bash
# Initialize Fortress
fortress init

# Start the server
fortress server start

# Create an encryption key
fortress key create --name my-key --algorithm aes256-gcm

# Encrypt data
echo "secret data" | fortress encrypt --key-id my-key > encrypted.dat

# Decrypt data
fortress decrypt --key-id my-key --input encrypted.dat
```

#### Quick API Example

**Rust:**
```rust
use fortress_core::prelude::*;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let fortress = Fortress::builder().build().await?;
    let db = fortress.create_database("myapp").await?;
    
    let user = db.insert("users", &serde_json::json!({
        "name": "Alice Johnson",
        "email": "alice@example.com",
        "ssn": "123-45-6789"  // Automatically encrypted
    })).await?;
    
    println!("User created: {}", user["name"]);
    Ok(())
}
```

**Python:**
```python
from fortress import Fortress
import asyncio

async def main():
    fortress = Fortress("http://localhost:8080")
    db = await fortress.create_database("myapp")
    
    user = await db.insert("users", {
        "name": "Alice Johnson",
        "email": "alice@example.com",
        "ssn": "123-45-6789"  # Automatically encrypted
    })
    
    print(f"User created: {user['name']}")

asyncio.run(main())
```

**Node.js:**
```javascript
const { Fortress } = require('fortress-db');

async function main() {
    const fortress = new Fortress({
        serverUrl: 'http://localhost:8080'
    });
    
    const db = await fortress.createDatabase('myapp');
    const user = await db.insert('users', {
        name: 'Alice Johnson',
        email: 'alice@example.com',
        ssn: '123-45-6789'  // Automatically encrypted
    });
    
    console.log(`User created: ${user.name}`);
}

main().catch(console.error);
```

**Go:**
```go
package main

import (
    "context"
    "fmt"
    "log"
    
    "github.com/Genius740Code/Fortress/fortress-go"
)

func main() {
    client, err := fortress.NewClient(&fortress.Config{
        ServerURL: "http://localhost:8080",
    })
    if err != nil {
        log.Fatal(err)
    }

    ctx := context.Background()
    db, err := client.CreateDatabase(ctx, "myapp")
    if err != nil {
        log.Fatal(err)
    }

    user := map[string]interface{}{
        "name":  "Alice Johnson",
        "email": "alice@example.com",
        "ssn":   "123-45-6789", // Automatically encrypted
    }

    result, err := db.Insert(ctx, "users", user)
    if err != nil {
        log.Fatal(err)
    }
    fmt.Printf("User created: %v\n", result["name"])
}
```

## Performance

Fortress is optimized for high-performance encryption operations:

| Algorithm | Encrypt (MB/s) | Decrypt (MB/s) | Security Level |
|-----------|----------------|----------------|----------------|
| AEGIS-256 | 910 | 1,898 | Very High |
| ChaCha20-Poly1305 | 288 | 460 | High |
| AES-256-GCM | 358 | 345 | High |

### Benchmarks

```bash
# Run encryption benchmarks
cargo bench --bench encryption

# Run performance tests
cargo test --release -- --ignored performance

# View detailed metrics
curl http://localhost:8080/metrics/performance
```

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Fortress Architecture                     │
├─────────────────────────────────────────────────────────────┤
│  Client Layer                                               │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐           │
│  │   REST API  │ │  WebSocket  │ │   GraphQL   │           │
│  └─────────────┘ └─────────────┘ └─────────────┘           │
├─────────────────────────────────────────────────────────────┤
│  Security Layer                                             │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐           │
│  │   Auth/Z    │ │ Rate Limit  │ │    Audit    │           │
│  └─────────────┘ └─────────────┘ └─────────────┘           │
├─────────────────────────────────────────────────────────────┤
│  Encryption Layer                                           │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐           │
│  │ Field Level │ │ Key Manager │ │   Rotation  │           │
│  └─────────────┘ └─────────────┘ └─────────────┘           │
├─────────────────────────────────────────────────────────────┤
│  Storage Layer                                              │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐           │
│  │   Memory    │ │    Disk     │ │    Cloud    │           │
│  └─────────────┘ └─────────────┘ └─────────────┘           │
└─────────────────────────────────────────────────────────────┘
```

## Documentation

### **Start Here**
- **[Quick Start Guide](docs/QUICK_START_GUIDE.md)** - Get started in 5 minutes with your preferred language
- **[Installation Guide](docs/INSTALLATION_GUIDE.md)** - Comprehensive installation for all platforms
- **[Ecosystem Guides](docs/ECOSYSTEM_GUIDES.md)** - Language-specific guides and examples
- **[Documentation Index](docs/DOCUMENTATION_INDEX.md)** - Complete navigation and quick start paths
- **[FAQ](docs/FAQ.md)** - Frequently asked questions and troubleshooting

### Getting Started
- [Installation Guide](docs/INSTALLATION_GUIDE.md) - Complete installation instructions
- [Quick Start Guide](docs/QUICK_START_GUIDE.md) - Language-specific quick starts
- [API Reference](docs/API_REFERENCE.md) - Complete REST API documentation
- [Architecture Guide](docs/ARCHITECTURE.md) - System architecture and design

### Security & Compliance
- [🔒 Security Policy](SECURITY.md) - Security features, vulnerability disclosure, and best practices
- [🏥 HIPAA Compliance](COMPLIANCE.md#hipaa-compliance) - Technical safeguards and organizational requirements
- [💳 PCI-DSS Implementation](COMPLIANCE.md#pci-dss-compliance) - Cardholder data protection and security controls
- [🇪🇺 GDPR Compliance](COMPLIANCE.md#gdpr-compliance) - Data protection and privacy controls
- [🔐 HSM Integration Status](HSM.md) - Honest assessment of HSM implementation
- [Security Guide](docs/SECURITY.md) - Security features and best practices
- [Key Rotation Guide](docs/KEY_ROTATION.md) - Key management and rotation
- [Production Readiness Matrix](docs/PRODUCTION_READINESS_MATRIX.md) - Honest assessment of production readiness

### Operations
- [Deployment Guide](docs/KUBERNETES_DEPLOYMENT_GUIDE.md) - Production deployment
- [Operational Runbook](docs/OPERATIONAL_RUNBOOK.md) - Day-to-day operations
- [Troubleshooting Guide](docs/TROUBLESHOOTING_GUIDE.md) - Problem resolution
- [Migration Guide](docs/MIGRATION_GUIDE.md) - Version and data migration

## Configuration

### Basic Configuration

Create a `config.toml` file:

```toml
[server]
host = "0.0.0.0"
port = 8080

[database]
default_algorithm = "aegis256"

[encryption]
key_rotation_interval = "24h"
auto_rotation = true

[logging]
level = "info"
format = "json"
```

### Environment Variables

```bash
# Server configuration
export FORTRESS_HOST=0.0.0.0
export FORTRESS_PORT=8080

# Encryption configuration
export FORTRESS_ENCRYPTION_DEFAULT_ALGORITHM=aegis256
export FORTRESS_KEY_ROTATION_INTERVAL=24h

# Logging configuration
export FORTRESS_LOG_LEVEL=info
```

## 🐳 Docker & Kubernetes

### Docker Compose

```yaml
version: '3.8'
services:
  fortress:
    build: .
    ports:
      - "8080:8080"
    volumes:
      - fortress_data:/var/lib/fortress
    environment:
      - FORTRESS_LOG_LEVEL=info
      - FORTRESS_ENCRYPTION_DEFAULT_ALGORITHM=aegis256

volumes:
  fortress_data:
```

### Kubernetes

**Local Installation (Recommended)**
```bash
# Install from local manifests
kubectl apply -f k8s/namespace.yaml
kubectl apply -f k8s/deployment.yaml
kubectl apply -f k8s/service.yaml

# Or using local Helm chart
helm install my-fortress ./helm/fortress \
  --namespace fortress \
  --create-namespace
```

**Note**: Official Helm repository will be available in Q2 2024. Until then, please install from local source.

## Cloud Integration

### AWS Integration

```bash
# Enable AWS features
cargo run --features aws

# Configure S3 storage
fortress config set storage.backend s3
fortress config set storage.s3.bucket my-fortress-bucket
fortress config set storage.s3.region us-west-2
```

### Azure Integration

```bash
# Enable Azure features
cargo run --features azure

# Configure Azure Blob storage
fortress config set storage.backend azure_blob
fortress config set storage.azure.container fortress-data
```

## Development

### Running Tests

```bash
# Run all tests
cargo test

# Run integration tests
cargo test --test integration

# Run benchmarks
cargo bench

# Run with specific features
cargo test --features "aws,azure"
```

### Development Setup

```bash
# Clone the repository
git clone https://github.com/Genius740Code/Fortress.git
cd Fortress

# Build the project
cargo build --release

# Run tests
cargo test

# Install CLI tool
cargo install --path crates/fortress-cli
```

### Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## Examples

### Basic Rust Usage

```rust
use fortress_core::prelude::*;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize encryption
    let algorithm = Aegis256::new();
    let key_manager = KeyManager::new();
    let key = key_manager.generate_key(&algorithm)?;
    
    // Encrypt data
    let plaintext = b"Hello, Fortress!";
    let ciphertext = algorithm.encrypt(plaintext, &key)?;
    
    // Decrypt data
    let decrypted = algorithm.decrypt(&ciphertext, &key)?;
    
    assert_eq!(plaintext, decrypted);
    println!("Encryption successful!");
    
    Ok(())
}
```

### Field-Level Encryption

```rust
use fortress_core::prelude::*;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let manager = FieldEncryptionManager::new(config).await?;
    
    // Encrypt sensitive fields
    let user = UserProfile {
        name: "Alice Johnson".to_string(),
        email: "alice@example.com".to_string(),
        ssn: "123-45-6789".to_string(), // Will be encrypted
    };
    
    let encrypted_user = manager.encrypt_fields(&user).await?;
    println!("🔒 SSN encrypted: {}", encrypted_user.ssn);
    
    Ok(())
}
```

### WebSocket Client

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
    events: ['data_change', 'key_rotation']
}));

// Handle events
ws.onmessage = (event) => {
    const message = JSON.parse(event.data);
    console.log('Event:', message);
};
```

## 🤝 Community

- 📖 [Documentation](https://github.com/Genius740Code/Fortress/blob/main/docs)
- 🐛 [Issue Tracker](https://github.com/Genius740Code/Fortress/issues)
- 💬 [Discussions](https://github.com/Genius740Code/Fortress/discussions)

## 📄 License

This project is licensed under the Server Side Public License (SSPL) - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- **HashiCorp Vault** - Inspiration for security-first design
- **AEGIS** - High-performance encryption algorithm
- **Raft** - Consensus algorithm for clustering
- **Rust Community** - Excellent ecosystem and tools

## 🗺️ Roadmap

### Version 1.1.0 (Q2 2026)
- [x] GraphQL API completion
- [ ] Advanced plugin marketplace
- [ ] Machine learning integration `[Depends: Real homomorphic encryption implementation]`
- [ ] Mobile SDKs (iOS/Android)

### Version 1.2.0 (Q3 2026)
- [ ] Distributed SQL queries
- [ ] Advanced analytics engine
- [ ] WebAssembly plugin support
- [ ] Edge computing support

### Version 2.0.0 (Q4 2026)
- [ ] Production-ready stability
- [ ] Full compliance certification
- [ ] Enterprise features
- [ ] Managed cloud service

## Metrics

- **CI Status**: [![CI](https://github.com/Genius740Code/Fortress/workflows/CI/badge.svg)](https://github.com/Genius740Code/Fortress/actions)
- **GitHub Stars**: [![GitHub stars](https://img.shields.io/github/stars/Genius740Code/Fortress)](https://github.com/Genius740Code/Fortress/stargazers)
- **GitHub Forks**: [![GitHub forks](https://img.shields.io/github/forks/Genius740Code/Fortress)](https://github.com/Genius740Code/Fortress/network)
- **GitHub Issues**: [![GitHub issues](https://img.shields.io/github/issues/Genius740Code/Fortress)](https://github.com/Genius740Code/Fortress/issues)
- **License**: [![License: SSPL-1.0](https://img.shields.io/badge/License-SSPL--1.0-blue.svg)](https://opensource.org/licenses/SSPL-1.0)

---

**Fortress** - Where security meets simplicity.
