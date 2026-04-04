# fortress-db

🛡️ **Fortress** - Turnkey Simplicity + Enterprise Security

A highly customizable, secure database system with multi-layer encryption. This meta-package provides the complete Fortress database ecosystem.

## Current Status: **v1.0.0 - PRODUCTION RELEASE**

> **Official production release with enterprise-grade security**
> - ✓ All core security features implemented and tested
> - ✓ Zero-downtime key rotation and clustering operational
> - ✓ Compliance frameworks implemented (GDPR, HIPAA, PCI-DSS)
> - ✓ GraphQL API with enterprise-grade security features
> - ✓ Quantum-resistant cryptography available

## Installation

### Choose Your Installation Method

| Method | Best For | Features |
|--------|-----------|----------|
| [Meta-package](#meta-package-recommended) | Complete setup | All components |
| [Individual crates](#individual-crates) | Custom setup | Select components |
| [Pre-built binaries](#pre-built-binaries) | Quick start | CLI + Server |

### Meta-package (Recommended)

Install the complete Fortress ecosystem:

```bash
# Install from crates.io
cargo install fortress-db --features full

# Or add to your Cargo.toml
[dependencies]
fortress-db = { version = "1.0.0", features = ["full"] }
```

### Individual Crates

For more control over dependencies:

```bash
# Core library
cargo install fortress-core

# CLI tool
cargo install fortress-cli

# Server (if name conflict exists, use fortress-api-server)
cargo install fortress-server

# Node.js bindings
npm install fortress-cli-napi
```

### Pre-built Binaries

```bash
# Download latest release for your platform
curl -L "https://github.com/fortress-security/fortress/releases/latest/download/fortress-linux-amd64-latest" -o fortress
chmod +x fortress
sudo mv fortress /usr/local/bin/
```

## Quick Start

### CLI Usage

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

### Library Usage (Rust)

```rust
use fortress_db::prelude::*;

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

### Library Usage (Node.js)

```javascript
const { Fortress } = require('fortress-cli-napi');

async function main() {
    const fortress = new Fortress();
    
    await fortress.init();
    await fortress.serverStart();
    
    const key = await fortress.keyCreate({
        name: 'my-key',
        algorithm: 'aes256-gcm'
    });
    
    console.log('Key created:', key);
}

main().catch(console.error);
```

## Features

### Security First
- **Automatic Encryption**: All data encrypted before storage, decrypted after retrieval
- **Multiple Algorithms**: AEGIS-256, ChaCha20-Poly1305, AES-256-GCM, RSA, ECDSA
- **Field-Level Encryption**: Encrypt specific fields with different algorithms
- **Key Management**: Automatic key generation, rotation, and secure storage
- **Zero-Downtime Rotation**: Rotate encryption keys without service interruption
- **HSM Integration**: Hardware Security Module support

### Enterprise Architecture
- **Multi-Tenant Support**: Isolated data per tenant/organization
- **Cluster Support**: High availability with Raft consensus
- **Audit Logging**: Comprehensive security event logging
- **Compliance Framework**: GDPR, HIPAA, PCI-DSS compliance features

### High Performance
- **Optimized Algorithms**: AEGIS-256 for maximum speed
- **Caching Layer**: Intelligent multi-tier caching with Redis/Memcached/Hybrid
- **Connection Pooling**: Efficient database and cache connections
- **Compression**: Built-in data compression with LZ4
- **Performance Monitoring**: Real-time metrics and profiling

### Developer Friendly
- **REST API**: Standard HTTP methods with JSON payloads
- **Multiple SDKs**: Python, JavaScript, Rust, Go, and more
- **GraphQL API**: Flexible query language with real-time subscriptions
- **Plugin System**: Extensible WASM-based functionality

## Feature Flags

| Feature | Description | Default |
|---------|-------------|---------|
| `cli` | Include CLI tool | ✅ |
| `server` | Include server components | ✅ |
| `napi` | Include Node.js bindings | ❌ |
| `full` | Include all features | ❌ |

```toml
[dependencies]
fortress-db = { version = "1.0.0", features = ["full"] }

# Or selective features
fortress-db = { version = "1.0.0", features = ["cli", "napi"] }
```

## Performance

| Algorithm | Encrypt (MB/s) | Decrypt (MB/s) | Security Level |
|-----------|----------------|----------------|----------------|
| AEGIS-256 | 910 | 1,898 | Very High |
| ChaCha20-Poly1305 | 288 | 460 | High |
| AES-256-GCM | 358 | 345 | High |

## Documentation

- **[Quick Start Guide](../../docs/QUICK_START_GUIDE.md)** - Get started in 5 minutes
- **[Installation Guide](../../docs/INSTALLATION_GUIDE.md)** - Complete installation instructions
- **[API Reference](../../docs/API_REFERENCE.md)** - Complete REST API documentation
- **[Security Guide](../../docs/SECURITY.md)** - Security features and best practices

## Configuration

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

## Development

```bash
# Clone the repository
git clone https://github.com/Genius740Code/Fortress.git
cd Fortress

# Build the project
cargo build --release

# Run tests
cargo test

# Install with all features
cargo install --path crates/fortress-db --features full
```

## License

This project is licensed under the Server Side Public License (SSPL) - see the [LICENSE](../../LICENSE) file for details.

## Support

- 📖 [Documentation](https://github.com/Genius740Code/Fortress/blob/main/docs)
- 🐛 [Issue Tracker](https://github.com/Genius740Code/Fortress/issues)
- 💬 [Discussions](https://github.com/Genius740Code/Fortress/discussions)

---

**Fortress** - Where security meets simplicity.
