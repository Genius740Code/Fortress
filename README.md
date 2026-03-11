# Fortress

🛡️ **Fortress** - Turnkey Simplicity + HashiCorp Vault Security

## 🚦 Current Status: **Alpha - Not Production Ready**
> Target v1.0 release: Q3 2026
> 
> ⚠️ **Not recommended for production workloads**
> - APIs may change without notice  
> - Data migration tools are experimental
> - Security features are under audit
> - Limited testing in production environments

A highly customizable, secure database system with multi-layer encryption that combines the simplicity of modern databases with enterprise-grade security.

## 🚀 Quick Start

### Installation

#### Binary Packages (Recommended)

**NPM (Node.js)**
```bash
# Install globally
npm install -g fortress-cli

# Install as dependency
npm install fortress-cli
```

**PyPI (Python)**
```bash
# Install from PyPI
pip install fortress

# Install with development features
pip install fortress[dev]
```

**Cargo (Rust)**
```bash
# Add fortress-core as dependency
cargo add fortress-core

# Install from crates.io (when published)
cargo install fortress-core

# Install from git repository
cargo install --git https://github.com/Genius740Code/Fortress fortress-core
```

**Standalone Binaries**
```bash
# Download from GitHub Releases
curl -L "https://github.com/Genius740Code/Fortress/releases/latest/download/fortress-cli-$(uname -s)-$(uname -m).tar.gz" | tar -xz
sudo mv fortress /usr/local/bin/
```

#### Build from Source

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

#### Docker Installation

```bash
# Pull the latest image
docker pull fortressdb/fortress:latest

# Run with default settings
docker run -p 8080:8080 -v fortress_data:/var/lib/fortress fortressdb/fortress

# Run with custom configuration
docker run -p 8080:8080 \
  -v $(pwd)/config.toml:/etc/fortress/config.toml \
  -v fortress_data:/var/lib/fortress \
  fortressdb/fortress --config /etc/fortress/config.toml
```

### Basic Usage

```bash
# Create a new database
fortress create --name myapp --template enterprise

# Start the server
fortress start --port 8080

# Check status
fortress status --detailed
```

### API Quick Start

```python
from fortress_client import FortressClient

client = FortressClient('http://localhost:8080')

# Create database
db = client.create_database('myapp_db', algorithm='aegis256')

# Create table with encrypted fields
table = client.create_table('myapp_db', 'users', [
    {'name': 'id', 'type': 'uuid', 'primary_key': True},
    {'name': 'name', 'type': 'text'},
    {'name': 'email', 'type': 'text', 'unique': True},
    {'name': 'password', 'type': 'encrypted', 'sensitivity': 'high'}
])

# Insert data (automatically encrypted)
user = client.insert_data('myapp_db', 'users', {
    'id': '550e8400-e29b-41d4-a716-446655440000',
    'name': 'Alice Johnson',
    'email': 'alice@example.com',
    'password': 'secure-password'
})
```

## ✨ Features

### 🔐 Security First
- **Automatic Encryption**: All data encrypted before storage, decrypted after retrieval
- **Multiple Algorithms**: AEGIS-256, ChaCha20-Poly1305, AES-256-GCM, and more
- **Field-Level Encryption**: Encrypt specific fields with different algorithms
- **Key Management**: Automatic key generation, rotation, and secure storage
- **Zero-Downtime Rotation**: Rotate encryption keys without service interruption

### 🏗️ Enterprise Architecture
- **Multi-Tenant Support**: Isolated data per tenant/organization
- **Cluster Support**: High availability with Raft consensus
- **Audit Logging**: Comprehensive security event logging
- **Compliance Framework**: GDPR, HIPAA, PCI-DSS compliance features
- **HSM Integration**: Hardware Security Module support

### ⚡ High Performance
- **Optimized Algorithms**: AEGIS-256 for maximum speed
- **Caching Layer**: Intelligent key and data caching
- **Connection Pooling**: Efficient database connections
- **Compression**: Built-in data compression
- **Performance Monitoring**: Real-time metrics and profiling

### 🔧 Developer Friendly
- **REST API**: Standard HTTP methods with JSON payloads
- **Multiple SDKs**: Python, JavaScript, Rust, Go, and more
- **WebSocket API**: Real-time updates and streaming
- **GraphQL Support**: Complex queries with GraphQL
- **Plugin System**: Extensible functionality

### 🐳 Modern Deployment
- **Docker Support**: Container-ready with official images
- **Kubernetes**: Production-ready K8s manifests
- **Helm Charts**: Easy deployment and management
- **Cloud Integration**: AWS, Azure, Google Cloud support

## 📚 Documentation

### Installation & Setup
- 📖 [Binary Installation Guide](docs/BINARY_INSTALLATION.md) - Complete installation instructions for all platforms
- �️ [CLI Documentation](docs/CLI_DOCUMENTATION.md) - Command-line interface guide
- 🏗️ [Architecture Guide](docs/ARCHITECTURE.md) - System architecture and design

### Core Documentation
- � [API Documentation](docs/API_DOCUMENTATION.md) - Complete REST API reference
- 💡 [Usage Examples](docs/USAGE_EXAMPLES.md) - Comprehensive examples and tutorials

### Quick Guides
- 🚀 [API Quick Start](examples/API_QUICK_START.md) - Get started with the REST API
- 📝 [API Usage Examples](examples/API_USAGE_EXAMPLES.md) - Practical API examples
- ☁️ [Cloud Deployment Guide](docs/CLOUD_DEPLOYMENT_GUIDE.md) - Deploy to cloud providers

### Advanced Topics
- 🔐 [Security Best Practices](docs/SECURITY.md) - Security recommendations
- 📊 [Performance Tuning](docs/PERFORMANCE.md) - Optimization guide
- 🔧 [Plugin Development](docs/PLUGIN_DEVELOPMENT.md) - Create custom plugins
- 🏢 [Multi-Tenant Setup](docs/MULTI_TENANT.md) - Tenant management

## 🏗️ Architecture

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
│  │   Auth/Z    │ │  Rate Limit │ │    Audit    │           │
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

## 🔧 Installation

### Prerequisites

- Rust 1.70 or higher
- OpenSSL development libraries (for some encryption algorithms)

### Build from Source

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

### Docker Installation

```bash
# Pull the latest image
docker pull fortressdb/fortress:latest

# Run with default settings
docker run -p 8080:8080 -v fortress_data:/var/lib/fortress fortressdb/fortress

# Run with custom configuration
docker run -p 8080:8080 \
  -v $(pwd)/config.toml:/etc/fortress/config.toml \
  -v fortress_data:/var/lib/fortress \
  fortressdb/fortress --config /etc/fortress/config.toml
```

### Kubernetes Installation

```bash
# Option 1: Install using local Helm chart (Recommended)
git clone https://github.com/Genius740Code/Fortress.git
cd Fortress
helm install my-fortress ./helm/fortress

# Option 2: Install using Kubernetes manifests directly
kubectl apply -f k8s/namespace.yaml
kubectl apply -f k8s/config.yaml
kubectl apply -f k8s/deployment.yaml
kubectl apply -f k8s/pvc.yaml

# Upgrade Fortress
helm upgrade my-fortress ./helm/fortress
```

### 🔧 Troubleshooting

If you encounter issues with the Helm installation:

#### Common Issues

**1. Namespace already exists**
```bash
kubectl delete namespace fortress
helm install my-fortress ./helm/fortress
```

**2. PVC binding issues**
```bash
# Check PVC status
kubectl get pvc -n fortress

# Check available storage classes
kubectl get storageclass

# Update storage class in values.yaml
helm upgrade my-fortress ./helm/fortress --set persistence.storageClass=standard
```

**3. Pod not starting**
```bash
# Check pod status
kubectl get pods -n fortress

# Describe pod for errors
kubectl describe pod -n fortress <pod-name>

# Check pod logs
kubectl logs -n fortress <pod-name>
```

**4. Service connectivity**
```bash
# Test service endpoints
kubectl get endpoints -n fortress

# Port-forward to test locally
kubectl port-forward -n fortress service/fortress-service 8080:8080
curl http://localhost:8080/health
```

#### Getting Help

- **Documentation**: [K8S Deployment Guide](docs/K8S_DEPLOYMENT.md)
- **Issues**: [GitHub Issues](https://github.com/Genius740Code/Fortress/issues)
- **Community**: [GitHub Discussions](https://github.com/Genius740Code/Fortress/discussions)

## 🚀 Getting Started

### 1. Create Your First Database

```bash
# Interactive database creation
fortress create --interactive

# Or with specific settings
fortress create \
  --name production_db \
  --template enterprise \
  --data-dir /var/lib/fortress/prod
```

### 2. Start the Server

```bash
# Start with default settings
fortress start

# Start on specific port and host
fortress start --port 8080 --host 0.0.0.0

# Start with custom data directory
fortress start --data-dir /var/lib/fortress/prod
```

### 3. Verify Installation

```bash
# Check server health
curl http://localhost:8080/health

# Check metrics
curl http://localhost:8080/metrics

# View database status
fortress status --detailed
```

### 4. Use the API

```bash
# Create database via API
curl -X POST http://localhost:8080/api/v1/databases \
  -H "Content-Type: application/json" \
  -d '{
    "name": "myapp_db",
    "algorithm": "aegis256",
    "key_rotation_interval": "24h"
  }'

# Create table with encrypted fields
curl -X POST http://localhost:8080/api/v1/databases/myapp_db/tables \
  -H "Content-Type: application/json" \
  -d '{
    "name": "users",
    "columns": [
      {"name": "id", "type": "uuid", "primary_key": true},
      {"name": "name", "type": "text"},
      {"name": "email", "type": "text", "unique": true},
      {"name": "password", "type": "encrypted", "sensitivity": "high"}
    ]
  }'
```

## 📊 Performance

Fortress is optimized for high-performance encryption operations:

| Algorithm | Throughput (MB/s) | Latency (ms) | Security Level |
|-----------|-------------------|--------------|----------------|
| AEGIS-256 | 1500+ | 0.5 | Very High |
| ChaCha20-Poly1305 | 1200+ | 0.7 | High |
| AES-256-GCM | 1000+ | 0.8 | High |

### Benchmarks

```bash
# Run encryption benchmarks
cargo bench --bench encryption

# Run performance tests
cargo test --release -- --ignored performance

# View detailed metrics
curl http://localhost:8080/metrics/performance
```

## 🔐 Encryption Algorithms

### Algorithm Selection Guide

| Use Case | Recommended Algorithm | Why | Performance |
|----------|---------------------|------|-------------|
| **General Purpose** | **AEGIS-256** | Fastest, post-quantum secure, hardware-accelerated | 1500+ MB/s |
| **Mobile Applications** | ChaCha20-Poly1305 | Battery efficient, no hardware acceleration needed | 1200+ MB/s |
| **Enterprise/Compliance** | AES-256-GCM | Industry standard, FIPS 140-2 certified, hardware acceleration | 1000+ MB/s |
| **Maximum Security** | XChaCha20-Poly1305 | Extended nonce protection, future-proof | 1100+ MB/s |

### Algorithm Details

#### **AEGIS-256** (Recommended)
- **Security Level**: Very High (Post-quantum resistant)
- **Performance**: 1500+ MB/s (fastest)
- **Use Cases**: General purpose, high-performance applications
- **Compliance**: Suitable for most compliance frameworks
- **Hardware**: Optimized for modern CPUs

#### **ChaCha20-Poly1305**
- **Security Level**: High
- **Performance**: 1200+ MB/s
- **Use Cases**: Mobile apps, battery-powered devices
- **Compliance**: Widely accepted
- **Hardware**: Software-based, no special requirements

#### **AES-256-GCM**
- **Security Level**: High
- **Performance**: 1000+ MB/s (with hardware acceleration)
- **Use Cases**: Enterprise, compliance-driven applications
- **Compliance**: Industry standard, FIPS 140-2 certified
- **Hardware**: AES-NI acceleration recommended

#### **XChaCha20-Poly1305**
- **Security Level**: Very High
- **Performance**: 1100+ MB/s
- **Use Cases**: Maximum security requirements, long-term data storage
- **Compliance**: Acceptable under most frameworks
- **Hardware**: Software-based, extended nonce protection

### Performance Context

All benchmarks are performed on:
- **Hardware**: AWS c6i.large (Intel Xeon) with NVMe storage
- **Data**: 1GB random data blocks
- **Concurrency**: 4 parallel threads
- **Metrics**: Throughput (MB/s) and latency (ms)

**Real-world performance may vary based on**:
- CPU architecture and capabilities
- Data size and access patterns
- Network latency (for client-server operations)
- Storage performance (SSD vs HDD)

### Decision Framework

#### Choose AEGIS-256 if:
- ✅ You need maximum performance
- ✅ Future-proof security is important
- ✅ Modern hardware is available
- ✅ General-purpose encryption needs

#### Choose ChaCha20-Poly1305 if:
- ✅ Deploying to mobile devices
- ✅ Battery life is a concern
- ✅ No hardware acceleration available
- ✅ Cross-platform compatibility needed

#### Choose AES-256-GCM if:
- ✅ Enterprise compliance required
- ✅ FIPS certification needed
- ✅ Hardware acceleration available
- ✅ Industry standards preferred

#### Choose XChaCha20-Poly1305 if:
- ✅ Maximum security is required
- ✅ Long-term data storage
- ✅ High-value sensitive data
- ✅ Future-proofing critical

### Migration Between Algorithms

```bash
# Check current algorithm
fortress config get encryption.default_algorithm

# Change algorithm (requires key rotation)
fortress config set encryption.default_algorithm aes256gcm
fortress key rotate --database myapp_db --algorithm aes256gcm
```

### Security Recommendations

1. **Use AEGIS-256** for new applications (best performance/security balance)
2. **Prefer AES-256-GCM** for regulated industries (compliance-friendly)
3. **Rotate algorithms** when security requirements change
4. **Test performance** with your specific hardware and data patterns
5. **Monitor performance** after algorithm changes

## 🔐 Security Features

### Encryption Algorithms

- **AEGIS-256**: Ultra-fast, post-quantum secure (recommended)
- **ChaCha20-Poly1305**: Fast, mobile-friendly
- **AES-256-GCM**: Industry standard, hardware acceleration
- **XChaCha20-Poly1305**: Extended nonce, high security

### Key Management

- **Automatic Rotation**: Schedule key rotation at custom intervals
- **Zero-Downtime**: Rotate keys without service interruption
- **HSM Support**: Integration with hardware security modules
- **Key Escrow**: Secure key recovery mechanisms

### Compliance

- **GDPR**: Data subject rights, consent management
- **HIPAA**: Healthcare data protection
- **PCI-DSS**: Payment card industry standards
- **SOC 2**: Service organization controls

## 🏢 Multi-Tenancy

Fortress provides built-in multi-tenant support with complete data isolation:

```bash
# Create tenant
fortress tenant create "Company A" --domain company-a.com --admin admin@company-a.com

# List tenants
fortress tenant list

# View tenant usage
fortress tenant show tenant_123 --usage
```

### Tenant Isolation

- **Data Isolation**: Complete separation of tenant data
- **Resource Limits**: Per-tenant resource quotas
- **Custom Encryption**: Tenant-specific encryption settings
- **Audit Separation**: Isolated audit logs per tenant

## 🔌 Plugin System

Extend Fortress functionality with plugins:

```bash
# Install plugin
fortress plugin install ./enhanced-audit.wasm

# List plugins
fortress plugin list

# Enable plugin
fortress plugin enable enhanced-audit
```

### Available Plugins

- **Enhanced Audit**: Advanced audit logging and analysis
- **Data Masking**: Automatic data masking for development
- **Backup Integration**: Cloud backup solutions
- **Monitoring**: Advanced monitoring and alerting

## 📈 Monitoring & Observability

### Built-in Metrics

```bash
# View system metrics
curl http://localhost:8080/metrics/system

# View performance metrics
curl http://localhost:8080/metrics/performance

# Prometheus metrics
curl http://localhost:8080/metrics/prometheus
```

### Health Checks

```bash
# Basic health check
curl http://localhost:8080/health

# Detailed health status
curl http://localhost:8080/health?detailed=true
```

### Monitoring Integration

- **Prometheus**: Native metrics export
- **Grafana**: Pre-built dashboards
- **OpenTelemetry**: Distributed tracing
- **Custom Metrics**: Application-specific metrics

## 🐳 Docker & Kubernetes

### Docker Compose

```yaml
version: '3.8'
services:
  fortress:
    image: fortressdb/fortress:latest
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

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: fortress
spec:
  replicas: 3
  selector:
    matchLabels:
      app: fortress
  template:
    metadata:
      labels:
        app: fortress
    spec:
      containers:
      - name: fortress
        image: fortressdb/fortress:latest
        ports:
        - containerPort: 8080
        resources:
          requests:
            memory: "512Mi"
            cpu: "250m"
          limits:
            memory: "1Gi"
            cpu: "500m"
```

## 🌐 Cloud Integration

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

## 🧪 Development

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
# Install development dependencies
cargo install cargo-watch cargo-flamegraph

# Run with auto-reload
cargo watch -x run

# Generate flamegraph
cargo flamegraph --bin fortress-server

# Run clippy
cargo clippy -- -D warnings

# Format code
cargo fmt
```

### Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📝 Examples

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
    println!("✅ Encryption successful!");
    
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

- 📖 [Documentation](https://docs.fortress-db.com)
- 🐛 [Issue Tracker](https://github.com/Genius740Code/Fortress/issues)
- 💬 [Discussions](https://github.com/Genius740Code/Fortress/discussions)
- 📧 [Email Support](mailto:support@fortress-db.com)
- 🐦 [Twitter](https://twitter.com/fortressdb)
- 💬 [Discord](https://discord.gg/fortress)

## 📄 License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- **HashiCorp Vault** - Inspiration for security-first design
- **AEGIS** - High-performance encryption algorithm
- **Raft** - Consensus algorithm for clustering
- **Rust Community** - Excellent ecosystem and tools

## 🗺️ Roadmap

### Version 0.2.0 (Q1 2026)
- [ ] GraphQL API completion
- [ ] Advanced plugin marketplace
- [ ] Machine learning integration
- [ ] Mobile SDKs (iOS/Android)

### Version 0.3.0 (Q2 2026)
- [ ] Distributed SQL queries
- [ ] Advanced analytics engine
- [ ] WebAssembly plugin support
- [ ] Edge computing support

### Version 1.0.0 (Q3 2026)
- [ ] Production-ready stability
- [ ] Full compliance certification
- [ ] Enterprise features
- [ ] Managed cloud service

---

**Fortress** - Where security meets simplicity. 🛡️✨
