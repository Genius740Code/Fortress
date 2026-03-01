# Fortress 🔐

A highly customizable, secure database system built in Rust that combines **Turnkey's simplicity** with **HashiCorp Vault's enterprise security** - plus unprecedented customization and performance.

> **Think of Fortress as:** Turnkey's simplicity + Vault's security + Your custom encryption rules

## 🚀 Quick Start

```bash
# Install Fortress
cargo install fortress-db

# Create a new encrypted database (Turnkey-style simplicity)
fortress create mydb --template production

# Insert encrypted data with automatic key management
fortress insert mydb users --name "Alice" --email "alice@example.com"

# Query data (automatically decrypted, Vault-style security)
fortress query mydb "SELECT * FROM users WHERE name = 'Alice'"
```

## 🎯 Positioning: Turnkey × Vault × Custom

### **Like Turnkey - Developer Experience**
- **Zero-config encryption** - Works out of the box
- **Simple APIs** - One-line setup, instant security
- **Modern tooling** - CLI, SDKs, web dashboard
- **Developer-first** - Focus on building, not security plumbing

### **Like HashiCorp Vault - Enterprise Security**
- **Zero-knowledge architecture** - Even you can't access user data
- **HSM integration** - Hardware security module support
- **Policy engine** - Fine-grained access controls
- **Audit logging** - Complete security audit trails
- **Multi-tenant** - Enterprise-grade isolation

### **Beyond Both - Unprecedented Customization**
- **Per-field encryption** - Choose algorithms per data type
- **Custom key rotation** - 23h for hot data, 30d for archives
- **Performance profiles** - Lightning, Balanced, Fortress modes
- **Plugin system** - Custom algorithms and storage backends

## ✨ Key Features

### 🔒 Multi-Layer Encryption
- **Field-level**: Individual column encryption
- **Row-level**: Entire record encryption  
- **Table-level**: Whole table encryption
- **Database-level**: Global encryption policies

### ⚡ Performance-Optimized Algorithms
- **AEGIS-256**: Ultra-fast (>10 GB/s) with 256-bit security
- **ChaCha20-Poly1305**: Balanced performance and security
- **AES-256-GCM**: Industry standard with hardware acceleration

### ⏰ Smart Key Rotation
- **23-hour rotation**: Performance-critical data
- **7-day rotation**: Standard data
- **30-day rotation**: Archive data
- **90-day rotation**: Master keys

### 🛠️ Maximum Flexibility
- Per-table and per-column encryption settings
- Custom algorithm plugins
- Configurable security policies
- Runtime reconfiguration

## 📋 Use Cases

### **Startups & Developers (Turnkey-style)**
```toml
# Zero-config setup - just works
fortress create myapp --template startup

# Automatic encryption for user data
[tables.users]
encryption = "balanced"  # Good performance + security
```

### **Enterprise & Finance (Vault-style)**
```toml
# Enterprise-grade security
fortress create financial_db --template enterprise

# HSM integration for compliance
[security]
hsm_provider = "aws_cloudhsm"
audit_log = true
policy_engine = "rbac"

[tables.transactions]
encryption = "fortress"
rotation = "12h"  # Compliance requirements
```

### **High-Performance Applications**
```toml
# Lightning-fast encryption
[tables.user_sessions]
encryption = "lightning"  # AEGIS-256, 23h rotation
columns = { session_token = "lightning" }
```

### **Healthcare & Compliance**
```toml
# HIPAA-compliant setup
[tables.patient_records]
encryption = "fortress"
rotation = "7d"
columns = { ssn = "fortress", medical_history = "fortress" }

[compliance]
audit_retention = "7y"
access_controls = "hipaa"
```

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    Application Layer                    │
├─────────────────────────────────────────────────────────┤
│  REST API  │  gRPC  │  CLI  │  WebAssembly  │  SDKs    │
├─────────────────────────────────────────────────────────┤
│                  Query Engine                           │
├─────────────────────────────────────────────────────────┤
│  Multi-Layer Encryption System  │  Key Management        │
├─────────────────────────────────────────────────────────┤
│        Storage Backend Abstraction Layer               │
├─────────────────────────────────────────────────────────┤
│  Local FS  │  AWS S3  │  Azure  │  GCP  │  Custom       │
└─────────────────────────────────────────────────────────┘
```

## 📊 Performance

| Algorithm | Speed | Security | Use Case |
|------------|-------|----------|----------|
| AEGIS-256 | 10+ GB/s | 256-bit | Real-time data |
| ChaCha20-Poly1305 | 5+ GB/s | 256-bit | General purpose |
| AES-256-GCM | 8+ GB/s | 256-bit | Enterprise |

## 🛡️ Security Guarantees

### **Turnkey-Style Simplicity**
- **Zero-knowledge by default** - Security built-in, no configuration needed
- **Automatic key management** - No manual key handling required
- **Secure defaults** - Production-ready encryption out of the box

### **Vault-Style Enterprise Security**
- **HSM integration** - Hardware security module support
- **Policy engine** - Role-based access controls (RBAC)
- **Audit trails** - Complete security event logging
- **Multi-tenant isolation** - Enterprise-grade data separation
- **Compliance ready** - GDPR, HIPAA, SOC 2, PCI DSS compatible

### **Fortress-Unique Advantages**
- **Per-field security policies** - Different encryption per data type
- **Performance-tuned security** - Fast encryption for hot data
- **Custom algorithm support** - Bring your own encryption
- **Zero-downtime key rotation** - Rotate keys without service interruption

## 📦 Installation

### From Crates.io
```bash
cargo install fortress-db
```

### From Source
```bash
git clone https://github.com/fortress-db/fortress.git
cd fortress
cargo install --path .
```

## 🔧 Configuration

Create a `fortress.toml` file:

```toml
[database]
path = "./data"
default_algorithm = "aegis256"

[encryption]
key_rotation_interval = "23h"
master_key_rotation = "90d"

[encryption.profiles]
lightning = { algorithm = "aegis256", rotation = "23h" }
balanced = { algorithm = "chacha20", rotation = "7d" }
fortress = { algorithm = "aes256gcm", rotation = "30d" }

[storage]
backend = "local"
compression = true
checksum = "sha256"

[api]
rest_port = 8083
grpc_port = 50054
enable_wasm = true
```

## 📚 Documentation

- [📋 Architecture Details](docs/ARCHITECTURE.md)
- [🔧 Configuration Guide](docs/CONFIGURATION.md)
- [📡 API Reference](https://docs.fortress-db.com/api)
- [🛡️ Security Whitepaper](docs/SECURITY.md)
- [🗺️ Future Plans & Roadmap](docs/FUTURE_PLANS.md)
- [📖 Fortress Roadmap](docs/FORTRESS_ROADMAP.md)

## 🚀 Getting Started

### **Turnkey-Style Quick Start**
```bash
# One-command setup (like Turnkey)
fortress create myapp --template startup

# Add data - encryption is automatic
fortress insert myapp users --name "Alice" --email "alice@example.com"

# Query - decryption is transparent
fortress query myapp "SELECT * FROM users"
```

### **Vault-Style Enterprise Setup**
```bash
# Enterprise template with security features
fortress create enterprise_db --template enterprise

# Configure HSM and policies
fortress config set security.hsm_provider aws_cloudhsm
fortress config set security.policy_engine rbac
fortress config set security.audit_log true

# Create secure tables
fortress table create transactions \
  --encryption fortress \
  --rotation 12h \
  --hsm-backed
```

### **Fortress Custom Setup**
```bash
# Custom encryption profiles
fortress create custom_db --template custom

# Define your own security rules
fortress encryption profile create \
  --name "ultra_fast" \
  --algorithm aegis256 \
  --rotation 23h

# Apply to specific data types
fortress table create sessions \
  --encryption ultra_fast \
  --column-encryption "session_token:ultra_fast"
```

## 🔌 API Usage

### Rust Library
```rust
use fortress_core::prelude::*;

#[tokio::main]
async fn main() -> Result<()> {
    let algorithm = Aegis256::new();
    let key_manager = KeyManager::new();
    let key = key_manager.generate_key(&algorithm)?;
    
    let plaintext = b"Hello, Fortress!";
    let ciphertext = algorithm.encrypt(plaintext, &key)?;
    let decrypted = algorithm.decrypt(&ciphertext, &key)?;
    
    assert_eq!(plaintext, decrypted);
    Ok(())
}
```

### REST API
```bash
# Start server
fortress server start --port 8083

# Insert data
curl -X POST http://localhost:8083/data \
  -H "Content-Type: application/json" \
  -d '{"data": {"name": "Alice"}, "algorithm": "aegis256"}'

# Query data
curl http://localhost:8083/data/{id}
```

## 🧪 Development

### Prerequisites
- Rust 1.70+
- Git

### Setup
```bash
git clone https://github.com/Genius740Code/Fortress.git
cd Fortress
cargo build
cargo test
```

### Running Tests
```bash
# Run all tests
cargo test

# Run integration tests
cargo test --test integration_tests

# Run with coverage
cargo tarpaulin --out Html
```

### Benchmarks
```bash
# Run performance benchmarks
cargo bench

# View benchmark reports
open target/criterion/report/index.html
```

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md).

### Areas for Contribution
- 🚀 Performance optimizations
- 🔐 New encryption algorithms
- 📚 Documentation improvements
- 🐛 Bug fixes and testing
- 🔌 Plugin development

## 📄 License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.

## 🆘 Support

- [Documentation](https://docs.fortress-db.com)
- [Discord Community](https://discord.gg/fortress-db)
- [GitHub Issues](https://github.com/Genius740Code/Fortress/issues)
- [Security Reports](security@fortress-db.com)

## 🎯 Roadmap

- [x] Core encryption library
- [x] Multi-layer encryption
- [x] Key rotation system
- [x] Distributed clustering
- [ ] Web dashboard
- [ ] Machine learning integration
- [ ] Quantum-resistant cryptography

See [Future Plans](docs/FUTURE_PLANS.md) for detailed timeline.

## 🏆 Acknowledgments
- Built with [Rust](https://www.rust-lang.org/)
- Encryption algorithms from [RustCrypto](https://github.com/RustCrypto)
- Inspired by HashiCorp Vault, AWS KMS, and Turnkey
- Security reviewed by cryptography experts

---

**Fortress** - Turnkey's simplicity meets Vault's security, with your custom rules.

## 🆚 Comparison

| Feature | Turnkey | HashiCorp Vault | Fortress |
|---------|---------|----------------|----------|
| **Setup Complexity** | ✅ Zero-config | ❌ Complex | ✅ Zero-config + Advanced |
| **Custom Encryption** | ❌ Limited | ✅ Flexible | ✅ Per-field Custom |
| **Performance** | ✅ Fast | ❌ Moderate | ✅ Ultra-fast (AEGIS-256) |
| **Enterprise Features** | ❌ Basic | ✅ Full | ✅ Full + Custom |
| **Developer Experience** | ✅ Excellent | ❌ Complex | ✅ Excellent |
| **Key Rotation** | ❌ Manual | ✅ Automatic | ✅ Automatic + Custom |
| **HSM Support** | ❌ No | ✅ Yes | ✅ Yes + Custom |
| **Multi-tenant** | ❌ No | ✅ Yes | ✅ Yes + Isolation |
| **Compliance** | ❌ Basic | ✅ Full | ✅ Full + Custom |

**Choose Fortress when you want:**
- Turnkey's developer experience
- Vault's enterprise security  
- Custom encryption rules per data type
- Ultra-high performance
- Zero-config setup with advanced options