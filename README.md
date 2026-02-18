# Fortress 🔐

A highly customizable, secure database system built in Rust that combines the developer experience of **Turnkey** with the enterprise security capabilities of **HashiCorp Vault** - but with unprecedented customization and performance.

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
rest_port = 8080
grpc_port = 50051
enable_wasm = true
```

## 📚 Documentation

- [Future Plans & Roadmap](docs/FUTURE_PLANS.md)
- [Architecture Details](docs/ARCHITECTURE.md)
- [API Reference](docs/API.md)
- [Configuration Guide](docs/CONFIGURATION.md)
- [Security Whitepaper](docs/SECURITY.md)

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
use fortress::{Fortress, Config};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = Config::from_file("fortress.toml")?;
    let db = Fortress::connect(config).await?;
    
    // Insert encrypted data
    db.insert("users", &json!({
        "name": "Alice",
        "email": "alice@example.com",
        "password": "secret123"
    })).await?;
    
    // Query automatically decrypted data
    let results = db.query("SELECT name, email FROM users").await?;
    
    Ok(())
}
```

### REST API
```bash
# Insert data
curl -X POST http://localhost:8080/api/v1/users \
  -H "Content-Type: application/json" \
  -d '{"name": "Bob", "email": "bob@example.com"}'

# Query data
curl http://localhost:8080/api/v1/users \
  -H "Accept: application/json"
```

## 🧪 Development

### Running Tests
```bash
cargo test
```

### Benchmarks
```bash
cargo bench
```

### Security Audit
```bash
cargo audit
```

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

### Development Setup
```bash
git clone https://github.com/fortress-db/fortress.git
cd fortress
cargo build
cargo test
```

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
#   F o r t r e s s 
 
 