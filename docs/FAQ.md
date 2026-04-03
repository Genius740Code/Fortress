# Fortress FAQ

Frequently asked questions about Fortress security platform.

## Table of Contents

- [General Questions](#general-questions)
- [Installation & Setup](#installation--setup)
- [Security & Encryption](#security--encryption)
- [Performance & Scaling](#performance--scaling)
- [API & Integration](#api--integration)
- [Troubleshooting](#troubleshooting)
- [Licensing & Support](#licensing--support)

## General Questions

### What is Fortress?

Fortress is an enterprise security platform that provides automatic encryption, key management, and secure data storage. It encrypts data before storage and decrypts it after retrieval, ensuring your sensitive information is always protected.

### How does Fortress work?

Fortress uses a "zero-knowledge" architecture where:
1. Data is encrypted on the client side before transmission
2. Encrypted data is stored in the database
3. Data is only decrypted when accessed by authorized applications
4. Fortress never has access to unencrypted data

### What makes Fortress different from other encryption solutions?

- **Automatic Encryption**: No manual encryption/decryption required
- **Field-Level Security**: Encrypt specific fields with different algorithms
- **Zero-Downtime Rotation**: Rotate keys without service interruption
- **Multi-Tenant**: Isolated data per organization
- **High Performance**: Optimized for speed and scalability

### Is Fortress open source?

Yes, Fortress is open source under the Server Side Public License (SSPL). You can view, modify, and distribute the source code.

## Installation & Setup

### How do I install Fortress?

Installation depends on your ecosystem:

**Rust:**
```bash
cargo install fortress-cli
```

**Python:**
```bash
pip install fortress-db
```

**Node.js:**
```bash
npm install fortress-db
```

**Docker:**
```bash
docker pull fortress-security/fortress:latest
```

For detailed instructions, see the [Installation Guide](INSTALLATION_GUIDE.md).

### What are the system requirements?

**Minimum Requirements:**
- CPU: 2 cores (64-bit)
- Memory: 4GB RAM
- Storage: 10GB available space
- Network: Internet connection

**Recommended Requirements:**
- CPU: 4+ cores (64-bit)
- Memory: 8GB+ RAM
- Storage: 50GB+ SSD
- Network: 1Gbps network

### Can I run Fortress on my local machine?

Yes! Fortress is designed to run anywhere from development laptops to production servers. Use the Docker image or install the binary directly.

### How do I configure Fortress?

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
```

Or use environment variables:

```bash
export FORTRESS_HOST=0.0.0.0
export FORTRESS_PORT=8080
export FORTRESS_DEFAULT_ALGORITHM=aegis256
```

## Security & Encryption

### What encryption algorithms does Fortress support?

Fortress supports multiple encryption algorithms:

| Algorithm | Type | Security Level | Performance |
|-----------|------|----------------|-------------|
| AEGIS-256 | AEAD | Very High | Very Fast |
| ChaCha20-Poly1305 | AEAD | High | Fast |
| AES-256-GCM | AEAD | High | Fast |
| AES-256-CBC | Block Cipher | High | Medium |

### How does key rotation work?

Fortress provides automatic key rotation:

1. **Generate New Key**: Create a new encryption key
2. **Re-encrypt Data**: Re-encrypt existing data with new key
3. **Update References**: Update all references to use new key
4. **Archive Old Key**: Securely archive the old key
5. **Verification**: Verify all data is properly encrypted

During rotation, your application continues to work without downtime.

### Are my encryption keys secure?

Yes, Fortress implements multiple security measures:

- **Key Derivation**: Uses Argon2id for key derivation
- **Key Storage**: Keys are encrypted at rest
- **Access Control**: Role-based access to keys
- **Audit Logging**: All key operations are logged
- **HSM Support**: Hardware Security Module integration available

### Can I use my own encryption keys?

Yes, Fortress supports:

- **External Keys**: Import your own encryption keys
- **HSM Integration**: Use Hardware Security Modules
- **Key Management**: Full lifecycle management
- **Custom Algorithms**: Support for custom encryption schemes

### How does Fortress handle data in transit?

Fortress uses TLS 1.3 for all network communications:

- **Encryption**: All data encrypted in transit
- **Authentication**: Mutual TLS authentication
- **Perfect Forward Secrecy**: PFS cipher suites
- **Certificate Pinning**: Optional certificate pinning

### Is Fortress compliant with regulations?

Fortress is designed to be compliant with:

- **GDPR**: Data protection and privacy
- **HIPAA**: Healthcare data protection
- **PCI DSS**: Payment card industry standards
- **SOC 2**: Security and compliance controls

### Can I export my encrypted data?

Yes, Fortress provides data export capabilities:

- **Encrypted Export**: Export data while encrypted
- **Decrypted Export**: Export decrypted data (with proper authorization)
- **Format Options**: JSON, CSV, and custom formats
- **Bulk Export**: Efficient bulk data export

## Performance & Scaling

### How fast is Fortress?

Fortress is optimized for high performance:

| Algorithm | Encrypt (MB/s) | Decrypt (MB/s) |
|-----------|----------------|----------------|
| AEGIS-256 | 910 | 1,898 |
| ChaCha20-Poly1305 | 288 | 460 |
| AES-256-GCM | 358 | 345 |

### Can Fortress handle high traffic?

Yes, Fortress is designed for scalability:

- **Concurrent Connections**: 10,000+ concurrent connections
- **Throughput**: 1,000+ operations per second
- **Horizontal Scaling**: Multiple server instances
- **Load Balancing**: Built-in load balancing support

### How does caching work?

Fortress includes intelligent caching:

- **Multi-Level Caching**: Memory, disk, and distributed cache
- **Cache Warming**: Automatic cache population
- **LRU Eviction**: Least Recently Used eviction policy
- **Cache Invalidation**: Automatic cache invalidation on updates

### What about database performance?

Fortress optimizes database operations:

- **Connection Pooling**: Efficient database connections
- **Batch Operations**: Bulk operations for better performance
- **Query Optimization**: Optimized query execution
- **Indexing**: Automatic index creation for encrypted fields

### How do I monitor Fortress performance?

Fortress provides comprehensive monitoring:

- **Metrics**: Real-time performance metrics
- **Health Checks**: Built-in health endpoints
- **Logging**: Structured logging with correlation IDs
- **Alerting**: Configurable alerts for performance issues

## API & Integration

### What APIs does Fortress provide?

Fortress offers multiple API interfaces:

- **REST API**: Standard HTTP/JSON API
- **GraphQL API**: Flexible query language
- **WebSocket API**: Real-time updates
- **gRPC API**: High-performance RPC interface

### How do I authenticate with Fortress?

Fortress supports multiple authentication methods:

- **JWT Tokens**: JSON Web Token authentication
- **API Keys**: Static API key authentication
- **OAuth 2.0**: OAuth 2.0 integration
- **LDAP/Active Directory**: Enterprise directory integration

### Can I integrate Fortress with my existing application?

Yes, Fortress provides SDKs for multiple languages:

- **Rust**: Native Rust SDK
- **Python**: Python SDK with async support
- **Node.js**: JavaScript/TypeScript SDK
- **Go**: Go SDK with goroutine support
- **Java**: Java SDK with Spring integration
- **.NET**: .NET SDK with ASP.NET Core integration

### How do I handle errors?

Fortress provides comprehensive error handling:

**Rust:**
```rust
match result {
    Ok(data) => println!("Success: {:?}", data),
    Err(FortressError::ValidationError(msg)) => {
        eprintln!("Validation error: {}", msg);
    },
    Err(err) => eprintln!("Error: {}", err),
}
```

**Python:**
```python
try:
    result = await fortress.insert(data)
except FortressValidationError as e:
    print(f"Validation error: {e}")
except FortressError as e:
    print(f"Error: {e}")
```

**Node.js:**
```javascript
try {
    const result = await fortress.insert(data);
    console.log('Success:', result);
} catch (error) {
    if (error instanceof FortressValidationError) {
        console.error('Validation error:', error.message);
    } else {
        console.error('Error:', error.message);
    }
}
```

### Can I use Fortress with my existing database?

Yes, Fortress can integrate with existing databases:

- **Migration Tools**: Data migration utilities
- **Schema Mapping**: Map existing schemas to Fortress
- **Gradual Migration**: Migrate data gradually
- **Dual Write**: Write to both systems during migration

## Troubleshooting

### Fortress won't start. What should I check?

1. **Configuration**: Verify your config file is valid
2. **Ports**: Check if ports are available
3. **Permissions**: Ensure proper file permissions
4. **Dependencies**: Verify all dependencies are installed
5. **Logs**: Check error logs for specific issues

```bash
# Check configuration
fortress config validate

# Check ports
netstat -tlnp | grep :8080

# Check logs
journalctl -u fortress -f
```

### I'm getting authentication errors. What should I do?

1. **API Key**: Verify your API key is correct
2. **Token Expiry**: Check if your token has expired
3. **Permissions**: Ensure proper permissions
4. **Network**: Check network connectivity

```bash
# Test authentication
curl -H "Authorization: Bearer $TOKEN" \
  http://localhost:8080/api/v1/health

# Check token info
curl -H "Authorization: Bearer $TOKEN" \
  http://localhost:8080/api/v1/auth/info
```

### Data is not being encrypted. What's wrong?

1. **Field Definition**: Ensure fields are marked as encrypted
2. **Algorithm**: Verify encryption algorithm is set
3. **Key Management**: Check if encryption keys exist
4. **Configuration**: Verify encryption is enabled

```rust
// Check field definition
FieldDefinition::new("ssn", FieldType::Encrypted)

// Verify encryption
let encrypted = fortress.is_field_encrypted("ssn");
```

### Performance is slow. How can I improve it?

1. **Caching**: Enable caching
2. **Connection Pooling**: Increase connection pool size
3. **Indexing**: Add appropriate indexes
4. **Hardware**: Check system resources

```toml
[cache]
enabled = true
backend = "redis"
ttl = "1h"

[database]
connection_pool_size = 20
```

### I'm getting out of memory errors. What should I do?

1. **Memory Limits**: Increase memory limits
2. **Batch Size**: Reduce batch operation sizes
3. **Cache Size**: Adjust cache configuration
4. **Monitoring**: Monitor memory usage

```bash
# Increase memory limit
export FORTRESS_MEMORY_LIMIT=2g

# Monitor memory
fortress metrics memory
```

## Licensing & Support

### What license does Fortress use?

Fortress is licensed under the Server Side Public License (SSPL). This means:

- **Open Source**: Source code is available
- **Commercial Use**: Requires commercial license for commercial use
- **Modification**: You can modify the source code
- **Distribution**: Must share modifications under the same license

### Do I need a commercial license?

You need a commercial license if:

- You use Fortress for commercial purposes
- You offer Fortress as a service to others
- You modify Fortress and distribute it

For open source projects and personal use, the SSPL license is sufficient.

### Where can I get support?

Multiple support channels are available:

- **Documentation**: [docs.fortress-security.org](https://docs.fortress-security.org)
- **GitHub Issues**: [github.com/fortress-security/fortress/issues](https://github.com/fortress-security/fortress/issues)
- **Discussions**: [github.com/fortress-security/fortress/discussions](https://github.com/fortress-security/fortress/discussions)
- **Community**: [Discord Server](https://discord.gg/fortress)
- **Email**: support@fortress-security.org

### How do I report security vulnerabilities?

For security vulnerabilities, please:

1. **Email**: security@fortress-security.org
2. **Private**: Do not disclose publicly
3. **Details**: Provide detailed reproduction steps
4. **Response**: We'll respond within 24 hours

### Can I contribute to Fortress?

Yes! Contributions are welcome:

1. **Fork**: Fork the repository
2. **Branch**: Create a feature branch
3. **Code**: Write your changes
4. **Test**: Add tests for your changes
5. **PR**: Submit a pull request

See the [Contributing Guide](CONTRIBUTING.md) for details.

### Where can I find more resources?

Additional resources:

- **Website**: [fortress-security.org](https://fortress-security.org)
- **Blog**: [blog.fortress-security.org](https://blog.fortress-security.org)
- **YouTube**: [Fortress Security Channel](https://youtube.com/fortress-security)
- **Twitter**: [@fortress_security](https://twitter.com/fortress_security)

---

Still have questions? Feel free to ask in our [GitHub Discussions](https://github.com/fortress-security/fortress/discussions) or join our [Discord community](https://discord.gg/fortress).
