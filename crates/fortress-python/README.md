# Fortress Python SDK

A Python interface to the Fortress secure database system, providing enterprise-grade encryption, key management, and multi-tenant isolation.

## Features

- **🔐 Enterprise-grade Encryption**: Support for AEGIS-256, ChaCha20-Poly1305, AES-256-GCM, and more
- **🔑 Advanced Key Management**: Automatic key generation, rotation, and secure storage
- **💾 Flexible Storage Backends**: Local filesystem, S3, Azure Blob Storage, and more
- **👥 Multi-tenant Support**: Complete tenant isolation and resource management
- **📊 Comprehensive Auditing**: Tamper-evident logging and security event tracking
- **🛡️ Policy Engine**: Role-based access control (RBAC) with fine-grained permissions
- **⚡ High Performance**: Rust-powered core with Python-friendly interface
- **🔧 Easy Configuration**: Pre-built profiles for different use cases

## Installation

### From PyPI (Recommended)

```bash
pip install fortress
```

### From Source

```bash
# Clone the repository
git clone https://github.com/Genius740Code/Fortress.git
cd Fortress/crates/fortress-python

# Install development dependencies
pip install -e ".[dev]"

# Build and install
maturin develop
```

## Quick Start

```python
import fortress
import asyncio

async def main():
    # Create configuration
    config = fortress.FortressConfig.lightning()
    
    # Initialize encryption
    algorithm = fortress.EncryptionAlgorithm.aegis256()
    key = fortress.generate_key("aegis256")
    
    # Encrypt and decrypt data
    plaintext = b"Hello, Fortress!"
    ciphertext = await algorithm.encrypt(plaintext, key)
    decrypted = await algorithm.decrypt(ciphertext, key)
    
    print(f"Original: {plaintext}")
    print(f"Decrypted: {decrypted}")
    
    # Key management
    key_manager = fortress.KeyManager()
    key_id = await key_manager.generate_key("aegis256")
    stored_key = await key_manager.get_key(key_id)
    
    # Storage operations
    storage = fortress.StorageBackend.local("/tmp/fortress-data")
    await storage.store("my-secret", ciphertext)
    retrieved = await storage.retrieve("my-secret")

# Run the async example
asyncio.run(main())
```

## Configuration

Fortress provides several pre-built configuration profiles:

```python
# Lightning - Maximum performance
config = fortress.FortressConfig.lightning()

# Balanced - Good performance with strong security
config = fortress.FortressConfig.balanced()

# Fortress - Maximum security
config = fortress.FortressConfig.fortress()

# Startup - Quick initialization for development
config = fortress.FortressConfig.startup()

# Enterprise - Production-ready with all features
config = fortress.FortressConfig.enterprise()
```

## Encryption Algorithms

Fortress supports multiple encryption algorithms:

```python
# AEGIS-256 - Ultra-fast and secure
algorithm = fortress.EncryptionAlgorithm.aegis256()

# ChaCha20-Poly1305 - Well-vetted and widely supported
algorithm = fortress.EncryptionAlgorithm.chacha20poly1305()

# AES-256-GCM - Hardware accelerated on many platforms
algorithm = fortress.EncryptionAlgorithm.aes256gcm()

# Generate keys for specific algorithms
key = fortress.generate_key("aegis256")
nonce = fortress.generate_nonce("aegis256")
```

## Key Management

```python
# Create key manager
key_manager = fortress.KeyManager()

# Generate a new key with metadata
metadata = fortress.KeyMetadata(
    algorithm="aegis256",
    created_at="2024-01-01T00:00:00Z",
    purpose="data-encryption",
    tags=["production", "user-data"]
)
key_id = await key_manager.generate_key("aegis256", metadata)

# Rotate keys automatically
new_key_id = await key_manager.rotate_key(key_id)

# List all keys
keys = await key_manager.list_keys()
print(f"Available keys: {keys}")
```

## Storage Backends

### Local Filesystem

```python
storage = fortress.StorageBackend.local("/path/to/storage")
await storage.store("key", b"data")
data = await storage.retrieve("key")
```

### Amazon S3

```python
storage = fortress.StorageBackend.s3(
    bucket="my-fortress-bucket",
    region="us-west-2",
    access_key="your-access-key",
    secret_key="your-secret-key"
)
```

### Azure Blob Storage

```python
storage = fortress.StorageBackend.azure_blob(
    account="myaccount",
    container="fortress-data",
    access_key="your-access-key"
)
```

## Multi-tenant Support

```python
# Create tenant manager
tenant_manager = fortress.TenantManager()

# Create resource limits
limits = fortress.TenantResourceLimitsWrapper(
    max_keys=1000,
    max_storage_mb=10240,
    max_users=100,
    max_api_calls_per_hour=10000
)

# Create a new tenant
request = fortress.CreateTenantRequestWrapper(
    name="Acme Corp",
    description="Enterprise customer",
    resource_limits=limits
)
tenant = await tenant_manager.create_tenant(request)

# Get tenant statistics
stats = await tenant_manager.get_tenant_stats(tenant.id())
print(f"Resource utilization: {stats.resource_utilization():.2%}")
```

## Policy Engine

```python
# Create policy engine
policy_engine = fortress.PolicyEngine()

# Define roles and permissions
admin_role = fortress.RoleWrapper.new_role(
    name="admin",
    description="Full administrative access",
    permissions=["key:*", "data:*", "config:*"]
)
await policy_engine.add_role(admin_role)

# Assign roles to users
await policy_engine.assign_role("user123", "admin")

# Check permissions
can_read = await policy_engine.check_permission("user123", "user-data", "read")
can_delete = await policy_engine.check_permission("user123", "system-config", "delete")
```

## Audit Logging

```python
# Create audit logger with custom configuration
audit_config = fortress.AuditConfigWrapper(
    log_file_path="/var/log/fortress/audit.log",
    max_file_size_mb=100,
    max_files=10,
    enable_compression=True,
    enable_encryption=True
)
audit_logger = fortress.AuditLogger.with_config(audit_config)

# Log security events
await audit_logger.log_event(
    event_type="Authentication",
    user_id="user123",
    resource="login-service",
    outcome="Success",
    security_level="Medium",
    details={"ip_address": "192.168.1.100", "method": "password"}
)

# Query audit events
events = await audit_logger.query_events(
    start_time="2024-01-01T00:00:00Z",
    end_time="2024-01-02T00:00:00Z",
    event_types=["Authentication", "DataAccess"],
    limit=100
)
```

## Error Handling

Fortress provides comprehensive error handling:

```python
try:
    ciphertext = await algorithm.encrypt(plaintext, key)
except fortress.FortressError as e:
    print(f"Fortress error: {e.message()}")
    print(f"Error kind: {e.kind()}")
    print(f"Retryable: {e.is_retryable()}")
    print(f"Temporary: {e.is_temporary()}")
```

## Command Line Interface

Fortress provides a comprehensive CLI for common operations:

```bash
# Show version information
fortress-python version --build-info

# List available algorithms
fortress-python list-algorithms --details

# Generate encryption key
fortress-python generate-key --algorithm aegis256 --output my-key.txt --base64

# Encrypt data
fortress-python encrypt --data "Hello, Fortress!" --key-file my-key.txt --algorithm aegis256

# Decrypt data
fortress-python decrypt --data "encrypted_base64_data" --key-file my-key.txt --algorithm aegis256

# Create configuration
fortress-python create-config --profile fortress --output fortress-config.json

# Run tests
fortress-python test --algorithm aegis256 --quick
```

## Examples

The `python/examples/` directory contains comprehensive examples:

- **`basic_encryption.py`** - Simple encryption/decryption demo
- **`key_management.py`** - Key generation and management
- **`multi_tenant_demo.py`** - Multi-tenant architecture demo
- **`policy_engine_demo.py`** - Role-based access control demo
- **`audit_logging_demo.py`** - Comprehensive audit logging demo

Run examples with:
```bash
cd python/examples
python basic_encryption.py
python key_management.py
python multi_tenant_demo.py
python policy_engine_demo.py
python audit_logging_demo.py
```

## Development

### Setup Development Environment

```bash
# Clone repository
git clone https://github.com/Genius740Code/Fortress.git
cd Fortress/crates/fortress-python

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install development dependencies
pip install -e ".[dev]"

# Install Rust toolchain if not already installed
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

### Building

```bash
# Development build
maturin develop

# Release build
maturin build --release

# Build wheels for distribution
maturin build --release --out dist
```

### Testing

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=fortress

# Run specific test categories
pytest -m unit
pytest -m integration
pytest -m "not slow"

# Run specific test files
pytest tests/test_encryption.py
pytest tests/test_key_management.py
pytest tests/test_storage.py
pytest tests/test_config.py
```

### Code Quality

```bash
# Format code
black python/
isort python/

# Type checking
mypy python/

# Linting
flake8 python/
```

## Performance

Fortress Python SDK provides excellent performance thanks to its Rust core:

- **AEGIS-256 encryption**: ~10GB/s on modern CPUs
- **Key operations**: Sub-millisecond latency
- **Storage I/O**: Async operations with minimal overhead
- **Memory usage**: Efficient zero-copy operations where possible

Benchmark results (typical on a modern laptop):

```python
import time
import fortress

async def benchmark():
    algorithm = fortress.EncryptionAlgorithm.aegis256()
    key = fortress.generate_key("aegis256")
    data = b"A" * 1024 * 1024  # 1MB
    
    start = time.time()
    for _ in range(100):
        await algorithm.encrypt(data, key)
    end = time.time()
    
    throughput = (100 * 1024 * 1024) / (end - start) / (1024**3)
    print(f"Encryption throughput: {throughput:.2f} GB/s")
```

## Security

Fortress is designed with security as the primary concern:

- **Zero-knowledge architecture**: Your data never leaves your control
- **Memory safety**: Rust's memory safety guarantees prevent entire classes of vulnerabilities
- **Secure defaults**: Strong encryption settings out of the box
- **Comprehensive auditing**: All operations are logged for compliance
- **Multi-tenant isolation**: Complete data separation between tenants
- **Hardware security**: HSM integration for key protection

## License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.

## Support

- **Documentation**: [https://docs.fortress-db.com](https://docs.fortress-db.com)
- **Issues**: [GitHub Issues](https://github.com/Genius740Code/Fortress/issues)
- **Discussions**: [GitHub Discussions](https://github.com/Genius740Code/Fortress/discussions)
- **Email**: team@fortress-db.com

## Contributing

We welcome contributions! Please see our [Contributing Guide](../../CONTRIBUTING.md) for details.

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for a list of changes and version history.
