# Fortress JavaScript/TypeScript SDK

A modern JavaScript/TypeScript interface to the Fortress secure database system, providing enterprise-grade encryption, key management, and multi-tenant isolation.

## Features

- **🔐 Enterprise-grade Encryption**: Support for AEGIS-256, ChaCha20-Poly1305, AES-256-GCM, and more
- **🔑 Advanced Key Management**: Automatic key generation, rotation, and secure storage
- **💾 Flexible Storage Backends**: Local filesystem, S3, Azure Blob Storage, and more
- **👥 Multi-tenant Support**: Complete tenant isolation and resource management
- **📊 Comprehensive Auditing**: Tamper-evident logging and security event tracking
- **🛡️ Policy Engine**: Role-based access control (RBAC) with fine-grained permissions
- **⚡ High Performance**: Rust-powered core with TypeScript-friendly interface
- **🔧 Easy Configuration**: Pre-built profiles for different use cases
- **📦 Full TypeScript Support**: Complete type definitions and IntelliSense

## Installation

### From NPM (Recommended)

```bash
npm install fortress
```

### From Source

```bash
# Clone the repository
git clone https://github.com/Genius740Code/Fortress.git
cd Fortress/crates/fortress-js

# Install dependencies
npm install

# Build the package
npm run build
```

## Quick Start

```typescript
import { Fortress, EncryptionAlgorithm } from 'fortress';

// Initialize Fortress
const fortress = new Fortress();

// Create encryption algorithm
const algorithm = fortress.createAlgorithm('aegis256');

// Generate key
const key = fortress.generateKey('aegis256');

// Encrypt data
const plaintext = new TextEncoder().encode('Hello, Fortress!');
const ciphertext = await algorithm.encrypt(plaintext, key);

// Decrypt data
const decrypted = await algorithm.decrypt(ciphertext, key);
console.log(new TextDecoder().decode(decrypted)); // "Hello, Fortress!"
```

## Configuration

Fortress provides several pre-built configuration profiles:

```typescript
import { FortressConfig } from 'fortress';

// Lightning - Maximum performance
const lightningConfig = FortressConfig.lightning();

// Balanced - Good performance with strong security
const balancedConfig = FortressConfig.balanced();

// Fortress - Maximum security
const fortressConfig = FortressConfig.fortress();

// Startup - Quick initialization for development
const startupConfig = FortressConfig.startup();

// Enterprise - Production-ready with all features
const enterpriseConfig = FortressConfig.enterprise();
```

## Encryption Algorithms

Fortress supports multiple encryption algorithms:

```typescript
import { EncryptionAlgorithm } from 'fortress';

// AEGIS-256 - Ultra-fast and secure
const aegisAlgorithm = fortress.createAlgorithm('aegis256');

// ChaCha20-Poly1305 - Well-vetted and widely supported
const chachaAlgorithm = fortress.createAlgorithm('chacha20poly1305');

// AES-256-GCM - Hardware accelerated on many platforms
const aesAlgorithm = fortress.createAlgorithm('aes256gcm');

// Generate keys and nonces
const key = fortress.generateKey('aegis256');
const nonce = fortress.generateNonce('aegis256');
```

## Key Management

```typescript
import { KeyManager } from 'fortress';

// Create key manager
const keyManager = new KeyManager();

// Generate a new key with metadata
const keyId = await keyManager.generateKey('aegis256', {
  purpose: 'data-encryption',
  tags: ['production', 'user-data']
});

// Rotate keys automatically
const newKeyId = await keyManager.rotateKey(keyId);

// List all keys
const keys = await keyManager.listKeys();
console.log('Available keys:', keys);
```

## Storage Backends

### Local Filesystem

```typescript
import { StorageBackend } from 'fortress';

const storage = StorageBackend.local('/path/to/storage');
await storage.store('key', new TextEncoder().encode('data'));
const data = await storage.retrieve('key');
```

### Amazon S3

```typescript
const storage = StorageBackend.s3({
  bucket: 'my-fortress-bucket',
  region: 'us-west-2',
  accessKey: 'your-access-key',
  secretKey: 'your-secret-key'
});
```

### Azure Blob Storage

```typescript
const storage = StorageBackend.azureBlob({
  account: 'myaccount',
  container: 'fortress-data',
  accessKey: 'your-access-key'
});
```

## Error Handling

Fortress provides comprehensive error handling:

```typescript
import { FortressError } from 'fortress';

try {
  const ciphertext = await algorithm.encrypt(plaintext, key);
} catch (error) {
  if (error instanceof FortressError) {
    console.error('Fortress error:', error.message);
    console.error('Error kind:', error.kind);
    console.error('Retryable:', error.isRetryable);
    console.error('Temporary:', error.isTemporary);
  }
}
```

## Development

### Setup Development Environment

```bash
# Clone repository
git clone https://github.com/Genius740Code/Fortress.git
cd Fortress/crates/fortress-js

# Install dependencies
npm install

# Install Rust toolchain if not already installed
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

### Building

```bash
# Development build
npm run build

# Watch mode for development
npm run build:watch

# Clean build artifacts
npm run clean
```

### Testing

```bash
# Run all tests
npm test

# Run tests in watch mode
npm run test:watch

# Run tests with coverage
npm run test:coverage
```

### Code Quality

```bash
# Lint code
npm run lint

# Fix linting issues
npm run lint:fix

# Format code
npm run format

# Check formatting
npm run format:check
```

## Performance

Fortress JavaScript SDK provides excellent performance thanks to its Rust core:

- **AEGIS-256 encryption**: ~10GB/s on modern CPUs
- **Key operations**: Sub-millisecond latency
- **Storage I/O**: Async operations with minimal overhead
- **Memory usage**: Efficient zero-copy operations where possible

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
