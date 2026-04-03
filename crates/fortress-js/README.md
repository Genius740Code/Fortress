# Fortress JavaScript/TypeScript SDK

[![npm version](https://badge.fury.io/js/fortress-db.svg)](https://badge.fury.io/js/fortress-db)
[![License: Fortress Sustainable Use License 1.0](https://img.shields.io/badge/License-Fortress%20Sustainable%20Use%20License%201.0-blue.svg)](../../LICENSE)

🛡️ **Fortress** - Turnkey Simplicity + Enterprise Security. JavaScript/TypeScript SDK for Fortress secure database system with multi-layer encryption.

## Features

- **Enterprise-grade Encryption**: Support for AEGIS-256, ChaCha20-Poly1305, AES-256-GCM, and more
- **Advanced Key Management**: Automatic key generation, rotation, and secure storage
- **Flexible Storage Backends**: Local filesystem, S3, Azure Blob Storage, and more
- **Multi-tenant Support**: Complete tenant isolation and resource management
- **Comprehensive Auditing**: Tamper-evident logging and security event tracking
- **Policy Engine**: Role-based access control (RBAC) with fine-grained permissions
- **High Performance**: Rust-powered core with TypeScript-friendly interface
- **Easy Configuration**: Pre-built profiles for different use cases
- **Full TypeScript Support**: Complete type definitions and IntelliSense

## Installation

### NPM (Recommended)

```bash
# Install the SDK
npm install fortress-db

# Install CLI tool globally
npm install -g fortress-cli
```

### Yarn

```bash
# Install the SDK
yarn add fortress-db

# Install CLI tool globally
yarn global add fortress-cli
```

### PNPM

```bash
# Install the SDK
pnpm add fortress-db

# Install CLI tool globally
pnpm add -g fortress-cli
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

### Basic Usage

```typescript
import { Fortress } from 'fortress-db';

// Initialize Fortress client
const fortress = new Fortress({
  serverUrl: 'http://localhost:8080',
  apiKey: process.env.FORTRESS_API_KEY
});

async function main() {
  try {
    // Create a database
    const db = await fortress.createDatabase('myapp');
    
    // Insert encrypted data
    const user = await db.insert('users', {
      name: 'Alice Johnson',
      email: 'alice@example.com',
      ssn: '123-45-6789', // Automatically encrypted
      creditCard: '4111-1111-1111-1111' // Automatically encrypted
    });
    
    console.log('User created:', user.name);
    
    // Query data (decrypted automatically)
    const users = await db.find('users', { 
      where: { email: 'alice@example.com' } 
    });
    
    console.log('Found users:', users.length);
    
  } catch (error) {
    console.error('Error:', error);
  }
}

main();
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

This project is licensed under the **Fortress Sustainable Use License 1.0** - see the [LICENSE](../../LICENSE) file for details.

## Support

- **Documentation**: [GitHub Docs](https://github.com/Genius740Code/Fortress/blob/main/docs)
- **Issues**: [GitHub Issues](https://github.com/Genius740Code/Fortress/issues)
- **Discussions**: [GitHub Discussions](https://github.com/Genius740Code/Fortress/discussions)

## Contributing

We welcome contributions! Please see our [Contributing Guide](../../CONTRIBUTING.md) for details.
