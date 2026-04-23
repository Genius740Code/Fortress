# Fortress Core

[![Crates.io](https://img.shields.io/crates/v/fortress-core.svg)](https://crates.io/crates/fortress-core)
[![Documentation](https://docs.rs/fortress-core/badge.svg)](https://docs.rs/fortress-core)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](../../LICENSE)

**Fortress Core** - The heart of Fortress secure database system. Enterprise-grade encryption, key management, and security primitives.

## Features

- **Multiple Encryption Algorithms**: AEGIS-256, ChaCha20-Poly1305, AES-256-GCM, and more
- **Advanced Key Management**: Automatic generation, rotation, and secure storage
- **High Performance**: Optimized for speed with hardware acceleration
- **Memory Safe**: Built with Rust for zero vulnerabilities
- **Developer Friendly**: Simple API with comprehensive error handling

## Quick Start

Add this to your `Cargo.toml`:

```toml
[dependencies]
fortress-core = "1.0.1"
```

Or install via cargo:

```bash
cargo add fortress-core
```

## Basic Usage

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

## Field-Level Encryption

```rust
use fortress_core::prelude::*;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let fortress = Fortress::new().await?;
    
    // Create encrypted field
    let encrypted_field = fortress.create_encrypted_field(
        "user_data",
        EncryptionAlgorithm::Aegis256
    )?;
    
    // Encrypt sensitive data
    let sensitive_data = "user-secret-key";
    let encrypted_data = encrypted_field.encrypt(sensitive_data.as_bytes())?;
    
    // Decrypt when needed
    let decrypted_data = encrypted_field.decrypt(&encrypted_data)?;
    
    println!("Decrypted: {}", String::from_utf8(decrypted_data)?);
    Ok(())
}
```

## Performance

Fortress Core is optimized for high-performance encryption:

| Algorithm | Throughput (MB/s) | Latency (ms) | Security Level |
|-----------|-------------------|--------------|----------------|
| AEGIS-256 | 1500+ | 0.5 | Very High |
| ChaCha20-Poly1305 | 1200+ | 0.7 | High |
| AES-256-GCM | 1000+ | 0.8 | High |

## Features

- **`default`**: Standard library support
- **`cloud-storage`**: AWS S3, Azure Blob, Google Cloud Storage integration
- **`postgres`**: PostgreSQL database backend
- **`simd`**: SIMD optimizations for supported platforms
- **`hardware-acceleration`**: Hardware acceleration support

## License

This project is licensed under MIT - see the [LICENSE](../../LICENSE) file for details.

## Documentation

- [API Documentation](https://docs.rs/fortress-core)
- [Examples](../../examples/)

## Contributing

Please read our [Contributing Guide](../../CONTRIBUTING.md) before contributing.

## Support

- **Issues**: [GitHub Issues](https://github.com/Genius740Code/Fortress/issues)
- **Discussions**: [GitHub Discussions](https://github.com/Genius740Code/Fortress/discussions)
