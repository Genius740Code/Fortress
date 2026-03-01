# True Random Number Generator (TRNG) Guide

## Overview

Fortress now includes a comprehensive True Random Number Generator (TRNG) system that provides cryptographically secure random numbers using multiple hardware entropy sources. This system enhances security by providing true randomness rather than relying solely on pseudo-random generators.

## Features

### Multiple Entropy Sources

The TRNG collects entropy from various hardware and environmental sources:

- **CPU Timing**: Measures instruction cycle variations and CPU timing fluctuations
- **Network Jitter**: Captures network packet timing variations and latency
- **Disk I/O**: Measures disk access timing and storage latency variations  
- **Memory Latency**: Collects memory access timing and cache behavior variations
- **System Time**: Uses high-resolution timer variations and system clock jitter

### Entropy Pool Management

- **Entropy Pooling**: Collects and mixes entropy from multiple sources
- **Cryptographic Mixing**: Uses SHA-256 to mix and distribute entropy
- **Health Monitoring**: Continuously monitors entropy quality and availability
- **Automatic Refresh**: Refreshes entropy when levels get low

### Fallback Mechanisms

- **Graceful Degradation**: Falls back to cryptographically secure pseudo-random generators if TRNG fails
- **Error Handling**: Comprehensive error handling with detailed error reporting
- **Configuration**: Configurable entropy requirements and fallback behavior

## Usage

### Basic Usage

```rust
use fortress_core::trng::*;

// Initialize TRNG
let trng = TrueRandomGenerator::new()?;

// Generate random bytes
let random_bytes = trng.generate_bytes(32)?;

// Generate random numbers
let random_u64 = trng.generate_u64()?;
let random_u32 = trng.generate_u32()?;

// Fill a buffer with random data
let mut buffer = [0u8; 64];
trng.fill_bytes(&mut buffer)?;
```

### Global TRNG Instance

```rust
use fortress_core::trng::*;

// Initialize global TRNG (once per application)
init_global_trng()?;

// Use convenience functions
let bytes = random_bytes(128)?;
let number = random_u64()?;
let mut buf = [0u8; 32];
fill_random(&mut buf)?;
```

### Custom Configuration

```rust
use fortress_core::trng::*;
use std::time::Duration;

let config = TrngConfig {
    min_entropy_bits: 512,           // Higher security requirement
    max_pool_size: 8192,             // Larger entropy pool
    health_check_interval: Duration::from_millis(500),
    entropy_sources: 5,
    enable_fallback: true,
};

let trng = TrueRandomGenerator::with_config(config)?;
```

## Integration with Encryption

The TRNG is automatically integrated with Fortress's encryption modules:

- **Nonce Generation**: All encryption algorithms use TRNG for nonce generation
- **Key Generation**: `SecureKey::generate()` uses TRNG for true random key material
- **Salt Generation**: Password-based encryption uses TRNG for salt generation
- **IV Generation**: Initialization vectors are generated using TRNG

### Example with Encryption

```rust
use fortress_core::encryption::{ChaCha20Poly1305, EncryptionAlgorithm};
use fortress_core::encryption::SecureKey;

// TRNG is automatically used for nonce generation
let algorithm = ChaCha20Poly1305::new();
let key = SecureKey::generate(algorithm.key_size()); // Uses TRNG

let plaintext = b"Hello, Fortress!";
let ciphertext = algorithm.encrypt(plaintext, key.as_bytes())?;
```

## Performance Characteristics

### Entropy Collection

- **CPU Timing**: ~1000 iterations provide ~800 bits of entropy
- **Network Jitter**: ~48 bytes provide ~64 bits of entropy
- **Disk I/O**: ~160 bytes provide ~32 bits of entropy
- **Memory Latency**: ~1600 bytes provide ~32 bits of entropy
- **System Time**: ~160 bytes provide ~16 bits of entropy

### Performance Benchmarks

- **Small chunks (100x32)**: ~3.9 seconds
- **Large chunk (1x3200)**: ~13 milliseconds
- **Concurrent access**: Thread-safe with minimal contention

## Security Considerations

### Entropy Quality

The TRNG implements multiple security measures:

1. **Source Diversity**: Multiple independent entropy sources
2. **Cryptographic Mixing**: SHA-256 ensures proper entropy distribution
3. **Health Monitoring**: Continuous entropy quality assessment
4. **Fallback Protection**: Secure CSPRNG fallback when needed

### Threat Mitigation

- **Entropy Depletion**: Automatic refresh prevents exhaustion
- **Predictable Sources**: Multiple sources make prediction difficult
- **Side-Channel Attacks**: Constant-time operations where possible
- **State Compromise**: Regular reinitialization limits impact

## Configuration Options

### TrngConfig

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `min_entropy_bits` | `usize` | 256 | Minimum entropy bits required |
| `max_pool_size` | `usize` | 4096 | Maximum entropy pool size in bytes |
| `health_check_interval` | `Duration` | 1000ms | Health check frequency |
| `entropy_sources` | `usize` | 5 | Number of entropy sources to use |
| `enable_fallback` | `bool` | true | Enable CSPRNG fallback |

### Health Status

- **Healthy**: Sufficient entropy, normal operation
- **Degraded**: Reduced entropy but still functional
- **Failed**: Insufficient entropy, fallback activated

## Best Practices

### Initialization

```rust
// Initialize early in application startup
let _trng = init_global_trng()?;

// Check health status
let trng = global_trng()?;
match trng.health_status() {
    TrngHealth::Healthy => println!("TRNG operating normally"),
    TrngHealth::Degraded => println!("TRNG degraded, using fallback"),
    TrngHealth::Failed => println!("TRNG failed, using fallback"),
}
```

### Error Handling

```rust
match trng.generate_bytes(32) {
    Ok(bytes) => {
        // Use random bytes
    },
    Err(e) => {
        // Handle error (fallback should prevent most failures)
        eprintln!("TRNG error: {}", e);
    }
}
```

### Performance Optimization

```rust
// For bulk generation, use larger chunks
let large_chunk = trng.generate_bytes(10240)?;

// For frequent small requests, consider buffering
let mut buffer = Vec::new();
trng.fill_bytes(&mut buffer)?;
```

## Testing

The TRNG includes comprehensive tests covering:

- **Initialization**: Various configuration scenarios
- **Entropy Sources**: Individual source testing
- **Random Generation**: Byte and number generation
- **Performance**: Timing and throughput
- **Concurrency**: Thread safety
- **Integration**: Encryption module compatibility
- **Error Handling**: Failure scenarios

### Running Tests

```bash
cargo test --test trng_tests
```

## Troubleshooting

### Common Issues

1. **Insufficient Entropy**: Increase `min_entropy_bits` or enable fallback
2. **Slow Performance**: Adjust `health_check_interval` or pool size
3. **Initialization Failure**: Check system entropy sources

### Debug Information

```rust
let trng = global_trng()?;
let (entropy_bits, pool_size) = trng.entropy_stats();
println!("Entropy: {} bits, Pool: {} bytes", entropy_bits, pool_size);
println!("Health: {:?}", trng.health_status());
```

## Implementation Details

### Entropy Collection Algorithm

1. **Source Sampling**: Collect timing measurements from each source
2. **Estimation**: Conservative entropy estimation per source
3. **Mixing**: SHA-256 hash mixing for distribution
4. **Pool Management**: Circular buffer with entropy tracking
5. **Health Monitoring**: Periodic entropy quality checks

### Thread Safety

- **Arc<Mutex<>>**: Safe sharing across threads
- **Lock Granularity**: Minimal lock contention
- **Deadlock Prevention**: Consistent locking order

### Memory Management

- **Zeroization**: Secure memory cleanup when possible
- **Pool Limits**: Bounded memory usage
- **Leak Prevention**: Proper cleanup on drop

## Future Enhancements

Planned improvements include:

- **Hardware TRNG**: Integration with hardware random number generators
- **Additional Sources**: More entropy sources (e.g., sensor data)
- **Adaptive Estimation**: Better entropy estimation algorithms
- **Performance Tuning**: Optimized entropy collection
- **Audit Logging**: Detailed entropy source logging

## References

- **NIST SP 800-90B**: Entropy sources and random bit generation
- **NIST SP 800-90C**: Random bit generation mechanisms
- **RFC 4086**: Randomness requirements for security

---

*This TRNG implementation provides enterprise-grade randomness for Fortress's cryptographic operations while maintaining high performance and reliability.*
