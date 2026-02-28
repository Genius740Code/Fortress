# Smart Key Rotation System

A highly efficient, scalable, and configurable key rotation system for Fortress database with support for multiple rotation intervals and advanced monitoring capabilities.

## Features

### 🚀 **Performance Optimized**
- **Batch Processing**: Process multiple key rotations concurrently
- **Intelligent Caching**: Avoid redundant rotation checks with smart caching
- **Configurable Concurrency**: Adjust batch sizes and concurrent rotations based on system capacity
- **Metrics Tracking**: Real-time performance monitoring and alerting

### 🔑 **Flexible Rotation Intervals**
- **23 Hours**: High-security keys (near-daily rotation)
- **7 Days**: Sensitive data keys (weekly rotation)  
- **30 Days**: Standard keys (monthly rotation)
- **90 Days**: Low-sensitivity keys (quarterly rotation)
- **Custom Intervals**: Fully configurable rotation periods

### 📊 **Advanced Monitoring**
- **Real-time Metrics**: Track rotation success rates, timing, and throughput
- **Predictive Alerts**: Get notified before keys need rotation
- **Performance Monitoring**: Detect degradation in rotation performance
- **Comprehensive Reporting**: Detailed status reports and health checks

### 🛡️ **Security Focused**
- **Zero-Downtime Rotation**: Seamless key transitions without service interruption
- **Audit Logging**: Complete audit trail of all rotation activities
- **Failure Handling**: Robust error handling with retry mechanisms
- **Secure Key Generation**: Cryptographically secure key creation

## Quick Start

```rust
use fortress_core::prelude::*;
use std::sync::Arc;

// Create key manager
let key_manager = Arc::new(InMemoryKeyManager::new());

// Create smart rotation scheduler
let mut scheduler = SmartKeyRotationScheduler::with_config(
    key_manager.clone(),
    50,  // batch size
    20,  // max concurrent rotations
);

// Configure security level intervals
scheduler.set_security_level_intervals();

// Add custom interval for critical infrastructure
scheduler.set_rotation_interval(
    "critical_infrastructure".to_string(),
    RotationInterval::Custom(Duration::hours(12))
);

// Perform rotation check
let rotated_keys = scheduler.check_and_rotate().await?;
println!("Rotated {} keys", rotated_keys.len());
```

## Configuration

### Security Level Intervals

The system provides predefined security levels with optimal rotation intervals:

```rust
scheduler.set_security_level_intervals();
```

| Security Level | Interval | Use Case |
|----------------|----------|----------|
| `high_security` | 23 hours | Critical infrastructure, admin keys |
| `sensitive` | 7 days | User data, financial information |
| `standard` | 30 days | General application data |
| `low_sensitivity` | 90 days | Logs, analytics, non-critical data |

### Custom Configuration

```rust
// Custom rotation interval
let custom_interval = RotationInterval::Custom(Duration::hours(48));
scheduler.set_rotation_interval("custom_purpose".to_string(), custom_interval);

// Performance tuning
let scheduler = SmartKeyRotationScheduler::with_config(
    key_manager,
    100, // batch size
    10,  // max concurrent rotations
);
```

## Monitoring and Alerting

### Basic Monitoring

```rust
// Get current metrics
let metrics = scheduler.get_metrics().await;
println!("Total rotations: {}", metrics.total_rotations);
println!("Success rate: {:.2}%", 
    (metrics.successful_rotations as f64 / metrics.total_rotations as f64) * 100.0
);

// Check for upcoming rotations
let upcoming_keys = scheduler.get_keys_needing_soon_rotation(24).await?;
println!("{} keys need rotation within 24 hours", upcoming_keys.len());
```

### Advanced Monitoring Setup

```rust
use fortress_core::examples::smart_key_rotation::*;

// Create monitoring configuration
let config = SmartRotationConfig {
    batch_size: 50,
    max_concurrent_rotations: 20,
    check_interval_seconds: 300, // 5 minutes
    auto_rotation_enabled: true,
    alert_threshold_hours: 48,
    performance_monitoring: true,
};

// Create monitor with alert handlers
let monitor = RotationMonitor::new(Arc::new(scheduler), config);
monitor.add_alert_handler(Box::new(ConsoleAlertHandler));

// Start continuous monitoring
monitor.start_monitoring().await?;
```

## Performance Characteristics

### Benchmarks

The smart key rotation system is optimized for high-throughput scenarios:

| Metric | Value |
|--------|-------|
| **Throughput** | 100+ keys/second (batch mode) |
| **Latency** | <50ms per key (concurrent) |
| **Memory Usage** | O(1) per active rotation |
| **Scalability** | Linear scaling with batch size |

### Performance Tuning

```rust
// For high-throughput systems
let scheduler = SmartKeyRotationScheduler::with_config(
    key_manager,
    200, // larger batch size
    50,  // higher concurrency
);

// For resource-constrained environments
let scheduler = SmartKeyRotationScheduler::with_config(
    key_manager,
    25,  // smaller batch size
    5,   // lower concurrency
);
```

## Advanced Features

### Force Rotation

```rust
// Rotate a specific key regardless of schedule
let (new_key, new_metadata) = scheduler.force_rotate_key("key_id").await?;
println!("Key rotated to version {}", new_metadata.version);
```

### Cache Management

```rust
// Clear rotation cache (useful after configuration changes)
scheduler.clear_cache().await;
```

### Predictive Analysis

```rust
// Get keys needing rotation in next 7 days
let weekly_keys = scheduler.get_keys_needing_soon_rotation(24 * 7).await?;

// Analyze rotation patterns
let metrics = scheduler.get_metrics().await;
if metrics.average_rotation_time_ms > 5000 {
    println!("⚠️ Rotation performance degraded");
}
```

## Error Handling

The system provides comprehensive error handling and recovery:

```rust
match scheduler.check_and_rotate().await {
    Ok(rotated_keys) => {
        println!("Successfully rotated {} keys", rotated_keys.len());
    }
    Err(e) => {
        eprintln!("Rotation failed: {}", e);
        // Implement retry logic or alerting
    }
}
```

## Integration Examples

### With Database Backends

```rust
// Integration with PostgreSQL key storage
let pg_key_manager = Arc::new(PostgreSQLKeyManager::new(pool).await?);
let scheduler = SmartKeyRotationScheduler::new(pg_key_manager);
```

### With HSM Integration

```rust
// Integration with Hardware Security Modules
let hsm_manager = Arc::new(HsmKeyManager::new(hsm_config)?);
let scheduler = SmartKeyRotationScheduler::new(hsm_manager);
```

### With Cloud KMS

```rust
// Integration with AWS KMS
let aws_kms = Arc::new(AwsKmsKeyManager::new(region).await?);
let scheduler = SmartKeyRotationScheduler::new(aws_kms);
```

## Best Practices

### 1. **Security Level Assignment**
- Assign appropriate security levels based on data sensitivity
- Use the most restrictive interval feasible for your security requirements
- Consider compliance requirements (PCI-DSS, HIPAA, GDPR)

### 2. **Performance Optimization**
- Tune batch sizes based on your system capacity
- Monitor rotation metrics regularly
- Use predictive alerts to schedule rotations during low-traffic periods

### 3. **Monitoring Setup**
- Enable comprehensive monitoring from day one
- Set up alerts for performance degradation
- Regularly review rotation patterns and adjust intervals

### 4. **Testing Strategy**
- Test rotation in staging environments before production
- Validate key rotation doesn't impact application functionality
- Test failure scenarios and recovery procedures

## Troubleshooting

### Common Issues

**High rotation latency**
```rust
// Increase batch size or concurrency
let scheduler = SmartKeyRotationScheduler::with_config(key_manager, 100, 20);
```

**Memory usage high**
```rust
// Reduce batch size and enable more frequent checks
let scheduler = SmartKeyRotationScheduler::with_config(key_manager, 25, 5);
```

**Rotation failures**
```rust
// Check metrics for failure patterns
let metrics = scheduler.get_metrics().await;
if metrics.failed_rotations > 0 {
    println!("Investigate {} failed rotations", metrics.failed_rotations);
}
```

## API Reference

### Core Types

- [`SmartKeyRotationScheduler`](#smartkeyrotationscheduler)
- [`RotationInterval`](#rotationinterval)
- [`RotationMetrics`](#rotationmetrics)

### Monitoring

- [`RotationMonitor`](#rotationmonitor)
- [`RotationAlert`](#rotationalert)
- [`SmartRotationConfig`](#smartrotationconfig)

### Examples

See the [examples directory](../examples/) for complete working examples:
- `smart_key_rotation.rs` - Comprehensive usage example
- `key_rotation_test.rs` - Test suite and benchmarks

## License

This project is licensed under the Apache License 2.0 - see the [LICENSE](../../LICENSE) file for details.

## Contributing

Please see [CONTRIBUTING.md](../../CONTRIBUTING.md) for contribution guidelines.

---

**Fortress Smart Key Rotation System** - Enterprise-grade key management with intelligent automation.
