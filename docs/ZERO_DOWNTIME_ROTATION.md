# Zero-Downtime Key Rotation

## Overview

Zero-Downtime Key Rotation is a critical security feature that allows encryption keys to be rotated without interrupting service operations. This ensures continuous availability while maintaining security best practices.

## Architecture

### 6-Phase Rotation Process

The zero-downtime rotation follows a carefully designed 6-phase process:

1. **Preparation Phase**: Create backup of existing key without disrupting operations
2. **Generation Phase**: Generate new key with updated metadata
3. **Validation Phase**: Validate new key before switching
4. **Atomic Switch**: Instantaneous switch to new key
5. **Post-Switch Validation**: Verify new key is working correctly
6. **Cleanup Phase**: Remove old versions and finalize transition

### Key Components

- **Concurrent Operation Protection**: Uses `tokio::sync::Mutex` and `std::sync::LazyLock` to prevent race conditions
- **Timeout Protection**: Prevents operations from hanging indefinitely
- **Rollback Mechanism**: Automatic rollback on validation failures
- **Comprehensive Audit Logging**: Tracks all rotation events with detailed metadata

## Implementation Details

### Core Methods

#### `rotate_key_with_zero_downtime()`

The main entry point for zero-downtime rotation:

```rust
async fn rotate_key_with_zero_downtime(&self, key_id: &KeyId, algorithm: &dyn EncryptionAlgorithm) -> Result<()>
```

**Features:**
- 6-phase rotation process
- Comprehensive error handling
- Automatic rollback on failure
- Detailed audit logging
- Timeout protection for all phases

#### `validate_new_key()`

Validates a newly generated key before switching:

```rust
async fn validate_new_key(&self, new_versioned_id: &KeyId) -> Result<()>
```

**Validations:**
- Key is not empty
- Metadata has valid version
- Key is accessible through the key manager

#### `validate_post_switch()`

Validates the system state after switching to the new key:

```rust
async fn validate_post_switch(&self, key_id: &KeyId, expected_version: u32) -> Result<()>
```

**Validations:**
- Version matches expected version
- New key is active
- System is in consistent state

#### Transition Management

- `initiate_key_transition()`: Starts the transition process with concurrent protection
- `complete_key_transition()`: Finalizes the transition with cleanup
- `rollback_key_transition()`: Emergency rollback with comprehensive validation

### Concurrency Control

The implementation uses a sophisticated locking mechanism to prevent concurrent rotations on the same key:

```rust
static TRANSITION_LOCKS: std::sync::LazyLock<Arc<Mutex<HashMap<String, ()>>>> = 
    std::sync::LazyLock::new(|| Arc::new(Mutex::new(HashMap::new())));
```

This ensures:
- Only one rotation operation per key at a time
- Other operations can continue accessing keys during rotation
- Automatic lock release on completion or failure

## Usage Examples

### Basic Rotation

```rust
use fortress_core::key::{KeyManager, InMemoryKeyManager};
use fortress_core::encryption::create_algorithm;

let key_manager = InMemoryKeyManager::new();
let algorithm = create_algorithm("aegis256")?;

// Create initial key
let key_id = "my_app_key".to_string();
let initial_key = key_manager.generate_key(algorithm.as_ref()).await?;
let metadata = KeyMetadata::new(
    key_id.clone(),
    algorithm.name().to_string(),
    1,
    Utc::now(),
    Utc::now() + ChronoDuration::days(90),
    "encryption".to_string(),
    PerformanceProfile::Balanced,
);
key_manager.store_key(&key_id, &initial_key, &metadata).await?;

// Perform zero-downtime rotation
key_manager.rotate_key_with_zero_downtime(&key_id, algorithm.as_ref()).await?;
```

### Rotation with Smart Scheduler

```rust
use fortress_core::key::{SmartKeyRotationScheduler, RotationPolicy, RotationInterval};

let scheduler = SmartKeyRotationScheduler::new(key_manager);
scheduler.set_security_level_intervals();

// Create keys with different security requirements
let high_security_key = "high_security_data".to_string();
let standard_key = "standard_data".to_string();

// Set up keys with appropriate metadata
// ... (key setup code)

// Check and rotate keys based on policies
let rotated_keys = scheduler.check_and_rotate().await?;
println!("Rotated {} keys", rotated_keys.len());
```

### Concurrent Operations During Rotation

```rust
use tokio::spawn;

// Start rotation in background
let rotation_task = spawn(async move {
    key_manager.rotate_key_with_zero_downtime(&key_id, algorithm.as_ref()).await
});

// Continue using the key during rotation
for i in 0..10 {
    let (key, metadata) = key_manager.retrieve_key(&key_id).await?;
    // Use key for encryption/decryption
    println!("Operation {} completed during rotation", i);
    tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
}

// Wait for rotation to complete
let rotation_result = rotation_task.await??;
println!("Rotation completed successfully");
```

## Error Handling and Rollback

### Automatic Rollback Scenarios

The system automatically rolls back when:

1. **New Key Validation Fails**: If the new key doesn't pass validation checks
2. **Post-Switch Validation Fails**: If the system state is inconsistent after switching
3. **Timeout Occurs**: If any phase takes longer than the configured timeout
4. **Concurrent Access Violation**: If another rotation is attempted on the same key

### Rollback Process

```rust
async fn rollback_key_transition(&self, key_id: &KeyId, old_version: u32, new_version: u32) -> Result<()>
```

The rollback process:
1. Validates backup key exists and is accessible
2. Restores old key as the active key
3. Validates rollback was successful
4. Cleans up failed new key version
5. Updates metadata to reflect rollback status

### Error Types

- `KeyErrorCode::RotationFailed`: General rotation failure
- `KeyErrorCode::InvalidKeyFormat`: Key format validation failure
- `KeyErrorCode::KeyNotFound`: Required key not found for rollback

## Performance Considerations

### Timeouts

Each phase has specific timeout limits:
- Backup creation: 30 seconds
- New key validation: 10 seconds
- Post-switch validation: 5 seconds
- Rollback validation: 10 seconds

### Memory Usage

The implementation is designed to minimize memory overhead:
- Versioned keys are cleaned up after successful rotation
- Temporary metadata is stored efficiently
- Locks are released promptly

### Concurrent Performance

- Read operations continue during rotation
- Multiple keys can be rotated simultaneously
- Lock contention is minimized through per-key locking

## Security Features

### Audit Logging

All rotation events are logged with comprehensive metadata:

```rust
let mut audit_metadata = HashMap::new();
audit_metadata.insert("rotation_id".to_string(), rotation_id);
audit_metadata.insert("key_id".to_string(), key_id.clone());
audit_metadata.insert("algorithm".to_string(), algorithm.name().to_string());
audit_metadata.insert("old_version".to_string(), old_version.to_string());
audit_metadata.insert("new_version".to_string(), new_version.to_string());
audit_metadata.insert("rotation_time_ms".to_string(), elapsed_ms.to_string());
```

### Key Versioning

- Old keys are backed up with versioned IDs (`key_id_v1`, `key_id_v2`)
- Metadata tracks transition status and timestamps
- Failed versions are automatically cleaned up

### Access Control

- Rotation requires appropriate permissions
- All operations are logged for security auditing
- Emergency rollback requires validation

## Testing

The implementation includes comprehensive tests covering:

1. **Basic Rotation**: Successful rotation scenarios
2. **Concurrent Operations**: Multiple operations during rotation
3. **Concurrent Rotation Protection**: Preventing simultaneous rotations
4. **Rollback Scenarios**: Various failure conditions
5. **Timeout Handling**: Operation timeout behavior
6. **Algorithm Support**: Different encryption algorithms
7. **Metadata Integrity**: Preservation of key metadata
8. **Sequential Rotations**: Multiple rotations in sequence

### Running Tests

```bash
# Run all zero-downtime rotation tests
cargo test test_zero_downtime_rotation --lib

# Run specific test scenarios
cargo test test_zero_downtime_rotation_basic --lib
cargo test test_concurrent_rotation_protection --lib
cargo test test_rotation_rollback_on_failure --lib
```

## Configuration

### Timeout Configuration

Timeouts can be adjusted based on your environment:

```rust
// In your key manager implementation
const BACKUP_TIMEOUT: Duration = Duration::from_secs(30);
const VALIDATION_TIMEOUT: Duration = Duration::from_secs(10);
const POST_SWITCH_TIMEOUT: Duration = Duration::from_secs(5);
const ROLLBACK_TIMEOUT: Duration = Duration::from_secs(10);
```

### Rotation Policies

Configure rotation intervals based on data sensitivity:

```rust
let policy = RotationPolicy::new(
    RotationInterval::Days90, // Low sensitivity data
    SecurityLevel::Standard,
);
```

## Best Practices

### Production Deployment

1. **Monitor Rotation Events**: Set up alerts for rotation failures
2. **Test Rollback Scenarios**: Regularly test rollback procedures
3. **Backup Strategy**: Ensure reliable backup mechanisms
4. **Performance Monitoring**: Track rotation performance metrics
5. **Security Auditing**: Regular audit of rotation logs

### Key Management Strategy

1. **Regular Rotation**: Rotate keys according to security policies
2. **Algorithm Updates**: Plan migration to stronger algorithms
3. **Key Purging**: Securely delete old key versions
4. **Access Control**: Limit rotation permissions to authorized users
5. **Documentation**: Maintain rotation procedures and runbooks

## Troubleshooting

### Common Issues

1. **Rotation Timeout**: Increase timeout limits or investigate performance
2. **Rollback Failure**: Verify backup key integrity
3. **Concurrent Access**: Check for stuck locks or long-running operations
4. **Validation Errors**: Verify key format and metadata consistency

### Debug Information

Enable debug logging to troubleshoot issues:

```rust
// In your application setup
env_logger::init();

// Rotation will now log detailed information
key_manager.rotate_key_with_zero_downtime(&key_id, algorithm.as_ref()).await?;
```

### Recovery Procedures

1. **Manual Rollback**: Use `rollback_key_transition()` manually
2. **Key Restoration**: Restore from secure backups
3. **System Restart**: Clear stuck locks with service restart
4. **Emergency Procedures**: Follow your organization's incident response

## Future Enhancements

### Planned Features

1. **Distributed Rotation**: Coordination across cluster nodes
2. **Automated Policies**: AI-driven rotation scheduling
3. **Enhanced Monitoring**: Real-time rotation dashboards
4. **Cross-Region Sync**: Multi-region key rotation
5. **Quantum-Resistant Algorithms**: Migration to post-quantum cryptography

### Integration Opportunities

1. **External KMS**: Integration with cloud key management services
2. **Secret Management**: Coordinated rotation of secrets and keys
3. **Certificate Management**: Automated certificate rotation
4. **Compliance Automation**: Automated compliance reporting

## Conclusion

Zero-Downtime Key Rotation is a critical feature for production systems that require both high availability and strong security. The implementation provides a robust, well-tested solution that handles edge cases, provides comprehensive logging, and ensures system reliability during key rotation operations.

The feature is production-ready and has been extensively tested for various scenarios including concurrent operations, failure conditions, and performance under load.
