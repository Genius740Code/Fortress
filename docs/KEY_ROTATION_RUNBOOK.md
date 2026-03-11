# Key Rotation Runbook

This guide provides step-by-step procedures for rotating encryption keys with zero downtime.

## 🚨 Current Status: Experimental

**⚠️ Key rotation tools are experimental and not recommended for production use until v1.0**

## Overview

Fortress supports automatic key rotation without service interruption. This runbook covers the complete rotation process including planning, execution, verification, and rollback procedures.

## Prerequisites

### System Requirements
- Fortress server version 0.1.0+
- Administrative access to Fortress
- Backup of current encryption keys
- Monitoring tools installed

### Permissions Required
- Database administration rights
- Key management permissions
- Audit log access

## Planning Phase

### 1. Assess Current Configuration

```bash
# Check current key status
fortress key list --detailed

# Review key rotation settings
fortress config get key_rotation.interval
fortress config get key_rotation.algorithm

# Check database encryption status
fortress db status --show-keys
```

### 2. Schedule Maintenance Window

**Recommended Timing**:
- **Low traffic periods** (2-4 AM local time)
- **Weekend maintenance** for critical systems
- **30-60 minutes** for large databases

### 3. Prepare Rollback Plan

```bash
# Export current keys for backup
fortress key export --backup --file keys_backup_$(date +%Y%m%d).json

# Verify backup integrity
fortress key verify --file keys_backup_$(date +%Y%m%d).json
```

## Rotation Procedures

### Option 1: Automatic Rotation (Recommended)

```bash
# Start automatic rotation
fortress key rotate \
  --database myapp_db \
  --automatic \
  --new-algorithm aegis256 \
  --batch-size 1000 \
  --progress

# Monitor progress
fortress key rotation-status --database myapp_db --watch
```

### Option 2: Manual Rotation

#### Step 1: Generate New Key

```bash
# Create new encryption key
fortress key create \
  --algorithm aegis256 \
  --purpose rotation \
  --database myapp_db \
  --description "Key rotation $(date)"

# Note the new key ID
NEW_KEY_ID=$(fortress key list --latest --format json | jq -r '.id')
```

#### Step 2: Test New Key

```bash
# Test encryption/decryption with new key
fortress key test \
  --key-id $NEW_KEY_ID \
  --sample-data "test rotation data"

# Verify test results
echo $?
```

#### Step 3: Gradual Migration

```bash
# Start gradual data re-encryption
fortress migrate-keys \
  --database myapp_db \
  --from-key current \
  --to-key $NEW_KEY_ID \
  --batch-size 500 \
  --dry-run  # First, test without changes

# Execute actual migration
fortress migrate-keys \
  --database myapp_db \
  --from-key current \
  --to-key $NEW_KEY_ID \
  --batch-size 500 \
  --progress
```

#### Step 4: Switch Active Key

```bash
# Switch to new key for new data
fortress key activate \
  --database myapp_db \
  --key-id $NEW_KEY_ID

# Verify key switch
fortress key list --database myapp_db --active
```

## Monitoring During Rotation

### Key Metrics to Watch

```bash
# Monitor encryption performance
fortress metrics --database myapp_db --watch

# Check rotation progress
fortress key rotation-status \
  --database myapp_db \
  --detailed

# Monitor system resources
fortress system status --resources
```

### Alert Thresholds

| Metric | Warning | Critical | Action |
|---------|---------|----------|--------|
| Encryption latency | >100ms | >500ms | Pause rotation |
| Memory usage | >80% | >95% | Reduce batch size |
| Error rate | >1% | >5% | Rollback |
| Rotation progress | <10%/hour | <5%/hour | Increase batch size |

## Verification Phase

### 1. Data Integrity Checks

```bash
# Verify all data re-encrypted
fortress verify \
  --database myapp_db \
  --check-encryption \
  --comprehensive

# Sample data verification
fortress query \
  --database myapp_db \
  --table users \
  --limit 10 \
  --verify-encryption
```

### 2. Application Testing

```python
# Test application functionality
from fortress_client import FortressClient

client = FortressClient('http://localhost:8080')

# Test data operations
test_data = {
    'name': 'rotation_test',
    'email': 'test@example.com',
    'sensitive_data': 'test encryption after rotation'
}

# Insert test data
result = client.insert_data('myapp_db', 'users', test_data)

# Retrieve and verify
retrieved = client.query_data('myapp_db', 'users', where="name='rotation_test'")
assert retrieved[0]['sensitive_data'] == test_data['sensitive_data']
print("✅ Post-rotation encryption working correctly")
```

### 3. Performance Validation

```bash
# Benchmark encryption performance
fortress benchmark \
  --database myapp_db \
  --algorithm aegis256 \
  --duration 60s

# Compare with baseline
fortress benchmark compare \
  --baseline baseline_before_rotation.json \
  --current current_after_rotation.json
```

## Rollback Procedures

### When to Rollback

- **Encryption errors** > 5% during rotation
- **Application failures** after key switch
- **Performance degradation** > 50%
- **Data corruption** detected

### Rollback Steps

#### 1. Stop Rotation

```bash
# Immediately stop any ongoing rotation
fortress key rotation-stop --database myapp_db

# Confirm rotation stopped
fortress key rotation-status --database myapp_db
```

#### 2: Restore Previous Key

```bash
# Reactivate previous key
fortress key activate \
  --database myapp_db \
  --key-id previous_key_id

# Verify key restoration
fortress key list --database myapp_db --active
```

#### 3. Verify Data Access

```bash
# Test data access with old key
fortress query \
  --database myapp_db \
  --table users \
  --limit 5

# Verify encryption/decryption works
fortress verify \
  --database myapp_db \
  --sample-size 1000
```

#### 4. Investigate Issues

```bash
# Review rotation logs
fortress logs \
  --database myapp_db \
  --component key_rotation \
  --since "1 hour ago"

# Check error patterns
fortress errors \
  --database myapp_db \
  --recent
```

## Post-Rotation Tasks

### 1. Update Documentation

```bash
# Document key rotation
fortress key rotation-document \
  --database myapp_db \
  --output key_rotation_report_$(date +%Y%m%d).md

# Update key inventory
fortress key inventory --update --database myapp_db
```

### 2. Clean Up

```bash
# Archive old keys (after verification period)
fortress key archive \
  --key-id old_key_id \
  --retention 90d

# Clean up temporary files
fortress cleanup --rotation-temp-files
```

### 3. Update Monitoring

```bash
# Set up key rotation monitoring
fortress monitor create \
  --name key_rotation_health \
  --database myapp_db \
  --alert-on encryption_failures,performance_degradation

# Test monitoring
fortress monitor test --name key_rotation_health
```

## Troubleshooting

### Common Issues

#### Rotation Stuck Mid-Process

**Symptoms**:
- Progress bar stuck at same percentage
- No error messages
- Normal system operation continues

**Solutions**:
```bash
# Check rotation status in detail
fortress key rotation-status --database myapp_db --verbose

# Resume rotation manually
fortress key rotation-resume --database myapp_db

# If still stuck, restart with smaller batch size
fortress key rotate \
  --database myapp_db \
  --batch-size 100 \
  --resume-from checkpoint
```

#### Performance Degradation

**Symptoms**:
- Query latency increased significantly
- High CPU/memory usage
- Application timeouts

**Solutions**:
```bash
# Reduce batch size immediately
fortress key rotation-adjust \
  --database myapp_db \
  --batch-size 100

# Pause rotation temporarily
fortress key rotation-pause --database myapp_db

# Monitor system recovery
fortress system status --watch
```

#### Data Access Failures

**Symptoms**:
- Applications cannot read data
- Encryption/decryption errors
- Authentication failures

**Solutions**:
```bash
# Verify key status
fortress key list --database myapp_db --active

# Test data access manually
fortress query --database myapp_db --table users --limit 1

# If needed, rollback immediately
fortress key rollback --database myapp_db --to previous
```

## Best Practices

### Before Rotation
1. **Test thoroughly** in staging environment
2. **Backup all keys** and configurations
3. **Schedule during low traffic** periods
4. **Prepare rollback plan** with tested procedures

### During Rotation
1. **Monitor continuously** with automated alerts
2. **Use small batch sizes** for large databases
3. **Pause on errors** rather than continuing
4. **Communicate status** to application teams

### After Rotation
1. **Verify thoroughly** before considering complete
2. **Document everything** for future reference
3. **Monitor performance** for extended period
4. **Archive old keys** securely

## Security Considerations

### Key Protection
- **Never store keys** in application code
- **Use secure key storage** (HSM recommended)
- **Limit key access** to authorized personnel
- **Rotate keys regularly** (every 90-180 days)

### Audit Trail
- **Log all rotation** activities
- **Monitor key access** patterns
- **Review audit logs** regularly
- **Report suspicious activities** immediately

---

## 🆘 Help and Support

- **Issues**: [GitHub Issues](https://github.com/Genius740Code/Fortress/issues)
- **Documentation**: [Fortress Docs](https://docs.fortress-db.com)
- **Community**: [Discussions](https://github.com/Genius740Code/Fortress/discussions)

**Note**: Key rotation tools are experimental. Please test thoroughly before production use.
