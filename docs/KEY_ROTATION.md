# Key Rotation Guide

## Overview

Key rotation is a critical security practice that involves periodically replacing encryption keys to limit the amount of data protected by any single key. Fortress provides automated, zero-downtime key rotation capabilities that maintain service availability while enhancing security.

## Key Rotation Concepts

### Why Rotate Keys?

1. **Limit Exposure**: Reduce the amount of data compromised if a key is exposed
2. **Compliance Requirements**: Meet regulatory requirements (PCI-DSS, HIPAA, GDPR)
3. **Cryptographic Best Practices**: Follow industry security standards
4. **Risk Mitigation**: Address potential cryptographic weaknesses over time

### Key Rotation Types

1. **Scheduled Rotation**: Automatic rotation based on time intervals
2. **Manual Rotation**: On-demand rotation for security incidents
3. **Emergency Rotation**: Immediate rotation for compromised keys
4. **Algorithm Migration**: Rotation when changing encryption algorithms

## Key Lifecycle Management

### Key States

```
┌─────────────┐    Generate    ┌─────────────┐
│   Pending   │ ──────────────► │   Active    │
└─────────────┘                └─────────────┘
       │                           │
       │ Activate                   │ Rotate
       ▼                           ▼
┌─────────────┐    Rotate     ┌─────────────┐
│  Deprecated │ ◄──────────── │  Rotating   │
└─────────────┘                └─────────────┘
       │                           │
       │ Retire                     │ Complete
       ▼                           ▼
┌─────────────┐    Delete     ┌─────────────┐
│   Retired   │ ──────────────► │  Deleted   │
└─────────────┘                └─────────────┘
```

### Key Versioning

Each key rotation creates a new version while maintaining previous versions for data decryption:

```json
{
  "key_id": "encryption_key_12345",
  "current_version": 3,
  "versions": [
    {
      "version": 1,
      "algorithm": "aes256gcm",
      "created_at": "2024-01-01T00:00:00Z",
      "status": "retired",
      "data_count": 1500
    },
    {
      "version": 2,
      "algorithm": "aes256gcm", 
      "created_at": "2024-04-01T00:00:00Z",
      "status": "deprecated",
      "data_count": 3200
    },
    {
      "version": 3,
      "algorithm": "aegis256",
      "created_at": "2024-07-01T00:00:00Z",
      "status": "active",
      "data_count": 800
    }
  ]
}
```

## Zero-Downtime Rotation

### How It Works

1. **Generate New Key**: Create new encryption key version
2. **Update Metadata**: Mark new key as active for new data
3. **Background Re-encryption**: Gradually re-encrypt existing data
4. **Verify Completion**: Ensure all data is re-encrypted
5. **Retire Old Key**: Mark old key as retired

### Rotation Process

```bash
# Start key rotation (zero-downtime)
fortress key rotate --database myapp_db --background

# Monitor rotation progress
fortress key rotation-status --database myapp_db

# View rotation details
fortress key rotation-details --key-id key_12345
```

### Re-encryption Strategy

#### Batch Processing
```toml
[key_rotation]
batch_size = 1000
concurrent_batches = 4
processing_interval = "1s"
retry_attempts = 3
retry_delay = "5s"
```

#### Priority-Based Processing
```json
{
  "priority_rules": [
    {
      "condition": "data.sensitivity = 'high'",
      "priority": "immediate"
    },
    {
      "condition": "data.access_frequency > 100/day",
      "priority": "high"
    },
    {
      "condition": "data.age < 30d",
      "priority": "medium"
    },
    {
      "condition": "default",
      "priority": "low"
    }
  ]
}
```

## Configuration

### Basic Rotation Setup

```toml
[key_rotation]
# Enable automatic key rotation
enabled = true

# Rotation interval (90 days default)
rotation_interval = "90d"

# Grace period before key retirement
grace_period = "7d"

# Background re-encryption
background_rotation = true

# Rotation schedule (cron format)
rotation_schedule = "0 2 * * 0"  # Every Sunday at 2 AM
```

### Advanced Configuration

```toml
[key_rotation.advanced]
# Maximum concurrent re-encryption tasks
max_concurrent_tasks = 8

# Batch size for re-encryption
batch_size = 500

# Processing delay between batches
batch_delay = "100ms"

# Retry configuration
max_retries = 3
retry_delay = "5s"
retry_backoff = "exponential"

# Resource limits
cpu_limit = "50%"
memory_limit = "2GB"
io_limit = "100MB/s"

# Notifications
notification_webhook = "https://hooks.slack.com/services/..."
notification_email = ["security@example.com"]
```

### Algorithm Migration

```toml
[key_rotation.algorithm_migration]
# Target algorithm for migration
target_algorithm = "aegis256"

# Migration strategy
migration_strategy = "gradual"

# Migration batch size
migration_batch_size = 1000

# Migration schedule
migration_schedule = "0 3 * * *"  # Daily at 3 AM

# Force migration deadline
force_migration_deadline = "2024-12-31T23:59:59Z"
```

## Key Rotation Commands

### Database-Level Rotation

```bash
# Rotate all keys for a database
fortress key rotate --database myapp_db

# Rotate with specific algorithm
fortress key rotate --database myapp_db --algorithm aegis256

# Schedule rotation for specific time
fortress key rotate --database myapp_db --schedule "2024-07-01T02:00:00Z"

# Dry run (preview changes)
fortress key rotate --database myapp_db --dry-run
```

### Key-Level Rotation

```bash
# Rotate specific key
fortress key rotate --key-id encryption_key_12345

# Rotate key with custom parameters
fortress key rotate --key-id encryption_key_12345 \
  --algorithm aegis256 \
  --key-size 256 \
  --derivation pbkdf2 \
  --iterations 100000

# Force immediate rotation (emergency)
fortress key rotate --key-id encryption_key_12345 --force
```

### Rotation Management

```bash
# List pending rotations
fortress key rotation list --status pending

# List active rotations
fortress key rotation list --status active

# List completed rotations
fortress key rotation list --status completed --last 30d

# Cancel rotation
fortress key rotation cancel --rotation-id rotation_12345

# Pause rotation
fortress key rotation pause --rotation-id rotation_12345

# Resume rotation
fortress key rotation resume --rotation-id rotation_12345
```

## Monitoring and Status

### Rotation Status

```bash
# Check overall rotation status
fortress key rotation-status

# Check database rotation status
fortress key rotation-status --database myapp_db

# Check specific key rotation
fortress key rotation-status --key-id encryption_key_12345

# Detailed rotation information
fortress key rotation-details --rotation-id rotation_12345
```

### Status Output

```json
{
  "rotation_id": "rotation_12345",
  "database": "myapp_db",
  "key_id": "encryption_key_12345",
  "status": "in_progress",
  "progress": {
    "total_records": 10000,
    "processed_records": 7500,
    "failed_records": 5,
    "percentage_complete": 75.0
  },
  "timing": {
    "started_at": "2024-07-01T02:00:00Z",
    "estimated_completion": "2024-07-01T02:15:00Z",
    "average_processing_rate": "1000 records/min"
  },
  "resources": {
    "cpu_usage": "25%",
    "memory_usage": "1.2GB",
    "io_rate": "50MB/s"
  }
}
```

### Progress Monitoring

```bash
# Real-time progress monitoring
fortress key rotation watch --rotation-id rotation_12345

# Progress summary
fortress key rotation progress --rotation-id rotation_12345 --format table

# Export progress report
fortress key rotation export --rotation-id rotation_12345 --format csv --output rotation_report.csv
```

## Key Rotation Policies

### Policy Definition

```json
{
  "policy": {
    "name": "enterprise_rotation_policy",
    "description": "Enterprise-grade key rotation policy",
    "rules": [
      {
        "name": "high_sensitivity_data",
        "condition": "data.sensitivity = 'high'",
        "rotation_interval": "30d",
        "grace_period": "3d",
        "priority": "high"
      },
      {
        "name": "medium_sensitivity_data",
        "condition": "data.sensitivity = 'medium'",
        "rotation_interval": "90d",
        "grace_period": "7d",
        "priority": "medium"
      },
      {
        "name": "low_sensitivity_data",
        "condition": "data.sensitivity = 'low'",
        "rotation_interval": "180d",
        "grace_period": "14d",
        "priority": "low"
      },
      {
        "name": "compliance_data",
        "condition": "data.compliance_requirements = true",
        "rotation_interval": "90d",
        "grace_period": "7d",
        "priority": "high",
        "notification_required": true
      }
    ]
  }
}
```

### Policy Management

```bash
# Create rotation policy
fortress key policy create --file policy.json

# Apply policy to database
fortress key policy apply --policy enterprise_rotation_policy --database myapp_db

# List policies
fortress key policy list

# Validate policy compliance
fortress key policy validate --policy enterprise_rotation_policy --database myapp_db
```

## Compliance and Regulations

### PCI-DSS Requirements

```toml
[compliance.pci_dss]
# Key rotation every 12 months minimum
key_rotation_interval = "90d"  # More frequent than requirement

# Strong cryptography requirements
min_key_strength = 256
approved_algorithms = ["aes256gcm", "aegis256"]

# Secure key storage
key_storage = "hsm"
hsm_fips_level = "3"

# Audit requirements
audit_key_operations = true
audit_retention_years = 1
```

### HIPAA Requirements

```toml
[compliance.hipaa]
# Key rotation for protected health information
phi_rotation_interval = "60d"

# Access controls
strict_access_controls = true
multi_factor_auth_required = true

# Audit and monitoring
comprehensive_auditing = true
tamper_resistance = true

# Business continuity
backup_key_rotation = true
disaster_recovery_testing = "quarterly"
```

### GDPR Requirements

```toml
[compliance.gdpr]
# Data protection by design and default
encryption_by_default = true
pseudonymization_support = true

# Data subject rights
key_deletion_on_request = true
automated_key_expiry = true

# Accountability
comprehensive_logging = true
data_protection_officer_notification = true

# International data transfers
cross_border_key_management = true
standard_contractual_clauses = true
```

## Emergency Rotation

### Emergency Triggers

1. **Key Compromise**: Suspicion or confirmation of key exposure
2. **Security Incident**: Related security breach
3. **Vulnerability Discovery**: Cryptographic vulnerability
4. **Insider Threat**: Malicious insider activity
5. **Regulatory Requirement**: Immediate compliance need

### Emergency Rotation Process

```bash
# Emergency rotation (immediate)
fortress key rotate --key-id encryption_key_12345 --emergency

# Emergency rotation with justification
fortress key rotate --key-id encryption_key_12345 \
  --emergency \
  --reason "Key compromise detected" \
  --approval-id incident_67890

# Emergency rotation for entire database
fortress key rotate --database myapp_db \
  --emergency \
  --reason "Security incident" \
  --force
```

### Emergency Configuration

```toml
[emergency_rotation]
# Require approval for emergency rotation
approval_required = true

# Approvers (list of user IDs)
approvers = ["admin_123", "security_lead_456"]

# Justification required
justification_required = true

# Notification settings
notify_security_team = true
notify_management = true
create_incident_ticket = true

# Rate limiting
max_emergency_rotations_per_hour = 5
max_emergency_rotations_per_day = 20
```

## Key Rotation Best Practices

### Planning and Preparation

1. **Assess Data Classification**
   - Identify sensitive data types
   - Determine rotation frequency requirements
   - Document compliance requirements

2. **Performance Impact Assessment**
   - Estimate re-encryption time
   - Plan resource allocation
   - Schedule maintenance windows if needed

3. **Backup and Recovery**
   - Create system backups before rotation
   - Test backup restoration
   - Document rollback procedures

### Execution Guidelines

1. **Start Small**
   - Test with non-critical databases
   - Validate rotation process
   - Monitor system performance

2. **Monitor Progress**
   - Track rotation completion
   - Monitor error rates
   - Adjust parameters as needed

3. **Validate Results**
   - Verify data integrity
   - Test data access
   - Confirm security improvements

### Post-Rotation Activities

1. **Cleanup**
   - Remove old key versions after grace period
   - Update documentation
   - Archive rotation logs

2. **Review and Improve**
   - Analyze rotation metrics
   - Update rotation policies
   - Improve processes

## Troubleshooting

### Common Issues

#### Rotation Stuck
```bash
# Check rotation status
fortress key rotation-status --rotation-id rotation_12345

# Restart rotation
fortress key rotation restart --rotation-id rotation_12345

# Force completion (use with caution)
fortress key rotation force-complete --rotation-id rotation_12345
```

#### High Resource Usage
```bash
# Pause rotation
fortress key rotation pause --rotation-id rotation_12345

# Adjust resource limits
fortress key rotation update --rotation-id rotation_12345 --cpu-limit 25%

# Resume with adjusted settings
fortress key rotation resume --rotation-id rotation_12345
```

#### Data Access Issues
```bash
# Check key status
fortress key status --key-id encryption_key_12345

# Verify data accessibility
fortress data verify --database myapp_db --sample-size 100

# Repair data access
fortress data repair --database myapp_db --key-id encryption_key_12345
```

### Error Handling

```toml
[key_rotation.error_handling]
# Retry failed operations
auto_retry = true
max_retries = 3
retry_delay = "5s"

# Error notification
notify_on_error = true
error_webhook = "https://hooks.slack.com/services/..."

# Error escalation
escalate_threshold = 10
escalation_webhook = "https://alerts.example.com/webhook"

# Manual intervention
manual_intervention_threshold = 100
manual_intervention_email = ["ops@example.com"]
```

## Key Rotation Metrics

### Performance Metrics

```bash
# Rotation performance report
fortress key rotation metrics --rotation-id rotation_12345

# Historical performance
fortress key rotation metrics --database myapp_db --last 90d

# Comparative analysis
fortress key rotation compare --databases myapp_db,other_db --metric throughput
```

### Metrics Dashboard

```json
{
  "rotation_metrics": {
    "total_rotations": 45,
    "successful_rotations": 43,
    "failed_rotations": 2,
    "average_rotation_time": "2h 15m",
    "average_throughput": "5000 records/hour",
    "resource_efficiency": 85.5
  },
  "key_metrics": {
    "total_keys": 125,
    "active_keys": 118,
    "retired_keys": 7,
    "average_key_age": "45d",
    "oldest_key_age": "89d"
  },
  "compliance_metrics": {
    "policy_compliance_rate": 98.2,
    "regulatory_compliance": 100,
    "audit_success_rate": 99.8,
    "security_incidents": 0
  }
}
```

This comprehensive key rotation guide provides all the information needed to implement and manage secure key rotation practices in Fortress.
