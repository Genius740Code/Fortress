# Configuration Reference

## Overview

This document provides a comprehensive reference for all Fortress configuration options, including environment variables, configuration files, and command-line parameters.

## Configuration Sources

Fortress loads configuration from multiple sources in order of precedence:

1. **Command Line Arguments** (highest precedence)
2. **Environment Variables**
3. **Configuration Files** (TOML, YAML, JSON)
4. **Default Values** (lowest precedence)

### Configuration File Locations

```
/opt/fortress/fortress.toml          # Default system location
~/.fortress/fortress.toml           # User home directory
./fortress.toml                      # Current working directory
/etc/fortress/fortress.toml          # System-wide configuration
```

## Server Configuration

### Basic Server Settings

```toml
[server]
# Server listening address
host = "0.0.0.0"

# Server port
port = 8080

# Number of worker threads
workers = 4

# Request timeout
request_timeout = "30s"

# Keep-alive timeout
keep_alive_timeout = "30s"

# Read timeout
read_timeout = "30s"

# Write timeout
write_timeout = "30s"

# Maximum request size (MB)
max_request_size = 100

# Maximum connections
max_connections = 10000

# Enable graceful shutdown
graceful_shutdown = true

# Graceful shutdown timeout
graceful_shutdown_timeout = "30s"
```

### Environment Variables

```bash
# Server configuration
export FORTRESS_HOST=0.0.0.0
export FORTRESS_PORT=8080
export FORTRESS_WORKERS=4
export FORTRESS_REQUEST_TIMEOUT=30s
export FORTRESS_MAX_CONNECTIONS=10000
```

### Command Line Arguments

```bash
fortress server \
  --host 0.0.0.0 \
  --port 8080 \
  --workers 4 \
  --max-connections 10000
```

## Database Configuration

### Storage Settings

```toml
[database]
# Database storage path
path = "/var/lib/fortress/data"

# Default encryption algorithm
default_algorithm = "aegis256"

# Enable automatic backups
backup_enabled = true

# Backup interval
backup_interval = "6h"

# Backup retention period (days)
backup_retention_days = 30

# Enable compression
compression_enabled = true

# Compression algorithm
compression_algorithm = "lz4"

# Database cache size (MB)
cache_size = 512

# Maximum database size (GB)
max_database_size = 100

# Enable WAL mode
wal_enabled = true

# WAL checkpoint interval
wal_checkpoint_interval = "15m"
```

### Connection Pool Settings

```toml
[database.pool]
# Maximum connections
max_connections = 100

# Minimum connections
min_connections = 10

# Connection timeout
connection_timeout = "30s"

# Idle timeout
idle_timeout = "300s"

# Maximum connection lifetime
max_lifetime = "3600s"

# Connection validation
validate_connections = true

# Validation query
validation_query = "SELECT 1"
```

### Environment Variables

```bash
# Database configuration
export FORTRESS_DATABASE_PATH=/var/lib/fortress/data
export FORTRESS_DEFAULT_ALGORITHM=aegis256
export FORTRESS_BACKUP_ENABLED=true
export FORTRESS_BACKUP_INTERVAL=6h
export FORTRESS_CACHE_SIZE=512
export FORTRESS_MAX_CONNECTIONS=100
```

## Encryption Configuration

### Key Management

```toml
[encryption]
# Default encryption algorithm
default_algorithm = "aegis256"

# Enable automatic key rotation
auto_rotation = true

# Key rotation interval
key_rotation_interval = "24h"

# Key derivation algorithm
key_derivation = "PBKDF2"

# Key derivation iterations
key_derivation_iterations = 100000

# Salt length (bytes)
salt_length = 32

# IV length (bytes)
iv_length = 16

# Enable key wrapping
key_wrapping = true

# Key wrapping algorithm
key_wrapping_algorithm = "aes256-gcm"
```

### HSM Configuration

```toml
[encryption.hsm]
# Enable HSM integration
enabled = false

# HSM provider (aws-cloudhsm, pkcs11, azure, gcp)
provider = "aws-cloudhsm"

# HSM configuration file
config_file = "/etc/fortress/hsm.conf"

# Connection pool size
pool_size = 10

# Connection timeout
connection_timeout = "30s"

# Operation timeout
operation_timeout = "60s"

# Enable connection pooling
pooling_enabled = true

# Health check interval
health_check_interval = "60s"
```

#### AWS CloudHSM Configuration

```toml
[encryption.hsm.aws]
# HSM configuration
hsm_config_file = "/opt/cloudhsm/etc/cloudhsm_client.cfg"

# User PIN
user_pin = "${HSM_USER_PIN}"

# Key label prefix
key_label_prefix = "fortress-"

# Enable connection pooling
pooling_enabled = true

# Pool size
pool_size = 10
```

#### PKCS#11 Configuration

```toml
[encryption.hsm.pkcs11]
# PKCS#11 library path
library_path = "/usr/lib/libpkcs11.so"

# Token label
token_label = "FortressHSM"

# Security Officer PIN
so_pin = "${PKCS11_SO_PIN}"

# User PIN
user_pin = "${PKCS11_USER_PIN}"

# Session timeout
session_timeout = "1800s"

# Enable failed attempt tracking
failed_attempt_tracking = true

# Maximum failed attempts
max_failed_attempts = 5

# Lockout duration
lockout_duration = "900s"
```

### Environment Variables

```bash
# Encryption configuration
export FORTRESS_DEFAULT_ALGORITHM=aegis256
export FORTRESS_AUTO_ROTATION=true
export FORTRESS_KEY_ROTATION_INTERVAL=24h
export FORTRESS_HSM_ENABLED=false
export FORTRESS_HSM_PROVIDER=aws-cloudhsm
export FORTRESS_HSM_POOL_SIZE=10
```

## Security Configuration

### Authentication

```toml
[security.authentication]
# Enable authentication
enabled = true

# JWT secret
jwt_secret = "${JWT_SECRET}"

# Token expiry
token_expiry = "24h"

# Refresh token expiry
refresh_token_expiry = "168h" # 7 days

# Issuer
issuer = "fortress"

# Audience
audience = "fortress-users"

# Enable token refresh
refresh_enabled = true

# Enable device fingerprinting
device_fingerprinting = true

# Enable multi-factor authentication
mfa_enabled = false

# MFA issuer
mfa_issuer = "Fortress"
```

### Authorization

```toml
[security.authorization]
# Enable role-based access control
rbac_enabled = true

# Default role
default_role = "user"

# Role hierarchy file
role_hierarchy_file = "/etc/fortress/roles.yaml"

# Policy file
policy_file = "/etc/fortress/policies.yaml"

# Enable attribute-based access control
abac_enabled = true

# Cache authorization results
cache_enabled = true

# Cache TTL
cache_ttl = "300s"
```

### TLS Configuration

```toml
[security.tls]
# Enable TLS
enabled = true

# Certificate file
cert_file = "/etc/ssl/certs/fortress.crt"

# Private key file
key_file = "/etc/ssl/private/fortress.key"

# CA certificate file
ca_file = "/etc/ssl/certs/ca.crt"

# Minimum TLS version
min_version = "1.2"

# Cipher suites
cipher_suites = [
  "TLS_AES_256_GCM_SHA384",
  "TLS_CHACHA20_POLY1305_SHA256",
  "TLS_AES_128_GCM_SHA256"
]

# Enable client certificate verification
client_cert_verification = false

# Enable OCSP stapling
ocsp_stapling = true
```

### Rate Limiting

```toml
[security.rate_limiting]
# Enable rate limiting
enabled = true

# Requests per minute
requests_per_minute = 1000

# Burst size
burst_size = 100

# Enable IP-based limiting
ip_based = true

# Enable user-based limiting
user_based = true

# Enable endpoint-based limiting
endpoint_based = true

# Whitelist IPs
whitelist_ips = ["127.0.0.1", "10.0.0.0/8"]

# Blacklist IPs
blacklist_ips = []
```

### Environment Variables

```bash
# Security configuration
export FORTRESS_AUTH_ENABLED=true
export FORTRESS_JWT_SECRET="your-super-secret-jwt-key"
export FORTRESS_TOKEN_EXPIRY=24h
export FORTRESS_TLS_ENABLED=true
export FORTRESS_CERT_FILE=/etc/ssl/certs/fortress.crt
export FORTRESS_KEY_FILE=/etc/ssl/private/fortress.key
export FORTRESS_RATE_LIMIT_ENABLED=true
export FORTRESS_RATE_LIMIT_RPM=1000
```

## Logging Configuration

### Basic Logging

```toml
[logging]
# Log level (trace, debug, info, warn, error)
level = "info"

# Log format (text, json)
format = "json"

# Log file
file = "/var/log/fortress/fortress.log"

# Maximum file size (MB)
max_size = "100MB"

# Maximum number of files
max_files = 10

# Enable log rotation
rotate = true

# Enable console logging
console = true

# Enable syslog
syslog = false

# Syslog facility
syslog_facility = "daemon"
```

### Structured Logging

```toml
[logging.fields]
# Service name
service = "fortress"

# Environment
environment = "production"

# Version
version = "0.1.0"

# Instance ID
instance_id = "${INSTANCE_ID}"

# Region
region = "us-west-2"

# Cluster
cluster = "main"
```

### Log Outputs

```toml
[logging.outputs]
# Enable file output
file = true

# Enable console output
console = true

# Enable syslog output
syslog = false

# Enable Elasticsearch output
elasticsearch = false

# Enable Loki output
loki = false
```

#### Elasticsearch Configuration

```toml
[logging.elasticsearch]
enabled = false
hosts = ["http://elasticsearch:9200"]
index_name = "fortress"
type_name = "_doc"
username = "elastic"
password = "${ELASTIC_PASSWORD}"
max_retries = 3
bulk_size = 1000
flush_interval = "5s"
```

#### Loki Configuration

```toml
[logging.loki]
enabled = false
url = "http://loki:3100/loki/api/v1/push"
tenant_id = "fortress"
labels = {job = "fortress", env = "production"}
batch_size = 1000
batch_wait = "5s"
max_retries = 3
```

### Environment Variables

```bash
# Logging configuration
export FORTRESS_LOG_LEVEL=info
export FORTRESS_LOG_FORMAT=json
export FORTRESS_LOG_FILE=/var/log/fortress/fortress.log
export FORTRESS_LOG_MAX_SIZE=100MB
export FORTRESS_LOG_MAX_FILES=10
export FORTRESS_LOG_SERVICE=fortress
export FORTRESS_LOG_ENVIRONMENT=production
```

## Metrics Configuration

### Prometheus Metrics

```toml
[metrics]
# Enable metrics
enabled = true

# Metrics port
port = 9090

# Metrics path
path = "/metrics"

# Metrics namespace
namespace = "fortress"

# Metrics subsystem
subsystem = "server"

# Enable histogram metrics
histograms = true

# Enable gauge metrics
gauges = true

# Enable counter metrics
counters = true

# Metrics collection interval
interval = "15s"
```

### Custom Metrics

```toml
[metrics.custom]
# Enable business metrics
business_metrics = true

# Enable security metrics
security_metrics = true

# Enable performance metrics
performance_metrics = true

# Enable system metrics
system_metrics = true
```

### Environment Variables

```bash
# Metrics configuration
export FORTRESS_METRICS_ENABLED=true
export FORTRESS_METRICS_PORT=9090
export FORTRESS_METRICS_PATH=/metrics
export FORTRESS_METRICS_NAMESPACE=fortress
export FORTRESS_METRICS_INTERVAL=15s
```

## Backup Configuration

### Backup Settings

```toml
[backup]
# Enable automatic backups
enabled = true

# Backup schedule (cron format)
schedule = "0 2 * * *"  # Daily at 2 AM

# Backup type (full, incremental, differential)
type = "full"

# Compression enabled
compression = true

# Compression algorithm
compression_algorithm = "lz4"

# Encryption enabled
encryption = true

# Encryption algorithm
encryption_algorithm = "aes256-gcm"

# Retention period (days)
retention_days = 30

# Verify backup after creation
verify_after_backup = true
```

### Storage Configuration

```toml
[backup.storage]
# Storage type (local, s3, azure, gcs)
type = "s3"

# Local storage path (for local type)
path = "/opt/fortress/backups"

# S3 configuration
bucket = "fortress-backups"
region = "us-west-2"
access_key_id = "${AWS_ACCESS_KEY_ID}"
secret_access_key = "${AWS_SECRET_ACCESS_KEY}"
prefix = "fortress/"
storage_class = "STANDARD_IA"

# Azure configuration
account_name = "${AZURE_STORAGE_ACCOUNT}"
container = "fortress-backups"
access_key = "${AZURE_STORAGE_ACCESS_KEY}"

# GCS configuration
bucket = "fortress-backups"
credentials_file = "/path/to/service-account.json"
storage_class = "NEARLINE"
```

### Environment Variables

```bash
# Backup configuration
export FORTRESS_BACKUP_ENABLED=true
export FORTRESS_BACKUP_SCHEDULE="0 2 * * *"
export FORTRESS_BACKUP_TYPE=full
export FORTRESS_BACKUP_COMPRESSION=true
export FORTRESS_BACKUP_ENCRYPTION=true
export FORTRESS_BACKUP_RETENTION_DAYS=30
export FORTRESS_BACKUP_STORAGE_TYPE=s3
export FORTRESS_BACKUP_BUCKET=fortress-backups
```

## Clustering Configuration

### Raft Configuration

```toml
[clustering.raft]
# Enable clustering
enabled = false

# Node ID
node_id = "node-1"

# Data directory
data_dir = "/var/lib/fortress/raft"

# Listen address
listen_address = "0.0.0.0:8082"

# Advertise address
advertise_address = "node-1:8082"

# Election timeout
election_timeout = "5s"

# Heartbeat interval
heartbeat_interval = "1s"

# Snapshot interval
snapshot_interval = "1h"

# Snapshot threshold
snapshot_threshold = 1000

# Enable logging
log_level = "info"
```

### Cluster Members

```toml
[clustering.members]
# Static cluster members
members = [
  "node-1:8082",
  "node-2:8082",
  "node-3:8082"
]

# Enable auto-discovery
auto_discovery = false

# Discovery service
discovery_service = "consul"

# Discovery service address
discovery_address = "consul:8500"
```

### Environment Variables

```bash
# Clustering configuration
export FORTRESS_CLUSTERING_ENABLED=false
export FORTRESS_NODE_ID=node-1
export FORTRESS_LISTEN_ADDRESS=0.0.0.0:8082
export FORTRESS_ADVERTISE_ADDRESS=node-1:8082
export FORTRESS_ELECTION_TIMEOUT=5s
export FORTRESS_HEARTBEAT_INTERVAL=1s
```

## Performance Configuration

### Memory Management

```toml
[performance.memory]
# Maximum heap size (GB)
max_heap_size = 4

# GC threshold (percentage)
gc_threshold = 80

# Buffer pool size (MB)
buffer_pool_size = 100

# Enable memory profiling
profiling = false

# Profiling interval
profiling_interval = "30s"
```

### Connection Management

```toml
[performance.connections]
# Maximum concurrent connections
max_concurrent = 10000

# Connection timeout
timeout = "30s"

# Keep-alive timeout
keep_alive = "30s"

# Connection queue size
queue_size = 1000

# Enable connection pooling
pooling = true

# Pool size
pool_size = 100
```

### Caching

```toml
[performance.cache]
# Enable caching
enabled = true

# Cache type (memory, redis, memcached)
type = "memory"

# Memory cache size (MB)
memory_size = 512

# Redis configuration
redis_url = "redis://localhost:6379"
redis_max_connections = 50

# Cache TTL
default_ttl = "1h"

# Enable cache warming
warming_enabled = true

# Warming interval
warming_interval = "10m"
```

### Environment Variables

```bash
# Performance configuration
export FORTRESS_MAX_HEAP_SIZE=4
export FORTRESS_GC_THRESHOLD=80
export FORTRESS_BUFFER_POOL_SIZE=100
export FORTRESS_MAX_CONCURRENT=10000
export FORTRESS_CACHE_ENABLED=true
export FORTRESS_CACHE_TYPE=memory
export FORTRESS_CACHE_SIZE=512
```

## Compliance Configuration

### GDPR Configuration

```toml
[compliance.gdpr]
# Enable GDPR features (NOT YET IMPLEMENTED)
enabled = false

# Data retention period (days)
data_retention_days = 2555

# Enable consent management
consent_management = false

# Consent storage
consent_storage = "database"

# Enable right to be forgotten
right_to_be_forgotten = false

# Data protection officer
dpo_email = "dpo@example.com"

# Privacy policy URL
privacy_policy_url = "https://example.com/privacy"
```

### HIPAA Configuration

```toml
[compliance.hipaa]
# Enable HIPAA features (NOT YET IMPLEMENTED)
enabled = false

# Audit retention period (years)
audit_retention_years = 6

# Enable strict access controls
strict_access_controls = false

# Minimum password length
min_password_length = 8

# Password complexity
password_complexity = true

# Session timeout (minutes)
session_timeout = 15

# Enable audit logging
audit_logging = true
```

### PCI-DSS Configuration

```toml
[compliance.pci_dss]
# Enable PCI-DSS features (NOT YET IMPLEMENTED)
enabled = false

# Encryption requirements
encryption_algorithm = "aes256gcm"
key_rotation_days = 90

# Enable tokenization
tokenization_enabled = false

# Tokenization algorithm
tokenization_algorithm = "FPE"

# Audit requirements
audit_all_access = true
audit_retention_years = 1

# Network security
network_segmentation = true
firewall_configured = true
```

### Environment Variables

```bash
# Compliance configuration (NOT YET IMPLEMENTED)
export FORTRESS_GDPR_ENABLED=false
export FORTRESS_GDPR_RETENTION_DAYS=2555
export FORTRESS_HIPAA_ENABLED=false
export FORTRESS_HIPAA_AUDIT_RETENTION_YEARS=6
export FORTRESS_PCI_DSS_ENABLED=false
export FORTRESS_PCI_DSS_KEY_ROTATION_DAYS=90
```

## Plugin Configuration

### Plugin System

```toml
[plugins]
# Enable plugin system
enabled = true

# Plugin directory
plugin_dir = "/opt/fortress/plugins"

# Plugin configuration file
plugin_config = "/etc/fortress/plugins.yaml"

# Enable hot reloading
hot_reload = true

# Plugin timeout
plugin_timeout = "30s"

# Enable plugin sandboxing
sandbox = true
```

### Plugin Examples

```toml
# Authentication plugin
[[plugins.auth]]
name = "ldap-auth"
path = "/opt/fortress/plugins/ldap-auth.so"
enabled = true
config_file = "/etc/fortress/ldap-auth.yaml"

# Storage plugin
[[plugins.storage]]
name = "s3-storage"
path = "/opt/fortress/plugins/s3-storage.so"
enabled = true
config_file = "/etc/fortress/s3-storage.yaml"

# Encryption plugin
[[plugins.encryption]]
name = "custom-kms"
path = "/opt/fortress/plugins/custom-kms.so"
enabled = true
config_file = "/etc/fortress/custom-kms.yaml"
```

### Environment Variables

```bash
# Plugin configuration
export FORTRESS_PLUGINS_ENABLED=true
export FORTRESS_PLUGIN_DIR=/opt/fortress/plugins
export FORTRESS_PLUGIN_CONFIG=/etc/fortress/plugins.yaml
export FORTRESS_PLUGIN_HOT_RELOAD=true
export FORTRESS_PLUGIN_TIMEOUT=30s
```

## Health Check Configuration

### Health Monitoring

```toml
[health]
# Enable health checks
enabled = true

# Health check port
port = 8081

# Health check path
path = "/health"

# Detailed health check path
detailed_path = "/health/detailed"

# Readiness check path
readiness_path = "/ready"

# Liveness check path
liveness_path = "/live"

# Check interval
check_interval = "30s"

# Check timeout
check_timeout = "10s"
```

### Health Checks

```toml
[health.checks]
# Enable database health check
database = true

# Enable encryption health check
encryption = true

# Enable storage health check
storage = true

# Enable memory health check
memory = true

# Enable CPU health check
cpu = true

# Enable disk health check
disk = true

# Enable network health check
network = true
```

### Health Thresholds

```toml
[health.thresholds]
# Memory usage threshold (percentage)
memory_usage_percent = 80

# CPU usage threshold (percentage)
cpu_usage_percent = 80

# Disk usage threshold (percentage)
disk_usage_percent = 85

# Response time threshold (milliseconds)
response_time_ms = 1000

# Connection threshold
connection_count = 1000
```

### Environment Variables

```bash
# Health check configuration
export FORTRESS_HEALTH_ENABLED=true
export FORTRESS_HEALTH_PORT=8081
export FORTRESS_HEALTH_PATH=/health
export FORTRESS_HEALTH_CHECK_INTERVAL=30s
export FORTRESS_HEALTH_CHECK_TIMEOUT=10s
export FORTRESS_HEALTH_MEMORY_THRESHOLD=80
export FORTRESS_HEALTH_CPU_THRESHOLD=80
```

## Configuration Validation

### Validation Commands

```bash
# Validate configuration file
fortress config validate --config /etc/fortress/fortress.toml

# Validate specific section
fortress config validate --section database --config /etc/fortress/fortress.toml

# Show configuration
fortress config show --config /etc/fortress/fortress.toml

# Show effective configuration
fortress config show --effective
```

### Configuration Schema

```bash
# Generate configuration schema
fortress config schema --format json > fortress-schema.json

# Validate against schema
fortress config validate --schema fortress-schema.json --config /etc/fortress/fortress.toml
```

## Environment-Specific Configuration

### Development Configuration

```toml
# fortress-dev.toml
[server]
host = "127.0.0.1"
port = 8080
workers = 2

[logging]
level = "debug"
format = "text"
console = true

[database]
path = "./dev-data"
default_algorithm = "aegis256"
backup_enabled = false

[security.authentication]
enabled = false
token_expiry = "1h"

[metrics]
enabled = true
port = 9090
```

### Staging Configuration

```toml
# fortress-staging.toml
[server]
host = "0.0.0.0"
port = 8080
workers = 4

[logging]
level = "info"
format = "json"
file = "/var/log/fortress/staging.log"

[database]
path = "/var/lib/fortress/staging"
default_algorithm = "aegis256"
backup_enabled = true
backup_interval = "2h"

[security.authentication]
enabled = true
token_expiry = "8h"

[metrics]
enabled = true
port = 9090
```

### Production Configuration

```toml
# fortress-prod.toml
[server]
host = "0.0.0.0"
port = 8080
workers = 8
max_connections = 10000

[logging]
level = "warn"
format = "json"
file = "/var/log/fortress/production.log"
max_size = "500MB"
max_files = 20

[database]
path = "/var/lib/fortress/production"
default_algorithm = "aegis256"
backup_enabled = true
backup_interval = "1h"
backup_retention_days = 90

[security.authentication]
enabled = true
token_expiry = "24h"
mfa_enabled = true

[security.tls]
enabled = true
cert_file = "/etc/ssl/certs/fortress.crt"
key_file = "/etc/ssl/private/fortress.key"

[metrics]
enabled = true
port = 9090

[health]
enabled = true
port = 8081
```

## Configuration Best Practices

### Security Best Practices

1. **Use Environment Variables for Secrets**
   ```toml
   # Good: Use environment variables
   jwt_secret = "${JWT_SECRET}"
   
   # Bad: Hardcode secrets
   jwt_secret = "super-secret-key"
   ```

2. **Enable TLS in Production**
   ```toml
   [security.tls]
   enabled = true
   cert_file = "/etc/ssl/certs/fortress.crt"
   key_file = "/etc/ssl/private/fortress.key"
   ```

3. **Configure Rate Limiting**
   ```toml
   [security.rate_limiting]
   enabled = true
   requests_per_minute = 1000
   burst_size = 100
   ```

### Performance Best Practices

1. **Optimize Worker Count**
   ```toml
   [server]
   workers = 4  # Number of CPU cores
   ```

2. **Enable Connection Pooling**
   ```toml
   [database.pool]
   max_connections = 100
   min_connections = 10
   ```

3. **Configure Appropriate Cache Size**
   ```toml
   [performance.cache]
   enabled = true
   memory_size = 512  # MB
   ```

### Operational Best Practices

1. **Use Structured Logging**
   ```toml
   [logging]
   format = "json"
   level = "info"
   ```

2. **Enable Health Checks**
   ```toml
   [health]
   enabled = true
   port = 8081
   ```

3. **Configure Metrics**
   ```toml
   [metrics]
   enabled = true
   port = 9090
   ```

## Troubleshooting Configuration

### Common Issues

#### Configuration File Not Found
```bash
# Check default locations
ls -la /opt/fortress/fortress.toml
ls -la ~/.fortress/fortress.toml
ls -la ./fortress.toml

# Specify config file explicitly
fortress server --config /path/to/fortress.toml
```

#### Invalid Configuration
```bash
# Validate configuration
fortress config validate --config /etc/fortress/fortress.toml

# Check syntax
toml-lint /etc/fortress/fortress.toml
```

#### Environment Variable Issues
```bash
# Check environment variables
env | grep FORTRESS

# Test configuration
fortress config test --config /etc/fortress/fortress.toml
```

### Debug Configuration

```bash
# Show effective configuration
fortress config show --effective

# Show configuration with defaults
fortress config show --with-defaults

# Debug configuration loading
fortress server --debug --config /etc/fortress/fortress.toml
```

---

**Last Updated**: 2025-03-24  
**Version**: v0.1.0  
**Status**: Alpha - Features Under Development
