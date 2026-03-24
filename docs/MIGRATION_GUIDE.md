# Fortress Migration Guide

## 🎯 Overview

This guide provides procedures for migrating between Fortress versions, upgrading configurations, and migrating data between deployments.

> **⚠️ Important**: Fortress is currently in Alpha stage. Migration procedures may change significantly between versions.

---

## 📋 Migration Planning

### Pre-Migration Checklist

- [ ] Review [Production Readiness Matrix](PRODUCTION_READINESS_MATRIX.md) for current limitations
- [ ] Create full system backup
- [ ] Test migration in staging environment
- [ ] Schedule maintenance window
- [ ] Prepare rollback plan
- [ ] Document current configuration
- [ ] Verify system requirements for new version

### Migration Types

1. **Version Upgrade**: Migrate between Fortress versions
2. **Configuration Migration**: Update configuration formats
3. **Data Migration**: Move data between deployments
4. **Platform Migration**: Move between different platforms/OS

---

## 🔄 Version Migration

### Supported Migration Paths

| From Version | To Version | Support Level | Notes |
|--------------|------------|---------------|-------|
| 0.1.0 | 0.2.0 | Supported | Breaking changes expected |
| 0.1.0 | 0.3.0 | Not Supported | Migrate to 0.2.0 first |
| 0.2.0 | 0.3.0 | Planned | Future compatibility |

### Pre-Migration Preparation

```bash
# 1. Check current version
fortress --version

# 2. Export current configuration
fortress config export --output current_config.toml

# 3. Create backup
fortress backup create --name pre-migration-backup

# 4. Verify system health
fortress health --all

# 5. Document current state
fortress info --all > pre_migration_state.txt
```

### Migration Procedure

#### Step 1: Stop Services
```bash
# Stop Fortress gracefully
fortress server stop --graceful

# Verify all processes stopped
ps aux | grep fortress

# Check no active connections
netstat -tulpn | grep :8080
```

#### Step 2: Backup Data
```bash
# Create full backup
fortress backup create --name version-migration-backup --full

# Export all data
fortress export --all --output data_export_$(date +%Y%m%d).tar.gz

# Verify backup integrity
fortress backup verify --name version-migration-backup
```

#### Step 3: Update Fortress
```bash
# Download new version
wget https://github.com/Genius740Code/Fortress/releases/latest/download/fortress-linux-amd64-latest

# Verify download
sha256sum fortress-linux-amd64-latest

# Stop old version
sudo systemctl stop fortress

# Replace binary
sudo mv fortress-linux-amd64-latest /usr/local/bin/fortress
sudo chmod +x /usr/local/bin/fortress

# Verify new version
fortress --version
```

#### Step 4: Migrate Configuration
```bash
# Check configuration compatibility
fortress config check --migrate-from 0.1.0

# Auto-migrate configuration
fortress config migrate --from 0.1.0 --to 0.2.0

# Review migrated configuration
fortress config show

# Fix any manual configuration issues
fortress config set server.host 0.0.0.0
fortress config set server.port 8080
```

#### Step 5: Start New Version
```bash
# Start Fortress with new version
fortress server start

# Verify startup
fortress status --detailed

# Check health
fortress health --all

# Verify data access
fortress data verify --sample-size 100
```

#### Step 6: Post-Migration Verification
```bash
# Test all operations
fortress test --all

# Verify encryption
fortress key test --all

# Check API functionality
curl -f http://localhost:8080/health

# Verify data integrity
fortress data verify --all
```

### Rollback Procedure

If migration fails:

```bash
# 1. Stop new version
fortress server stop

# 2. Restore previous binary
sudo mv /usr/local/bin/fortress.backup /usr/local/bin/fortress

# 3. Restore configuration
fortress config import --input current_config.toml

# 4. Restore data if needed
fortress restore --name pre-migration-backup

# 5. Start previous version
fortress server start

# 6. Verify rollback
fortress status --detailed
```

---

## ⚙️ Configuration Migration

### Configuration Format Changes

#### Version 0.1.0 to 0.2.0 Changes

**Old Format (0.1.0):**
```toml
[server]
host = "localhost"
port = 8080

[database]
path = "/var/lib/fortress/data"

[encryption]
algorithm = "aes256"
```

**New Format (0.2.0):**
```toml
[server]
host = "0.0.0.0"
port = 8080
workers = 4

[database]
type = "sqlite"
path = "/var/lib/fortress/data"
connection_pool_size = 10

[encryption]
default_algorithm = "aegis256"
key_rotation_interval = "24h"
auto_rotation = true

[logging]
level = "info"
format = "json"
file = "/var/log/fortress/fortress.log"
```

### Automatic Configuration Migration

```bash
# Migrate configuration automatically
fortress config migrate --auto

# Review changes
fortress config diff --before current_config.toml --after current_config_migrated.toml

# Apply migration
fortress config apply --migrated-config current_config_migrated.toml

# Verify new configuration
fortress config validate
```

### Manual Configuration Migration

```bash
# Export current configuration
fortress config export --output old_config.toml

# Create new configuration template
fortress config template --version 0.2.0 --output new_config_template.toml

# Manually merge configurations
# (Use your preferred editor or diff tool)

# Validate new configuration
fortress config validate --input new_config.toml

# Apply new configuration
fortress config import --input new_config.toml
```

### Environment Variable Migration

```bash
# Export current environment variables
fortress config env export > old_env.sh

# Generate new environment template
fortress config env template --version 0.2.0 > new_env_template.sh

# Merge environment variables
# (Manual process - compare and update)

# Apply new environment
source new_env.sh

# Restart with new environment
fortress restart
```

---

## 📦 Data Migration

### Data Export/Import

#### Export Data
```bash
# Export all data
fortress export --all --output fortress_export_$(date +%Y%m%d).tar.gz

# Export specific database
fortress export --database myapp_db --output myapp_db_export.tar.gz

# Export with encryption
fortress export --all --encrypt --output encrypted_export.tar.gz

# Export metadata only
fortress export --metadata-only --output metadata.json
```

#### Import Data
```bash
# Import all data
fortress import --input fortress_export_20250324.tar.gz

# Import specific database
fortress import --database myapp_db --input myapp_db_export.tar.gz

# Import with decryption
fortress import --input encrypted_export.tar.gz --decrypt

# Import with validation
fortress import --input data.tar.gz --validate --repair
```

### Cross-Platform Migration

#### Linux to Linux
```bash
# On source system
fortress export --all --compress --output linux_migration.tar.gz

# Transfer to target system
scp linux_migration.tar.gz user@target:/tmp/

# On target system
fortress import --input /tmp/linux_migration.tar.gz
```

#### Docker to Native
```bash
# Export from Docker container
docker exec fortress-container fortress export --all --output /tmp/docker_export.tar.gz
docker cp fortress-container:/tmp/docker_export.tar.gz .

# Import to native installation
fortress import --input docker_export.tar.gz
```

#### Native to Docker
```bash
# Export from native
fortress export --all --output native_export.tar.gz

# Copy to Docker container
docker cp native_export.tar.gz fortress-container:/tmp/

# Import in Docker container
docker exec fortress-container fortress import --input /tmp/native_export.tar.gz
```

### Database Migration

#### SQLite to PostgreSQL
```bash
# 1. Export from SQLite
fortress export --database myapp_db --format sql --output sqlite_dump.sql

# 2. Set up PostgreSQL
sudo -u postgres createdb fortress_migration
sudo -u postgres createuser fortress_user

# 3. Import to PostgreSQL
psql -h localhost -U fortress_user -d fortress_migration < sqlite_dump.sql

# 4. Update Fortress configuration
fortress config set database.type postgresql
fortress config set database.host localhost
fortress config set database.name fortress_migration
fortress config set database.user fortress_user

# 5. Test new database
fortress db test --connection
```

#### PostgreSQL to SQLite
```bash
# 1. Export from PostgreSQL
pg_dump -h localhost -U fortress_user fortress_migration > postgres_dump.sql

# 2. Convert to SQLite format
fortress db convert --from postgresql --to sqlite --input postgres_dump.sql --output sqlite_dump.sql

# 3. Import to SQLite
fortress import --database myapp_db --input sqlite_dump.sql

# 4. Update configuration
fortress config set database.type sqlite
fortress config set database.path /var/lib/fortress/data.db

# 5. Test new database
fortress db test --connection
```

---

## 🌐 Platform Migration

### Operating System Migration

#### Linux to Windows
```bash
# On Linux source
fortress export --all --platform-cross --output linux_to_windows.tar.gz

# Transfer to Windows
# (Use SCP, USB drive, or network transfer)

# On Windows target
# 1. Install Fortress for Windows
# 2. Open Command Prompt as Administrator
# 3. Import data
fortress.exe import --input linux_to_windows.tar.gz

# 4. Update configuration for Windows
fortress.exe config set database.path "C:\\Fortress\\Data"
fortress.exe config set logging.file "C:\\Fortress\\Logs\\fortress.log"
```

#### Windows to Linux
```cmd
REM On Windows source
fortress.exe export --all --platform-cross --output windows_to_linux.tar.gz

REM Transfer to Linux
REM (Use SCP, USB drive, or network transfer)
```

```bash
# On Linux target
# 1. Install Fortress for Linux
# 2. Import data
fortress import --input windows_to_linux.tar.gz

# 3. Update configuration for Linux
fortress config set database.path /var/lib/fortress/data
fortress config set logging.file /var/log/fortress/fortress.log
```

### Cloud Platform Migration

#### AWS to Azure
```bash
# On AWS
# 1. Export data
fortress export --all --encrypt --output aws_export.tar.gz

# 2. Upload to S3
aws s3 cp aws_export.tar.gz s3://migration-bucket/

# 3. Transfer to Azure
# (Use Azure Storage Explorer or azcopy)
```

```bash
# On Azure
# 1. Download from Azure Storage
az storage blob download --container-name migration --name aws_export.tar.gz --file aws_export.tar.gz

# 2. Import data
fortress import --input aws_export.tar.gz

# 3. Update configuration for Azure
fortress config set storage.backend azure_blob
fortress config set storage.azure.connection_string "your-connection-string"
```

---

## 🔧 Advanced Migration Scenarios

### Multi-Database Migration

```bash
# Migrate multiple databases in sequence
databases=("db1" "db2" "db3")

for db in "${databases[@]}"; do
    echo "Migrating database: $db"
    
    # Export each database
    fortress export --database $db --output ${db}_export.tar.gz
    
    # Verify export
    fortress export verify --input ${db}_export.tar.gz
    
    # Import to new system
    fortress import --database $db --input ${db}_export.tar.gz
    
    # Verify import
    fortress data verify --database $db --sample-size 50
    
    echo "Database $db migration completed"
done
```

### Zero-Downtime Migration

```bash
# 1. Set up replication
fortress replication enable --target new-server:8080

# 2. Wait for sync completion
fortress replication status --wait-for-sync

# 3. Switch DNS to new server
# (Update DNS records)

# 4. Verify traffic is flowing to new server
fortress metrics traffic --new-server

# 5. Decommission old server
fortress server stop --old-server
```

### Blue-Green Migration

```bash
# 1. Set up green environment
fortress deploy --environment green --version 0.2.0

# 2. Test green environment
fortress test --environment green --all

# 3. Switch traffic to green
fortress traffic switch --to green

# 4. Monitor green environment
fortress monitor --environment green --duration 300

# 5. If successful, decommission blue
fortress deploy --cleanup blue

# 6. If failed, rollback to blue
fortress traffic switch --to blue
```

---

## 📊 Migration Validation

### Health Checks

```bash
# Comprehensive health check
fortress health --all --detailed

# Check specific components
fortress health --component database
fortress health --component encryption
fortress health --component network

# Performance validation
fortress benchmark --duration 60s --compare-baseline
```

### Data Integrity

```bash
# Verify all data
fortress data verify --all --detailed

# Check encryption integrity
fortress encryption verify --all

# Validate database consistency
fortress db verify --consistency

# Check for data corruption
fortress data check-corruption --all
```

### Performance Validation

```bash
# Run performance tests
fortress test performance --duration 300s

# Compare with baseline
fortress benchmark compare --baseline pre_migration.json

# Check response times
fortress metrics latency --percentile 95

# Verify throughput
fortress metrics throughput --duration 60s
```

---

## 🚨 Migration Troubleshooting

### Common Issues

#### Configuration Conflicts
```bash
# Check configuration conflicts
fortress config check --conflicts

# Reset to default configuration
fortress config reset --defaults

# Re-apply custom configuration
fortress config import --input custom_config.toml
```

#### Data Import Failures
```bash
# Check import errors
fortress import --input data.tar.gz --dry-run

# Repair corrupted data
fortress data repair --input corrupted_data.tar.gz

# Import with validation disabled
fortress import --input data.tar.gz --no-validate
```

#### Performance Degradation
```bash
# Check performance metrics
fortress metrics performance --post-migration

# Optimize new installation
fortress optimize --all

# Rebuild indexes
fortress db rebuild-indexes
```

### Emergency Procedures

#### Migration Failure Recovery
```bash
# 1. Stop migration process
fortress migration stop --force

# 2. Restore from backup
fortress restore --name pre-migration-backup --force

# 3. Verify system state
fortress health --all

# 4. Document failure
fortress migration log --export migration_failure.log
```

#### Partial Migration Recovery
```bash
# 1. Identify what was migrated
fortress migration status --detailed

# 2. Complete remaining migration
fortress migration continue --from checkpoint

# 3. Verify consistency
fortress data verify --all

# 4. Fix any issues
fortress repair --auto
```

---

## 📋 Migration Checklist

### Pre-Migration
- [ ] Review migration guide
- [ ] Create full system backup
- [ ] Test migration in staging
- [ ] Schedule maintenance window
- [ ] Prepare rollback plan
- [ ] Document current state
- [ ] Verify target system requirements

### During Migration
- [ ] Stop services gracefully
- [ ] Create migration backup
- [ ] Update Fortress binary
- [ ] Migrate configuration
- [ ] Import data
- [ ] Start services
- [ ] Verify functionality

### Post-Migration
- [ ] Run health checks
- [ ] Validate data integrity
- [ ] Test performance
- [ ] Monitor system stability
- [ ] Update documentation
- [ ] Clean up old files
- [ ] Document migration results

---

**Last Updated**: 2025-03-24  
**Version**: 0.1.0  
**Maintainer**: Fortress Development Team

> **Note**: Migration procedures are evolving with Fortress development. Always test migrations in a non-production environment first and maintain recent backups.
