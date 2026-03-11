# Data Migration Guide

This guide helps you migrate existing databases to Fortress with encryption.

## 🚨 Current Status: Experimental

**⚠️ Migration tools are experimental and not recommended for production use until v1.0**

## Supported Source Databases

### PostgreSQL (Recommended)
- Direct table structure migration
- Bulk data import with encryption
- Preserves primary keys and indexes

### MySQL
- Basic table structure migration
- Data type conversion
- Limited encryption field mapping

### SQLite
- Simple file-based migration
- Good for development/testing
- Limited to smaller datasets

## Migration Process

### 1. Prepare Source Database

```bash
# Export table structures
pg_dump -s your_database > schema.sql

# Export data (optional - Fortress can pull directly)
pg_dump -a your_database > data.sql
```

### 2. Create Fortress Database

```bash
# Create target database
fortress create \
  --name migrated_db \
  --template enterprise \
  --algorithm aegis256

# Start Fortress server
fortress start --port 8080
```

### 3. Map Schema

```python
from fortress_client import FortressClient

client = FortressClient('http://localhost:8080')

# Example: Users table migration
table_schema = {
    "name": "users",
    "columns": [
        {"name": "id", "type": "uuid", "primary_key": True},
        {"name": "name", "type": "text"},
        {"name": "email", "type": "text", "unique": True},
        {"name": "password", "type": "encrypted", "sensitivity": "high"},
        {"name": "phone", "type": "encrypted", "sensitivity": "medium"},
        {"name": "created_at", "type": "date"},
        {"name": "updated_at", "type": "date"}
    ]
}

# Create table in Fortress
client.create_table('migrated_db', 'users', table_schema)
```

### 4. Migrate Data

#### Option A: Using Fortress CLI (Experimental)

```bash
# Basic migration command
fortress migrate \
  --from postgres://user:pass@localhost/source_db \
  --to fortress://localhost:8080/migrated_db \
  --table users \
  --batch-size 1000

# Full database migration
fortress migrate \
  --from postgres://user:pass@localhost/source_db \
  --to fortress://localhost:8080/migrated_db \
  --all-tables \
  --batch-size 1000 \
  --progress
```

#### Option B: Custom Migration Script

```python
import psycopg2
from fortress_client import FortressClient

# Source database connection
source_conn = psycopg2.connect("postgresql://user:pass@localhost/source_db")
source_cursor = source_conn.cursor()

# Fortress client
fortress_client = FortressClient('http://localhost:8080')

# Migration function
def migrate_table(table_name, columns, batch_size=1000):
    offset = 0
    
    while True:
        # Fetch batch from source
        source_cursor.execute(
            f"SELECT * FROM {table_name} ORDER BY id LIMIT {batch_size} OFFSET {offset}"
        )
        rows = source_cursor.fetchall()
        
        if not rows:
            break
            
        # Convert to dict format
        data = []
        for row in rows:
            row_dict = dict(zip([col[0] for col in source_cursor.description], row))
            data.append(row_dict)
        
        # Insert into Fortress
        fortress_client.insert_data('migrated_db', table_name, data)
        
        offset += batch_size
        print(f"Migrated {offset} rows to {table_name}")

# Run migration
migrate_table('users', user_columns)
migrate_table('orders', order_columns)
```

## Field Type Mapping

| PostgreSQL Type | Fortress Type | Encryption Notes |
|----------------|----------------|------------------|
| TEXT, VARCHAR | text | No encryption |
| INTEGER, BIGINT | integer | No encryption |
| BOOLEAN | boolean | No encryption |
| TIMESTAMP | date | No encryption |
| UUID | uuid | No encryption |
| JSONB | json | No encryption |
| TEXT (sensitive) | encrypted | Automatic encryption |
| VARCHAR (sensitive) | encrypted | Automatic encryption |

## Performance Considerations

### Batch Size
- **Small tables (< 10K rows)**: Use batch size 100-500
- **Medium tables (10K-1M rows)**: Use batch size 500-1000  
- **Large tables (> 1M rows)**: Use batch size 1000-5000

### Encryption Performance
- **AEGIS-256**: Fastest, ~1500 MB/s
- **ChaCha20-Poly1305**: Good balance, ~1200 MB/s
- **AES-256-GCM**: Hardware accelerated, ~1000 MB/s

### Memory Usage
- Fortress caches encryption keys in memory
- Large migrations may require increased memory allocation
- Monitor memory usage during migration

## Validation

### Data Integrity Checks

```python
# Row count verification
source_count = source_cursor.execute("SELECT COUNT(*) FROM users").fetchone()[0]
fortress_count = len(fortress_client.query_data('migrated_db', 'users'))

assert source_count == fortress_count, "Row count mismatch!"

# Sample data verification
sample_data = fortress_client.query_data('migrated_db', 'users', limit=10)
print("Sample migrated data:", sample_data)
```

### Encryption Verification

```python
# Check that sensitive fields are encrypted
raw_data = fortress_client.query_data('migrated_db', 'users', limit=1)
user = raw_data[0]

# Encrypted fields should be base64 strings
import base64
try:
    base64.b64decode(user['password'])
    print("✅ Password field appears encrypted")
except:
    print("❌ Password field may not be encrypted")
```

## Troubleshooting

### Common Issues

#### Memory Errors
```
Error: Out of memory during migration
```
**Solution**: Reduce batch size or increase available memory

#### Connection Timeouts
```
Error: Connection timeout during large migration
```
**Solution**: Increase timeout settings or use smaller batches

#### Type Conversion Errors
```
Error: Invalid data type for encrypted field
```
**Solution**: Check field type mapping and data validation

#### Performance Issues
**Symptom**: Migration is very slow
**Solutions**:
- Increase batch size
- Use faster encryption algorithm (AEGIS-256)
- Ensure sufficient network bandwidth
- Consider parallel migration for large tables

### Recovery Procedures

#### Failed Migration
1. Identify last successful batch using offset tracking
2. Resume migration from that offset
3. Verify data integrity after resumption

#### Partial Data Loss
1. Compare source and target row counts
2. Identify missing data ranges
3. Re-migrate specific ranges only

## Best Practices

### Before Migration
1. **Backup source database** completely
2. **Test migration** on development copy
3. **Validate schema mapping** thoroughly
4. **Plan maintenance window** for production

### During Migration
1. **Monitor system resources** closely
2. **Log progress** for recovery
3. **Validate batches** periodically
4. **Monitor Fortress server health**

### After Migration
1. **Verify all data** migrated successfully
2. **Test application functionality**
3. **Update application configuration**
4. **Plan source database retirement**

## Production Considerations

### Downtime Planning
- **Small databases** (< 1GB): 1-2 hours
- **Medium databases** (1-10GB): 2-6 hours  
- **Large databases** (> 10GB): 6+ hours

### Rollback Strategy
1. Keep source database read-only during migration
2. Maintain application compatibility layer
3. Test rollback procedures before production migration

### Monitoring
- Monitor Fortress server metrics during migration
- Track migration progress and error rates
- Set up alerts for migration failures

---

## 🆘 Help and Support

- **Issues**: [GitHub Issues](https://github.com/Genius740Code/Fortress/issues)
- **Documentation**: [Fortress Docs](https://docs.fortress-db.com)
- **Community**: [Discussions](https://github.com/Genius740Code/Fortress/discussions)

**Note**: Migration tools are experimental. Please test thoroughly before production use.
