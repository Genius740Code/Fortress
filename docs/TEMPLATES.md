# Database Templates

Fortress provides pre-configured database templates to quickly set up common deployment scenarios.

## Available Templates

### 🚀 **startup** - Development & Small Projects
**Best for**: Development environments, small applications, proof of concepts

#### Configuration Details

**Database Settings**
- **Max Size**: 1GB
- **Cache Size**: 32MB  
- **Connection Pool**: 5 connections
- **WAL Enabled**: Yes (for data integrity)

**Encryption Settings**
- **Default Algorithm**: AEGIS-256 (fastest, post-quantum secure)
- **Key Rotation**: Every 23 hours
- **Master Key Rotation**: Every 90 days
- **Key Derivation**: Default settings

**Storage Settings**
- **Backend**: Filesystem
- **Base Path**: `./data`
- **Compression**: Enabled
- **Checksum**: SHA-256

**API Settings**
- **REST Port**: 8080
- **gRPC Port**: 50051
- **CORS**: Enabled
- **WebAssembly**: Disabled
- **Rate Limiting**: None
- **Authentication**: None (development mode)

**Monitoring Settings**
- **Metrics**: Disabled
- **Tracing**: Disabled
- **Log Level**: Info

#### Use Cases
- Local development
- Testing and experimentation
- Small applications (< 100K records)
- Proof of concepts
- Learning Fortress

#### Performance Characteristics
- **Memory Usage**: ~50-100MB
- **Disk Usage**: Minimal (compression enabled)
- **Startup Time**: < 5 seconds
- **Throughput**: Good for small workloads

---

### 🏢 **enterprise** - Production & Large Scale
**Best for**: Production environments, large applications, enterprise deployments

#### Configuration Details

**Database Settings**
- **Max Size**: 10GB
- **Cache Size**: 256MB
- **Connection Pool**: 20 connections
- **WAL Enabled**: Yes (for data integrity)

**Encryption Settings**
- **Default Algorithm**: AES-256-GCM (hardware acceleration, industry standard)
- **Key Rotation**: Every 7 days
- **Master Key Rotation**: Every 30 days
- **Key Derivation**: Argon2id with enhanced parameters
  - **Memory Cost**: 256 MiB
  - **Iterations**: 5
  - **Parallelism**: 8
  - **Salt Length**: 64 bytes

**Storage Settings**
- **Backend**: Filesystem
- **Base Path**: `./data`
- **Compression**: Enabled
- **Checksum**: SHA-512 (stronger integrity)

**API Settings**
- **REST Port**: 8080
- **gRPC Port**: 50051
- **CORS**: Enabled
- **WebAssembly**: Enabled (for plugins)
- **Rate Limiting**: 1000 requests/minute, burst 100
- **Authentication**: JWT-based
  - **Auth Type**: JWT
  - **API Key Header**: `X-Fortress-API-Key`

**Monitoring Settings**
- **Metrics**: Enabled (Prometheus format)
- **Metrics Port**: 9090
- **Tracing**: Enabled (Jaeger compatible)
- **Log Level**: Info

#### Use Cases
- Production deployments
- Large applications (> 1M records)
- Enterprise environments
- High-availability requirements
- Compliance-driven deployments

#### Performance Characteristics
- **Memory Usage**: ~200-500MB
- **Disk Usage**: Optimized (compression + strong checksums)
- **Startup Time**: < 30 seconds
- **Throughput**: High (optimized for production)

#### Security Features
- **Enhanced Key Derivation**: Argon2id with high memory cost
- **Frequent Rotation**: 7-day key rotation for security
- **Strong Checksums**: SHA-512 for data integrity
- **Authentication**: JWT-based with API key support
- **Rate Limiting**: DDoS protection
- **Monitoring**: Full observability

---

### ⚙️ **custom** - Blank Slate
**Best for**: Advanced users with specific requirements

#### Configuration Details
All settings use Fortress defaults and can be customized via:

```bash
# Interactive configuration
fortress create --interactive

# Manual configuration
fortress create --name mydb --template custom
# Then edit config/fortress.toml
```

#### Default Settings
- **Database**: 1GB max, 32MB cache, 5 connections
- **Encryption**: AEGIS-256, 24-hour rotation
- **Storage**: Filesystem with compression
- **API**: Basic REST/gRPC, no authentication
- **Monitoring**: Disabled

#### Customization Options
All configuration sections can be customized:

**Database Customization**
```toml
[database]
max_size = "5GB"
cache_size = "128MB"
pool_size = 10
enable_wal = true
```

**Encryption Customization**
```toml
[encryption]
default_algorithm = "chacha20-poly1305"
key_rotation_interval = "12h"
master_key_rotation_interval = "60d"

[encryption.key_derivation]
kdf = "argon2id"
memory_cost = 131072  # 128 MiB
iterations = 3
parallelism = 4
```

**Storage Customization**
```toml
[storage]
backend = "s3"
base_path = "./data"
compression = true
checksum = "sha256"

[storage.s3]
bucket = "my-fortress-bucket"
region = "us-west-2"
access_key_id = "your-key"
secret_access_key = "your-secret"
```

**API Customization**
```toml
[api]
rest_port = 9090
grpc_port = 50052
enable_cors = true
enable_wasm = true

[api.rate_limit]
requests_per_minute = 500
burst_size = 50

[api.authentication]
auth_type = "jwt"
jwt_secret = "your-secret"
api_key_header = "X-My-API-Key"
```

**Monitoring Customization**
```toml
[monitoring]
enable_metrics = true
metrics_port = 9090
enable_tracing = true
jaeger_endpoint = "http://jaeger:14268/api/traces"
log_level = "debug"
```

---

## Template Selection Guide

### Choose **startup** if:
- ✅ You're developing locally
- ✅ You have < 100K records
- ✅ You need quick setup
- ✅ You're learning Fortress
- ✅ You're building a proof of concept

### Choose **enterprise** if:
- ✅ You're deploying to production
- ✅ You have > 1M records
- ✅ You need enterprise security
- ✅ You require compliance features
- ✅ You need monitoring and observability

### Choose **custom** if:
- ✅ You have specific requirements
- ✅ You need non-standard configuration
- ✅ You're migrating from another system
- ✅ You need custom storage backends
- ✅ You have special security requirements

## Template Comparison

| Feature | startup | enterprise | custom |
|---------|----------|------------|---------|
| **Database Size** | 1GB | 10GB | Configurable |
| **Cache Size** | 32MB | 256MB | Configurable |
| **Connection Pool** | 5 | 20 | Configurable |
| **Algorithm** | AEGIS-256 | AES-256-GCM | Configurable |
| **Key Rotation** | 23 hours | 7 days | Configurable |
| **Authentication** | None | JWT | Configurable |
| **Rate Limiting** | None | 1000/min | Configurable |
| **Monitoring** | Disabled | Enabled | Configurable |
| **WebAssembly** | Disabled | Enabled | Configurable |
| **Key Derivation** | Default | Argon2id (high) | Configurable |

## Using Templates

### Command Line

```bash
# Use startup template
fortress create --name myapp --template startup

# Use enterprise template
fortress create --name production --template enterprise

# Use custom template
fortress create --name special --template custom

# Interactive template selection
fortress create --interactive
```

### Preview Template

```bash
# Preview what will be created (dry run)
fortress create --name test --template enterprise --dry-run

# List available templates
fortress create --list-templates
```

### Post-Creation Customization

After creating a database, you can modify settings by editing `config/fortress.toml`:

```bash
# Navigate to database directory
cd /path/to/your/database

# Edit configuration
vim config/fortress.toml

# Restart to apply changes
fortress restart
```

## Migration Between Templates

You can upgrade from startup to enterprise template:

```bash
# Export current configuration
fortress config export --template current

# Create new enterprise database
fortress create --name production --template enterprise

# Import data from startup database
fortress migrate --from ./startup_db --to ./production_db
```

---

## 🆘 Help and Support

- **Documentation**: [Fortress Docs](https://docs.fortress-db.com)
- **Issues**: [GitHub Issues](https://github.com/Genius740Code/Fortress/issues)
- **Community**: [Discussions](https://github.com/Genius740Code/Fortress/discussions)

**Note**: Templates are starting points. Always review and customize configurations for your specific use case.
