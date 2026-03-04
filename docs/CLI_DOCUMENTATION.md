# Fortress CLI Documentation

## Table of Contents

1. [Overview](#overview)
2. [Installation](#installation)
3. [Global Options](#global-options)
4. [Commands](#commands)
5. [Examples](#examples)
6. [Configuration](#configuration)
7. [Troubleshooting](#troubleshooting)

## Overview

The Fortress CLI is a powerful command-line interface for managing Fortress databases, clusters, tenants, and plugins. It provides comprehensive functionality for database administration, security management, and system operations.

### Features

- **Database Management**: Create, configure, and manage Fortress databases
- **Server Operations**: Start, stop, and monitor Fortress servers
- **Key Management**: Generate, rotate, and manage encryption keys
- **Cluster Management**: Configure and manage distributed clusters
- **Tenant Management**: Multi-tenant administration
- **Plugin Management**: Install and manage plugins
- **Configuration Management**: System configuration and validation

## Installation

### Build from Source

```bash
git clone https://github.com/Genius740Code/Fortress.git
cd Fortress
cargo build --release
```

The binary will be available at `target/release/fortress`.

### Install via Cargo

```bash
cargo install fortress-cli
```

### Verify Installation

```bash
fortress --version
fortress --help
```

## Global Options

These options can be used with any command:

| Option | Short | Long | Description |
|--------|-------|-------|-------------|
| Verbose | `-v` | `--verbose` | Enable verbose output |
| Config | `-c` | `--config <FILE>` | Configuration file path |
| Help | `-h` | `--help` | Show help information |
| Version | `-V` | `--version` | Show version information |

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `FORTRESS_CONFIG` | Default config file path | `~/.fortress/config.toml` |
| `FORTRESS_LOG_LEVEL` | Logging level | `info` |
| `FORTRESS_DATA_DIR` | Default data directory | `./data` |

## Commands

### fortress create

Create a new Fortress database with specified configuration.

#### Syntax
```bash
fortress create [OPTIONS]
```

#### Options

| Option | Short | Long | Description | Default |
|--------|-------|-------|-------------|---------|
| Name | `-n` | `--name <NAME>` | Database name | Auto-generated |
| Template | `-t` | `--template <TEMPLATE>` | Template to use | `startup` |
| Data Dir | `-d` | `--data-dir <DIR>` | Data directory path | `./data` |
| Interactive | `-i` | `--interactive` | Interactive mode | `false` |

#### Templates

| Template | Description | Use Case |
|----------|-------------|----------|
| `startup` | Optimized for startups | Small to medium applications |
| `enterprise` | Enterprise-grade setup | Large production systems |
| `custom` | Custom configuration | Advanced users |
| `development` | Development setup | Local development |

#### Examples

**Create with default settings:**
```bash
fortress create
```

**Create with specific name and template:**
```bash
fortress create --name myapp_db --template enterprise
```

**Create with custom data directory:**
```bash
fortress create --name production_db --data-dir /var/lib/fortress/prod
```

**Interactive mode:**
```bash
fortress create --interactive
```

Interactive mode will prompt for:
- Database name
- Template selection
- Encryption algorithm
- Key rotation interval
- Storage backend
- Performance settings

### fortress start

Start a Fortress server instance.

#### Syntax
```bash
fortress start [OPTIONS]
```

#### Options

| Option | Short | Long | Description | Default |
|--------|-------|-------|-------------|---------|
| Data Dir | `-d` | `--data-dir <DIR>` | Data directory path | `./data` |
| Port | `-p` | `--port <PORT>` | Port to listen on | `8080` |
| Host | | `--host <HOST>` | Host to bind to | `127.0.0.1` |

#### Examples

**Start with default settings:**
```bash
fortress start
```

**Start on specific port:**
```bash
fortress start --port 9000
```

**Start with custom data directory:**
```bash
fortress start --data-dir /var/lib/fortress/prod --port 8080
```

**Start on all interfaces:**
```bash
fortress start --host 0.0.0.0 --port 8080
```

### fortress stop

Stop a running Fortress server.

#### Syntax
```bash
fortress stop
```

#### Options

| Option | Short | Long | Description | Default |
|--------|-------|-------|-------------|---------|
| Graceful | `-g` | `--graceful` | Graceful shutdown | `true` |
| Timeout | `-t` | `--timeout <SECONDS>` | Shutdown timeout | `30` |

#### Examples

**Graceful shutdown:**
```bash
fortress stop --graceful --timeout 60
```

**Force shutdown:**
```bash
fortress stop --no-graceful
```

### fortress status

Show database and server status information.

#### Syntax
```bash
fortress status [OPTIONS]
```

#### Options

| Option | Short | Long | Description | Default |
|--------|-------|-------|-------------|---------|
| Data Dir | `-d` | `--data-dir <DIR>` | Data directory path | `./data` |
| Detailed | | `--detailed` | Show detailed status | `false` |
| JSON | | `--json` | Output in JSON format | `false` |

#### Examples

**Basic status:**
```bash
fortress status
```

**Detailed status:**
```bash
fortress status --detailed
```

**JSON output:**
```bash
fortress status --json
```

**Status for specific database:**
```bash
fortress status --data-dir /var/lib/fortress/prod
```

### fortress key

Manage encryption keys for Fortress databases.

#### Subcommands

##### fortress key generate

Generate a new encryption key.

**Syntax:**
```bash
fortress key generate [OPTIONS]
```

**Options:**
| Option | Short | Long | Description | Default |
|--------|-------|-------|-------------|---------|
| Algorithm | `-a` | `--algorithm <ALGO>` | Encryption algorithm | `aegis256` |
| Key Size | `-s` | `--key-size <SIZE>` | Key size in bits | `256` |
| Purpose | `-p` | `--purpose <PURPOSE>` | Key purpose | `data-encryption` |
| Output | `-o` | `--output <FILE>` | Output file for key | stdout |

**Algorithms:**
- `aegis256` - AEGIS-256 (recommended)
- `aes256gcm` - AES-256-GCM
- `chacha20poly1305` - ChaCha20-Poly1305
- `xchacha20poly1305` - XChaCha20-Poly1305

**Examples:**
```bash
# Generate AEGIS-256 key
fortress key generate --algorithm aegis256

# Generate AES-256-GCM key for specific purpose
fortress key generate --algorithm aes256gcm --purpose field-encryption

# Save key to file
fortress key generate --output mykey.key
```

##### fortress key list

List all encryption keys.

**Syntax:**
```bash
fortress key list [OPTIONS]
```

**Options:**
| Option | Short | Long | Description | Default |
|--------|-------|-------|-------------|---------|
| Algorithm | `-a` | `--algorithm <ALGO>` | Filter by algorithm | all |
| Status | `-s` | `--status <STATUS>` | Filter by status | all |
| Format | `-f` | `--format <FORMAT>` | Output format | `table` |

**Status values:** `active`, `inactive`, `rotating`, `deprecated`

**Format values:** `table`, `json`, `csv`

**Examples:**
```bash
# List all keys
fortress key list

# List active AEGIS-256 keys
fortress key list --algorithm aegis256 --status active

# JSON output
fortress key list --format json
```

##### fortress key rotate

Rotate an encryption key.

**Syntax:**
```bash
fortress key rotate <KEY_ID> [OPTIONS]
```

**Options:**
| Option | Short | Long | Description | Default |
|--------|-------|-------|-------------|---------|
| Algorithm | `-a` | `--algorithm <ALGO>` | New algorithm | same |
| Strategy | `-s` | `--strategy <STRATEGY>` | Rotation strategy | `zero-downtime` |
| Dry Run | | `--dry-run` | Simulate rotation | `false` |

**Strategies:**
- `zero-downtime` - Rotate without service interruption
- `immediate` - Immediate rotation with brief downtime
- `scheduled` - Schedule rotation for later

**Examples:**
```bash
# Rotate key with zero downtime
fortress key rotate key_123456

# Rotate to different algorithm
fortress key rotate key_123456 --algorithm aes256gcm

# Dry run to test rotation
fortress key rotate key_123456 --dry-run
```

##### fortress key show

Show detailed information about a specific key.

**Syntax:**
```bash
fortress key show <KEY_ID> [OPTIONS]
```

**Options:**
| Option | Short | Long | Description | Default |
|--------|-------|-------|-------------|---------|
| Metadata | `-m` | `--metadata` | Show key metadata | `true` |
| Usage | `-u` | `--usage` | Show usage statistics | `false` |

**Examples:**
```bash
# Show key information
fortress key show key_123456

# Show with usage statistics
fortress key show key_123456 --usage
```

### fortress config

Manage Fortress configuration.

#### Subcommands

##### fortress config show

Show current configuration.

**Syntax:**
```bash
fortress config show [OPTIONS]
```

**Options:**
| Option | Short | Long | Description | Default |
|--------|-------|-------|-------------|---------|
| Section | `-s` | `--section <SECTION>` | Show specific section | all |
| Format | `-f` | `--format <FORMAT>` | Output format | `toml` |

**Sections:** `network`, `security`, `storage`, `encryption`, `performance`

**Format values:** `toml`, `json`, `yaml`

**Examples:**
```bash
# Show all configuration
fortress config show

# Show network configuration
fortress config show --section network

# JSON format
fortress config show --format json
```

##### fortress config set

Set a configuration value.

**Syntax:**
```bash
fortress config set <KEY> <VALUE> [OPTIONS]
```

**Options:**
| Option | Short | Long | Description | Default |
|--------|-------|-------|-------------|---------|
| Section | `-s` | `--section <SECTION>` | Configuration section | `default` |

**Examples:**
```bash
# Set network port
fortress config set network.port 9000

# Set encryption algorithm
fortress config set encryption.default_algorithm aegis256

# Set log level
fortress config set logging.level debug
```

##### fortress config reset

Reset configuration to defaults.

**Syntax:**
```bash
fortress config reset [OPTIONS]
```

**Options:**
| Option | Short | Long | Description | Default |
|--------|-------|-------|-------------|---------|
| Section | `-s` | `--section <SECTION>` | Reset specific section | all |
| Force | `-f` | `--force` | Skip confirmation | `false` |

**Examples:**
```bash
# Reset all configuration
fortress config reset --force

# Reset only network section
fortress config reset --section network
```

##### fortress config validate

Validate current configuration.

**Syntax:**
```bash
fortress config validate [OPTIONS]
```

**Options:**
| Option | Short | Long | Description | Default |
|--------|-------|-------|-------------|---------|
| Strict | | `--strict` | Strict validation | `false` |

**Examples:**
```bash
# Validate configuration
fortress config validate

# Strict validation
fortress config validate --strict
```

### fortress cluster

Manage Fortress clusters for high availability and scaling.

#### Subcommands

##### fortress cluster init

Initialize a new cluster.

**Syntax:**
```bash
fortress cluster init [OPTIONS]
```

**Options:**
| Option | Short | Long | Description | Default |
|--------|-------|-------|-------------|---------|
| Name | `-n` | `--name <NAME>` | Cluster name | Auto-generated |
| Nodes | | `--nodes <NODES>` | Initial node count | `3` |
| Algorithm | `-a` | `--algorithm <ALGO>` | Consensus algorithm | `raft` |

**Examples:**
```bash
# Initialize 3-node cluster
fortress cluster init --name prod-cluster --nodes 3
```

##### fortress cluster join

Join a node to an existing cluster.

**Syntax:**
```bash
fortress cluster join <CLUSTER_ADDRESS> [OPTIONS]
```

**Options:**
| Option | Short | Long | Description | Default |
|--------|-------|-------|-------------|---------|
| Node ID | `-i` | `--node-id <ID>` | Node ID | Auto-generated |
| Role | `-r` | `--role <ROLE>` | Node role | `follower` |

**Roles:** `leader`, `follower`, `observer`

**Examples:**
```bash
# Join cluster as follower
fortress cluster join 192.168.1.10:8080

# Join with specific node ID
fortress cluster join 192.168.1.10:8080 --node-id node-4
```

##### fortress cluster status

Show cluster status and health.

**Syntax:**
```bash
fortress cluster status [OPTIONS]
```

**Options:**
| Option | Short | Long | Description | Default |
|--------|-------|-------|-------------|---------|
| Detailed | `-d` | `--detailed` | Detailed status | `false` |
| Watch | `-w` | `--watch` | Watch for changes | `false` |

**Examples:**
```bash
# Basic cluster status
fortress cluster status

# Detailed status
fortress cluster status --detailed

# Watch mode (updates every 2 seconds)
fortress cluster status --watch
```

##### fortress cluster remove

Remove a node from the cluster.

**Syntax:**
```bash
fortress cluster remove <NODE_ID> [OPTIONS]
```

**Options:**
| Option | Short | Long | Description | Default |
|--------|-------|-------|-------------|---------|
| Force | `-f` | `--force` | Force removal | `false` |

**Examples:**
```bash
# Remove node gracefully
fortress cluster remove node-4

# Force removal
fortress cluster remove node-4 --force
```

### fortress tenant

Manage multi-tenant operations.

#### Subcommands

##### fortress tenant create

Create a new tenant.

**Syntax:**
```bash
fortress tenant create <NAME> [OPTIONS]
```

**Options:**
| Option | Short | Long | Description | Default |
|--------|-------|-------|-------------|---------|
| Domain | `-d` | `--domain <DOMAIN>` | Tenant domain | required |
| Admin | `-a` | `--admin <EMAIL>` | Admin email | required |
| Limits | `-l` | `--limits <LIMITS>` | Resource limits | default |

**Examples:**
```bash
# Create tenant with default limits
fortress tenant create "Acme Corp" --domain acme.com --admin admin@acme.com

# Create with custom limits
fortress tenant create "Big Corp" --domain bigcorp.com --admin admin@bigcorp.com --limits "max_dbs=20,max_storage=500GB"
```

##### fortress tenant list

List all tenants.

**Syntax:**
```bash
fortress tenant list [OPTIONS]
```

**Options:**
| Option | Short | Long | Description | Default |
|--------|-------|-------|-------------|---------|
| Status | `-s` | `--status <STATUS>` | Filter by status | all |
| Format | `-f` | `--format <FORMAT>` | Output format | `table` |

**Examples:**
```bash
# List all tenants
fortress tenant list

# List active tenants
fortress tenant list --status active

# JSON output
fortress tenant list --format json
```

##### fortress tenant show

Show tenant details.

**Syntax:**
```bash
fortress tenant show <TENANT_ID> [OPTIONS]
```

**Options:**
| Option | Short | Long | Description | Default |
|--------|-------|-------|-------------|---------|
| Usage | `-u` | `--usage` | Show resource usage | `false` |

**Examples:**
```bash
# Show tenant info
fortress tenant show tenant_123

# Show with usage statistics
fortress tenant show tenant_123 --usage
```

### fortress plugin

Manage Fortress plugins.

#### Subcommands

##### fortress plugin install

Install a plugin from file or repository.

**Syntax:**
```bash
fortress plugin install <PLUGIN_PATH> [OPTIONS]
```

**Options:**
| Option | Short | Long | Description | Default |
|--------|-------|-------|-------------|---------|
| Name | `-n` | `--name <NAME>` | Plugin name | from manifest |
| Config | `-c` | `--config <FILE>` | Configuration file | none |
| Force | `-f` | `--force` | Overwrite existing | `false` |

**Examples:**
```bash
# Install from local file
fortress plugin install ./audit-plugin.wasm

# Install from repository
fortress plugin install fortress/audit-enhanced

# Install with configuration
fortress plugin install ./plugin.wasm --config plugin-config.toml
```

##### fortress plugin list

List installed plugins.

**Syntax:**
```bash
fortress plugin list [OPTIONS]
```

**Options:**
| Option | Short | Long | Description | Default |
|--------|-------|-------|-------------|---------|
| Status | `-s` | `--status <STATUS>` | Filter by status | all |
| Type | `-t` | `--type <TYPE>` | Filter by type | all |

**Examples:**
```bash
# List all plugins
fortress plugin list

# List active plugins
fortress plugin list --status active

# List audit plugins
fortress plugin list --type audit
```

##### fortress plugin enable

Enable a plugin.

**Syntax:**
```bash
fortress plugin enable <PLUGIN_NAME>
```

**Examples:**
```bash
fortress plugin enable audit-enhanced
```

##### fortress plugin disable

Disable a plugin.

**Syntax:**
```bash
fortress plugin disable <PLUGIN_NAME>
```

**Examples:**
```bash
fortress plugin disable audit-enhanced
```

##### fortress plugin uninstall

Uninstall a plugin.

**Syntax:**
```bash
fortress plugin uninstall <PLUGIN_NAME> [OPTIONS]
```

**Options:**
| Option | Short | Long | Description | Default |
|--------|-------|-------|-------------|---------|
| Force | `-f` | `--force` | Force removal | `false` |

**Examples:**
```bash
# Uninstall plugin
fortress plugin uninstall audit-enhanced

# Force uninstall
fortress plugin uninstall audit-enhanced --force
```

## Examples

### Complete Database Setup

```bash
# 1. Create a new database
fortress create --name myapp --template enterprise --data-dir /var/lib/fortress/myapp

# 2. Start the server
fortress start --data-dir /var/lib/fortress/myapp --port 8080 --host 0.0.0.0

# 3. Check status
fortress status --data-dir /var/lib/fortress/myapp --detailed

# 4. Generate encryption keys
fortress key generate --algorithm aegis256 --purpose data-encryption

# 5. List keys
fortress key list --status active
```

### Cluster Setup

```bash
# On node 1 (leader)
fortress cluster init --name prod-cluster --nodes 3

# On node 2
fortress cluster join 192.168.1.10:8080 --node-id node-2

# On node 3
fortress cluster join 192.168.1.10:8080 --node-id node-3

# Check cluster status
fortress cluster status --detailed
```

### Multi-Tenant Setup

```bash
# Create tenants
fortress tenant create "Company A" --domain company-a.com --admin admin@company-a.com
fortress tenant create "Company B" --domain company-b.com --admin admin@company-b.com

# List tenants
fortress tenant list

# Show tenant details
fortress tenant show tenant_123 --usage
```

### Plugin Management

```bash
# Install audit plugin
fortress plugin install ./enhanced-audit.wasm --name audit-pro

# Enable plugin
fortress plugin enable audit-pro

# List plugins
fortress plugin list --status active

# Configure plugin
fortress config set plugins.audit-pro.log_level debug
```

## Configuration

### Configuration File

The default configuration file is located at `~/.fortress/config.toml`.

### Example Configuration

```toml
[general]
data_dir = "./data"
log_level = "info"

[network]
host = "127.0.0.1"
port = 8080
max_body_size = 10485760  # 10MB

[security]
jwt_secret = "your-secret-key"
token_expiration = 3600  # 1 hour

[encryption]
default_algorithm = "aegis256"
key_rotation_interval = "24h"

[storage]
backend = "sqlite"
path = "./data/fortress.db"

[performance]
cache_size = 1000
connection_pool_size = 10
```

### Environment Variables

You can override configuration with environment variables:

```bash
export FORTRESS_DATA_DIR=/var/lib/fortress
export FORTRESS_NETWORK_PORT=9000
export FORTRESS_LOG_LEVEL=debug
export FORTRESS_ENCRYPTION_DEFAULT_ALGORITHM=aes256gcm
```

## Troubleshooting

### Common Issues

#### Permission Denied
```bash
# Fix permissions
sudo chown -R $USER:$USER /var/lib/fortress
chmod 755 /var/lib/fortress
```

#### Port Already in Use
```bash
# Check what's using the port
netstat -tulpn | grep :8080

# Use different port
fortress start --port 8081
```

#### Configuration Validation Failed
```bash
# Validate configuration
fortress config validate --strict

# Show current config
fortress config show --section network
```

#### Cluster Node Not Joining
```bash
# Check network connectivity
ping 192.168.1.10

# Check cluster status
fortress cluster status --detailed

# Force join if needed
fortress cluster join 192.168.1.10:8080 --force
```

### Debug Mode

Enable debug logging for troubleshooting:

```bash
# Enable verbose output
fortress --verbose start

# Set debug log level
export FORTRESS_LOG_LEVEL=debug
fortress start
```

### Log Files

Log files are located in the data directory:

```bash
# View logs
tail -f ./data/logs/fortress.log

# View error logs
tail -f ./data/logs/error.log
```

### Getting Help

```bash
# General help
fortress --help

# Command-specific help
fortress create --help
fortress key generate --help

# Subcommand help
fortress key --help
fortress cluster --help
```

## Advanced Usage

### Scripting

The CLI can be used in scripts with JSON output:

```bash
#!/bin/bash

# Create database and get ID
DB_ID=$(fortress create --name script_db --format json | jq -r '.data.id')

# Start server
fortress start --data-dir "./data/$DB_ID" &

# Wait for server to be ready
until curl -f http://localhost:8080/health; do
  sleep 1
done

echo "Fortress server is ready!"
```

### Configuration Templates

Create configuration templates for different environments:

```bash
# Development template
fortress config set network.host 127.0.0.1
fortress config set logging.level debug
fortress config set encryption.default_algorithm aegis256

# Production template
fortress config set network.host 0.0.0.0
fortress config set logging.level info
fortress config set security.jwt_secret $JWT_SECRET
```

### Automation

Use the CLI in CI/CD pipelines:

```yaml
# GitHub Actions example
- name: Setup Fortress
  run: |
    fortress create --name $DB_NAME --template enterprise
    fortress start --port 8080 &
    
- name: Run Tests
  run: |
    # Run integration tests against Fortress
    pytest tests/integration/
    
- name: Cleanup
  run: |
    fortress stop
    rm -rf ./data
```

## Support

- 📖 [Documentation](https://docs.fortress-db.com)
- 🐛 [Issue Tracker](https://github.com/Genius740Code/Fortress/issues)
- 💬 [Discussions](https://github.com/Genius740Code/Fortress/discussions)
- 📧 [Email Support](mailto:support@fortress-db.com)
