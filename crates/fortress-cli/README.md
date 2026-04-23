# Fortress CLI

[![Crates.io](https://img.shields.io/crates/v/fortress-cli.svg)](https://crates.io/crates/fortress-cli)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](../../LICENSE)

**Fortress CLI** - Command-line interface for Fortress secure database system. Enterprise-grade encryption and key management from your terminal.

## Installation

### Install from Crates.io (Recommended)

```bash
cargo install fortress-cli
```

### Install from Source

```bash
# Clone repository
git clone https://github.com/Genius740Code/Fortress.git
cd Fortress

# Install CLI
cargo install --path crates/fortress-cli
```

### NPM Package (Node.js bindings)

```bash
# Install globally
npm install -g fortress-cli

# Or locally
npm install fortress-cli
```

## Quick Start

### Initialize Fortress

```bash
# Initialize Fortress configuration
fortress init

# Start the Fortress server
fortress server start

# Create an encryption key
fortress key create --name my-key --algorithm aes256-gcm

# Encrypt data
echo "secret data" | fortress encrypt --key-id my-key > encrypted.dat

# Decrypt data
fortress decrypt --key-id my-key --input encrypted.dat
```

### Database Operations

```bash
# Create a database
fortress db create myapp

# List databases
fortress db list

# Insert data
fortress db insert myapp users '{"name": "Alice", "email": "alice@example.com"}'

# Query data
fortress db query myapp users --where '{"email": "alice@example.com"}'

# Create index
fortress db index create myapp users email
```

### Key Management

```bash
# Generate a new key
fortress key generate --algorithm aegis256 --name production-key

# List all keys
fortress key list

# Get key details
fortress key info production-key

# Rotate a key
fortress key rotate production-key

# Delete a key
fortress key delete production-key
```

## Commands

### Server Management

```bash
# Start server
fortress server start

# Start with custom configuration
fortress server start --config /path/to/config.toml

# Stop server
fortress server stop

# Restart server
fortress server restart

# Check server status
fortress server status

# View server logs
fortress server logs
```

### Database Operations

```bash
# Create database
fortress db create <database-name>

# List databases
fortress db list

# Delete database
fortress db delete <database-name>

# Insert data
fortress db insert <database> <collection> '<json-data>'

# Query data
fortress db query <database> <collection> [--where <json-filter>]

# Update data
fortress db update <database> <collection> --where <json-filter> --data <json-data>

# Delete data
fortress db delete <database> <collection> [--where <json-filter>]

# Create index
fortress db index create <database> <collection> <field>

# List indexes
fortress db index list <database> <collection>

# Drop index
fortress db index drop <database> <collection> <field>
```

### Key Management

```bash
# Generate key
fortress key generate [--algorithm <algorithm>] [--name <name>] [--format <format>]

# List keys
fortress key list [--format <format>]

# Get key info
fortress key info <key-id>

# Rotate key
fortress key rotate <key-id>

# Delete key
fortress key delete <key-id>

# Export key
fortress key export <key-id> [--format <format>] [--output <file>]

# Import key
fortress key import <file> [--name <name>]
```

### Encryption Operations

```bash
# Encrypt data
fortress encrypt --key-id <key-id> [--input <file>] [--output <file>]

# Decrypt data
fortress decrypt --key-id <key-id> [--input <file>] [--output <file>]

# Encrypt file
fortress encrypt-file --key-id <key-id> <input-file> <output-file>

# Decrypt file
fortress decrypt-file --key-id <key-id> <input-file> <output-file>
```

### Configuration

```bash
# Show current configuration
fortress config show

# Set configuration value
fortress config set <key> <value>

# Get configuration value
fortress config get <key>

# Reset configuration
fortress config reset

# Create configuration file
fortress config init [--profile <profile>]
```

### Cluster Management

```bash
# Initialize cluster
fortress cluster init [--name <cluster-name>] [--node-id <node-id>]

# Join cluster
fortress cluster join <seed-node> [--node-id <node-id>]

# Leave cluster
fortress cluster leave

# List cluster nodes
fortress cluster nodes

# Show cluster status
fortress cluster status
```

## Configuration

### Configuration File

The Fortress CLI uses a TOML configuration file located at:

- Linux/macOS: `~/.config/fortress/config.toml`
- Windows: `%APPDATA%\fortress\config.toml`

### Example Configuration

```toml
[server]
host = "0.0.0.0"
port = 8080
workers = 4

[database]
default_algorithm = "aegis256"
auto_rotation = true
rotation_interval = "24h"

[encryption]
default_algorithm = "aegis256"
key_size = 32
compression = true

[storage]
backend = "memory"
path = "/var/lib/fortress"

[logging]
level = "info"
format = "json"
file = "/var/log/fortress/fortress.log"

[security]
require_authentication = true
audit_logging = true
max_key_size = 1048576  # 1MB

[cluster]
enabled = false
node_id = "node-1"
seed_nodes = []
```

### Environment Variables

```bash
# Server configuration
export FORTRESS_HOST=0.0.0.0
export FORTRESS_PORT=8080

# Database configuration
export FORTRESS_DEFAULT_ALGORITHM=aegis256
export FORTRESS_KEY_ROTATION_INTERVAL=24h

# Storage configuration
export FORTRESS_STORAGE_BACKEND=memory
export FORTRESS_STORAGE_PATH=/var/lib/fortress

# Logging configuration
export FORTRESS_LOG_LEVEL=info
export FORTRESS_LOG_FORMAT=json
```

## Supported Algorithms

| Algorithm | CLI Name | Security Level | Performance |
|-----------|------------|----------------|-------------|
| AEGIS-256 | `aegis256` | Very High | Fastest |
| ChaCha20-Poly1305 | `chacha20-poly1305` | High | Very Fast |
| AES-256-GCM | `aes256-gcm` | High | Fast |
| XChaCha20-Poly1305 | `xchacha20-poly1305` | High | Fast |

## Output Formats

### Key Formats

```bash
# Base64 (default)
fortress key generate --format base64

# Hex
fortress key generate --format hex

# Binary
fortress key generate --format raw
```

### Data Formats

```bash
# JSON (default)
fortress db query myapp users --format json

# Table
fortress db query myapp users --format table

# CSV
fortress db query myapp users --format csv

# Pretty-printed JSON
fortress db query myapp users --format pretty
```

## Examples

### Basic Workflow

```bash
# 1. Initialize Fortress
fortress init

# 2. Start server
fortress server start

# 3. Create database
fortress db create myapp

# 4. Generate key
fortress key generate --name user-data --algorithm aegis256

# 5. Insert encrypted data
fortress db insert myapp users '{
  "name": "Alice Johnson",
  "email": "alice@example.com",
  "ssn": "123-45-6789"
}'

# 6. Query data
fortress db query myapp users --where '{"email": "alice@example.com"}'
```

### Batch Operations

```bash
# Insert multiple records
cat users.json | fortress db insert-batch myapp users

# Bulk encrypt files
for file in *.txt; do
  fortress encrypt-file --key-id my-key "$file" "$file.enc"
done

# Bulk decrypt files
for file in *.enc; do
  fortress decrypt-file --key-id my-key "$file" "${file%.enc}"
done
```

### Script Integration

```bash
#!/bin/bash
# backup.sh - Fortress backup script

set -e

BACKUP_DIR="/backups/fortress"
DATE=$(date +%Y%m%d_%H%M%S)

# Create backup directory
mkdir -p "$BACKUP_DIR"

# Export all databases
for db in $(fortress db list --format json | jq -r '.[]'); do
  echo "Backing up database: $db"
  fortress db export "$db" --output "$BACKUP_DIR/${db}_${DATE}.json"
done

# Export all keys
fortress key list --format json > "$BACKUP_DIR/keys_${DATE}.json"

echo "Backup completed: $BACKUP_DIR"
```

## Advanced Usage

### Custom Profiles

```bash
# Development profile
fortress config init --profile development

# Production profile  
fortress config init --profile production

# High-security profile
fortress config init --profile fortress
```

### Plugin Management

```bash
# List available plugins
fortress plugin list

# Install plugin
fortress plugin install <plugin-name>

# Enable plugin
fortress plugin enable <plugin-name>

# Disable plugin
fortress plugin disable <plugin-name>

# Uninstall plugin
fortress plugin uninstall <plugin-name>
```

### Performance Monitoring

```bash
# Show performance metrics
fortress metrics show

# Show real-time metrics
fortress metrics watch

# Export metrics
fortress metrics export --format prometheus --output metrics.txt
```

## Troubleshooting

### Common Issues

**Server won't start**
```bash
# Check configuration
fortress config show

# Check logs
fortress server logs

# Check port availability
netstat -tlnp | grep :8080
```

**Key not found**
```bash
# List available keys
fortress key list

# Check key details
fortress key info <key-id>
```

**Connection refused**
```bash
# Check server status
fortress server status

# Check firewall settings
sudo ufw status
```

### Debug Mode

```bash
# Enable debug logging
export FORTRESS_LOG_LEVEL=debug

# Run with verbose output
fortress --verbose server start

# Enable trace logging
export FORTRESS_LOG_LEVEL=trace
```

## Completion

### Shell Completion

```bash
# Generate completion script
fortress completion bash > /etc/bash_completion.d/fortress
fortress completion zsh > /usr/local/share/zsh/site-functions/_fortress
fortress completion fish > ~/.config/fish/completions/fortress.fish

# Reload shell
source ~/.bashrc  # or ~/.zshrc
```

### Installation

```bash
# Bash
echo 'source <(fortress completion bash)' >> ~/.bashrc

# Zsh
echo 'source <(fortress completion zsh)' >> ~/.zshrc

# Fish
echo 'source <(fortress completion fish)' >> ~/.config/fish/config.fish
```

## License

This project is licensed under **MIT** - see the [LICENSE](../../LICENSE) file for details.

## Support

- **Documentation**: [https://github.com/Genius740Code/Fortress/blob/main/docs](https://github.com/Genius740Code/Fortress/blob/main/docs)
- **Issues**: [https://github.com/Genius740Code/Fortress/issues](https://github.com/Genius740Code/Fortress/issues)
- **Discussions**: [https://github.com/Genius740Code/Fortress/discussions](https://github.com/Genius740Code/Fortress/discussions)
- **Email**: team@fortressdb.io

---

**Fortress CLI** - Security at your fingertips.
