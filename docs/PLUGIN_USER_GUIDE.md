# Fortress Plugin User Guide

## 🚀 Quick Start: Installing Your First Plugin

Fortress plugins extend the functionality of your secure database with custom encryption algorithms, external API integrations, and specialized business logic. Here's how to get started:

### Prerequisites

- Fortress CLI installed (`cargo install fortress-cli`)
- Internet connection for downloading plugins
- Appropriate permissions for your Fortress plugins directory

### Basic Plugin Installation

```bash
# Search for available plugins
fortress plugin search "crypto signing"

# Install a plugin
fortress plugin install sign-transaction

# List installed plugins
fortress plugin list

# Use the plugin (example)
fortress data encrypt --plugin sign-transaction --data "my sensitive data"
```

## 📦 Plugin Marketplace

Fortress provides a centralized plugin marketplace where you can discover, download, and install plugins securely.

### Official Repository

The default plugin repository is hosted at:
- **URL**: `https://plugins.fortress-db.com`
- **Status**: Officially curated and verified
- **Security**: All plugins are cryptographically signed and scanned

### Using Custom Repositories

You can use custom plugin repositories:

```bash
# Install from a custom repository
fortress plugin install my-plugin --repo https://my-plugins.com

# Or configure a default repository
fortress config set plugins.repository https://my-plugins.com
```

## 🔍 Searching for Plugins

### Basic Search

```bash
# Search by keyword
fortress plugin search "encryption"

# Search with result limit
fortress plugin search "api integration" --limit 20
```

### Browse by Category

```bash
# List popular plugins
fortress plugin popular --limit 10

# Browse by category
fortress plugin category "crypto"
fortress plugin category "api"
fortress plugin category "storage"
```

### Available Categories

- **crypto**: Cryptographic operations (signing, hashing, key management)
- **api**: External API integrations
- **storage**: Storage backend plugins
- **monitoring**: Metrics and monitoring plugins
- **security**: Security and compliance plugins
- **utility**: General utility plugins

## 📥 Installing Plugins

### Simple Installation

```bash
# Install by plugin ID
fortress plugin install sign-transaction

# Install by plugin name (searches first)
fortress plugin install "Transaction Signer"
```

### Installation with Configuration

```bash
# Configure during installation
fortress plugin install weather-api \
  --config api_key=your_api_key \
  --config timeout=30 \
  --config city="New York"

# Interactive configuration
fortress plugin install weather-api --interactive
```

### Installation Options

| Option | Description | Example |
|--------|-------------|---------|
| `--repo` | Custom repository URL | `--repo https://plugins.example.com` |
| `--config` | Set configuration values | `--config key=value` |
| `--yes` | Skip confirmation prompts | `--yes` |
| `--dry-run` | Preview installation without installing | `--dry-run` |

### Installation Process

When you install a plugin, Fortress performs these steps:

1. **Download**: Fetches the plugin package from the repository
2. **Verify**: Checks cryptographic signatures and checksums
3. **Validate**: Ensures compatibility with your Fortress version
4. **Extract**: Unpacks the plugin to your plugins directory
5. **Configure**: Applies your configuration settings
6. **Register**: Makes the plugin available to Fortress

## 📋 Managing Installed Plugins

### List Installed Plugins

```bash
# Basic list
fortress plugin list

# Detailed information
fortress plugin list --detailed

# Filter by category
fortress plugin list --category crypto
```

### Plugin Information

```bash
# Show plugin details
fortress plugin show sign-transaction

# Shows:
# - Plugin metadata
# - Configuration schema
# - Installation date
# - Version information
# - Dependencies
```

### Updating Plugins

```bash
# Update a specific plugin
fortress plugin update sign-transaction

# Update all plugins
fortress plugin update

# Check for updates without installing
fortress plugin update --dry-run
```

### Uninstalling Plugins

```bash
# Uninstall with confirmation
fortress plugin uninstall sign-transaction

# Force uninstall (skip confirmation)
fortress plugin uninstall sign-transaction --yes
```

## ⚙️ Plugin Configuration

### Configuration Methods

#### 1. During Installation
```bash
fortress plugin install my-plugin --config key=value
```

#### 2. After Installation
```bash
# Edit configuration file
fortress plugin config edit my-plugin

# Set individual values
fortress plugin config set my-plugin api_key=new_key

# View current configuration
fortress plugin config show my-plugin
```

#### 3. Configuration Files
Plugin configurations are stored in:
```
~/.fortress/plugins/
├── plugin-id/
│   ├── metadata.json
│   ├── config.json
│   └── plugin.so
```

### Configuration Schema

Each plugin defines its own configuration schema. View it with:

```bash
fortress plugin show my-plugin --schema
```

Example configuration schema:
```json
{
  "type": "object",
  "properties": {
    "api_endpoint": {
      "type": "string",
      "description": "API endpoint URL"
    },
    "api_key": {
      "type": "string",
      "description": "API authentication key"
    },
    "timeout_seconds": {
      "type": "integer",
      "default": 30,
      "description": "Request timeout in seconds"
    }
  },
  "required": ["api_endpoint", "api_key"]
}
```

## 🔒 Security and Validation

### Plugin Verification

All plugins from the official repository are:

- **Cryptographically signed** with Fortress developer keys
- **Scanned for malware** and security vulnerabilities
- **Tested for compatibility** with specific Fortress versions
- **Reviewed for performance** and resource usage

### Security Checks During Installation

1. **Signature Verification**: Ensures plugin authenticity
2. **Checksum Validation**: Verifies download integrity
3. **Version Compatibility**: Checks Fortress version requirements
4. **Permission Review**: Validates requested permissions
5. **Dependency Validation**: Ensures required dependencies are available

### Security Best Practices

- **Only install from trusted repositories**
- **Review plugin permissions before installation**
- **Keep plugins updated to latest versions**
- **Monitor plugin resource usage**
- **Use environment variables for sensitive configuration**

## 🛠️ Advanced Usage

### Plugin Dependencies

Some plugins depend on other plugins:

```bash
# Install plugin with dependencies
fortress plugin install advanced-crypto

# Fortress will automatically install dependencies:
# ✅ Installing crypto-utils (dependency)
# ✅ Installing advanced-crypto
```

### Plugin Versioning

```bash
# Install specific version
fortress plugin install sign-transaction --version 2.1.0

# Install latest compatible version
fortress plugin install sign-transaction --latest-compatible

# Pin to current version (prevent auto-updates)
fortress plugin pin sign-transaction
```

### Plugin Environments

Use different plugin sets for different environments:

```bash
# Development environment
fortress plugin env dev
fortress plugin install mock-api

# Production environment  
fortress plugin env prod
fortress plugin install production-api

# Switch between environments
fortress plugin env dev
```

## 🔍 Troubleshooting

### Common Issues

#### Plugin Not Found
```bash
❌ Plugin 'unknown-plugin' not found

# Solutions:
# 1. Check spelling
fortress plugin search "similar-name"

# 2. Check repository
fortress plugin list --repo https://plugins.fortress-db.com

# 3. Update plugin index
fortress plugin update-index
```

#### Installation Failed
```bash
❌ Installation failed: Permission denied

# Solutions:
# 1. Check permissions
ls -la ~/.fortress/plugins/

# 2. Fix permissions
chmod 755 ~/.fortress/plugins/

# 3. Use sudo if necessary
sudo fortress plugin install system-plugin
```

#### Configuration Errors
```bash
❌ Plugin configuration validation failed

# Solutions:
# 1. Check required fields
fortress plugin show my-plugin --schema

# 2. Validate configuration
fortress plugin config validate my-plugin

# 3. Reset to defaults
fortress plugin config reset my-plugin
```

### Debug Mode

Enable debug logging for troubleshooting:

```bash
# Enable debug output
FORTRESS_LOG=debug fortress plugin install my-plugin

# Show detailed installation steps
fortress plugin install my-plugin --verbose

# Check plugin health
fortress plugin validate my-plugin
```

### Plugin Health Monitoring

```bash
# Check all plugins
fortress plugin validate

# Check specific plugin
fortress plugin validate my-plugin

# Show plugin metrics
fortress plugin metrics my-plugin
```

## 📚 Plugin Development

If you want to create your own plugins, see:
- [Plugin Development Guide](PLUGIN_DEVELOPMENT_GUIDE.md)
- [Plugin Architecture](PLUGIN_ARCHITECTURE.md)
- [API Reference](API_DOCUMENTATION.md)

## 🆘 Getting Help

### Command Help

```bash
# General help
fortress plugin --help

# Command-specific help
fortress plugin install --help
fortress plugin search --help
```

### Community Support

- **Discord**: [Fortress Community](https://discord.gg/fortress-db)
- **GitHub Issues**: [Report bugs](https://github.com/Genius740Code/Fortress/issues)
- **Documentation**: [Full docs](https://docs.fortress-db.com)

### Plugin Repository Issues

If you encounter issues with the plugin repository:

```bash
# Check repository status
fortress plugin repo status

# Change repository
fortress plugin repo set https://backup-plugins.fortress-db.com

# Reset to default
fortress plugin repo reset
```

## 📈 Best Practices

### 1. Plugin Management

- **Regular Updates**: Keep plugins updated for security and performance
- **Version Pinning**: Pin critical plugins to prevent breaking changes
- **Environment Isolation**: Use different plugin sets for dev/staging/prod
- **Monitoring**: Track plugin performance and resource usage

### 2. Security

- **Trusted Sources**: Only install from official or trusted repositories
- **Permission Review**: Understand what permissions each plugin requests
- **Configuration Security**: Use environment variables for sensitive data
- **Regular Audits**: Periodically review installed plugins and configurations

### 3. Performance

- **Resource Monitoring**: Monitor CPU, memory, and disk usage
- **Plugin Limits**: Set reasonable resource limits per plugin
- **Load Testing**: Test plugin performance under expected load
- **Cleanup**: Remove unused plugins to free up resources

---

## 🎉 Summary

With Fortress plugins, you can:

- **Extend functionality** with custom encryption, APIs, and business logic
- **Install securely** with verified, signed plugins from official repositories
- **Configure easily** with intuitive CLI commands and configuration files
- **Manage safely** with version control, updates, and health monitoring
- **Develop custom** plugins using the comprehensive plugin development framework

Start exploring plugins today:

```bash
# Search for plugins
fortress plugin search "encryption"

# Install your first plugin
fortress plugin install aegis-256-optimizer

# List what you have
fortress plugin list --detailed
```

Happy plugin hunting! 🚀
