# Fortress Usage Examples

## Table of Contents

1. [Quick Start Examples](#quick-start-examples)
2. [Core Library Examples](#core-library-examples)
3. [Server API Examples](#server-api-examples)
4. [CLI Examples](#cli-examples)
5. [Advanced Examples](#advanced-examples)
6. [Integration Examples](#integration-examples)
7. [Security Examples](#security-examples)
8. [Performance Examples](#performance-examples)

## Quick Start Examples

### Basic Encryption/Decryption

```rust
use fortress_core::prelude::*;
use fortress_core::encryption::{Aegis256, EncryptionAlgorithm};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize encryption algorithm
    let algorithm = Aegis256::new();
    
    // Generate encryption key
    let key_manager = KeyManager::new();
    let key = key_manager.generate_key(&algorithm)?;
    
    // Encrypt data
    let plaintext = b"Hello, Fortress!";
    let ciphertext = algorithm.encrypt(plaintext, &key)?;
    
    // Decrypt data
    let decrypted = algorithm.decrypt(&ciphertext, &key)?;
    
    assert_eq!(plaintext, decrypted);
    println!("✅ Encryption/Decryption successful!");
    
    Ok(())
}
```

### Simple Database Operations

```rust
use fortress_core::prelude::*;
use fortress_core::storage::{StorageBackend, MemoryStorage};
use fortress_core::config::Config;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create configuration
    let config = Config::default();
    
    // Initialize storage backend
    let storage = MemoryStorage::new(config).await?;
    
    // Store encrypted data
    let data = b"Sensitive user data";
    let metadata = serde_json::json!({
        "type": "user_data",
        "user_id": "user_123"
    });
    
    let data_id = storage.store(data, &metadata).await?;
    println!("✅ Data stored with ID: {}", data_id);
    
    // Retrieve data
    let (retrieved_data, retrieved_metadata) = storage.retrieve(&data_id).await?;
    assert_eq!(data, &retrieved_data[..]);
    
    println!("✅ Data retrieved successfully!");
    println!("📋 Metadata: {}", retrieved_metadata);
    
    Ok(())
}
```

## Core Library Examples

### Field-Level Encryption

```rust
use fortress_core::prelude::*;
use fortress_core::field_encryption::{FieldEncryptionManager, FieldEncryptionConfig};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
struct UserProfile {
    id: String,
    name: String,
    email: String,
    ssn: String,        // Will be encrypted with separate key
    credit_card: String, // Will be encrypted with separate key
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create field encryption manager
    let config = FieldEncryptionConfig::builder()
        .field("ssn", "aes256gcm", "critical")
        .field("credit_card", "aes256gcm", "high")
        .default_algorithm("aegis256")
        .build();
    
    let manager = FieldEncryptionManager::new(config).await?;
    
    // Create user profile
    let profile = UserProfile {
        id: "user_123".to_string(),
        name: "Alice Johnson".to_string(),
        email: "alice@example.com".to_string(),
        ssn: "123-45-6789".to_string(),
        credit_card: "4111-1111-1111-1111".to_string(),
    };
    
    // Encrypt sensitive fields
    let encrypted_profile = manager.encrypt_fields(&profile).await?;
    
    println!("✅ Profile encrypted:");
    println!("📝 Name: {} (not encrypted)", encrypted_profile.name);
    println!("🔒 SSN: {} (encrypted)", encrypted_profile.ssn);
    println!("💳 Credit Card: {} (encrypted)", encrypted_profile.credit_card);
    
    // Decrypt fields
    let decrypted_profile = manager.decrypt_fields(&encrypted_profile).await?;
    
    assert_eq!(profile.ssn, decrypted_profile.ssn);
    assert_eq!(profile.credit_card, decrypted_profile.credit_card);
    
    println!("✅ Fields decrypted successfully!");
    
    Ok(())
}
```

### Key Rotation

```rust
use fortress_core::prelude::*;
use fortress_core::key::{KeyManager, SmartKeyRotationScheduler, RotationInterval};
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize key manager
    let key_manager = KeyManager::new();
    
    // Create rotation scheduler
    let scheduler = SmartKeyRotationScheduler::new(key_manager.clone());
    
    // Configure rotation interval
    let rotation_interval = RotationInterval::Duration(Duration::from_secs(86400)); // 24 hours
    
    // Start automatic rotation
    scheduler.start_rotation(rotation_interval).await?;
    
    // Generate initial key
    let algorithm = Aegis256::new();
    let key = key_manager.generate_key(&algorithm)?;
    
    println!("🔑 Generated key: {}", key.id());
    
    // Manually trigger rotation for demo
    let new_key = scheduler.rotate_key(&key.id()).await?;
    
    println!("🔄 Rotated key: {} -> {}", key.id(), new_key.id());
    
    // Get rotation metrics
    let metrics = scheduler.get_metrics().await?;
    println!("📊 Rotation metrics:");
    println!("   Total rotations: {}", metrics.total_rotations);
    println!("   Successful rotations: {}", metrics.successful_rotations);
    println!("   Failed rotations: {}", metrics.failed_rotations);
    
    Ok(())
}
```

### Performance Profiling

```rust
use fortress_core::prelude::*;
use fortress_core::performance_profile::{PerformanceProfile, ProfileManager};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create performance profile
    let profile = PerformanceProfile::builder()
        .name("high_performance")
        .encryption_algorithm("aegis256")
        .cache_size(10000)
        .connection_pool_size(50)
        .compression_enabled(true)
        .build();
    
    // Initialize profile manager
    let manager = ProfileManager::new().await?;
    
    // Register profile
    manager.register_profile(profile.clone()).await?;
    
    // Apply profile
    manager.apply_profile("high_performance").await?;
    
    println!("🚀 Applied high performance profile:");
    println!("   Algorithm: {}", profile.encryption_settings.algorithm);
    println!("   Cache size: {}", profile.cache_size);
    println!("   Connection pool: {}", profile.connection_pool_size);
    
    // Benchmark performance
    let start = std::time::Instant::now();
    
    // Perform encryption operations
    let algorithm = Aegis256::new();
    let key_manager = KeyManager::new();
    let key = key_manager.generate_key(&algorithm)?;
    
    for i in 0..1000 {
        let data = format!("Test data {}", i);
        let ciphertext = algorithm.encrypt(data.as_bytes(), &key)?;
        let _decrypted = algorithm.decrypt(&ciphertext, &key)?;
    }
    
    let duration = start.elapsed();
    println!("⏱️  1000 operations in {:?}", duration);
    println!("📈 Average: {:.2}ms per operation", duration.as_millis() as f64 / 1000.0);
    
    Ok(())
}
```

## Server API Examples

### HTTP Client with Authentication

```python
import requests
import json
import time
from typing import Optional, Dict, Any

class FortressAPIClient:
    def __init__(self, base_url: str = "http://localhost:8080"):
        self.base_url = base_url
        self.session = requests.Session()
        self.token: Optional[str] = None
    
    def login(self, username: str, password: str, tenant_id: Optional[str] = None) -> bool:
        """Authenticate with the Fortress server"""
        try:
            response = self.session.post(
                f"{self.base_url}/auth/login",
                json={
                    "username": username,
                    "password": password,
                    "tenant_id": tenant_id
                }
            )
            
            if response.status_code == 200:
                data = response.json()
                if data["success"]:
                    self.token = data["data"]["token"]
                    self.session.headers.update({
                        "Authorization": f"Bearer {self.token}"
                    })
                    return True
            return False
        except Exception as e:
            print(f"Login error: {e}")
            return False
    
    def create_database(self, name: str, algorithm: str = "aegis256") -> Optional[Dict[str, Any]]:
        """Create a new database"""
        try:
            response = self.session.post(
                f"{self.base_url}/databases",
                json={
                    "name": name,
                    "algorithm": algorithm,
                    "key_rotation_interval": "24h"
                }
            )
            
            if response.status_code == 200:
                data = response.json()
                if data["success"]:
                    return data["data"]
            return None
        except Exception as e:
            print(f"Create database error: {e}")
            return None
    
    def create_table(self, database_id: str, table_name: str, columns: list) -> Optional[Dict[str, Any]]:
        """Create a new table"""
        try:
            response = self.session.post(
                f"{self.base_url}/databases/{database_id}/tables",
                json={
                    "name": table_name,
                    "columns": columns,
                    "encryption": "balanced"
                }
            )
            
            if response.status_code == 200:
                data = response.json()
                if data["success"]:
                    return data["data"]
            return None
        except Exception as e:
            print(f"Create table error: {e}")
            return None
    
    def insert_data(self, database_id: str, table_name: str, data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Insert data into table"""
        try:
            response = self.session.post(
                f"{self.base_url}/databases/{database_id}/tables/{table_name}/data",
                json={"data": data}
            )
            
            if response.status_code == 200:
                result = response.json()
                if result["success"]:
                    return result["data"]
            return None
        except Exception as e:
            print(f"Insert data error: {e}")
            return None
    
    def query_data(self, database_id: str, table_name: str, filter_expr: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """Query data from table"""
        try:
            params = {}
            if filter_expr:
                params["filter"] = filter_expr
            
            response = self.session.get(
                f"{self.base_url}/databases/{database_id}/tables/{table_name}/data",
                params=params
            )
            
            if response.status_code == 200:
                data = response.json()
                if data["success"]:
                    return data["data"]
            return None
        except Exception as e:
            print(f"Query data error: {e}")
            return None

# Usage example
def main():
    client = FortressAPIClient()
    
    # Authenticate
    if not client.login("admin", "admin123"):
        print("❌ Authentication failed")
        return
    
    print("✅ Authentication successful")
    
    # Create database
    db = client.create_database("myapp_db")
    if not db:
        print("❌ Failed to create database")
        return
    
    print(f"✅ Database created: {db['id']}")
    
    # Create table
    table_columns = [
        {"name": "id", "type": "uuid", "primary_key": True},
        {"name": "name", "type": "text"},
        {"name": "email", "type": "text", "unique": True},
        {"name": "password", "type": "encrypted", "sensitivity": "high"},
        {"name": "ssn", "type": "encrypted", "sensitivity": "critical"}
    ]
    
    table = client.create_table(db["id"], "users", table_columns)
    if not table:
        print("❌ Failed to create table")
        return
    
    print(f"✅ Table created: {table['id']}")
    
    # Insert data
    user_data = {
        "id": "550e8400-e29b-41d4-a716-446655440000",
        "name": "Alice Johnson",
        "email": "alice@example.com",
        "password": "secure-password-123",
        "ssn": "123-45-6789"
    }
    
    result = client.insert_data(db["id"], "users", user_data)
    if not result:
        print("❌ Failed to insert data")
        return
    
    print(f"✅ Data inserted: {result['id']}")
    
    # Query data
    users = client.query_data(db["id"], "users")
    if users:
        print(f"✅ Found {len(users)} users")
        for user in users:
            print(f"   👤 {user['name']} ({user['email']})")
    
    print("🎉 All operations completed successfully!")

if __name__ == "__main__":
    main()
```

### WebSocket Real-time Updates

```javascript
const WebSocket = require('ws');

class FortressWebSocketClient {
    constructor(url = 'ws://localhost:8080/ws') {
        this.url = url;
        this.ws = null;
        this.token = null;
        this.eventHandlers = {};
    }
    
    async connect(username, password) {
        return new Promise((resolve, reject) => {
            this.ws = new WebSocket(this.url);
            
            this.ws.on('open', () => {
                console.log('🔗 WebSocket connected');
                
                // Authenticate
                this.send({
                    type: 'auth',
                    username: username,
                    password: password
                });
            });
            
            this.ws.on('message', (data) => {
                const message = JSON.parse(data.toString());
                
                if (message.type === 'auth_response') {
                    if (message.success) {
                        this.token = message.token;
                        console.log('✅ Authentication successful');
                        resolve();
                    } else {
                        console.error('❌ Authentication failed');
                        reject(new Error('Authentication failed'));
                    }
                } else if (message.type === 'event') {
                    this.handleEvent(message.event);
                }
            });
            
            this.ws.on('error', (error) => {
                console.error('❌ WebSocket error:', error);
                reject(error);
            });
            
            this.ws.on('close', () => {
                console.log('🔌 WebSocket disconnected');
            });
        });
    }
    
    send(message) {
        if (this.ws && this.ws.readyState === WebSocket.OPEN) {
            this.ws.send(JSON.stringify(message));
        }
    }
    
    subscribe(events) {
        this.send({
            type: 'subscribe',
            events: events
        });
    }
    
    on(eventType, handler) {
        if (!this.eventHandlers[eventType]) {
            this.eventHandlers[eventType] = [];
        }
        this.eventHandlers[eventType].push(handler);
    }
    
    handleEvent(event) {
        const handlers = this.eventHandlers[event.type] || [];
        handlers.forEach(handler => handler(event));
    }
    
    close() {
        if (this.ws) {
            this.ws.close();
        }
    }
}

// Usage example
async function main() {
    const client = new FortressWebSocketClient();
    
    try {
        // Connect and authenticate
        await client.connect('admin', 'admin123');
        
        // Subscribe to events
        client.subscribe(['data_change', 'key_rotation', 'audit_log']);
        
        // Set up event handlers
        client.on('data_change', (event) => {
            console.log(`📝 Data change: ${event.operation} on ${event.table}`);
            console.log(`   Record ID: ${event.record_id}`);
            console.log(`   Timestamp: ${event.timestamp}`);
        });
        
        client.on('key_rotation', (event) => {
            console.log(`🔄 Key rotation: ${event.rotation_id}`);
            console.log(`   Progress: ${event.progress}%`);
            console.log(`   Status: ${event.status}`);
        });
        
        client.on('audit_log', (event) => {
            console.log(`📋 Audit: ${event.audit_entry.event_type}`);
            console.log(`   User: ${event.audit_entry.user_id}`);
            console.log(`   Action: ${event.audit_entry.action}`);
        });
        
        console.log('👂 Listening for events...');
        
        // Keep connection alive
        await new Promise(resolve => setTimeout(resolve, 60000)); // 1 minute
        
    } catch (error) {
        console.error('❌ Error:', error.message);
    } finally {
        client.close();
    }
}

main();
```

## CLI Examples

### Database Setup Script

```bash
#!/bin/bash

# Fortress Database Setup Script
set -e

# Configuration
DB_NAME="production_db"
DATA_DIR="/var/lib/fortress/prod"
TEMPLATE="enterprise"
PORT=8080

echo "🚀 Setting up Fortress database..."

# Create data directory
sudo mkdir -p "$DATA_DIR"
sudo chown -R $USER:$USER "$DATA_DIR"
chmod 755 "$DATA_DIR"

# Create database
echo "📦 Creating database: $DB_NAME"
fortress create \
    --name "$DB_NAME" \
    --template "$TEMPLATE" \
    --data-dir "$DATA_DIR" \
    --verbose

# Generate encryption keys
echo "🔑 Generating encryption keys"
fortress key generate \
    --algorithm aegis256 \
    --purpose data-encryption \
    --output "$DATA_DIR/primary.key"

fortress key generate \
    --algorithm aes256gcm \
    --purpose field-encryption \
    --output "$DATA_DIR/field.key"

# List generated keys
echo "📋 Generated keys:"
fortress key list --status active

# Configure server
echo "⚙️ Configuring server"
fortress config set network.host 0.0.0.0
fortress config set network.port $PORT
fortress config set encryption.default_algorithm aegis256
fortress config set logging.level info

# Validate configuration
echo "✅ Validating configuration"
fortress config validate --strict

# Start server
echo "🚀 Starting Fortress server"
fortress start \
    --data-dir "$DATA_DIR" \
    --port $PORT \
    --host 0.0.0.0 &

# Wait for server to be ready
echo "⏳ Waiting for server to start..."
sleep 5

# Check server status
echo "📊 Checking server status"
if curl -f http://localhost:$PORT/health > /dev/null 2>&1; then
    echo "✅ Fortress server is running on port $PORT"
    echo "🌐 API available at: http://localhost:$PORT/api/v1"
    echo "📊 Health check: http://localhost:$PORT/health"
    echo "📈 Metrics: http://localhost:$PORT/metrics"
else
    echo "❌ Failed to start server"
    exit 1
fi

echo "🎉 Setup completed successfully!"
```

### Cluster Management Script

```bash
#!/bin/bash

# Fortress Cluster Management Script
set -e

# Configuration
CLUSTER_NAME="prod-cluster"
NODES=("192.168.1.10" "192.168.1.11" "192.168.1.12")
PORT=8080

echo "🏗️ Setting up Fortress cluster..."

# Function to check if node is reachable
check_node() {
    local node=$1
    if ping -c 1 "$node" > /dev/null 2>&1; then
        echo "✅ Node $node is reachable"
        return 0
    else
        echo "❌ Node $node is not reachable"
        return 1
    fi
}

# Function to initialize cluster on leader node
init_cluster() {
    local leader=$1
    echo "👑 Initializing cluster on leader: $leader"
    
    ssh $1 "
        fortress cluster init \
            --name $CLUSTER_NAME \
            --nodes ${#NODES[@]} \
            --algorithm raft
    "
}

# Function to join node to cluster
join_node() {
    local node=$1
    local leader=$2
    echo "🔗 Joining node $node to cluster"
    
    ssh $node "
        fortress cluster join $leader:$PORT \
            --node-id node-$(echo $node | tr '.' '-')
    "
}

# Check all nodes are reachable
echo "🔍 Checking node connectivity..."
for node in "${NODES[@]}"; do
    check_node $node || exit 1
done

# Initialize cluster on first node
echo "🚀 Initializing cluster..."
init_cluster ${NODES[0]}

# Join remaining nodes to cluster
for i in "${!NODES[@]}"; do
    if [ $i -gt 0 ]; then
        join_node ${NODES[$i]} ${NODES[0]}
    fi
done

# Check cluster status
echo "📊 Checking cluster status..."
ssh ${NODES[0]} "fortress cluster status --detailed"

echo "🎉 Cluster setup completed!"
echo "📋 Cluster nodes:"
for node in "${NODES[@]}"; do
    echo "   🖥️  $node:$PORT"
done
```

### Backup and Restore Script

```bash
#!/bin/bash

# Fortress Backup and Restore Script
set -e

# Configuration
BACKUP_DIR="/var/backups/fortress"
DATA_DIR="/var/lib/fortress/prod"
RETENTION_DAYS=30

# Create backup directory
mkdir -p "$BACKUP_DIR"

# Function to create backup
create_backup() {
    local backup_name="fortress_backup_$(date +%Y%m%d_%H%M%S)"
    local backup_path="$BACKUP_DIR/$backup_name"
    
    echo "📦 Creating backup: $backup_name"
    
    # Stop server gracefully
    echo "🛑 Stopping Fortress server"
    fortress stop --graceful --timeout 60
    
    # Create backup
    mkdir -p "$backup_path"
    
    # Backup data directory
    echo "📁 Backing up data directory"
    tar -czf "$backup_path/data.tar.gz" -C "$(dirname "$DATA_DIR")" "$(basename "$DATA_DIR")"
    
    # Backup configuration
    echo "⚙️ Backing up configuration"
    cp ~/.fortress/config.toml "$backup_path/"
    
    # Backup keys
    echo "🔑 Backing up encryption keys"
    cp "$DATA_DIR"/*.key "$backup_path/" 2>/dev/null || true
    
    # Create backup metadata
    cat > "$backup_path/metadata.json" << EOF
{
    "backup_name": "$backup_name",
    "created_at": "$(date -Iseconds)",
    "fortress_version": "$(fortress --version)",
    "data_size_bytes": $(du -sb "$DATA_DIR" | cut -f1),
    "files": [
        "data.tar.gz",
        "config.toml",
        "metadata.json"
    ]
}
EOF
    
    echo "✅ Backup created: $backup_path"
    
    # Start server
    echo "🚀 Starting Fortress server"
    fortress start --data-dir "$DATA_DIR"
    
    # Wait for server to be ready
    sleep 5
    curl -f http://localhost:8080/health > /dev/null 2>&1 || {
        echo "❌ Failed to start server after backup"
        exit 1
    }
    
    echo "🎉 Backup completed successfully!"
}

# Function to restore backup
restore_backup() {
    local backup_name=$1
    local backup_path="$BACKUP_DIR/$backup_name"
    
    if [ ! -d "$backup_path" ]; then
        echo "❌ Backup not found: $backup_name"
        exit 1
    fi
    
    echo "🔄 Restoring from backup: $backup_name"
    
    # Stop server
    echo "🛑 Stopping Fortress server"
    fortress stop --graceful --timeout 60
    
    # Backup current data (just in case)
    if [ -d "$DATA_DIR" ]; then
        echo "💾 Backing up current data"
        mv "$DATA_DIR" "${DATA_DIR}.backup.$(date +%s)"
    fi
    
    # Restore data
    echo "📁 Restoring data directory"
    tar -xzf "$backup_path/data.tar.gz" -C "$(dirname "$DATA_DIR")"
    
    # Restore configuration
    echo "⚙️ Restoring configuration"
    cp "$backup_path/config.toml" ~/.fortress/
    
    # Restore keys
    echo "🔑 Restoring encryption keys"
    cp "$backup_path"/*.key "$DATA_DIR/" 2>/dev/null || true
    
    # Set permissions
    chown -R $USER:$USER "$DATA_DIR"
    chmod 755 "$DATA_DIR"
    
    # Start server
    echo "🚀 Starting Fortress server"
    fortress start --data-dir "$DATA_DIR"
    
    # Wait for server to be ready
    sleep 5
    if curl -f http://localhost:8080/health > /dev/null 2>&1; then
        echo "✅ Server started successfully"
    else
        echo "❌ Failed to start server after restore"
        exit 1
    fi
    
    echo "🎉 Restore completed successfully!"
}

# Function to list backups
list_backups() {
    echo "📋 Available backups:"
    ls -la "$BACKUP_DIR" | grep "^d" | awk '{print $9}' | grep "fortress_backup_" | while read backup; do
        echo "   📦 $backup"
        echo "      📅 Created: $(stat -c %y "$BACKUP_DIR/$backup")"
        echo "      📊 Size: $(du -sh "$BACKUP_DIR/$backup" | cut -f1)"
    done
}

# Function to clean old backups
cleanup_backups() {
    echo "🧹 Cleaning up old backups (older than $RETENTION_DAYS days)"
    
    find "$BACKUP_DIR" -type d -name "fortress_backup_*" -mtime +$RETENTION_DAYS -exec rm -rf {} \;
    
    echo "✅ Cleanup completed"
}

# Main script logic
case "${1:-}" in
    "create")
        create_backup
        ;;
    "restore")
        if [ -z "${2:-}" ]; then
            echo "❌ Please specify backup name"
            echo "Usage: $0 restore <backup_name>"
            exit 1
        fi
        restore_backup "$2"
        ;;
    "list")
        list_backups
        ;;
    "cleanup")
        cleanup_backups
        ;;
    *)
        echo "Usage: $0 {create|restore|list|cleanup}"
        echo ""
        echo "Commands:"
        echo "  create    - Create a new backup"
        echo "  restore   - Restore from backup"
        echo "  list      - List available backups"
        echo "  cleanup   - Clean up old backups"
        exit 1
        ;;
esac
```

## Advanced Examples

### Custom Plugin Development

```rust
use fortress_core::prelude::*;
use fortress_core::plugin::{Plugin, PluginContext, PluginResult};
use serde_json::Value;

struct AuditPlugin {
    enabled: bool,
    log_level: String,
}

impl Plugin for AuditPlugin {
    fn name(&self) -> &str {
        "enhanced-audit"
    }
    
    fn version(&self) -> &str {
        "1.0.0"
    }
    
    async fn initialize(&mut self, context: &PluginContext) -> PluginResult<()> {
        self.enabled = context.config.get("enabled").unwrap_or(&Value::Bool(true)).as_bool().unwrap_or(true);
        self.log_level = context.config.get("log_level").unwrap_or(&Value::String("info".to_string())).as_str().unwrap_or("info").to_string();
        
        println!("🔍 Enhanced Audit Plugin initialized");
        println!("   Enabled: {}", self.enabled);
        println!("   Log level: {}", self.log_level);
        
        Ok(())
    }
    
    async fn execute(&self, input: PluginInput) -> PluginResult<PluginOutput> {
        if !self.enabled {
            return Ok(PluginOutput::success(Value::Null));
        }
        
        match input.operation.as_str() {
            "log_access" => {
                let user_id = input.params.get("user_id").unwrap().as_str().unwrap();
                let resource = input.params.get("resource").unwrap().as_str().unwrap();
                let action = input.params.get("action").unwrap().as_str().unwrap();
                
                let audit_entry = serde_json::json!({
                    "timestamp": chrono::Utc::now().to_rfc3339(),
                    "user_id": user_id,
                    "resource": resource,
                    "action": action,
                    "outcome": "success",
                    "plugin": "enhanced-audit"
                });
                
                // Log to enhanced audit system
                println!("📋 Enhanced Audit: {}", audit_entry);
                
                Ok(PluginOutput::success(audit_entry))
            }
            _ => Ok(PluginOutput::error("Unsupported operation"))
        }
    }
    
    async fn cleanup(&mut self) -> PluginResult<()> {
        println!("🔍 Enhanced Audit Plugin cleaned up");
        Ok(())
    }
}

// Plugin factory function
#[no_mangle]
pub extern "C" fn create_plugin() -> *mut dyn Plugin {
    let plugin = AuditPlugin {
        enabled: true,
        log_level: "info".to_string(),
    };
    Box::into_raw(Box::new(plugin))
}
```

### Multi-Tenant Application

```rust
use fortress_core::prelude::*;
use fortress_core::tenant::{TenantManager, InMemoryTenantManager, CreateTenantRequest};
use std::collections::HashMap;

struct MultiTenantApp {
    tenant_manager: InMemoryTenantManager,
    tenant_connections: HashMap<String, DatabaseConnection>,
}

impl MultiTenantApp {
    fn new() -> Self {
        Self {
            tenant_manager: InMemoryTenantManager::new(),
            tenant_connections: HashMap::new(),
        }
    }
    
    async fn create_tenant(&mut self, name: &str, domain: &str) -> Result<String, Box<dyn std::error::Error>> {
        let request = CreateTenantRequest {
            name: name.to_string(),
            domain: domain.to_string(),
            resource_limits: Default::default(),
            encryption_config: Default::default(),
        };
        
        let tenant = self.tenant_manager.create_tenant(request).await?;
        
        // Create isolated database for tenant
        let connection = self.create_tenant_database(&tenant.id).await?;
        self.tenant_connections.insert(tenant.id.clone(), connection);
        
        println!("🏢 Created tenant: {} ({})", tenant.name, tenant.id);
        
        Ok(tenant.id)
    }
    
    async fn create_tenant_database(&self, tenant_id: &str) -> Result<DatabaseConnection, Box<dyn std::error::Error>> {
        // Create tenant-specific database with isolation
        let db_name = format!("tenant_{}", tenant_id);
        let data_dir = format!("./data/tenants/{}", tenant_id);
        
        // Initialize database with tenant-specific configuration
        let config = Config::builder()
            .database_name(&db_name)
            .data_path(&data_dir)
            .encryption_algorithm("aegis256")
            .tenant_isolation(true)
            .build();
        
        let connection = DatabaseConnection::new(config).await?;
        
        println!("🗄️ Created database for tenant: {}", db_name);
        
        Ok(connection)
    }
    
    async fn get_tenant_connection(&mut self, tenant_id: &str) -> Option<&DatabaseConnection> {
        self.tenant_connections.get(tenant_id)
    }
    
    async fn store_tenant_data(&mut self, tenant_id: &str, data: &[u8]) -> Result<String, Box<dyn std::error::Error>> {
        let connection = self.get_tenant_connection(tenant_id).ok_or("Tenant not found")?;
        
        let metadata = serde_json::json!({
            "tenant_id": tenant_id,
            "created_at": chrono::Utc::now().to_rfc3339()
        });
        
        let data_id = connection.store(data, &metadata).await?;
        
        println!("💾 Stored data for tenant {}: {}", tenant_id, data_id);
        
        Ok(data_id)
    }
    
    async fn get_tenant_stats(&self, tenant_id: &str) -> Result<TenantStats, Box<dyn std::error::Error>> {
        let stats = self.tenant_manager.get_tenant_stats(tenant_id).await?;
        
        println!("📊 Stats for tenant {}:", tenant_id);
        println!("   Databases: {}", stats.database_count);
        println!("   Storage used: {} MB", stats.storage_used_mb);
        println!("   Request count: {}", stats.request_count);
        
        Ok(stats)
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut app = MultiTenantApp::new();
    
    // Create tenants
    let tenant1 = app.create_tenant("Company A", "company-a.com").await?;
    let tenant2 = app.create_tenant("Company B", "company-b.com").await?;
    
    // Store data for each tenant
    let data1 = b"Sensitive data for Company A";
    let data2 = b"Confidential data for Company B";
    
    let id1 = app.store_tenant_data(&tenant1, data1).await?;
    let id2 = app.store_tenant_data(&tenant2, data2).await?;
    
    // Get tenant statistics
    app.get_tenant_stats(&tenant1).await?;
    app.get_tenant_stats(&tenant2).await?;
    
    println!("🎉 Multi-tenant application demo completed!");
    
    Ok(())
}
```

## Integration Examples

### Docker Integration

```dockerfile
# Dockerfile for Fortress application
FROM rust:1.70 as builder

WORKDIR /app
COPY . .

# Build Fortress
RUN cargo build --release

# Runtime image
FROM debian:bookworm-slim

# Install dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Create fortress user
RUN useradd -m -u 1000 fortress

# Copy binary
COPY --from=builder /app/target/release/fortress /usr/local/bin/
COPY --from=builder /app/target/release/fortress-server /usr/local/bin/

# Create directories
RUN mkdir -p /var/lib/fortress /var/log/fortress /etc/fortress
RUN chown -R fortress:fortress /var/lib/fortress /var/log/fortress /etc/fortress

# Copy configuration
COPY docker/fortress.toml /etc/fortress/

# Switch to fortress user
USER fortress

# Expose port
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

# Start command
CMD ["fortress-server", "--config", "/etc/fortress/fortress.toml"]
```

```yaml
# docker-compose.yml
version: '3.8'

services:
  fortress:
    build: .
    ports:
      - "8080:8080"
    volumes:
      - fortress_data:/var/lib/fortress
      - fortress_logs:/var/log/fortress
    environment:
      - FORTRESS_LOG_LEVEL=info
      - FORTRESS_DATA_DIR=/var/lib/fortress
    networks:
      - fortress_network
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8080/health"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 40s

  fortress-cli:
    build: .
    command: tail -f /dev/null
    volumes:
      - fortress_data:/var/lib/fortress
      - ./scripts:/scripts
    networks:
      - fortress_network
    profiles:
      - cli

volumes:
  fortress_data:
  fortress_logs:

networks:
  fortress_network:
    driver: bridge
```

### Kubernetes Integration

```yaml
# k8s/fortress-deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: fortress
  labels:
    app: fortress
spec:
  replicas: 3
  selector:
    matchLabels:
      app: fortress
  template:
    metadata:
      labels:
        app: fortress
    spec:
      containers:
      - name: fortress
        image: fortress:latest
        ports:
        - containerPort: 8080
        env:
        - name: FORTRESS_LOG_LEVEL
          value: "info"
        - name: FORTRESS_DATA_DIR
          value: "/var/lib/fortress"
        volumeMounts:
        - name: fortress-data
          mountPath: /var/lib/fortress
        - name: fortress-config
          mountPath: /etc/fortress
        resources:
          requests:
            memory: "512Mi"
            cpu: "250m"
          limits:
            memory: "1Gi"
            cpu: "500m"
        livenessProbe:
          httpGet:
            path: /health
            port: 8080
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /health
            port: 8080
          initialDelaySeconds: 5
          periodSeconds: 5
      volumes:
      - name: fortress-data
        persistentVolumeClaim:
          claimName: fortress-pvc
      - name: fortress-config
        configMap:
          name: fortress-config
---
apiVersion: v1
kind: Service
metadata:
  name: fortress-service
spec:
  selector:
    app: fortress
  ports:
  - protocol: TCP
    port: 8080
    targetPort: 8080
  type: ClusterIP
---
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: fortress-pvc
spec:
  accessModes:
    - ReadWriteOnce
  resources:
    requests:
      storage: 10Gi
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: fortress-config
data:
  fortress.toml: |
    [general]
    log_level = "info"
    
    [network]
    host = "0.0.0.0"
    port = 8080
    
    [encryption]
    default_algorithm = "aegis256"
    key_rotation_interval = "24h"
    
    [storage]
    backend = "sqlite"
    path = "/var/lib/fortress/fortress.db"
```

### Prometheus Monitoring

```yaml
# monitoring/prometheus.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: prometheus-config
data:
  prometheus.yml: |
    global:
      scrape_interval: 15s
    
    scrape_configs:
    - job_name: 'fortress'
      static_configs:
      - targets: ['fortress-service:8080']
      metrics_path: /metrics/prometheus
      scrape_interval: 10s
      
    - job_name: 'fortress-health'
      static_configs:
      - targets: ['fortress-service:8080']
      metrics_path: /health
      scrape_interval: 30s
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: prometheus
spec:
  replicas: 1
  selector:
    matchLabels:
      app: prometheus
  template:
    metadata:
      labels:
        app: prometheus
    spec:
      containers:
      - name: prometheus
        image: prom/prometheus:latest
        ports:
        - containerPort: 9090
        volumeMounts:
        - name: prometheus-config
          mountPath: /etc/prometheus
        command:
        - '/bin/prometheus'
        - '--config.file=/etc/prometheus/prometheus.yml'
        - '--storage.tsdb.path=/prometheus'
        - '--web.console.libraries=/etc/prometheus/console_libraries'
        - '--web.console.templates=/etc/prometheus/consoles'
      volumes:
      - name: prometheus-config
        configMap:
          name: prometheus-config
---
apiVersion: v1
kind: Service
metadata:
  name: prometheus-service
spec:
  selector:
    app: prometheus
  ports:
  - protocol: TCP
    port: 9090
    targetPort: 9090
  type: LoadBalancer
```

## Security Examples

### HSM Integration

```rust
use fortress_core::prelude::*;
use fortress_core::hsm::{HsmProvider, HsmConfig, HsmKeyManager};

struct HsmIntegration {
    hsm_provider: Box<dyn HsmProvider>,
    key_manager: HsmKeyManager,
}

impl HsmIntegration {
    async fn new() -> Result<Self, Box<dyn std::error::Error>> {
        // Configure HSM provider
        let config = HsmConfig::builder()
            .provider("thales")
            .endpoint("https://hsm.example.com")
            .api_key("your-hsm-api-key")
            .build();
        
        // Initialize HSM provider
        let hsm_provider = fortress_core::hsm::create_provider(config).await?;
        
        // Initialize key manager with HSM
        let key_manager = HsmKeyManager::new(hsm_provider.clone()).await?;
        
        Ok(Self {
            hsm_provider,
            key_manager,
        })
    }
    
    async fn generate_hsm_key(&self, key_name: &str) -> Result<String, Box<dyn std::error::Error>> {
        let key_id = self.key_manager.generate_key(key_name, "aes256").await?;
        
        println!("🔐 Generated HSM key: {} ({})", key_name, key_id);
        
        Ok(key_id)
    }
    
    async fn encrypt_with_hsm(&self, key_id: &str, data: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let ciphertext = self.key_manager.encrypt(key_id, data).await?;
        
        println!("🔒 Encrypted data with HSM key: {}", key_id);
        
        Ok(ciphertext)
    }
    
    async fn decrypt_with_hsm(&self, key_id: &str, ciphertext: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let plaintext = self.key_manager.decrypt(key_id, ciphertext).await?;
        
        println!("🔓 Decrypted data with HSM key: {}", key_id);
        
        Ok(plaintext)
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let hsm_integration = HsmIntegration::new().await?;
    
    // Generate HSM key
    let key_id = hsm_integration.generate_hsm_key("data-encryption-key").await?;
    
    // Encrypt and decrypt data
    let data = b"Highly sensitive data requiring HSM protection";
    let ciphertext = hsm_integration.encrypt_with_hsm(&key_id, data).await?;
    let plaintext = hsm_integration.decrypt_with_hsm(&key_id, &ciphertext).await?;
    
    assert_eq!(data, &plaintext[..]);
    
    println!("✅ HSM integration successful!");
    
    Ok(())
}
```

### Compliance Framework

```rust
use fortress_core::prelude::*;
use fortress_core::compliance::{ComplianceManager, ComplianceStandard, DataClassification};

struct ComplianceExample {
    compliance_manager: ComplianceManager,
}

impl ComplianceExample {
    fn new() -> Self {
        Self {
            compliance_manager: ComplianceManager::new(),
        }
    }
    
    async fn setup_gdpr_compliance(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        // Create GDPR compliance policy
        let gdpr_policy = fortress_core::compliance::create_default_gdpr_policy();
        
        // Register policy
        self.compliance_manager.register_policy(gdpr_policy).await?;
        
        println!("🇪🇺 GDPR compliance policy registered");
        
        Ok(())
    }
    
    async fn classify_data(&self, data: &[u8]) -> Result<DataClassification, Box<dyn std::error::Error>> {
        let classification = self.compliance_manager.classify_data(data).await?;
        
        println!("📊 Data classification: {:?}", classification);
        
        Ok(classification)
    }
    
    async fn handle_data_subject_request(&self, user_id: &str, request_type: &str) -> Result<(), Box<dyn std::error::Error>> {
        let request = fortress_core::compliance::DataSubjectRequest {
            user_id: user_id.to_string(),
            request_type: request_type.parse().unwrap(),
            timestamp: chrono::Utc::now(),
        };
        
        let result = self.compliance_manager.process_data_subject_request(request).await?;
        
        println!("👤 Data subject request processed: {:?}", result);
        
        Ok(())
    }
    
    async fn generate_compliance_report(&self, standard: ComplianceStandard) -> Result<(), Box<dyn std::error::Error>> {
        let report = self.compliance_manager.generate_report(standard).await?;
        
        println!("📋 Compliance report for {:?}:", standard);
        println!("   Overall score: {}%", report.overall_score);
        println!("   Passed controls: {}", report.passed_controls);
        println!("   Failed controls: {}", report.failed_controls);
        
        Ok(())
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut compliance_example = ComplianceExample::new();
    
    // Setup compliance
    compliance_example.setup_gdpr_compliance().await?;
    
    // Classify data
    let personal_data = b"John Doe, john@example.com, +1-555-0123";
    let classification = compliance_example.classify_data(personal_data).await?;
    
    // Handle data subject request
    compliance_example.handle_data_subject_request("user_123", "access").await?;
    
    // Generate compliance report
    compliance_example.generate_compliance_report(ComplianceStandard::GDPR).await?;
    
    println!("✅ Compliance framework demo completed!");
    
    Ok(())
}
```

## Performance Examples

### Benchmarking Encryption Algorithms

```rust
use fortress_core::prelude::*;
use fortress_core::encryption::{Aegis256, ChaCha20Poly1305, Aes256Gcm, EncryptionAlgorithm};
use std::time::Instant;

struct EncryptionBenchmark {
    test_data: Vec<u8>,
    iterations: usize,
}

impl EncryptionBenchmark {
    fn new(data_size: usize, iterations: usize) -> Self {
        Self {
            test_data: vec![0u8; data_size],
            iterations,
        }
    }
    
    fn benchmark_algorithm<T: EncryptionAlgorithm>(&self, algorithm: &T, name: &str) -> Result<(), Box<dyn std::error::Error>> {
        let key_manager = KeyManager::new();
        let key = key_manager.generate_key(algorithm)?;
        
        println!("🚀 Benchmarking: {}", name);
        
        // Benchmark encryption
        let start = Instant::now();
        for _ in 0..self.iterations {
            let ciphertext = algorithm.encrypt(&self.test_data, &key)?;
            // Prevent compiler optimization
            std::hint::black_box(ciphertext);
        }
        let encrypt_duration = start.elapsed();
        
        // Benchmark decryption
        let ciphertext = algorithm.encrypt(&self.test_data, &key)?;
        let start = Instant::now();
        for _ in 0..self.iterations {
            let plaintext = algorithm.decrypt(&ciphertext, &key)?;
            // Prevent compiler optimization
            std::hint::black_box(plaintext);
        }
        let decrypt_duration = start.elapsed();
        
        // Calculate metrics
        let data_size_mb = (self.test_data.len() * self.iterations) as f64 / 1_000_000.0;
        let encrypt_throughput = data_size_mb / encrypt_duration.as_secs_f64();
        let decrypt_throughput = data_size_mb / decrypt_duration.as_secs_f64();
        
        println!("   📊 Data size: {} MB", data_size_mb);
        println!("   ⏱️  Encryption: {:?} ({:.2} MB/s)", encrypt_duration, encrypt_throughput);
        println!("   ⏱️  Decryption: {:?} ({:.2} MB/s)", decrypt_duration, decrypt_throughput);
        println!("   📈 Total: {:?} ({:.2} MB/s)", 
                encrypt_duration + decrypt_duration, 
                data_size_mb / (encrypt_duration + decrypt_duration).as_secs_f64());
        
        Ok(())
    }
    
    fn run_comprehensive_benchmark(&self) -> Result<(), Box<dyn std::error::Error>> {
        println!("🔬 Running comprehensive encryption benchmark");
        println!("   Data size: {} bytes", self.test_data.len());
        println!("   Iterations: {}", self.iterations);
        println!();
        
        // Benchmark different algorithms
        let aegis = Aegis256::new();
        self.benchmark_algorithm(&aegis, "AEGIS-256")?;
        
        let chacha = ChaCha20Poly1305::new();
        self.benchmark_algorithm(&chacha, "ChaCha20-Poly1305")?;
        
        let aes = Aes256Gcm::new();
        self.benchmark_algorithm(&aes, "AES-256-GCM")?;
        
        println!("✅ Benchmark completed!");
        
        Ok(())
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create benchmark with 1MB data, 1000 iterations
    let benchmark = EncryptionBenchmark::new(1_048_576, 1000);
    
    benchmark.run_comprehensive_benchmark()?;
    
    Ok(())
}
```

### Load Testing

```rust
use fortress_core::prelude::*;
use tokio::task::JoinSet;
use std::sync::Arc;
use std::atomic::{AtomicU64, Ordering};

struct LoadTester {
    concurrent_requests: usize,
    total_requests: usize,
    success_count: Arc<AtomicU64>,
    error_count: Arc<AtomicU64>,
    total_time: Arc<AtomicU64>,
}

impl LoadTester {
    fn new(concurrent_requests: usize, total_requests: usize) -> Self {
        Self {
            concurrent_requests,
            total_requests,
            success_count: Arc::new(AtomicU64::new(0)),
            error_count: Arc::new(AtomicU64::new(0)),
            total_time: Arc::new(AtomicU64::new(0)),
        }
    }
    
    async fn run_load_test(&self) -> Result<(), Box<dyn std::error::Error>> {
        println!("🚀 Starting load test");
        println!("   Concurrent requests: {}", self.concurrent_requests);
        println!("   Total requests: {}", self.total_requests);
        println!();
        
        let start_time = std::time::Instant::now();
        let mut join_set = JoinSet::new();
        
        // Spawn concurrent tasks
        for i in 0..self.concurrent_requests {
            let requests_per_task = self.total_requests / self.concurrent_requests;
            let success_count = self.success_count.clone();
            let error_count = self.error_count.clone();
            let total_time = self.total_time.clone();
            
            join_set.spawn(async move {
                for j in 0..requests_per_task {
                    let request_start = std::time::Instant::now();
                    
                    // Simulate database operation
                    match simulate_database_operation(i, j).await {
                        Ok(_) => {
                            success_count.fetch_add(1, Ordering::Relaxed);
                        }
                        Err(_) => {
                            error_count.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                    
                    let request_duration = request_start.elapsed();
                    total_time.fetch_add(request_duration.as_millis() as u64, Ordering::Relaxed);
                }
            });
        }
        
        // Wait for all tasks to complete
        while let Some(result) = join_set.join_next().await {
            result??;
        }
        
        let total_duration = start_time.elapsed();
        let success_count = self.success_count.load(Ordering::Relaxed);
        let error_count = self.error_count.load(Ordering::Relaxed);
        let total_time_ms = self.total_time.load(Ordering::Relaxed);
        
        // Calculate metrics
        let total_operations = success_count + error_count;
        let success_rate = (success_count as f64 / total_operations as f64) * 100.0;
        let requests_per_second = total_operations as f64 / total_duration.as_secs_f64();
        let avg_response_time = total_time_ms as f64 / total_operations as f64;
        
        println!("📊 Load Test Results:");
        println!("   ⏱️  Total duration: {:?}", total_duration);
        println!("   📈 Total operations: {}", total_operations);
        println!("   ✅ Successful operations: {}", success_count);
        println!("   ❌ Failed operations: {}", error_count);
        println!("   📊 Success rate: {:.2}%", success_rate);
        println!("   🚀 Requests per second: {:.2}", requests_per_second);
        println!("   ⏱️  Average response time: {:.2} ms", avg_response_time);
        
        Ok(())
    }
}

async fn simulate_database_operation(task_id: usize, request_id: usize) -> Result<(), Box<dyn std::error::Error>> {
    // Simulate database operation with encryption
    let algorithm = Aegis256::new();
    let key_manager = KeyManager::new();
    let key = key_manager.generate_key(&algorithm)?;
    
    let data = format!("Test data from task {} request {}", task_id, request_id);
    let ciphertext = algorithm.encrypt(data.as_bytes(), &key)?;
    let _plaintext = algorithm.decrypt(&ciphertext, &key)?;
    
    // Simulate network latency
    tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
    
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Run load test with 50 concurrent requests, 1000 total requests
    let load_tester = LoadTester::new(50, 1000);
    
    load_tester.run_load_test().await?;
    
    println!("✅ Load test completed!");
    
    Ok(())
}
```

These examples demonstrate the comprehensive capabilities of Fortress across different use cases, from basic encryption to advanced multi-tenant applications, security compliance, and performance optimization. Each example is designed to be practical and can be adapted for real-world scenarios.
