# Hot-Swappable Authentication Plugin System

Fortress provides a **production-ready, hot-swappable authentication plugin system** that allows JWT, OAuth, SAML, and other authentication methods to be deployed, updated, and managed independently without system restarts.

## 🚀 Key Features

### **Plugin-Based Architecture**
- **WebAssembly Runtime**: Secure sandboxed execution environment
- **Hot-Swapping**: Zero-downtime plugin updates and replacements
- **Multi-Method Support**: JWT, OAuth 2.0, SAML 2.0, Basic Auth, API Keys
- **Independent Updates**: Each auth method can be updated separately

### **Deployment Strategies**
- **Rolling Updates**: Zero-downtime gradual replacement
- **Blue-Green**: Full environment switching with instant rollback
- **Canary**: Gradual traffic shifting with risk mitigation
- **Immediate**: Instant replacement for critical updates

### **Production Features**
- **Health Monitoring**: Continuous plugin health checks and auto-recovery
- **Performance Metrics**: Real-time authentication performance tracking
- **Automatic Rollback**: Failed deployments automatically revert
- **Circuit Breaker**: Prevents cascading failures

## 📁 Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│                    Fortress Core                             │
├─────────────────────────────────────────────────────────────┤
│  AuthPluginIntegrationService                               │
│  ├─ HotSwappableAuthPluginManager                           │
│  ├─ PluginAuthService                                       │
│  └─ Health Monitoring                                       │
├─────────────────────────────────────────────────────────────┤
│  WebAssembly Runtime                                        │
│  ├─ JWT Plugin (jwt_plugin.wasm)                           │
│  ├─ OAuth Plugin (oauth_plugin.wasm)                        │
│  ├─ SAML Plugin (saml_plugin.wasm)                         │
│  └─ Custom Plugins (extensible)                             │
└─────────────────────────────────────────────────────────────┘
```

## 🔧 Building and Deployment

### Prerequisites
```bash
# Install Rust target for WebAssembly
rustup target add wasm32-unknown-unknown

# Install cargo-wasi for WASM support (optional)
cargo install cargo-wasi
```

### Build Authentication Plugins
```bash
# Navigate to plugin directory
cd plugins/auth

# Build all plugins (Windows)
.\build.bat

# Build all plugins (Linux/Mac)
./build.sh

# Manual build for specific plugin
cargo build --release --bin jwt_plugin --target wasm32-unknown-unknown
```

### Generated Files
```
target/wasm-plugins/
├── jwt_plugin.wasm           # JWT authentication plugin
├── oauth_plugin.wasm         # OAuth 2.0 authentication plugin  
├── saml_plugin.wasm          # SAML 2.0 authentication plugin
└── plugin-manifest.json      # Plugin registry and metadata
```

## 💻 Usage Examples

### Basic Plugin Management
```rust
use fortress_core::{
    auth_plugin_integration::{AuthPluginIntegrationService, IntegrationConfig},
    auth_plugin_integration::DeploymentStrategy,
};

// Create integration service
let config = IntegrationConfig::default();
let service = AuthPluginIntegrationService::new(config)?;

// Initialize service
service.initialize().await?;

// Deploy JWT plugin
let deployment_id = service.deploy_plugin(
    "jwt",
    "./target/wasm-plugins/jwt_plugin.wasm",
    DeploymentStrategy::Rolling,
).await?;

// Test authentication
let credentials = json!({
    "username": "admin",
    "password": "admin123"
});

let result = service.test_authentication("jwt", credentials).await?;
println!("Auth result: {}", serde_json::to_string_pretty(&result)?);
```

### Hot-Swapping Plugins
```rust
// Hot-swap JWT plugin with zero downtime
let hot_swap_id = service.hot_swap_plugin(
    "jwt",
    "./target/wasm-plugins/jwt_plugin_v2.wasm",
    DeploymentStrategy::BlueGreen,
).await?;

// Monitor deployment status
let status = service.get_deployment_status(&hot_swap_id).await?;
match status.status {
    DeploymentStatus::Completed => println!("✅ Plugin hot-swapped successfully"),
    DeploymentStatus::Failed => println!("❌ Hot-swap failed: {:?}", status.error),
    _ => println!("⏳ Hot-swap in progress..."),
}
```

### Health Monitoring
```rust
// Get system health
let health = service.get_health_status().await;
println!("System health: {}", serde_json::to_string_pretty(&health)?);

// Get authentication method metrics
let metrics = service.get_auth_method_metrics().await;
for metric in metrics {
    println!("Method {}: {} requests, healthy: {}", 
             metric.method, metric.total_requests, metric.plugin_healthy);
}
```

## 🔐 Authentication Methods

### JWT Authentication
```rust
let jwt_credentials = json!({
    "username": "admin",
    "password": "admin123"
});

let result = service.test_authentication("jwt", jwt_credentials).await?;
// Returns JWT token and user information
```

### OAuth 2.0 Authentication
```rust
let oauth_credentials = json!({
    "authorization_code": "auth_code_from_provider",
    "state": "random_state_value",
    "redirect_uri": "http://localhost:8080/callback"
});

let result = service.test_authentication("oauth", oauth_credentials).await?;
// Returns access token and user profile
```

### SAML 2.0 Authentication
```rust
let saml_credentials = json!({
    "saml_assertion": "base64_encoded_saml_assertion"
});

let result = service.test_authentication("saml", saml_credentials).await?;
// Returns user information from SAML assertion
```

## 📊 Deployment Strategies

### Rolling Update (Zero Downtime)
```rust
let deployment = service.deploy_plugin(
    "jwt",
    "./target/wasm-plugins/jwt_plugin.wasm",
    DeploymentStrategy::Rolling,
).await?;
```
- Gradual replacement of plugin instances
- No service interruption
- Automatic rollback on failure

### Blue-Green Deployment
```rust
let deployment = service.deploy_plugin(
    "oauth",
    "./target/wasm-plugins/oauth_plugin.wasm", 
    DeploymentStrategy::BlueGreen,
).await?;
```
- Deploy alongside existing plugin
- Instant traffic switch
- Immediate rollback capability

### Canary Deployment
```rust
let deployment = service.deploy_plugin(
    "saml",
    "./target/wasm-plugins/saml_plugin.wasm",
    DeploymentStrategy::Canary { percentage: 10 },
).await?;
```
- Route percentage of traffic to new plugin
- Monitor performance before full rollout
- Risk mitigation for production updates

## 🛠️ Plugin Development

### Creating a Custom Authentication Plugin
```rust
// plugins/auth/src/custom_plugin.rs

use serde::{Deserialize, Serialize};

#[no_mangle]
pub extern "C" fn initialize() -> i32 {
    // Plugin initialization logic
    1 // Success
}

#[no_mangle]
pub extern "C" fn authenticate(
    request_ptr: *const u8,
    request_len: usize,
    response_ptr: *mut u8,
    response_len: usize
) -> i32 {
    // Authentication logic
    // Parse request, perform auth, generate response
    response_len as i32
}

#[no_mangle]
pub extern "C" fn validate_token(
    token_ptr: *const u8,
    token_len: usize,
    response_ptr: *mut u8,
    response_len: usize
) -> i32 {
    // Token validation logic
    1 // Success
}

// Add other required functions...
```

### Plugin Configuration
```toml
# plugins/auth/Cargo.toml
[[bin]]
name = "custom_plugin"
path = "src/custom_plugin.rs"
```

## 📈 Performance and Monitoring

### Health Checks
```rust
// Individual plugin health
let health_results = service.plugin_manager.health_check_all().await;
for (plugin, healthy) in health_results {
    println!("Plugin {}: {}", plugin, if healthy { "✅ Healthy" } else { "❌ Unhealthy" });
}
```

### Performance Metrics
```rust
let metrics = service.get_auth_method_metrics().await;
for metric in metrics {
    println!("Authentication Method: {}", metric.method);
    println!("  Total Requests: {}", metric.total_requests);
    println!("  Success Rate: {:.2}%", 
             (metric.successful_requests as f64 / metric.total_requests as f64) * 100.0);
    println!("  Avg Response Time: {:.2}ms", metric.avg_response_time_ms);
    println!("  Plugin Health: {}", if metric.plugin_healthy { "✅" } else { "❌" });
}
```

## 🔒 Security Features

### WebAssembly Sandbox
- **Memory Isolation**: Each plugin runs in isolated memory space
- **Resource Limits**: Configurable memory and CPU constraints
- **Secure Host Functions**: Controlled access to system resources
- **No Direct File Access**: Plugins cannot access filesystem directly

### Authentication Security
- **Input Validation**: All credentials validated before processing
- **Rate Limiting**: Built-in protection against brute force attacks
- **Audit Logging**: Complete audit trail for all authentication attempts
- **Token Security**: Secure token generation and validation

## 🚨 Production Deployment

### Configuration
```rust
let config = IntegrationConfig {
    enable_hot_swapping: true,
    plugin_directory: "/opt/fortress/wasm-plugins".to_string(),
    default_auth_method: "jwt".to_string(),
    enable_health_monitoring: true,
    health_check_interval: 30,
    auto_reload_on_failure: true,
    max_reload_attempts: 3,
};
```

### Docker Integration
```dockerfile
# Dockerfile
FROM rust:1.70 as builder
WORKDIR /app
COPY . .
RUN cargo build --release

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates
COPY --from=builder /app/target/wasm-plugins /opt/fortress/wasm-plugins
COPY --from=builder /app/target/release/fortress-server /usr/local/bin/
EXPOSE 8080
CMD ["fortress-server"]
```

### Kubernetes Deployment
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: fortress-auth
spec:
  replicas: 3
  selector:
    matchLabels:
      app: fortress-auth
  template:
    metadata:
      labels:
        app: fortress-auth
    spec:
      containers:
      - name: fortress
        image: fortress:latest
        ports:
        - containerPort: 8080
        volumeMounts:
        - name: wasm-plugins
          mountPath: /opt/fortress/wasm-plugins
      volumes:
      - name: wasm-plugins
        configMap:
          name: auth-wasm-plugins
```

## 🧪 Testing

### Run the Demo
```bash
# Build plugins first
cd plugins/auth && ./build.sh && cd ../..

# Run the hot-swapping demo
cargo run --example auth_plugin_hotswap_demo
```

### Unit Tests
```bash
# Run all authentication tests
cargo test auth

# Run specific plugin tests
cargo test auth_plugin
cargo test auth_integration
```

### Integration Tests
```bash
# Test plugin loading and authentication
cargo test --test auth_integration_tests

# Test hot-swapping functionality
cargo test --test hot_swap_tests
```

## 📚 API Reference

### AuthPluginIntegrationService
- `new(config)` - Create new integration service
- `initialize()` - Initialize service and load plugins
- `deploy_plugin(name, path, strategy)` - Deploy new plugin
- `hot_swap_plugin(name, path, strategy)` - Hot-swap existing plugin
- `test_authentication(method, credentials)` - Test auth method
- `get_health_status()` - Get system health
- `get_auth_method_metrics()` - Get performance metrics

### Deployment Strategies
- `Rolling` - Zero-downtime gradual replacement
- `BlueGreen` - Instant switch with rollback capability
- `Canary { percentage }` - Gradual traffic shifting
- `Immediate` - Instant replacement

### Configuration Options
- `enable_hot_swapping` - Enable/disable hot-swapping
- `plugin_directory` - Directory containing WASM plugins
- `default_auth_method` - Default authentication method
- `health_check_interval` - Health monitoring frequency
- `auto_reload_on_failure` - Automatic recovery on failure

## 🎯 Best Practices

### Plugin Development
1. **Memory Management**: Minimize memory allocations in plugins
2. **Error Handling**: Return proper error codes for all failure cases
3. **Performance**: Use efficient algorithms for authentication
4. **Security**: Validate all inputs and handle edge cases
5. **Testing**: Include comprehensive tests for all plugin functions

### Production Deployment
1. **Health Monitoring**: Always enable health monitoring in production
2. **Rollback Strategy**: Configure automatic rollback for failed deployments
3. **Performance Monitoring**: Track authentication latency and success rates
4. **Security Auditing**: Regularly audit authentication logs and plugin updates
5. **Resource Limits**: Set appropriate memory and CPU limits for plugins

### Hot-Swapping
1. **Test Thoroughly**: Test new plugins in staging before production
2. **Monitor Closely**: Watch system metrics during hot-swap operations
3. **Rollback Ready**: Always have rollback plan ready
4. **Gradual Rollout**: Use canary deployments for major updates
5. **Document Changes**: Maintain detailed deployment history

## 🔗 Related Components

- **WebAssembly Runtime**: `crates/fortress-core/src/wasm_runtime.rs`
- **Plugin System**: `crates/fortress-core/src/plugin.rs`
- **Authentication Core**: `crates/fortress-core/src/auth.rs`
- **Security Framework**: `crates/fortress-core/src/security.rs`

---

**The Fortress hot-swappable authentication plugin system provides enterprise-grade, production-ready authentication management with zero-downtime updates and comprehensive monitoring capabilities.**
