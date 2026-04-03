# Fortress Authentication Plugins

WebAssembly-based authentication plugins for the Fortress security platform.

## Overview

The Fortress authentication plugin system provides secure, sandboxed authentication modules that can be dynamically loaded and executed. Each plugin implements specific authentication methods while maintaining security isolation through WebAssembly runtime.

## Available Plugins

### JWT Authentication Plugin (`jwt_plugin`)
- **Methods**: JWT token validation, Basic username/password
- **Features**: Token generation, validation, refresh, user management
- **Security**: HMAC-SHA256 signatures, configurable expiration
- **Use Case**: Stateless authentication for APIs and web services

### OAuth 2.0 / OpenID Connect Plugin (`oauth_plugin`)
- **Methods**: OAuth 2.0 authorization code flow, OpenID Connect
- **Features**: Authorization code flow, token exchange, user info retrieval
- **Security**: PKCE support, token validation, secure state management
- **Use Case**: Social login, enterprise SSO, third-party authentication

### SAML 2.0 Plugin (`saml_plugin`)
- **Methods**: SAML 2.0 assertion validation
- **Features**: Assertion parsing, attribute extraction, user mapping
- **Security**: XML signature validation, timestamp verification
- **Use Case**: Enterprise SSO, federated authentication

## Building

### Prerequisites
- Rust 1.70+ with WASM target: `rustup target add wasm32-unknown-unknown`
- Make (Linux/macOS) or PowerShell (Windows)

### Build Commands

#### Linux/macOS
```bash
cd plugins/auth
./build.sh
```

#### Windows
```powershell
cd plugins\auth
.\build.bat
```

### Manual Build
```bash
# Build individual plugin
rustc --target wasm32-unknown-unknown --crate-type bin src/jwt_plugin.rs -o target/wasm-plugins/jwt_plugin.wasm

# Build all plugins
cargo build --release --target wasm32-unknown-unknown
```

## Configuration

### JWT Plugin Configuration
```json
{
  "jwt_secret": "your-secret-key",
  "token_expiration": 3600,
  "issuer": "your-issuer",
  "audience": "your-audience"
}
```

### OAuth Plugin Configuration
```json
{
  "client_id": "your-client-id",
  "client_secret": "your-client-secret",
  "redirect_uri": "https://your-app.com/callback",
  "authorization_endpoint": "https://provider.com/oauth/authorize",
  "token_endpoint": "https://provider.com/oauth/token",
  "userinfo_endpoint": "https://provider.com/oauth/userinfo",
  "enable_pkce": true
}
```

### SAML Plugin Configuration
```json
{
  "entity_id": "https://your-app.com",
  "sso_url": "https://idp.com/sso",
  "certificate": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----",
  "clock_skew": 300
}
```

## Usage

### Loading Plugins
```rust
use fortress_auth_plugins::PluginRegistry;

let mut registry = PluginRegistry::new();
registry.initialize().await?;

// List available plugins
let plugins = registry.list_plugins();
for plugin in plugins {
    println!("Plugin: {} - {}", plugin.name, plugin.description);
}
```

### Authentication with JWT Plugin
```rust
use fortress_auth_plugins::AuthContext;

let context = AuthContext {
    method: "JWT".to_string(),
    credentials: serde_json::json!({
        "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
    }),
    request_id: "req-123".to_string(),
};

let result = registry.authenticate("jwt_auth", context).await?;
if result.success {
    println!("User authenticated: {}", result.user_id);
}
```

### Authentication with OAuth Plugin
```rust
let context = AuthContext {
    method: "OAuth".to_string(),
    credentials: serde_json::json!({
        "authorization_code": "auth-code-here",
        "redirect_uri": "https://your-app.com/callback"
    }),
    request_id: "req-456".to_string(),
};

let result = registry.authenticate("oauth_auth", context).await?;
```

### Authentication with SAML Plugin
```rust
let context = AuthContext {
    method: "SAML".to_string(),
    credentials: serde_json::json!({
        "saml_response": "base64-encoded-saml-response",
        "relay_state": "optional-relay-state"
    }),
    request_id: "req-789".to_string(),
};

let result = registry.authenticate("saml_auth", context).await?;
```

## Security Features

### WebAssembly Sandbox
- Memory isolation between plugins
- Controlled resource usage
- Secure host function interfaces
- No direct system access

### Cryptographic Security
- Industry-standard algorithms
- Secure key management
- Proper random number generation
- Timing attack protection

### Input Validation
- Comprehensive input sanitization
- Size limits on all inputs
- Malformed data rejection
- Attack vector prevention

## Performance

### Optimization Features
- Near-native WASM execution speed
- Minimal memory footprint (< 10MB per plugin)
- Fast initialization (< 100ms)
- Intelligent caching (5-15 minute TTL)

### Benchmarks
- JWT validation: < 5ms
- OAuth token exchange: < 50ms
- SAML assertion parsing: < 10ms
- Plugin loading: < 100ms

## Development

### Creating Custom Plugins

1. **Create Plugin Structure**
```rust
use fortress_auth_plugins::*;

#[no_mangle]
pub extern "C" fn plugin_init() -> u32 {
    // Plugin initialization
    0
}

#[no_mangle]
pub extern "C" fn plugin_authenticate(
    method_ptr: *const u8,
    method_len: usize,
    credentials_ptr: *const u8,
    credentials_len: usize,
) -> u32 {
    // Authentication logic
    0
}
```

2. **Build to WASM**
```bash
rustc --target wasm32-unknown-unknown --crate-type bin src/my_plugin.rs -o my_plugin.wasm
```

3. **Register Plugin**
```rust
registry.register_plugin("my_auth", "my_plugin.wasm")?;
```

### Host Functions
Plugins can call secure host functions:

- `log_message(level, message)`: Write logs
- `get_config(key)`: Retrieve configuration
- `get_timestamp()`: Get current time
- `store_session(key, value)`: Store session data
- `get_session(key)`: Retrieve session data
- `http_request(url, method, headers, body)`: Make HTTP requests

## Testing

### Unit Tests
```bash
cargo test --package fortress-auth-plugins
```

### Integration Tests
```bash
cargo test --test integration_tests
```

### WASM Tests
```bash
wasm-pack test --headless --firefox
```

## Deployment

### Production Deployment
1. Build plugins: `./build.sh`
2. Copy WASM files to production server
3. Update plugin configuration
4. Restart Fortress service
5. Verify plugin health: `curl http://localhost:8080/health/plugins`

### Monitoring
- Plugin health checks: `/health/plugins`
- Performance metrics: `/metrics/plugins`
- Error logs: `journalctl -u fortress -f`

## Troubleshooting

### Common Issues

#### Plugin Fails to Load
- Check WASM file integrity
- Verify plugin dependencies
- Check memory limits
- Review error logs

#### Authentication Fails
- Verify configuration
- Check credentials format
- Validate external service connectivity
- Review security policies

#### Performance Issues
- Monitor resource usage
- Check cache hit rates
- Review plugin complexity
- Optimize configuration

### Debug Mode
Enable debug logging:
```rust
env_logger::init();
registry.set_log_level(LogLevel::Debug);
```

## Security Considerations

### Production Security
- Use strong secrets and keys
- Enable HTTPS for all external calls
- Implement rate limiting
- Monitor for suspicious activity
- Regular security audits

### Plugin Security
- Validate all inputs
- Use secure memory management
- Implement proper error handling
- Avoid timing attacks
- Follow secure coding practices

## License

MIT License - see LICENSE file for details.

## Support

- Documentation: [Fortress Docs](https://docs.fortressdb.io)
- Issues: [GitHub Issues](https://github.com/fortress-security/fortress/issues)
- Community: [Discord](https://discord.gg/fortress)

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
    DeploymentStatus::Completed => println!("Plugin hot-swapped successfully"),
    DeploymentStatus::Failed => println!("Hot-swap failed: {:?}", status.error),
    _ => println!("Hot-swap in progress..."),
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

## Deployment Strategies

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

## Performance and Monitoring

### Health Checks
```rust
// Individual plugin health
let health_results = service.plugin_manager.health_check_all().await;
for (plugin, healthy) in health_results {
    println!("Plugin {}: {}", plugin, if healthy { "Healthy" } else { "Unhealthy" });
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
    println!("  Plugin Health: {}", if metric.plugin_healthy { "✓" } else { "✗" });
}
```

## Security Features

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

## Production Deployment

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
